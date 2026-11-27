package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randLabel(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}
	return string(b)
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

func realityKeys() (string, string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		die("生成 Reality 密钥失败: %v", err)
	}
	e := base64.RawURLEncoding
	return e.EncodeToString(k.Bytes()), e.EncodeToString(k.PublicKey().Bytes())
}

// 官方默认填充方案人人都用，包长分布本身就成了特征；
// 这里每台机器随机生成一份，由服务端下发给客户端
func randPadding() []string {
	r := func(a, b int) int { return a + mrand.IntN(b-a+1) }
	rng := func(lo, hi, minw, maxw int) string {
		a := r(lo, hi)
		return fmt.Sprintf("%d-%d", a, a+r(minw, maxw))
	}
	stop := r(6, 10)
	lines := []string{
		fmt.Sprintf("stop=%d", stop),
		"0=" + rng(20, 70, 10, 90), // 认证包，官方固定 30，抓包里就是固定的 86 字节
		"1=" + rng(90, 300, 80, 300),
	}
	// 2 号包装着内层 ClientHello，多切几段打散
	segs := []string{rng(300, 600, 100, 300)}
	for i, n := 0, r(2, 4); i < n; i++ {
		segs = append(segs, "c", rng(400, 900, 100, 400))
	}
	lines = append(lines, "2="+strings.Join(segs, ","))
	for i := 3; i < stop; i++ {
		seg := rng(200, 900, 100, 500)
		if mrand.IntN(3) == 0 {
			seg += "," + rng(300, 900, 100, 400)
		}
		lines = append(lines, fmt.Sprintf("%d=%s", i, seg))
	}
	return lines
}

func ensureToken(st *State) {
	if st.Token == "" {
		st.Token = randLabel(16)
	}
}

// ── Cloudflare 域名 ──────────────────────────────────
func cfPickZone(st *State, c *CF) {
	if st.Zone != nil {
		return
	}
	zs, err := c.Zones()
	if err != nil {
		die("读取域名列表失败: %v", err)
	}
	if len(zs) == 0 {
		die("这个 CF 账号下没有已激活的域名，先把域名接入 Cloudflare")
	}
	fmt.Fprintln(os.Stderr)
	info("选一个域名：")
	names := []string{}
	for _, z := range zs {
		names = append(names, z.Name)
	}
	i := choose(names, 1)
	if i < 0 {
		die("已取消")
	}
	st.Zone = &Zone{ID: zs[i].ID, Name: zs[i].Name, NS: zs[i].NS, Account: zs[i].Account.ID}
	st.save()
	ok("域名: %s", st.Zone.Name)
}

var reLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// 选子域名；已有解析时问一句，覆盖前备份，卸载时还原
func cfPickHost(st *State, c *CF, hint string) (string, []DNSRecord) {
	return cfPickHostUnder(st, c, hint, st.Zone.Name)
}

func cfPickHostUnder(st *State, c *CF, hint, parent string) (string, []DNSRecord) {
	for {
		l := strings.ToLower(ask(hint+" 子域名前缀，回车随机", randLabel(6)))
		l = strings.Split(l, ".")[0]
		if !reLabel.MatchString(l) {
			warn("只能用字母、数字和中划线")
			continue
		}
		host := l + "." + parent
		if (st.TLS != nil && st.TLS.Host == host) || (st.WS != nil && st.WS.Host == host) ||
			(st.Argo != nil && st.Argo.Host == host) {
			warn("%s 已经被本脚本用了", host)
			continue
		}
		rs, err := c.DNSList(st.Zone.ID, host)
		if err != nil {
			die("查询解析失败: %v", err)
		}
		var bk []DNSRecord
		if len(rs) > 0 {
			var desc []string
			tunnel := false
			for _, r := range rs {
				desc = append(desc, r.Type+" "+r.Content)
				bk = append(bk, r.DNSRecord)
				tunnel = tunnel || (r.Type == "CNAME" && strings.HasSuffix(strings.ToLower(r.Content), ".cfargotunnel.com"))
			}
			warn("%s 已有 %d 条解析：%s", host, len(rs), strings.Join(desc, ", "))
			if tunnel {
				warn("它正被一条 CF 隧道使用，覆盖后那条隧道上这个域名的节点会断，卸载 dun 时才会恢复。建议换个名字")
			}
			if !confirm("覆盖它？卸载时会还原", false) {
				continue
			}
		}
		return host, bk
	}
}

// 删掉这个名字下的所有解析；原有的在选子域名时已经备份过
func dnsClear(st *State, c *CF, host string) {
	if rs, err := c.DNSList(st.Zone.ID, host); err == nil {
		for _, r := range rs {
			c.DNSDelete(st.Zone.ID, r.ID)
		}
	}
}

func dnsSet(st *State, c *CF, host string, proxied bool) string {
	dnsClear(st, c, host)
	rec := DNSRecord{Type: "A", Name: host, Content: st.IP4, Proxied: proxied, TTL: 1, Comment: "dun"}
	if st.IP4 == "" {
		rec.Type, rec.Content = "AAAA", st.IP6
	}
	id, err := c.DNSCreate(st.Zone.ID, rec)
	if err != nil {
		die("添加解析失败: %v", err)
	}
	return id
}

func dnsDrop(st *State, c *CF, host, id string, backup []DNSRecord) {
	if c == nil || st.Zone == nil {
		warn("没有 CF 凭据，%s 的解析请自己去 CF 后台删", host)
		return
	}
	if id != "" {
		c.DNSDelete(st.Zone.ID, id)
	}
	for _, r := range backup {
		if _, err := c.DNSCreate(st.Zone.ID, r); err == nil {
			info("已还原 %s 原有的 %s 解析", host, r.Type)
		}
	}
}

func wsRules(st *State, c *CF) {
	host, zid := st.WS.Host, st.Zone.ID
	expr := fmt.Sprintf(`(http.host eq "%s")`, host)
	if err := c.RuleUpsert(zid, "http_request_origin", rulePrefix+host, map[string]any{
		"expression": expr, "action": "route",
		"action_parameters": map[string]any{"origin": map[string]any{"port": st.WS.PubPort}},
	}); err != nil {
		die("写回源规则失败: %v", err)
	}
	// 只对这个子域名改 SSL 和安全级别，整个域名的设置不动
	if err := c.RuleUpsert(zid, "http_config_settings", rulePrefix+host, map[string]any{
		"expression": expr, "action": "set_config",
		"action_parameters": map[string]any{"ssl": "flexible", "security_level": "essentially_off", "bic": false},
	}); err != nil {
		die("写配置规则失败: %v", err)
	}
	if c.Setting(zid, "websockets") != "on" {
		if c.SetSetting(zid, "websockets", "on") == nil {
			info("已打开 CF 的 WebSockets 开关")
		}
	}
}

// 偷自己、AnyTLS、Hysteria2、TUIC 共用一个只解析、不走 CF 代理的子域名。
// 证书签成 *.<随机>.<域名>：证书公开日志里只有通配符，扫描器拿不到真正的节点域名
func pickTLSHost(st *State, c *CF) *TLSHost {
	mid := randLabel(5) + "." + st.Zone.Name
	host, bk := cfPickHostUnder(st, c, "节点域名", mid)
	id := dnsSet(st, c, host, false)
	ok("解析 %s → %s（仅 DNS）", host, st.srvAddr())
	return &TLSHost{Host: host, CertName: "*." + mid, RecordID: id, Backup: bk}
}

func tlsHostEnsure(st *State) {
	c := cfLogin()
	if st.TLS == nil {
		cfPickZone(st, c)
		fmt.Fprintln(os.Stderr)
		info("Reality 偷自己、AnyTLS、Hysteria2、TUIC 共用一个子域名，只做解析，不开 CF 代理")
		st.TLS = pickTLSHost(st, c)
		st.save()
	}
	if _, has := certExpiry(); has {
		return
	}
	info("申请证书 %s（DNS 验证，大概半分钟）", certLabel(st))
	if err := issueCert(st, c); err != nil {
		die("证书申请失败：%v", err)
	}
	ok("证书已签发")
}

func certLabel(st *State) string {
	if st.TLS.CertName != "" {
		return st.TLS.CertName
	}
	return st.TLS.Host
}

// 节点域名被盯上了，或者从老版本的单域名证书升级上来，就换一个
func changeNodeHost(st *State) {
	if st.TLS == nil {
		warn("还没装用节点域名的协议")
		return
	}
	c := cfLogin()
	old := *st.TLS
	info("现在的节点域名：%s，证书：%s", old.Host, certLabel(st))
	fresh := pickTLSHost(st, c)
	st.TLS = fresh
	info("申请证书 %s", fresh.CertName)
	if err := issueCert(st, c); err != nil {
		c.DNSDelete(st.Zone.ID, fresh.RecordID)
		st.TLS = &old
		st.save()
		die("证书申请失败，没换：%v", err)
	}
	applyAll(st)
	dnsDrop(st, c, old.Host, old.RecordID, old.Backup)
	ok("节点域名已换成 %s，旧的解析删了；订阅会自动更新，单独导入的链接要重新导入", fresh.Host)
}

func tlsHostRelease(st *State) {
	if st.needTLS() || st.TLS == nil {
		return
	}
	dnsDrop(st, cfLoad(), st.TLS.Host, st.TLS.RecordID, st.TLS.Backup)
	os.RemoveAll(certDir)
	ok("已删除 %s 的解析和证书", st.TLS.Host)
	st.TLS = nil
	st.save()
}

func zoneRelease(st *State) {
	if st.TLS == nil && st.WS == nil && st.Argo == nil {
		st.Zone = nil
		st.save()
	}
}

// ── 安装 ─────────────────────────────────────────────
func defPort(st *State, want int) int {
	if o := portOwner(want); o != "" && o != "ours" {
		warn("%d 被 %s 占用", want, o)
		return randPort(st)
	}
	if _, u := st.usedPorts("")[want]; u {
		return randPort(st)
	}
	return want
}

func installReality(st *State) {
	if st.Reality != nil {
		warn("Reality 偷自己已经装过了，改端口、换密钥走管理菜单")
		return
	}
	hr()
	info("安装 VLESS + Vision + Reality（偷自己）")
	port := askPort(st, "Reality 监听端口", defPort(st, 443), "reality")
	pub := askPubPort(st, port)
	tlsHostEnsure(st)
	ensureToken(st)
	priv, pubk := realityKeys()
	st.Reality = &Reality{Port: port, PubPort: pub, Fallback: randPort(st, port), UUID: newUUID(),
		PrivateKey: priv, PublicKey: pubk, ShortID: randHex(8)}
	fwOpen(port)
	applyAll(st)
	ok("Reality 偷自己 安装完成")
}

func installAnyTLS(st *State) {
	if st.AnyTLS != nil {
		warn("AnyTLS 已经装过了，改端口、换密码走管理菜单")
		return
	}
	hr()
	info("安装 AnyTLS")
	port := askPort(st, "AnyTLS 监听端口", defPort(st, 443), "anytls")
	pub := askPubPort(st, port)
	tlsHostEnsure(st)
	st.AnyTLS = &AnyTLS{Port: port, PubPort: pub, Password: newUUID(), Padding: randPadding()}
	fwOpen(port)
	applyAll(st)
	ok("AnyTLS 安装完成，填充方案是这台机器随机生成的")
}

func installWS(st *State) {
	if st.WS != nil {
		warn("CF WS 已经装过了，改端口、换 UUID 走管理菜单")
		return
	}
	hr()
	info("安装 VLESS + WS，走 Cloudflare CDN")
	port := askPort(st, "WS 监听端口（CF 回源到这个端口）", randPort(st), "ws")
	pub := askPubPort(st, port)
	c := cfLogin()
	cfPickZone(st, c)
	fmt.Fprintln(os.Stderr)
	info("CF WS 单独用一个子域名，会开 CF 代理（橙云）")
	host, bk := cfPickHost(st, c, "WS 域名")
	ensureToken(st)
	st.WS = &WS{Host: host, Port: port, PubPort: pub, Inner: randPort(st, port), UUID: newUUID(),
		Path: "/" + randLabel(10), Backup: bk}
	fwOpen(port)
	applyAll(st)
	st.WS.RecordID = dnsSet(st, c, host, true)
	st.save()
	ok("解析 %s → %s（CF 代理）", host, st.srvAddr())
	wsRules(st, c)
	ok("CF 回源规则：%s → 端口 %d，SSL 只对这个子域名用 Flexible", host, pub)
	if st.CFIP.fetches() {
		if n, err := refreshWetest(st); err != nil {
			warn("优选 IP 拉取失败：%v", err)
		} else {
			ok("拉到 %d 个优选 IP", n)
		}
	}
	ok("CF WS 安装完成，新解析生效可能要一两分钟")
}

func removeReality(st *State) {
	if st.Reality == nil {
		warn("Reality 没装")
		return
	}
	st.Reality = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("Reality 已卸载")
}

func removeAnyTLS(st *State) {
	if st.AnyTLS == nil {
		warn("AnyTLS 没装")
		return
	}
	st.AnyTLS = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("AnyTLS 已卸载")
}

func removeWS(st *State) {
	if st.WS == nil {
		warn("CF WS 没装")
		return
	}
	w := *st.WS
	if c := cfLoad(); c != nil && st.Zone != nil {
		c.RuleRemove(st.Zone.ID, "http_request_origin", rulePrefix+w.Host)
		c.RuleRemove(st.Zone.ID, "http_config_settings", rulePrefix+w.Host)
		dnsDrop(st, c, w.Host, w.RecordID, w.Backup)
		ok("已清理 %s 的解析和 CF 规则", w.Host)
	} else {
		warn("没有 CF 凭据，%s 的解析和规则请自己去 CF 后台删", w.Host)
	}
	st.WS = nil
	applyAll(st)
	if st.Argo == nil { // Argo 也用这份优选缓存
		os.Remove(wetestPath)
	}
	zoneRelease(st)
	ok("CF WS 已卸载")
}

// UDP 端口里找一段没人用的；avoid 是本脚本别的 UDP 协议（TUIC）的端口，还没起来时 /proc 里查不到
func freeUDPRange(width int, avoid ...int) (int, int) {
	busy := map[int]bool{}
	for _, p := range avoid {
		busy[p] = true
	}
	for _, f := range []string{"udp", "udp6"} {
		b, _ := os.ReadFile(procDir + "/net/" + f)
		for i, line := range strings.Split(string(b), "\n") { // 不看状态：未连接（07）和已连接（01）的都算占用
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 4 {
				continue
			}
			if p, err := strconv.ParseUint(fs[1][strings.LastIndex(fs[1], ":")+1:], 16, 32); err == nil {
				busy[int(p)] = true
			}
		}
	}
	for i := 0; i < 50; i++ {
		a := 20000 + mrand.IntN(45000-width)
		clash := false
		for p := a; p < a+width && !clash; p++ {
			clash = busy[p]
		}
		if !clash {
			return a, a + width - 1
		}
	}
	return 0, 0
}

// UDP 端口 p 是不是分给了本脚本 key 以外的 UDP 协议。Hy2 的整个跳跃范围都算：
// REDIRECT 占着的端口在 /proc/net/udp 里查不到，可发到那里的包都会被转给 Hy2
func (st *State) udpTaken(p int, key string) bool {
	if h := st.Hy2; h != nil && key != "hy2" && (p == h.Port || (h.HopStart > 0 && p >= h.HopStart && p <= h.HopEnd)) {
		return true
	}
	return st.TUIC != nil && key != "tuic" && p == st.TUIC.Port
}

// 已装 TUIC 的监听端口和外网端口，算 Hy2 跳跃范围时都要避开：端口方式从映射切到直连后，TUIC 可能还留着映射的外网端口
func (st *State) tuicPorts() []int {
	if st.TUIC == nil {
		return nil
	}
	return []int{st.TUIC.Port, st.TUIC.PubPort}
}

func askUDPPort(st *State, key string, def int) int {
	for {
		p := askInt(protoLabel(key)+" 监听端口（UDP）", def, 1, 65535)
		if st.udpTaken(p, key) {
			reask("UDP %d 已经分给本脚本的其他协议了（Hy2 的跳跃范围也算）", p)
			continue
		}
		if o := udpOwner(p); o != "" && o != "ours" {
			reask("UDP %d 被 %s 占用，换一个", p, o)
			continue
		}
		return p
	}
}

// 问外网端口（def 是默认值），返回监听端口和外网端口。两个 UDP 协议的外网端口不能重，否则链接指到同一个公网端口。
// 端口方式是全局的，可能刚从映射切到直连：直连时外网端口就是监听端口，撞了另一个协议留着的外网端口就得换监听端口
func askUDPPub(st *State, key string, port, def int) (int, int) {
	for {
		pub := askPubPort(st, def)
		if !st.udpPubTaken(pub, key) {
			return port, pub
		}
		reask("外网 UDP %d 已经分给本脚本的其他协议了，换一个", pub)
		if st.PortMode != portMapped {
			port = askUDPPort(st, key, port)
			def = port
		}
	}
}

// 外网端口撞了另一个 UDP 协议的监听端口、外网端口或 Hy2 跳跃范围
func (st *State) udpPubTaken(pub int, key string) bool {
	return st.udpTaken(pub, key) || (st.Hy2 != nil && key != "hy2" && pub == st.Hy2.PubPort) ||
		(st.TUIC != nil && key != "tuic" && pub == st.TUIC.PubPort)
}

func randUDPPort(st *State, key string) int {
	for i := 0; i < 100; i++ {
		p := 20000 + mrand.IntN(40000)
		if udpOwner(p) == "" && !st.udpTaken(p, key) {
			return p
		}
	}
	return 0
}

// 密码、混淆包长、跳跃间隔全部随机，每台机器不一样
func newHy2(port, pub int) *Hy2 {
	r := func(a, b int) int { return a + mrand.IntN(b-a+1) }
	h := &Hy2{Port: port, PubPort: pub, Password: randLabel(32), Obfs: randLabel(24), HopSec: r(12, 40)}
	h.MaxPkt = r(1000, 1250)
	h.MinPkt = r(300, h.MaxPkt-250)
	h.CMaxPkt = r(1000, 1250)
	h.CMinPkt = r(300, h.CMaxPkt-250)
	return h
}

func setHy2Range(h *Hy2, mode string, avoid ...int) {
	switch {
	case mode == portMapped:
		h.HopStart, h.HopEnd = 0, 0
		info("使用服务商分配的 UDP 端口，Hy2 走单端口")
	case !hopUsable(): // 已有范围也要探测：换到不让加 nat 规则的环境后别再发跳不过去的范围
		h.HopStart, h.HopEnd = 0, 0
		warn("这台机器加不了 iptables 的端口转发规则，Hy2 走单端口")
	case h.HopStart == 0:
		h.HopStart, h.HopEnd = freeUDPRange(r2(2000, 6000), avoid...)
	}
}

// 端口跳跃靠 iptables 的 nat 规则把一段 UDP 转到 Hy2 端口。没有 iptables 就先装；
// 装不上，或者容器不让加 nat 规则，就别分配跳跃范围，免得订阅里带着跳不过去的端口
var hopUsable = func() bool {
	if !have("iptables") {
		info("端口跳跃要用 iptables，先装上")
		pkgInstall("iptables")
	}
	if !have("iptables") {
		return false
	}
	probe := []string{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "1", "-m", "comment", "--comment", hopTag + "-probe", "-j", "REDIRECT", "--to-ports", "2"}
	if run("iptables", probe...) != nil {
		return false
	}
	probe[2] = "-D"
	if run("iptables", probe...) != nil {
		warn("端口跳跃的探测规则没删掉，请自己删：iptables %s", strings.Join(probe, " "))
		return false
	}
	return true
}

func installHy2(st *State) {
	if st.Hy2 != nil {
		warn("Hysteria2 已经装过了，跳过；改端口、换密码走管理菜单")
		return
	}
	hr()
	info("安装 Hysteria2：gecko 混淆 + 端口跳跃，参数每台机器随机")
	port := askUDPPort(st, "hy2", randUDPPort(st, "hy2"))
	port, pub := askUDPPub(st, "hy2", port, port)
	h := newHy2(port, pub)
	setHy2Range(h, st.PortMode, st.tuicPorts()...)
	tlsHostEnsure(st)
	st.Hy2 = h
	fwOpenProto(fmt.Sprint(port), "udp")
	if h.HopStart > 0 {
		fwOpenProto(fmt.Sprintf("%d:%d", h.HopStart, h.HopEnd), "udp")
	}
	applyAll(st)
	ok("Hysteria2 安装完成")
	if h.HopStart > 0 {
		ok("端口跳跃：UDP %d-%d 都转到 %d", h.HopStart, h.HopEnd, port)
	}
	info("甲骨文、谷歌云、AWS 这类机器，云后台的安全组要放行 UDP")
}

// 不开 0-RTT：会被重放。拥塞控制用 bbr，丢包多的线路上比默认的 cubic 快
func installTUIC(st *State) {
	if st.TUIC != nil {
		warn("TUIC v5 已经装过了，跳过；改端口、换密码走管理菜单")
		return
	}
	hr()
	info("安装 TUIC v5（QUIC），和 Hy2 共用节点域名和证书，端口各用各的")
	port := askUDPPort(st, "tuic", randUDPPort(st, "tuic"))
	port, pub := askUDPPub(st, "tuic", port, port)
	tlsHostEnsure(st)
	st.TUIC = &TUIC{Port: port, PubPort: pub, UUID: newUUID(), Password: randLabel(32), CC: "bbr"}
	fwOpenProto(fmt.Sprint(port), "udp")
	applyAll(st)
	ok("TUIC v5 安装完成")
	info("云后台有安全组的（甲骨文、AWS、Azure NSG 这类），要放行 UDP %d", pub)
}

// 菜单「安装 HY2 | TUIC5」的选项，和 udpPlan 一一对应
var udpChoices = []string{"一起安装 HY2 + TUIC5（默认，直接回车）", "仅安装 HY2", "仅安装 TUIC5"}

func udpPlan(i int) []string { return [][]string{{"hy2", "tuic"}, {"hy2"}, {"tuic"}}[i] }

var udpInstallers = map[string]func(*State){"hy2": installHy2, "tuic": installTUIC} // 测试里换成记录调用的替身

// 已经装了的那个由 installHy2 / installTUIC 自己提示跳过，凭据和端口不动
func installUDP(st *State) {
	i := choose(udpChoices, 1)
	if i < 0 {
		return
	}
	for _, k := range udpPlan(i) {
		udpInstallers[k](st)
	}
}

func r2(a, b int) int { return a + mrand.IntN(b-a+1) }

func removeHy2(st *State) {
	if st.Hy2 == nil {
		warn("Hysteria2 没装")
		return
	}
	st.Hy2 = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("Hysteria2 已卸载")
}

func removeTUIC(st *State) {
	if st.TUIC == nil {
		warn("TUIC v5 没装")
		return
	}
	st.TUIC = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("TUIC v5 已卸载")
}
