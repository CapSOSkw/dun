package main

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Argo 隧道 + VLESS + XHTTP：
//
//	客户端 ─TLS(h2 走 TCP / h3 走 UDP)─> CF 边缘 ══> 隧道 ══> cloudflared（VPS 主动连出去）
//	  ├─ <Argo 域名> + XHTTP 路径 → 127.0.0.1:Inner  Xray
//	  └─ <Argo 域名> 其他请求     → 127.0.0.1:Web    dun（伪装站 + 订阅）
//
// 隧道路由由 dun 用 API 写在 CF 上，VPS 一个公网端口都不开。
// XHTTP 经过 Argo 只有 packet-up 能通，stream-up / stream-one 都不行，订阅里固定写 packet-up

// ── Xray / cloudflared 二进制 ───────────────────────
func binVersion(bin string, field int, args ...string) string {
	out, err := runOut(bin, args...)
	if err != nil {
		return ""
	}
	f := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if len(f) > field {
		return f[field]
	}
	return ""
}

// 第一行形如 Xray 26.11.9 (Xray, Penetrates Everything.) ...
func xrayVersionAt(bin string) string { return binVersion(bin, 1, "version") }
func xrayVersion() string             { return xrayVersionAt(xrayBin) }

// 第一行形如 cloudflared version 2026.11.2 (built ...)
func cfdVersionAt(bin string) string { return binVersion(bin, 2, "--version") }
func cfdVersion() string             { return cfdVersionAt(cfdBin) }

// 重启服务，等一会儿看还在不在跑
func restartCheck(svc string, wait time.Duration) error {
	if err := svcDo("restart", svc); err != nil {
		return err
	}
	sleep(wait)
	if !svcActive(svc) {
		return fmt.Errorf("%s 重启后没在运行", svc)
	}
	return nil
}

// 新文件先放在 .new，自己能跑才换上去，跑不起来就删掉，原来的不动；
// 换上去以后跑不起来就换回旧的。旧的留成 .old，更新后服务起不来时回退用
func placeBin(bin, name string, ver func(string) string) {
	if ver(bin+".new") == "" {
		os.Remove(bin + ".new")
		die("新下载的 %s 跑不起来，原来的没动", name)
	}
	had, err := present(bin) // 悬空的符号链接也算原来有，一样挪成 .old、失败时换回
	if err != nil {
		os.Remove(bin + ".new")
		die("查不了 %s，原来的没动: %v", bin, err)
	}
	if had {
		if err := os.Rename(bin, bin+".old"); err != nil {
			os.Remove(bin + ".new")
			die("%s 换不上去，原来的没动: %v", name, err)
		}
	}
	err = os.Rename(bin+".new", bin)
	if err == nil && ver(bin) == "" {
		err = fmt.Errorf("换上去跑不起来")
	}
	if err != nil {
		os.Remove(bin + ".new")
		os.Remove(bin)
		if had {
			if rerr := os.Rename(bin+".old", bin); rerr != nil {
				warn("换回原来的 %s 失败，手动把 %s.old 改回 %s: %v", name, bin, bin, rerr)
			}
		}
		die("%s %v，已换回原来的", name, err)
	}
}

// 手动把 .old 换回去的命令：现在占着位置的（文件、目录、符号链接）先挪成 .bad.<时间>，内容留着
func restoreCmd(bin, svc string) string {
	restart := "systemctl restart " + svc
	if initSys != "systemd" {
		restart = "rc-service " + svc + " restart"
	}
	return fmt.Sprintf("{ { [ ! -e %[1]s ] && [ ! -L %[1]s ]; } || mv %[1]s %[1]s.bad.$(date +%%s); } && mv %[1]s.old %[1]s && %[2]s", bin, restart)
}

// 路径上有没有目录项，悬空的符号链接也算；查不了返回 error
func present(p string) (bool, error) {
	_, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// 更新前看有没有上次留下的 .old，返回原来有没有装、能不能接着更新。
// 更新成功后 .old 会删掉，还在就说明上次失败了，交给人处理：不删、不更新，打出手动命令
func prepOld(bin, svc string) (had, goOn bool) {
	old, err := present(bin + ".old")
	if err != nil {
		warn("查不了 %s.old: %v，这次不更新", bin, err)
		return false, false
	}
	if old {
		warn("%s.old 是上次更新失败留下的旧版本，这次不更新。确认要换回旧版本：%s；确认现在的能用：rm %s.old", bin, restoreCmd(bin, svc), bin)
		return false, false
	}
	had, err = present(bin)
	if err != nil {
		warn("查不了 %s: %v，这次不更新", bin, err)
		return false, false
	}
	return had, true
}

// 测试里换掉，不真等
var sleep = time.Sleep

// 更新后服务起不来：换回 .old 再重启。原来没有装就把新的删掉，不留在正式路径上；
// 换不回去时不重启，免得再起一次坏的
func rollbackBin(bin, svc string, had bool) {
	if !had {
		if err := os.Remove(bin); err != nil {
			warn("原来没有装 %s，新装的也删不掉: %v，手动删掉它", bin, err)
			return
		}
		warn("原来没有装 %s，新装的跑不起来，已删掉", bin)
		return
	}
	if err := os.Rename(bin+".old", bin); err != nil {
		warn("换回旧版本失败: %v。%s 没有重启，手动恢复：%s", err, svc, restoreCmd(bin, svc))
		return
	}
	if err := svcDo("restart", svc); err != nil {
		warn("已换回旧版本，但 %s 重启失败: %v，看看日志", svc, err)
		return
	}
	ok("已换回旧版本")
}

func unzipOne(zf, name, dst string) error {
	zr, err := zip.OpenReader(zf)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Base(f.Name) != name {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, src)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	}
	return fmt.Errorf("包里没有 %s", name)
}

func xrayInstall(ver string) {
	if ver == "" {
		ver = xrayPinned
	}
	arch := map[string]string{"amd64": "64", "arm64": "arm64-v8a"}[runtime.GOARCH]
	if arch == "" {
		die("Xray 暂不支持 %s", runtime.GOARCH)
	}
	info("下载 Xray %s", ver)
	os.MkdirAll(path.Dir(xrayBin), 0755)
	zf := xrayBin + ".zip"
	defer os.Remove(zf)
	if err := dlVerified("XTLS/Xray-core", "v"+ver, "Xray-linux-"+arch+".zip", zf, 0600); err != nil {
		die("Xray 下载失败: %v", err)
	}
	if err := unzipOne(zf, "xray", xrayBin+".new"); err != nil {
		os.Remove(xrayBin + ".new")
		die("Xray 包解不开: %v", err)
	}
	placeBin(xrayBin, "Xray", xrayVersionAt)
	ok("Xray %s", xrayVersion())
}

func cfdInstall(ver string) {
	if ver == "" {
		ver = cfdPinned
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		die("cloudflared 暂不支持 %s", runtime.GOARCH)
	}
	info("下载 cloudflared %s", ver)
	os.MkdirAll(path.Dir(cfdBin), 0755)
	if err := dlVerified("cloudflare/cloudflared", ver, "cloudflared-linux-"+runtime.GOARCH, cfdBin+".new", 0755); err != nil {
		die("cloudflared 下载失败: %v", err)
	}
	placeBin(cfdBin, "cloudflared", cfdVersionAt)
	ok("cloudflared %s", cfdVersion())
}

// 复用别人的隧道时不用 cloudflared
func ensureArgoBins(cfd bool) {
	if !exists(xrayBin) {
		xrayInstall("")
	}
	if cfd && !exists(cfdBin) {
		cfdInstall("")
	}
}

// ── Xray 配置 ───────────────────────────────────────
// 和服务端 sing-box 一样只拦两样：BT 和访问内网地址
var privateNets = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8"}

func xrayConfig(st *State) map[string]any {
	a := st.Argo
	return map[string]any{
		// access 不写会把访问记录（每个目标网站）打到 stdout，进 journald，所以关掉
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		// 只听 127.0.0.1，外面连不到；TLS 在 CF 边缘就解开了，这里不用证书
		"inbounds": []any{map[string]any{
			"tag": "argo", "listen": "127.0.0.1", "port": a.Inner, "protocol": "vless",
			"settings": map[string]any{"clients": []any{map[string]any{"id": a.UUID}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "xhttp",
				"xhttpSettings": map[string]any{"path": a.Path, "mode": "auto"}},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		}},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		// 目标是域名时先解析再比对 IP，不然 localhost、*.nip.io 这类域名能绕过内网拦截
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []any{
			map[string]any{"protocol": []string{"bittorrent"}, "outboundTag": "block"},
			map[string]any{"ip": privateNets, "outboundTag": "block"},
		}},
	}
}

var svcExists = func(name string) bool { // 测试里换掉
	return exists("/etc/systemd/system/"+name+".service") || exists("/etc/init.d/"+name)
}

// 由 applyAll 调用，Xray 配置已经检查过、换好了。配置没变就不重启，免得 Argo 节点断线；
// cloudflared 的路由在 CF 上，平时也不用重启它。一步出错也接着做完，错误汇总返回
func xrayApply(st *State, changed bool) error {
	var errs []error
	add := func(err error, what string) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", what, err))
		}
	}
	if st.Argo == nil { // 单元文件不在、也没在跑的，svcDisable 直接当已停好；文件不在但还在跑的照样要停
		for _, s := range []string{svcArgo, svcXray} {
			add(svcDisable(s), s+" 停不掉")
		}
		return errors.Join(errs...)
	}
	if changed || !svcActive(svcXray) {
		add(svcEnable(svcXray), "Xray 设不了开机启动")
		action := "start"
		if changed {
			action = "restart"
		}
		add(svcDo(action, svcXray), "Xray 服务起不来")
	}
	if st.Argo.External { // 复用的隧道由这台机器上别的 cloudflared 在跑，dun 不再起一个
		add(svcDisable(svcArgo), "dun-argo 停不掉")
		return errors.Join(errs...)
	}
	add(svcEnable(svcArgo), "cloudflared 设不了开机启动")
	if !svcActive(svcArgo) {
		add(svcDo("start", svcArgo), "cloudflared 服务起不来")
	}
	return errors.Join(errs...)
}

// ── 隧道 ─────────────────────────────────────────────
// 隧道路由：XHTTP 的路径直接给 Xray，其他请求给 dun，兜底 404。
// 服务地址写 127.0.0.1 不写 localhost，免得先解析成 ::1
func argoIngress(a *Argo) []map[string]any {
	return []map[string]any{
		{"hostname": a.Host, "path": "^" + regexp.QuoteMeta(a.Path) + "(/|$)",
			"service": fmt.Sprintf("http://127.0.0.1:%d", a.Inner)},
		{"hostname": a.Host, "service": fmt.Sprintf("http://127.0.0.1:%d", a.Web)},
		{"service": "http_status:404"},
	}
}

var reTunnelToken = regexp.MustCompile(`eyJ[A-Za-z0-9+/_=-]{40,}`)

// 隧道 token 是 base64 编码的 {"a":账户 ID,"t":隧道 ID,"s":密钥}
func parseTunnelToken(raw string) (tok, acc, id string, good bool) {
	tok = reTunnelToken.FindString(raw)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(tok)
		if err != nil {
			continue
		}
		var t struct{ A, T, S string }
		if json.Unmarshal(b, &t) == nil && t.A != "" && t.T != "" && t.S != "" {
			return tok, t.A, t.T, true
		}
	}
	return "", "", "", false
}

// 老版本存的 Zone 没有账户 ID，用到时补上
func zoneAccount(st *State, c *CF) (string, error) {
	if st.Zone.Account != "" {
		return st.Zone.Account, nil
	}
	acc, err := c.ZoneAccount(st.Zone.ID)
	if err == nil {
		st.Zone.Account = acc
		// 只把账户 ID 写回磁盘，别把调用者还没应用的改动（比如刚换的 Argo UUID、路径）提前存进去
		if cur, rerr := readState(); rerr == nil && cur.Zone != nil && cur.Zone.ID == st.Zone.ID {
			cur.Zone.Account = acc
			if werr := cur.write(); werr != nil {
				warn("CF 账户 ID 没存上，下次用到时再查: %v", werr)
			}
		}
	}
	return acc, err
}

func argoCNAME(a *Argo) DNSRecord {
	return DNSRecord{Type: "CNAME", Name: a.Host, Content: a.Tunnel + ".cfargotunnel.com", Proxied: true, TTL: 1, Comment: "dun"}
}

// 找指向这条隧道的解析（手动建隧道时，解析是 CF 后台自己建的）
func argoRecord(st *State, c *CF, a *Argo) string {
	rs, err := c.DNSList(st.Zone.ID, a.Host)
	if err != nil {
		return ""
	}
	for _, r := range rs {
		if r.Type == "CNAME" && strings.EqualFold(r.Content, a.Tunnel+".cfargotunnel.com") {
			return r.ID
		}
	}
	return ""
}

// 自动建隧道并写好路由，不碰解析。中途失败就把建了一半的隧道删掉，返回错误
func argoCreate(st *State, c *CF, a *Argo) (string, error) {
	acc, err := zoneAccount(st, c)
	if err != nil {
		return "", fmt.Errorf("读不到 CF 账户 ID：%v", err)
	}
	info("在 CF 上创建隧道")
	t, err := c.TunnelCreate(acc, "dun-"+nodeName()+"-"+randLabel(4))
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		c.TunnelDelete(acc, t.ID)
		return "", err
	}
	if t.Token == "" {
		if t.Token, err = c.TunnelToken(acc, t.ID); err != nil {
			return fail(fmt.Errorf("拿不到隧道 token：%v", err))
		}
	}
	a.Tunnel, a.TName = t.ID, t.Name
	if err := c.TunnelIngress(acc, t.ID, argoIngress(a)); err != nil {
		return fail(fmt.Errorf("写隧道路由失败：%v", err))
	}
	ok("隧道 %s 已建好", t.Name)
	return t.Token, nil
}

// API 建不了隧道（比如这个账号还没开通过 Zero Trust），就让用户去 CF 后台建，把 token 粘过来。
// 只收 token，不碰解析。返回 token（空串表示用户放弃），以及能不能用 API 改这条隧道的路由
func argoManual(st *State, c *CF, a *Argo) (string, bool) {
	fmt.Fprintln(os.Stderr)
	info("改成手动：在 CF 后台建一条隧道，把 token 粘过来")
	info("1. 打开 https://one.dash.cloudflare.com → 网络 → Tunnels → 创建隧道，类型选 Cloudflared，名字随便起")
	info("2. 安装连接器那一步的命令里有一长串 eyJ 开头的 token，复制 token 或者整条命令都行")
	warn("一定要新建一条隧道，别用正在用的隧道：同一条隧道的流量会被分一部分到这台机器上")
	for {
		raw := askSecret("粘贴 token（直接回车放弃）")
		if raw == "" {
			return "", false
		}
		tok, acc, id, good := parseTunnelToken(raw)
		if !good {
			warn("没认出 token，再粘一次")
			continue
		}
		if st.Zone.Account != "" && acc != st.Zone.Account {
			warn("这条隧道不在 %s 所在的 CF 账号里，解析指不过去。在同一个账号里新建一条", st.Zone.Name)
			continue
		}
		// 已经给别的域名用着的隧道不能碰：改路由会覆盖掉人家的，流量也会被分到这台机器
		hs, err := c.TunnelHosts(acc, id)
		var others []string
		for _, h := range hs {
			if !strings.EqualFold(h, a.Host) {
				others = append(others, h)
			}
		}
		if len(others) > 0 {
			warn("这条隧道已经在给 %s 用了，dun 不能动它。新建一条隧道，粘新的 token", strings.Join(others, "、"))
			continue
		}
		if err != nil && !confirm("读不到这条隧道的路由，没法确认它有没有在用。确定是刚新建、没在用的隧道？", false) {
			continue
		}
		a.Tunnel, a.Manual = id, true
		if st.Zone.Account == "" {
			st.Zone.Account = acc
		}
		return tok, err == nil
	}
}

// 解析指向隧道。调用前状态已经存好（含原有记录的备份），失败了能用「卸载 Argo」还原
func argoDNS(st *State, c *CF, a *Argo) {
	dnsClear(st, c, a.Host)
	id, err := c.DNSCreate(st.Zone.ID, argoCNAME(a))
	if err != nil {
		die("添加解析失败：%v。在菜单里卸载 Argo 能还原原来的解析，再重装", err)
	}
	a.RecordID = id
	ok("解析 %s → 隧道（CF 代理）", a.Host)
}

// API 改不了路由，只能让用户在后台加；后台加路由会自己建解析，名字被占着会报错，所以先清掉
func argoDashboardRoute(st *State, c *CF, a *Argo) {
	dnsClear(st, c, a.Host)
	sub := strings.TrimSuffix(a.Host, "."+st.Zone.Name)
	info("3. 在这条隧道里添加路由，类型选「已发布的应用程序」：")
	info("   子域 %s，域 %s，路径留空，服务类型 HTTP，URL 127.0.0.1:%d", sub, st.Zone.Name, a.Web)
	for {
		ask("加好了按回车", "")
		if a.RecordID = argoRecord(st, c, a); a.RecordID != "" {
			ok("看到 %s 指向隧道的解析了", a.Host)
			return
		}
		warn("还没看到 %s 指向这条隧道的解析，路由加好了吗？", a.Host)
		if !confirm("再查一次？", true) {
			return
		}
	}
}

// ── 复用已有隧道 ─────────────────────────────────────
// 一条隧道的路由所有连接器共用，CF 会把请求分给任意一个连接器。dun 的路由指向 127.0.0.1，
// 所以只有连接器全在这台机器上的隧道能复用。复用时 dun 不另跑 cloudflared，只往里加路由

func (a *Argo) tunnelLabel() string {
	if a.TName != "" {
		return a.TName
	}
	if len(a.Tunnel) > 8 {
		return a.Tunnel[:8]
	}
	return a.Tunnel
}

func containsFold(ss []string, s string) bool {
	for _, x := range ss {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func normIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// 这台机器的公网 IP，加上网卡上的地址
func localIPs(st *State) map[string]bool {
	m := map[string]bool{}
	for _, ip := range []string{st.IP4, st.IP6} {
		if ip != "" {
			m[normIP(ip)] = true
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				m[n.IP.String()] = true
			}
		}
	}
	return m
}

// here：有连接器，而且全在这台机器上；others：在别的机器上的连接器 IP
func connectorPlace(t *cfTunnel, local map[string]bool) (here bool, others []string) {
	seen := map[string]bool{}
	for _, c := range t.Conns {
		ip := normIP(c.OriginIP)
		if !local[ip] && !seen[ip] {
			seen[ip] = true
			others = append(others, ip)
		}
	}
	return len(t.Conns) > 0 && len(others) == 0, others
}

// 列出隧道让用户选。只有能复用的才进选择列表，不能用的单独列出原因；一条能用的都没有就直接问要不要改成新建。
// 返回的隧道为 nil 表示改成新建；cancel 表示用户放弃安装
func pickTunnel(st *State, c *CF, acc string, ts []cfTunnel) (reuse *cfTunnel, cancel bool) {
	local := localIPs(st)
	var cand []cfTunnel
	var labels, bad []string
	moved := false
	for _, t := range ts {
		if !t.remote() {
			bad = append(bad, t.Name+"：用的是本地配置文件，API 改不了它的路由")
			continue
		}
		l := t.Name
		if hs, err := c.TunnelHosts(acc, t.ID); err == nil && len(hs) > 0 {
			l += "（路由：" + strings.Join(hs, "、") + "）"
		}
		here, others := connectorPlace(&t, local)
		switch {
		case here:
			cand, labels = append(cand, t), append(labels, l)
		case len(others) > 0:
			bad = append(bad, l+"：连接器在别的机器上（"+strings.Join(others, "、")+"）")
			moved = true
		default:
			bad = append(bad, l+"：现在没有连接器在跑，确认不了它在哪台机器上")
		}
	}
	if len(bad) > 0 {
		info("这些隧道不能复用（复用要求它的 cloudflared 就跑在这台机器上）：")
		for _, b := range bad {
			fmt.Fprintln(os.Stderr, "  - "+b)
		}
		if moved {
			info("如果「别的机器」其实就是这台（比如 IP 刚变过），先执行 dun syncip 再来")
		}
	}
	if len(cand) == 0 {
		warn("没有能复用的隧道")
		if confirm("改成新建一条隧道？", true) {
			return nil, false
		}
		return nil, true
	}
	info("能复用的隧道：")
	i := choose(append(labels, "不复用了，新建一条"), 1)
	switch {
	case i < 0:
		return nil, true
	case i == len(cand):
		return nil, false
	}
	return &cand[i], false
}

func ingressHosts(v any) []string {
	rs, _ := v.([]any)
	var hs []string
	for _, r := range rs {
		if m, ok := r.(map[string]any); ok {
			if h, _ := m["hostname"].(string); h != "" {
				hs = append(hs, h)
			}
		}
	}
	return hs
}

func withoutHost(v any, host string) []any {
	rs, _ := v.([]any)
	out := []any{}
	for _, r := range rs {
		if m, ok := r.(map[string]any); ok {
			if h, _ := m["hostname"].(string); strings.EqualFold(h, host) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// 最后一条必须是不带域名、不带路径的兜底规则
func withCatchAll(rs []any) []any {
	if n := len(rs); n > 0 {
		if m, ok := rs[n-1].(map[string]any); ok {
			h, _ := m["hostname"].(string)
			p, _ := m["path"].(string)
			if h == "" && p == "" {
				return rs
			}
		}
	}
	return append(rs, map[string]any{"service": "http_status:404"})
}

// 往已有隧道的配置里加 dun 的两条路由：放最前面，免得被前面的通配规则抢走；
// 同一个域名的旧规则去掉，别的规则和路由之外的设置原样保留
func mergeIngress(cfg map[string]any, a *Argo) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		out[k] = v
	}
	rules := []any{}
	for _, r := range argoIngress(a)[:2] {
		rules = append(rules, r)
	}
	out["ingress"] = withCatchAll(append(rules, withoutHost(cfg["ingress"], a.Host)...))
	return out
}

// 卸载时只删 dun 那个域名的路由
func dropIngress(cfg map[string]any, host string) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		out[k] = v
	}
	out["ingress"] = withCatchAll(withoutHost(cfg["ingress"], host))
	return out
}

// 把 dun 的路由写进隧道：dun 自己建的隧道整份覆盖；不是 dun 建的只改 dun 那个域名的规则
func argoSyncIngress(st *State, c *CF) error {
	a := st.Argo
	acc, err := zoneAccount(st, c)
	if err != nil {
		return err
	}
	if !a.External && !a.Manual {
		return c.TunnelIngress(acc, a.Tunnel, argoIngress(a))
	}
	cfg, err := c.TunnelConfig(acc, a.Tunnel)
	if err != nil {
		return err
	}
	return c.TunnelConfigPut(acc, a.Tunnel, mergeIngress(cfg, a))
}

// 从外面完整走一遍：解析（直接问 1.1.1.1，免得本机缓存了「不存在」）→ CF → 隧道 → dun 的伪装站
func argoProbe(st *State) {
	host := st.Argo.Host
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		ips, err := r.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("解析不到 %s", host)
		}
		ip := ips[0]
		for _, x := range ips { // 本机有 IPv4 就连 IPv4 地址，纯 IPv6 的机器连 IPv6 地址
			if p := net.ParseIP(x); p != nil && (p.To4() != nil) == (st.IP4 != "") {
				ip = x
				break
			}
		}
		return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	}}
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	last := ""
	for i := 0; i < 8; i++ {
		resp, err := hc.Get("https://" + host + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				ok("从外面打开 https://%s/ 正常（HTTP %d），CF → 隧道 → 本机这一路通了", host, resp.StatusCode)
				return
			}
			last = fmt.Sprintf("HTTP %d", resp.StatusCode)
		} else {
			last = err.Error()
		}
		time.Sleep(3 * time.Second)
	}
	warn("从外面打开 https://%s/ 不正常：%s", host, last)
	info("530 一般是隧道没连上；502 是隧道连上了但到不了本机的 dun。复用别人的隧道时，多半是那个 cloudflared 跑在 Docker 里，访问不到本机的 127.0.0.1")
}

// Argo 子域名只调低安全级别、关浏览器完整性检查、不缓存；整个域名的设置只碰 HTTP/3 和 Bot Fight Mode
func argoRules(st *State, c *CF) {
	host, zid := st.Argo.Host, st.Zone.ID
	expr := fmt.Sprintf(`(http.host eq "%s")`, host)
	if err := c.RuleUpsert(zid, "http_config_settings", argoPrefix+host, map[string]any{
		"expression": expr, "action": "set_config",
		"action_parameters": map[string]any{"security_level": "essentially_off", "bic": false},
	}); err != nil {
		warn("写配置规则失败（不影响使用，偶尔可能被 CF 拦一下）：%v", err)
	}
	if err := c.RuleUpsert(zid, "http_request_cache_settings", argoPrefix+host, map[string]any{
		"expression": expr, "action": "set_cache_settings",
		"action_parameters": map[string]any{"cache": false},
	}); err != nil {
		warn("写缓存规则失败（不影响使用）：%v", err)
	}
	ok("CF 规则：%s 安全级别调低、不缓存，只对这个子域名生效", host)
	// UDP 版节点走 HTTP/3，这个开关只能整个域名开，作用是允许浏览器用 HTTP/3 访问
	if c.Setting(zid, "http3") != "on" {
		if c.SetSetting(zid, "http3", "on") == nil {
			info("已打开 CF 的 HTTP/3 开关，UDP 版节点要用")
		} else {
			warn("HTTP/3 开关打不开，UDP 版节点可能连不上，可以去 CF 后台「网络」里手动打开")
		}
	}
	if bm, err := c.BotManagement(zid); err == nil && bm["fight_mode"] == true {
		warn("这个域名开着 Bot Fight Mode（机器人打击模式），代理流量可能被当成机器人拦掉")
		info("它只能整个域名一起开关，关掉后你这个域名下的网站都不再用它挡机器人")
		if confirm("关掉它？", true) {
			if err := c.BotFightOff(zid, bm); err != nil {
				warn("没关掉：%v。可以去 CF 后台「安全性 → 机器人」里手动关", err)
			} else {
				ok("Bot Fight Mode 已关闭")
			}
		}
	}
}

func tunnelColos(t *cfTunnel) string {
	seen := map[string]bool{}
	var cs []string
	for _, c := range t.Conns {
		if c.Colo != "" && !seen[c.Colo] {
			seen[c.Colo] = true
			cs = append(cs, c.Colo)
		}
	}
	return strings.Join(cs, " ")
}

// 等 cloudflared 连上 CF 再报成功；c 为空或读不到隧道状态时只看服务
func argoWait(st *State, c *CF) {
	for i := 0; c != nil && i < 20; i++ {
		t, err := c.TunnelGet(st.Zone.Account, st.Argo.Tunnel)
		if err != nil {
			break
		}
		if len(t.Conns) > 0 {
			ok("隧道已连上 Cloudflare：%s", tunnelColos(t))
			return
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if st.Argo.External {
		warn("隧道 %s 现在没有连接。它的 cloudflared 不归 dun 管，去看看这台机器上跑它的那个服务", st.Argo.tunnelLabel())
		return
	}
	time.Sleep(2 * time.Second)
	if svcActive(svcArgo) {
		info("隧道服务在运行，连上 CF 可能还要一会儿，dun log 能看到进度")
		return
	}
	svcLog(30, false)
	warn("隧道服务没起来，看上面的日志")
}

func installArgo(st *State) {
	if st.Argo != nil {
		warn("Argo 隧道已经装过了，在菜单「Argo 隧道」里管理")
		return
	}
	hr()
	info("安装 VLESS + XHTTP + Argo 隧道：VPS 主动连 Cloudflare，不开公网端口，IP 被墙也能用")
	c := cfLogin()
	cfPickZone(st, c)
	// 账号里已经有隧道的话问一句：新建（推荐），还是复用这台机器上已经在跑的
	var reuse *cfTunnel
	if acc, err := zoneAccount(st, c); err == nil {
		if ts, err := c.Tunnels(acc); err == nil && len(ts) > 0 {
			fmt.Fprintln(os.Stderr)
			info("这个 CF 账号里已经有 %d 条隧道，dun 用哪条？", len(ts))
			switch choose([]string{"新建一条，专门给 dun 用（推荐）", "复用已有的隧道（它的 cloudflared 得跑在这台机器上）"}, 1) {
			case -1:
				return
			case 1:
				var cancel bool
				if reuse, cancel = pickTunnel(st, c, acc, ts); cancel {
					return
				}
				if reuse != nil {
					info("复用隧道 %s：dun 只往里加两条路由，不另跑 cloudflared；那个 cloudflared 停了，Argo 节点也会断", reuse.Name)
				}
			}
		}
	}
	ensureArgoBins(reuse == nil)
	writeServices()
	fmt.Fprintln(os.Stderr)
	info("Argo 单独用一个子域名，开 CF 代理（橙云），解析指向隧道")
	var taken []string // 复用的隧道里已有的域名，不能拿来用
	if reuse != nil {
		taken, _ = c.TunnelHosts(st.Zone.Account, reuse.ID)
	}
	var host string
	var bk []DNSRecord
	for {
		host, bk = cfPickHost(st, c, "Argo 域名")
		if !containsFold(taken, host) {
			break
		}
		warn("%s 已经是隧道 %s 里的路由了，换一个", host, reuse.Name)
	}
	a := &Argo{Host: host, Backup: bk, UUID: newUUID(), Path: "/" + randLabel(10)}
	a.Inner = randPort(st)
	a.Web = randPort(st, a.Inner)
	a.Metrics = randPort(st, a.Inner, a.Web)
	api := true
	if reuse != nil {
		a.Tunnel, a.TName, a.External = reuse.ID, reuse.Name, true
	} else {
		tok, err := argoCreate(st, c, a)
		if err != nil {
			warn("自动建隧道失败：%v", err)
			if tok, api = argoManual(st, c, a); tok == "" {
				die("已取消，CF 上什么都没改")
			}
		}
		if err := writeFileAtomic(argoToken, []byte(tok), 0600); err != nil {
			if !a.Manual {
				c.TunnelDelete(st.Zone.Account, a.Tunnel)
			}
			die("保存隧道 token 失败: %v", err)
		}
	}
	// 下面开始动 CF 上的路由和解析。先把状态（含原有解析的备份）存下来，中途断了也能用「卸载 Argo」收拾干净。
	// 这里和下面那次保存都在 applyAll 的预检之前，是故意的：预检不过时 state.json 里留着 Argo，
	// 才能在菜单里卸载 Argo，清掉 CF 上已经建好的隧道和解析
	ensureToken(st)
	st.Argo = a
	st.save()
	if a.External || (a.Manual && api) {
		if err := argoSyncIngress(st, c); err != nil {
			if a.External {
				die("往隧道 %s 里加路由失败：%v。在菜单里卸载 Argo 能还原", a.tunnelLabel(), err)
			}
			api = false
		} else if a.External {
			ok("已在隧道 %s 里加上 %s 的两条路由，原有的路由都没动", a.tunnelLabel(), a.Host)
		}
	}
	if api {
		argoDNS(st, c, a)
	} else {
		argoDashboardRoute(st, c, a)
	}
	st.save() // 记下解析的记录 ID，原因见上
	argoRules(st, c)
	applyAll(st)
	argoWait(st, c)
	argoProbe(st)
	if st.WS == nil && st.CFIP.fetches() {
		if n, err := refreshWetest(st); err != nil {
			warn("优选 IP 拉取失败，先只用内置优选域名：%v", err)
		} else {
			ok("拉到 %d 个优选 IP", n)
		}
	}
	ok("Argo 隧道安装完成，新解析生效可能要一两分钟")
}

func removeArgo(st *State) {
	if st.Argo == nil {
		warn("Argo 隧道没装")
		return
	}
	a := *st.Argo
	c := argoCF()
	if (c == nil || st.Zone == nil) &&
		!confirm("没有能用的 CF 账号，CF 上的解析、隧道和规则删不掉，得自己去后台删。还是继续卸载？", false) {
		return
	}
	// 先按卸掉 Argo 的状态应用：预检不过什么都不动；停 Xray 和隧道（隧道上还挂着连接就删不掉）
	// 在 applyAll 可回滚的阶段里做，失败会换回原来的配置、把服务起回来。成功后再清 CF 上的东西
	st.Argo = nil
	applyAll(st)
	if c != nil && st.Zone != nil {
		argoCFCleanup(st, c, a)
	}
	os.Remove(argoToken)
	if st.WS == nil {
		os.Remove(wetestPath)
	}
	zoneRelease(st)
	ok("Argo 隧道已卸载")
}

// 卸载 Argo 用的 CF 账号，登不上返回 nil；测试里换掉，不读真凭据、不发请求
var argoCF = func() *CF {
	c := cfLoad()
	if c != nil && c.Check() != nil {
		return nil
	}
	return c
}

// 删 CF 上 Argo 的规则、解析、隧道或路由；测试里换掉
var argoCFCleanup = func(st *State, c *CF, a Argo) {
	zid := st.Zone.ID
	c.RuleRemove(zid, "http_config_settings", argoPrefix+a.Host)
	c.RuleRemove(zid, "http_request_cache_settings", argoPrefix+a.Host)
	if a.RecordID == "" && a.Tunnel != "" {
		a.RecordID = argoRecord(st, c, &a)
	}
	dnsDrop(st, c, a.Host, a.RecordID, a.Backup)
	acc, err := zoneAccount(st, c)
	switch {
	case err != nil:
		warn("读不到 CF 账户 ID：%v。隧道 %s 请去 CF 后台处理", err, a.tunnelLabel())
	case a.External || a.Manual:
		// 不是 dun 建的隧道：只删 dun 加的路由，隧道和别的路由都留着
		cfg, err := c.TunnelConfig(acc, a.Tunnel)
		if err == nil {
			err = c.TunnelConfigPut(acc, a.Tunnel, dropIngress(cfg, a.Host))
		}
		if err != nil {
			warn("隧道 %s 里 %s 的路由没删掉：%v。去 CF 后台手动删", a.tunnelLabel(), a.Host, err)
		} else {
			info("隧道 %s 不是 dun 建的，只删了 %s 的路由，隧道留着", a.tunnelLabel(), a.Host)
		}
	case a.Tunnel != "":
		if err := c.TunnelDelete(acc, a.Tunnel); err != nil {
			warn("隧道没删掉：%v。去 CF 后台 Zero Trust → 网络 → Tunnels 手动删", err)
		}
	}
	ok("已清理 %s 的解析、路由和 CF 规则", a.Host)
}

func argoStatus(st *State) {
	a := st.Argo
	if a.External {
		fmt.Fprintf(os.Stderr, "  Argo 域名 %s   复用隧道 %s（cloudflared 由这台机器上别的程序在跑，不归 dun 管）\n", a.Host, a.tunnelLabel())
	} else {
		run := "\033[33m未运行\033[0m"
		if svcActive(svcArgo) {
			run = "\033[32m运行中\033[0m"
		}
		proto := "auto（QUIC 优先）"
		if a.HTTP2 {
			proto = "http2"
		}
		fmt.Fprintf(os.Stderr, "  Argo 域名 %s   隧道服务 %s   隧道协议 %s\n", a.Host, run, proto)
	}
	if c := cfLoad(); c != nil && st.Zone != nil && st.Zone.Account != "" {
		if t, err := c.TunnelGet(st.Zone.Account, a.Tunnel); err == nil {
			fmt.Fprintf(os.Stderr, "  CF 上的隧道状态 %s，%d 条连接 %s\n", t.Status, len(t.Conns), tunnelColos(t))
		}
	}
}

// 菜单「Argo 隧道」：没装就装，装了就管理
func argoMenu(st *State) {
	if st.Argo == nil {
		installArgo(st)
		showLinks(st)
		return
	}
	argoStatus(st)
	if st.Argo.External { // 隧道协议、重启这些归跑 cloudflared 的那个程序管
		if choose([]string{"卸载 Argo（只删 dun 加的路由和解析，隧道留着）"}, 1) == 0 && confirm("确定卸载 Argo 隧道？", false) {
			removeArgo(st)
		}
		return
	}
	i := choose([]string{"切换隧道协议：auto（QUIC 优先）/ http2（UDP 出不去的机器用）", "重启隧道", "卸载 Argo 隧道"}, 1)
	switch i {
	case 0:
		st.Argo.HTTP2 = !st.Argo.HTTP2
		st.save()
		svcDo("restart", svcArgo)
		if st.Argo.HTTP2 {
			ok("隧道改成 http2（走 TCP）")
		} else {
			ok("隧道改回 auto：优先 QUIC，连不上自动退回 http2")
		}
		argoWait(st, cfLoad())
	case 1:
		svcDo("restart", svcArgo)
		argoWait(st, cfLoad())
	case 2:
		if confirm("确定卸载 Argo 隧道？", false) {
			removeArgo(st)
		}
	}
}

// dun-argo 服务的入口：按状态拼好参数，把自己换成 cloudflared
func runTunnel() {
	st := loadState()
	if st.Argo == nil {
		die("没装 Argo 隧道")
	}
	if st.Argo.External {
		die("Argo 复用的是已有隧道，cloudflared 由这台机器上别的程序跑，不归 dun 管")
	}
	// auto 会优先挑 IPv6，有些机器的 IPv6 是借别的机器转出去的，丢包很重，有 IPv4 就固定走 IPv4
	ipv := "4"
	if st.IP4 == "" {
		ipv = "6"
	}
	proto := "auto"
	if st.Argo.HTTP2 {
		proto = "http2"
	}
	// 代理连接都是长连接，停服务时等不到它们自己结束，默认 30 秒的宽限期只会白等
	args := []string{cfdBin, "tunnel", "--no-autoupdate", "--edge-ip-version", ipv, "--protocol", proto,
		"--grace-period", "3s"}
	if st.Argo.Metrics > 0 {
		args = append(args, "--metrics", fmt.Sprintf("127.0.0.1:%d", st.Argo.Metrics))
	}
	args = append(args, "run", "--token-file", argoToken)
	err := syscall.Exec(cfdBin, args, os.Environ())
	die("cloudflared 起不来: %v", err)
}

// ── 更新 ─────────────────────────────────────────────
func updateXray() {
	had, goOn := prepOld(xrayBin, svcXray)
	if !goOn {
		return
	}
	cur := xrayVersion()
	ver := pickVersion("Xray", cur, xrayPinned, ghLatest("XTLS/Xray-core"))
	if ver == "" {
		return
	}
	xrayInstall(ver)
	out, err := runOut(xrayBin, "run", "-test", "-c", xrayConf)
	if err == nil {
		err = restartCheck(svcXray, 2*time.Second)
	}
	if err != nil {
		warn("新版本 Xray 跑不起来，回退到 %s: %v\n%s", cur, err, out)
		rollbackBin(xrayBin, svcXray, had)
		return
	}
	os.Remove(xrayBin + ".old")
	ok("Xray 已更新到 %s", ver)
}

func updateCfd() {
	had, goOn := prepOld(cfdBin, svcArgo)
	if !goOn {
		return
	}
	cur := cfdVersion()
	ver := pickVersion("cloudflared", cur, cfdPinned, ghLatest("cloudflare/cloudflared"))
	if ver == "" {
		return
	}
	cfdInstall(ver)
	if err := restartCheck(svcArgo, 3*time.Second); err != nil {
		warn("新版本 cloudflared 跑不起来，回退到 %s: %v", cur, err)
		rollbackBin(cfdBin, svcArgo, had)
		return
	}
	os.Remove(cfdBin + ".old")
	ok("cloudflared 已更新到 %s", ver)
}
