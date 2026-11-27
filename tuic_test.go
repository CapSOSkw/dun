package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func tuicState() *State {
	return &State{IP4: "203.0.113.5", TLS: &TLSHost{Host: "n.r4nd.example.com"},
		Hy2:  &Hy2{Port: 5443, PubPort: 5443, Password: "hy2pass", Obfs: "obfs", HopStart: 20000, HopEnd: 39999, HopSec: 30},
		TUIC: &TUIC{Port: 45000, PubPort: 45000, UUID: "11111111-2222-4333-8444-555555555555", Password: "tuicpass", CC: "bbr"}}
}

func findInbound(t *testing.T, st *State, typ string) map[string]any {
	t.Helper()
	cfg, _ := sbConfig(st)
	for _, in := range cfg["inbounds"].([]any) {
		if m := in.(map[string]any); m["type"] == typ {
			return m
		}
	}
	return nil
}

func TestTUICSingBoxConfig(t *testing.T) {
	st := tuicState()
	in := findInbound(t, st, "tuic")
	if in == nil {
		t.Fatal("没有 tuic 入站")
	}
	if in["listen_port"] != 45000 || in["congestion_control"] != "bbr" || in["zero_rtt_handshake"] != false {
		t.Fatalf("tuic 入站字段不对：%v", in)
	}
	u := in["users"].([]any)[0].(map[string]any)
	if u["uuid"] != st.TUIC.UUID || u["password"] != "tuicpass" {
		t.Fatalf("用户不对：%v", u)
	}
	tl := in["tls"].(map[string]any)
	if tl["certificate_path"] != certFile || tl["key_path"] != keyFile || tl["server_name"] != st.TLS.Host ||
		!reflect.DeepEqual(tl["alpn"], []string{"h3"}) || tl["enabled"] != true {
		t.Fatalf("tls 不对：%v", tl)
	}
	// 字段名只能是 sing-box 1.14 文档里有的
	for k := range in {
		if !strings.Contains(" type tag listen listen_port users congestion_control zero_rtt_handshake tls ", " "+k+" ") {
			t.Fatalf("多了 sing-box 不认的字段 %s", k)
		}
	}
	if _, n := sbConfig(st); n != 2 {
		t.Fatalf("入站数 = %d", n)
	}
	// 两个 UDP 协议互不影响：去掉一个，另一个原样
	hy2 := findInbound(t, st, "hysteria2")
	st.TUIC = nil
	if !reflect.DeepEqual(findInbound(t, st, "hysteria2"), hy2) || findInbound(t, st, "tuic") != nil {
		t.Fatal("去掉 TUIC 影响了 Hy2")
	}
	st = tuicState()
	st.Hy2 = nil
	if !reflect.DeepEqual(findInbound(t, st, "tuic"), in) || findInbound(t, st, "hysteria2") != nil {
		t.Fatal("去掉 Hy2 影响了 TUIC")
	}
}

func TestTUICLinks(t *testing.T) {
	st := tuicState()
	st.PortMode = portMapped
	st.TUIC.PubPort = 30443 // 映射端口：链接和 Clash 用外网端口
	st.TUIC.Password = "p@ss:w/rd?#%"
	l := linkTUIC(st, "vps-TUIC")
	u, err := url.Parse(l)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := u.User.Password()
	q := u.Query()
	if u.Scheme != "tuic" || u.User.Username() != st.TUIC.UUID || pw != st.TUIC.Password || u.Hostname() != st.TLS.Host ||
		u.Port() != "30443" || u.Fragment != "vps-TUIC" {
		t.Fatalf("链接不对：%s", l)
	}
	if q.Get("congestion_control") != "bbr" || q.Get("alpn") != "h3" || q.Get("sni") != st.TLS.Host || q.Get("udp_relay_mode") != "native" {
		t.Fatalf("参数不对：%s", l)
	}
	if !strings.Contains(l, ":p%40ss%3Aw%2Frd%3F%23%25@") {
		t.Fatalf("密码没转义：%s", l)
	}

	sub, _ := base64.StdEncoding.DecodeString(subV2ray(st))
	if !strings.Contains(string(sub), l[:strings.Index(l, "#")]) || !strings.Contains(string(sub), "hysteria2://") {
		t.Fatalf("/sub 里没有 TUIC 或丢了 Hy2：\n%s", sub)
	}
	c := subClash(st)
	for _, want := range []string{"    type: tuic\n", `    server: "n.r4nd.example.com"`, "    port: 30443\n",
		`    uuid: "11111111-2222-4333-8444-555555555555"`, `    password: "p@ss:w/rd?#%"`, "    alpn: [h3]\n",
		`    sni: "n.r4nd.example.com"`, "    congestion-controller: bbr\n", "    udp-relay-mode: native\n",
		"    reduce-rtt: false\n", "type: hysteria2"} {
		if !strings.Contains(c, want) {
			t.Fatalf("/clash 里没有 %q：\n%s", want, c)
		}
	}

	// 节点地址是 IPv6 字面量时要加方括号
	st.TLS.Host = "2001:db8::1"
	l = linkTUIC(st, "v6")
	if u, err := url.Parse(l); err != nil || u.Hostname() != "2001:db8::1" || u.Port() != "30443" || !strings.Contains(l, "@[2001:db8::1]:30443?") {
		t.Fatalf("IPv6 链接不对：%s", l)
	}
	if !strings.Contains(subClash(st), `    server: "2001:db8::1"`) {
		t.Fatal("Clash 的 IPv6 server 不对")
	}
}

// TUIC 端口和 Hy2 主端口、整个跳跃范围双向互斥；UDP 443 和 Reality 的 TCP 443 可以共存
func TestTUICHy2PortExclusion(t *testing.T) {
	st := tuicState()
	st.Reality = &Reality{Port: 443, PubPort: 443}
	for _, tc := range []struct {
		p     int
		key   string
		taken bool
	}{
		{5443, "tuic", true}, {20000, "tuic", true}, {30000, "tuic", true}, {39999, "tuic", true},
		{45000, "hy2", true}, {45000, "tuic", false}, {5443, "hy2", false}, {25000, "hy2", false},
		{40000, "tuic", false}, {443, "tuic", false}, {443, "hy2", false},
	} {
		if st.udpTaken(tc.p, tc.key) != tc.taken {
			t.Fatalf("udpTaken(%d, %s) 应为 %v", tc.p, tc.key, tc.taken)
		}
	}
	for i := 0; i < 300; i++ {
		if p := randUDPPort(st, "tuic"); p == 5443 || (p >= 20000 && p <= 39999) {
			t.Fatalf("TUIC 随机到了 Hy2 占的 %d", p)
		} else if p < 20000 || p > 59999 {
			t.Fatalf("TUIC 随机端口 %d 不在 20000-59999", p)
		}
	}

	old := in
	t.Cleanup(func() { in = old })
	in = bufio.NewReader(strings.NewReader("25000\n5443\n443\n"))
	if p := askUDPPort(st, "tuic", 45000); p != 443 {
		t.Fatalf("TUIC 手动端口 = %d，应跳过跳跃范围和 Hy2 端口后得到 443", p)
	}
	in = bufio.NewReader(strings.NewReader("45000\n6000\n"))
	if p := askUDPPort(st, "hy2", 5443); p != 6000 {
		t.Fatalf("Hy2 手动端口 = %d，应跳过 TUIC 端口", p)
	}

	// 算跳跃范围时避开 TUIC：宽度大到任何起点都会盖住 45000，只能找不到
	if a, b := freeUDPRange(39990, 45000); a != 0 || b != 0 {
		t.Fatalf("跳跃范围 %d-%d 盖住了 TUIC 端口", a, b)
	}
	if a, _ := freeUDPRange(39990); a == 0 {
		t.Fatal("没有要避开的端口时应该找得到")
	}
	oldHop := hopUsable
	t.Cleanup(func() { hopUsable = oldHop })
	hopUsable = func() bool { return true }
	for i := 0; i < 300; i++ {
		h := &Hy2{Port: 5443}
		setHy2Range(h, portDirect, st.tuicPorts()...)
		if h.HopStart <= 45000 && 45000 <= h.HopEnd {
			t.Fatalf("跳跃范围 %d-%d 盖住了 TUIC 端口", h.HopStart, h.HopEnd)
		}
	}
	if (&State{}).tuicPorts() != nil {
		t.Fatal("没装 TUIC 不该有要避开的端口")
	}
}

func fwRule(ps, proto string) string { return "-A INPUT " + strings.Join(fwSpec(ps, proto), " ") }

// 放行 TUIC 端口：插一条带 dun-allow 标记的 UDP 规则，开机文件改之前先备份
func TestTUICFwOpen(t *testing.T) {
	cmds := fakeFw(t, "-P INPUT ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited", func(a []string) bool { return a[0] == "-C" })
	p := fakeRulesFile(t)
	fwAllow(fwFamilies[0], "45000", "udp", false) // 不走 fwOpenProto：它会碰机器上真的 ufw、firewalld
	want := "-I INPUT 1 " + strings.Join(fwSpec("45000", "udp"), " ")
	if len(*cmds) != 2 || (*cmds)[1] != want {
		t.Fatalf("实时规则不对：%q", *cmds)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), fwRule("45000", "udp")+"\n-A INPUT -j REJECT") {
		t.Fatalf("开机文件没写进去：\n%s", b)
	}
	if bak, _ := os.ReadFile(p + ".dun.bak"); !strings.Contains(string(bak), "-A INPUT -j REJECT") || strings.Contains(string(bak), "45000") {
		t.Fatal("改开机文件前没备份原文件")
	}
}

// 换端口、卸载 TUIC 后由 fwPrune 回收，IPv4、IPv6 两边都清；Hy2 的不动，同号的 TCP 规则不算 TUIC 的
func TestTUICFwPrune(t *testing.T) {
	oldT, newT, hy2, hop, tcp := fwRule("30000", "udp"), fwRule("45000", "udp"), fwRule("5443", "udp"), fwRule("20000:39999", "udp"), fwRule("45000", "tcp")
	live := strings.Join([]string{oldT, newT, hy2, hop, tcp}, "\n")
	cmds := fakeFw(t, live, func([]string) bool { return false })
	var files []string
	fwFamilies = nil
	for _, v := range []string{"v4", "v6"} {
		p := filepath.Join(t.TempDir(), "rules."+v)
		os.WriteFile(p, []byte(strings.Replace(ociRules, "-A INPUT -j REJECT", live+"\n-A INPUT -j REJECT", 1)), 0640)
		fwFamilies = append(fwFamilies, fwFamily{"ip" + v, "restore", p})
		files = append(files, p)
	}
	check := func(gone, kept []string) {
		t.Helper()
		if len(*cmds) != 2*len(gone) {
			t.Fatalf("实时规则删得不对：%q", *cmds)
		}
		for _, g := range gone {
			if !strings.Contains(strings.Join(*cmds, "\n"), "-D"+g[2:]) {
				t.Fatalf("没删 %s：%q", g, *cmds)
			}
		}
		for _, p := range files {
			b, _ := os.ReadFile(p)
			for _, g := range gone {
				if strings.Contains(string(b), g+"\n") {
					t.Fatalf("%s 里没删 %s", p, g)
				}
			}
			for _, k := range kept {
				if !strings.Contains(string(b), k+"\n") {
					t.Fatalf("%s 里误删了 %s", p, k)
				}
			}
		}
		*cmds = nil
	}
	st := tuicState()
	fwPrune(st) // TUIC 从 30000 换到了 45000
	check([]string{oldT, tcp}, []string{newT, hy2, hop})
	st.TUIC = nil // 卸载 TUIC
	fwPrune(st)
	check([]string{oldT, newT, tcp}, []string{hy2, hop})
}

func TestTUICNeedsCert(t *testing.T) {
	st := &State{TUIC: &TUIC{}}
	if !st.installed() || !st.needTLS() || !st.certInBox() {
		t.Fatal("只装 TUIC 也要算已安装、要证书、续期后重启 sing-box")
	}
	if (&State{Reality: &Reality{}}).certInBox() || !(&State{Reality: &Reality{}}).needTLS() {
		t.Fatal("Reality 要节点域名，但证书由 dun 现读，续期不用重启 sing-box")
	}
	// 卸载 Hy2 后 TUIC 还用着节点域名和证书，不能释放
	st = tuicState()
	st.Hy2 = nil
	tlsHostRelease(st)
	if st.TLS == nil {
		t.Fatal("TUIC 还在却释放了节点域名")
	}
}

// v1.2.0 写出的 state.json（有 port_mode、Hy2、Argo、cfip），值全是虚构的
const v120State = `{
  "ip4": "203.0.113.5",
  "port_mode": "mapped",
  "zone": {"id": "zone-id-test", "name": "example.com", "account": "acct-id-test"},
  "tls": {"host": "a.r4nd.example.com", "cert_name": "*.r4nd.example.com", "record_id": "rec-tls"},
  "reality": {"port": 443, "pub_port": 30443, "fallback": 21003, "uuid": "11111111-2222-4333-8444-555555555555",
    "private_key": "test-private-key", "public_key": "test-public-key", "short_id": "0123abcd"},
  "hy2": {"port": 5443, "pub_port": 30444, "password": "hy2-pass", "obfs": "obfs-pass", "min_pkt": 400, "max_pkt": 1100,
    "cmin_pkt": 500, "cmax_pkt": 1200, "hop_sec": 25},
  "argo": {"host": "xh.example.com", "record_id": "rec-argo", "tunnel": "c1744f8b-faa1-48a4-9e5c-02ac921467fa",
    "inner": 21001, "web": 21002, "metrics": 21005, "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "path": "/abc123xyz0"},
  "disguise": {"seed": 42},
  "token": "sub-token-test",
  "cfip": {"wetest": true, "no_h3": true}
}`

func TestV120StateWithTUIC(t *testing.T) {
	old := statePath
	t.Cleanup(func() { statePath = old })
	statePath = filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(statePath, []byte(v120State), 0600)
	keys := []string{"ip4", "port_mode", "zone", "tls", "reality", "hy2", "argo", "disguise", "token", "cfip"}
	same := func(raw []byte) {
		t.Helper()
		var orig, saved map[string]any
		json.Unmarshal([]byte(v120State), &orig)
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if !reflect.DeepEqual(orig[k], saved[k]) {
				t.Fatalf("%s 往返后变了：\n原 %v\n现 %v", k, orig[k], saved[k])
			}
		}
	}
	st := loadState()
	if st.TUIC != nil || st.PortMode != portMapped {
		t.Fatalf("旧文件读出来不对：TUIC=%v port_mode=%q", st.TUIC, st.PortMode)
	}
	st.save()
	b, _ := os.ReadFile(statePath)
	same(b)
	if strings.Contains(string(b), "tuic") {
		t.Fatal("没装 TUIC 却写出了 tuic 字段")
	}
	// 在旧状态上加装 TUIC：别的字段一个不变，TUIC 能读回来
	st.TUIC = &TUIC{Port: 45000, PubPort: 30445, UUID: newUUID(), Password: "tuic-pass", CC: "bbr"}
	st.save()
	b, _ = os.ReadFile(statePath)
	same(b)
	if got := loadState().TUIC; !reflect.DeepEqual(got, st.TUIC) {
		t.Fatalf("TUIC 读回来不一样：%+v", got)
	}
}

// 菜单 5：回车一起装；已装的那个跳过并提示，凭据端口不动；只装一个时不碰另一个
func TestInstallUDPMenu(t *testing.T) {
	for i, want := range [][]string{{"hy2", "tuic"}, {"hy2"}, {"tuic"}} {
		if got := udpPlan(i); len(udpChoices) != 3 || !reflect.DeepEqual(got, want) {
			t.Fatalf("选项 %d = %v", i+1, got)
		}
	}
	old := in
	t.Cleanup(func() { in = old })
	run := func(st *State, input string) string {
		in = bufio.NewReader(strings.NewReader(input))
		return captureStderr(func() { installUDP(st) })
	}

	st := tuicState()
	hy2, tuic := *st.Hy2, *st.TUIC
	out := run(st, "\n")
	if strings.Count(out, "跳过") != 2 || *st.Hy2 != hy2 || *st.TUIC != tuic {
		t.Fatalf("都装了再选一起装，应该两个都跳过、什么都不动：\n%s", out)
	}
	st.Hy2 = nil
	out = run(st, "3\n")
	if !strings.Contains(out, "TUIC v5 已经装过了，跳过") || strings.Contains(out, "Hysteria2 已经") || st.Hy2 != nil || *st.TUIC != tuic {
		t.Fatalf("仅装 TUIC5 不该碰 Hy2：\n%s", out)
	}
	if out = run(st, "0\n"); strings.Contains(out, "跳过") || st.Hy2 != nil || *st.TUIC != tuic {
		t.Fatalf("选 0 应该直接返回：\n%s", out)
	}
	st = tuicState()
	st.TUIC = nil
	out = run(st, "2\n")
	if !strings.Contains(out, "Hysteria2 已经装过了，跳过") || strings.Contains(out, "TUIC v5 已经") || st.TUIC != nil || *st.Hy2 != hy2 {
		t.Fatalf("仅装 HY2 不该碰 TUIC：\n%s", out)
	}
}

// 管理菜单里 HY2 和 TUIC5 是两项，端口、放行、节点各管各的
func TestTUICIndependentManage(t *testing.T) {
	st := tuicState()
	old := in
	t.Cleanup(func() { in = old })
	in = bufio.NewReader(strings.NewReader("2\n"))
	if k := pickProto(st); k != "tuic" || protoLabel(k) != "TUIC v5" {
		t.Fatalf("管理菜单第 2 项应是 TUIC，得到 %q", k)
	}
	if p, pub := curPorts(st, "tuic"); p != 45000 || pub != 45000 {
		t.Fatalf("TUIC 端口 = %d/%d", p, pub)
	}
	if st.hasMappedPorts() {
		t.Fatal("内外端口相同不算映射")
	}
	st.TUIC.PubPort = 30445
	if !st.hasMappedPorts() {
		t.Fatal("TUIC 的映射端口没算进去")
	}
	names := func() (s []string) {
		for _, n := range buildNodes(st) {
			s = append(s, n.name[strings.LastIndex(n.name, "-")+1:])
		}
		return
	}
	if got := names(); !reflect.DeepEqual(got, []string{"Hy2", "TUIC"}) {
		t.Fatalf("节点 = %v", got)
	}
	st.TUIC = nil
	if got := names(); !reflect.DeepEqual(got, []string{"Hy2"}) || !st.fwInUse("5443", "udp") || !st.fwInUse("20000:39999", "udp") {
		t.Fatalf("卸载 TUIC 影响了 Hy2：%v", got)
	}
	st = tuicState()
	st.Hy2 = nil
	if got := names(); !reflect.DeepEqual(got, []string{"TUIC"}) || !st.fwInUse("45000", "udp") || st.fwInUse("5443", "udp") {
		t.Fatalf("卸载 Hy2 影响了 TUIC：%v", got)
	}
}

// 映射端口时两个 UDP 协议的外网端口不能重，安装和改端口都走 askUDPPub；直连时不多问
func TestUDPMappedPubExclusion(t *testing.T) {
	st := tuicState()
	st.PortMode = portMapped
	st.Hy2.HopStart, st.Hy2.HopEnd, st.Hy2.PubPort, st.TUIC.PubPort = 0, 0, 30443, 30444
	old := in
	t.Cleanup(func() { in = old })
	for _, tc := range []struct {
		key, input string
		port, want int
	}{
		{"tuic", "30443\n30445\n", 45000, 30445}, // TUIC 填了 Hy2 的外网端口
		{"hy2", "30444\n30446\n", 5443, 30446},   // 反过来
		{"tuic", "30444\n", 45000, 30444},        // 自己原来的外网端口照样能用
	} {
		in = bufio.NewReader(strings.NewReader(tc.input))
		if got := askUDPPub(st, tc.key, tc.port); got != tc.want {
			t.Fatalf("%s 外网端口 = %d，应为 %d", tc.key, got, tc.want)
		}
	}
	st.PortMode = portDirect
	in = nil // 直连不读输入，外网端口就是监听端口
	if got := askUDPPub(st, "tuic", 30443); got != 30443 {
		t.Fatalf("直连模式外网端口 = %d", got)
	}
}

// 绑了端口再 connect 的 UDP 套接字（状态 01）也占着端口
func TestUDPConnectedSocketBusy(t *testing.T) {
	old := procNet
	t.Cleanup(func() { procNet = old })
	procNet = t.TempDir() + "/"
	udp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"  1: 00000000:75BB 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 111 2 0000000000000000 0\n" +
		"  2: 00000000:75BC 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 222 2 0000000000000000 0\n"
	os.WriteFile(procNet+"udp", []byte(udp), 0644)
	if got := sockInodes(30139, true); !reflect.DeepEqual(got, []string{"111"}) {
		t.Fatalf("已连接的 UDP 套接字没认出来：%v", got)
	}
	if got := sockInodes(30140, true); !reflect.DeepEqual(got, []string{"222"}) {
		t.Fatalf("未连接的 UDP 套接字没认出来：%v", got)
	}
	if sockInodes(30139, false) != nil || udpOwner(30139) == "" || udpOwner(30141) != "" {
		t.Fatal("UDP 占用判断不对")
	}
	oldIn := in
	t.Cleanup(func() { in = oldIn })
	in = bufio.NewReader(strings.NewReader("30139\n30141\n"))
	if p := askUDPPort(&State{}, "tuic", 30139); p != 30141 {
		t.Fatalf("选了被已连接套接字占着的端口：%d", p)
	}
	if a, _ := freeUDPRange(39990); a != 0 { // 任何起点都盖住 30139
		t.Fatal("跳跃范围盖住了已连接套接字的端口")
	}
}

// CC 只认 sing-box 支持的三种，别的一律 bbr；Clash 的 TUIC 节点不带 Mihomo 没定义的 udp 键
func TestTUICCCAndYAMLKeys(t *testing.T) {
	for cc, want := range map[string]string{"": "bbr", "bbr": "bbr", "cubic": "cubic", "new_reno": "new_reno",
		"BBR": "bbr", "reno": "bbr", "bbr\n    skip-cert-verify: true": "bbr"} {
		st := tuicState()
		st.Hy2 = nil
		st.TUIC.CC = cc
		c := subClash(st)
		if st.TUIC.cc() != want || findInbound(t, st, "tuic")["congestion_control"] != want ||
			!strings.Contains(linkTUIC(st, "x"), "congestion_control="+want+"&") ||
			!strings.Contains(c, "    congestion-controller: "+want+"\n") || strings.Contains(c, "skip-cert-verify") {
			t.Fatalf("CC %q 应当成 %q", cc, want)
		}
		if strings.Contains(c, "udp: true") {
			t.Fatal("TUIC 节点不该有 udp 键")
		}
	}
}

func TestRenewRestarts(t *testing.T) {
	for _, tc := range []struct {
		st   State
		want []string
	}{
		{State{TUIC: &TUIC{}}, []string{svcBox}},
		{State{Hy2: &Hy2{}}, []string{svcBox}},
		{State{AnyTLS: &AnyTLS{}}, []string{svcBox}},
		{State{Reality: &Reality{}}, nil},
		{State{}, nil},
	} {
		if got := renewRestarts(&tc.st); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%+v 续期后重启 %v，应为 %v", tc.st, got, tc.want)
		}
	}
}

// 首次安装：回车或 1 依次装 Hy2、TUIC，2 只装 Hy2，3 只装 TUIC
func TestInstallUDPFresh(t *testing.T) {
	var calls []string
	oi, oin := udpInstallers, in
	t.Cleanup(func() { udpInstallers, in = oi, oin })
	udpInstallers = map[string]func(*State){
		"hy2":  func(*State) { calls = append(calls, "hy2") },
		"tuic": func(*State) { calls = append(calls, "tuic") },
	}
	for input, want := range map[string][]string{"\n": {"hy2", "tuic"}, "1\n": {"hy2", "tuic"}, "2\n": {"hy2"}, "3\n": {"tuic"}, "0\n": nil} {
		calls = nil
		in = bufio.NewReader(strings.NewReader(input))
		captureStderr(func() { installUDP(&State{}) })
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("输入 %q 装了 %v，应为 %v", input, calls, want)
		}
	}
}

// 真走 removeTUIC / removeHy2：另一个协议的端口、跳跃范围、密码在内存和磁盘上都不变。
// 测试里没有 sing-box，applyAll 在配置检查处 die（换成 panic）；之后的重启、等端口、回收规则要真服务，跑不了
func TestRemoveOneUDPKeepsOther(t *testing.T) {
	ob, oc, os_, oe := sbBin, sbConf, statePath, dieExit
	t.Cleanup(func() { sbBin, sbConf, statePath, dieExit = ob, oc, os_, oe })
	dir := t.TempDir()
	sbBin, sbConf, statePath = dir+"/no-sing-box", dir+"/sing-box.json", dir+"/state.json"
	dieExit = func(int) { panic("die") }
	remove := func(f func(*State), st *State) {
		defer func() {
			if recover() == nil {
				t.Fatal("没有 sing-box 却没在配置检查处停下")
			}
		}()
		captureStderr(func() { f(st) })
	}

	st := tuicState()
	hy2 := *st.Hy2
	remove(removeTUIC, st)
	if disk := loadState(); st.TUIC != nil || disk.TUIC != nil || *st.Hy2 != hy2 || disk.Hy2 == nil || *disk.Hy2 != hy2 {
		t.Fatal("卸载 TUIC 动了 Hy2，或者 TUIC 没删掉")
	}
	if _, n := sbConfig(st); n != 1 || findInbound(t, st, "hysteria2")["listen_port"] != 5443 {
		t.Fatal("卸载 TUIC 后 sing-box 配置里的 Hy2 不对")
	}

	st = tuicState()
	tuic := *st.TUIC
	remove(removeHy2, st)
	if disk := loadState(); st.Hy2 != nil || disk.Hy2 != nil || *st.TUIC != tuic || disk.TUIC == nil || *disk.TUIC != tuic {
		t.Fatal("卸载 Hy2 动了 TUIC，或者 Hy2 没删掉")
	}
}
