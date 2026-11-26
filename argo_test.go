package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func testArgoState() *State {
	return &State{
		Token: "tok123",
		CFIP:  CFIPOpt{NoTokyo: true},
		Argo: &Argo{Host: "xh.example.com", Tunnel: "c1744f8b-faa1-48a4-9e5c-02ac921467fa",
			Inner: 21001, Web: 21002, UUID: "11111111-2222-4333-8444-555555555555", Path: "/abc123xyz0"},
	}
}

func TestArgoIngress(t *testing.T) {
	rules := argoIngress(testArgoState().Argo)
	if len(rules) != 3 || rules[2]["service"] != "http_status:404" {
		t.Fatalf("规则不对: %v", rules)
	}
	if rules[0]["service"] != "http://127.0.0.1:21001" || rules[1]["service"] != "http://127.0.0.1:21002" {
		t.Fatalf("服务地址不对: %v", rules)
	}
	if _, has := rules[1]["path"]; has {
		t.Fatal("第二条不该限制路径")
	}
	re := regexp.MustCompile(rules[0]["path"].(string))
	for p, want := range map[string]bool{
		"/abc123xyz0": true, "/abc123xyz0/": true, "/abc123xyz0/9f8e7d/3": true,
		"/abc123xyz0x": false, "/x/abc123xyz0": false, "/": false,
	} {
		if re.MatchString(p) != want {
			t.Errorf("路径 %s 应该是 %v", p, want)
		}
	}
}

func TestParseTunnelToken(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{"a": "acc123", "t": "c1744f8b-faa1-48a4-9e5c-02ac921467fa",
		"s": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"})
	tok := base64.StdEncoding.EncodeToString(raw)
	for _, in := range []string{tok, "  " + tok + "\n", "sudo cloudflared service install " + tok,
		"cloudflared.exe tunnel run --token " + tok} {
		got, acc, id, good := parseTunnelToken(in)
		if !good || got != tok || acc != "acc123" || id != "c1744f8b-faa1-48a4-9e5c-02ac921467fa" {
			t.Errorf("%q => %v %q %q", in, good, acc, id)
		}
	}
	noSecret, _ := json.Marshal(map[string]string{"a": "acc123", "t": "c1744f8b-faa1-48a4-9e5c-02ac921467fa"})
	for _, in := range []string{"", "hello", "eyJhIjoiYiJ9", base64.StdEncoding.EncodeToString(noSecret)} {
		if _, _, _, good := parseTunnelToken(in); good {
			t.Errorf("%q 不该认成 token", in)
		}
	}
}

func TestXrayConfig(t *testing.T) {
	b, err := json.Marshal(xrayConfig(testArgoState()))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Log      struct{ Access string }
		Routing  struct{ DomainStrategy string }
		Inbounds []struct {
			Listen, Protocol string
			Port             int
			Settings         struct {
				Clients    []struct{ ID string }
				Decryption string
			}
			StreamSettings struct {
				Network       string
				XhttpSettings struct{ Path, Mode string }
			}
		}
	}
	if err := json.Unmarshal(b, &cfg); err != nil || len(cfg.Inbounds) != 1 {
		t.Fatalf("配置解析不了: %v %s", err, b)
	}
	in := cfg.Inbounds[0]
	if in.Listen != "127.0.0.1" || in.Port != 21001 || in.Protocol != "vless" || in.Settings.Decryption != "none" ||
		len(in.Settings.Clients) != 1 || in.Settings.Clients[0].ID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("入站不对: %+v", in)
	}
	if x := in.StreamSettings; x.Network != "xhttp" || x.XhttpSettings.Path != "/abc123xyz0" || x.XhttpSettings.Mode != "auto" {
		t.Fatalf("XHTTP 设置不对: %+v", x)
	}
	// 访问记录不能落盘；域名目标要先解析，内网拦截才拦得住 localhost 这类域名
	if cfg.Log.Access != "none" || cfg.Routing.DomainStrategy != "IPIfNonMatch" {
		t.Fatalf("日志或路由策略不对: %+v %+v", cfg.Log, cfg.Routing)
	}
}

func TestArgoNodes(t *testing.T) {
	st := testArgoState()
	ns := buildNodes(st)
	if len(ns) != 2 || !strings.HasSuffix(ns[0].name, "-Argo") || !strings.HasSuffix(ns[1].name, "-Argo-UDP") {
		t.Fatalf("节点不对: %+v", ns)
	}
	for i, alpn := range []string{"h2", "h3"} {
		l := ns[i].link
		for _, want := range []string{"vless://11111111-2222-4333-8444-555555555555@xh.example.com:443?",
			"security=tls", "sni=xh.example.com", "host=xh.example.com", "type=xhttp", "mode=packet-up",
			"path=%2Fabc123xyz0", "alpn=" + alpn} {
			if !strings.Contains(l, want) {
				t.Errorf("链接里没有 %s: %s", want, l)
			}
		}
		for _, want := range []string{"network: xhttp", "mode: packet-up", "alpn: [" + alpn + "]", `path: "/abc123xyz0"`, "host: xh.example.com"} {
			if !strings.Contains(ns[i].clash, want) {
				t.Errorf("Clash 节点里没有 %s:\n%s", want, ns[i].clash)
			}
		}
	}

	st.CFIP.NoH3 = true
	if ns := buildNodes(st); len(ns) != 1 || strings.HasSuffix(ns[0].name, "-UDP") {
		t.Fatalf("关掉 UDP 版以后还有: %+v", ns)
	}

	// 优选地址每个出 TCP、UDP 两个，名字带 Argo- 前缀
	// 默认只有内置东京 IP；wetest 和内置域名默认关
	st.CFIP = CFIPOpt{}
	ns = buildNodes(st)
	if len(ns) != 2*(1+len(tokyoIPs)) {
		t.Fatalf("节点数 %d，应该是 %d", len(ns), 2*(1+len(tokyoIPs)))
	}
	if ns[2].name != "Argo-东京-"+tokyoIPs[0] || ns[3].name != "Argo-东京-"+tokyoIPs[0]+"-UDP" ||
		!strings.Contains(ns[2].link, "@"+tokyoIPs[0]+":443?") {
		t.Fatalf("东京节点不对: %s / %s / %s", ns[2].name, ns[3].name, ns[2].link)
	}

	// 打开内置域名以后才有域名节点
	st.CFIP = CFIPOpt{Domains: true}
	if ns := buildNodes(st); len(ns) != 2*(1+len(tokyoIPs)+len(builtinDomains)) {
		t.Fatalf("打开内置域名后节点数 %d", len(ns))
	}
}

// 复用已有隧道：dun 的两条放最前面，同名旧规则换掉，别人的规则和路由之外的设置原样保留
func TestMergeDropIngress(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(`{
		"ingress": [
			{"hostname": "cdn.example.com", "service": "http://localhost:8080", "originRequest": {"connectTimeout": 30}},
			{"hostname": "*.example.com", "service": "http://localhost:9000"},
			{"hostname": "xh.example.com", "service": "http://localhost:1111"},
			{"service": "http_status:404"}
		],
		"warp-routing": {"enabled": false}
	}`), &cfg); err != nil {
		t.Fatal(err)
	}
	a := testArgoState().Argo
	m := mergeIngress(cfg, a)
	got := ingressHosts(m["ingress"])
	want := []string{"xh.example.com", "xh.example.com", "cdn.example.com", "*.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("合并后的域名顺序 %v，应该是 %v", got, want)
	}
	rs := m["ingress"].([]any)
	if rs[0].(map[string]any)["service"] != "http://127.0.0.1:21001" || rs[1].(map[string]any)["service"] != "http://127.0.0.1:21002" {
		t.Fatalf("dun 的规则不对: %v", rs[:2])
	}
	if last := rs[len(rs)-1].(map[string]any); last["service"] != "http_status:404" || len(rs) != 5 {
		t.Fatalf("兜底规则不对: %v", rs)
	}
	b, _ := json.Marshal(m)
	if !strings.Contains(string(b), `"warp-routing":{"enabled":false}`) || !strings.Contains(string(b), `"connectTimeout":30`) {
		t.Fatalf("路由之外的设置丢了: %s", b)
	}
	if n := len(cfg["ingress"].([]any)); n != 4 {
		t.Fatalf("原配置被改了，现在 %d 条", n)
	}

	d := dropIngress(m, a.Host)
	if got := ingressHosts(d["ingress"]); strings.Join(got, ",") != "cdn.example.com,*.example.com" {
		t.Fatalf("卸载后剩下 %v", got)
	}
	if rs := d["ingress"].([]any); rs[len(rs)-1].(map[string]any)["service"] != "http_status:404" {
		t.Fatalf("卸载后兜底规则没了: %v", rs)
	}

	// 空配置、缺兜底、最后一条带路径的都要补兜底
	for _, in := range [][]any{nil, {map[string]any{"hostname": "a.example.com", "service": "x"}},
		{map[string]any{"path": "^/x", "service": "x"}}} {
		out := withCatchAll(in)
		if last := out[len(out)-1].(map[string]any); last["service"] != "http_status:404" || len(out) != len(in)+1 {
			t.Errorf("%v 补完是 %v", in, out)
		}
	}
}

func TestConnectorPlace(t *testing.T) {
	mk := func(ips ...string) *cfTunnel {
		tn := &cfTunnel{}
		for _, ip := range ips {
			tn.Conns = append(tn.Conns, struct {
				Colo     string `json:"colo_name"`
				OriginIP string `json:"origin_ip"`
			}{"lax01", ip})
		}
		return tn
	}
	local := map[string]bool{"203.0.113.5": true, "2001:db8::1": true}
	if here, others := connectorPlace(mk("203.0.113.5", "2001:DB8:0::1"), local); !here || len(others) != 0 {
		t.Fatalf("都在本机却判成 %v %v", here, others)
	}
	if here, others := connectorPlace(mk("203.0.113.5", "198.51.100.7", "198.51.100.7"), local); here || len(others) != 1 || others[0] != "198.51.100.7" {
		t.Fatalf("有一个在别的机器却判成 %v %v", here, others)
	}
	if here, others := connectorPlace(mk(), local); here || len(others) != 0 {
		t.Fatalf("没有连接器却判成 %v %v", here, others)
	}
}

// 普通橙云域名在 108.162.198.x、172.64.52.x 上会被 CF 拒绝（1034），CF WS 只能用 172.64.229.x
func TestWSUsesOnlyAllowedTokyoIPs(t *testing.T) {
	st := testArgoState()
	st.CFIP = CFIPOpt{}
	st.WS = &WS{Host: "ws.example.com", UUID: "11111111-2222-4333-8444-555555555555", Path: "/p"}
	argo, ws := 0, 0
	for _, n := range buildNodes(st) {
		switch {
		case strings.Contains(n.link, "type=xhttp"):
			argo++
		case strings.Contains(n.link, "type=ws"):
			ws++
			if strings.Contains(n.link, "@108.162.198.") || strings.Contains(n.link, "@172.64.52.") {
				t.Fatalf("CF WS 用了会被 1034 拒绝的 IP: %s", n.name)
			}
		}
	}
	if argo != 2*(1+len(tokyoIPs)) || ws != 1+len(tokyoWSIPs) {
		t.Fatalf("Argo %d 个、CF WS %d 个", argo, ws)
	}
}

func TestSubBasePrefersArgo(t *testing.T) {
	st := testArgoState()
	st.WS = &WS{Host: "ws.example.com"}
	if got := subBase(st); got != "https://xh.example.com/tok123" {
		t.Fatalf("订阅地址 %s", got)
	}
	if c := subClash(st); !strings.Contains(c, "network: xhttp") || !strings.Contains(c, "proxies:") {
		t.Fatal("Clash 订阅里没有 Argo 节点")
	}
}
