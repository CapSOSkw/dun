package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
)

func TestCloudPortMapping(t *testing.T) {
	var st State
	if err := json.Unmarshal([]byte(`{"ip4":"203.0.113.5","nat":true}`), &st); err != nil {
		t.Fatal(err)
	}
	old := in
	t.Cleanup(func() { in = old })
	in = bufio.NewReader(strings.NewReader("1\n"))
	if got := askPubPort(&st, 443); got != 443 {
		t.Fatalf("独享公网实例应沿用监听端口 443，实际为 %d", got)
	}
	if st.PortMode != portDirect {
		t.Fatalf("端口方式 = %q", st.PortMode)
	}
	in = nil
	if got := askPubPort(&st, 8443); got != 8443 {
		t.Fatalf("第二个协议的外网端口 = %d", got)
	}
	oldHop := hopUsable
	t.Cleanup(func() { hopUsable = oldHop })
	hopUsable = func() bool { return true }
	h := &Hy2{}
	setHy2Range(h, st.PortMode)
	if h.HopStart <= 0 || h.HopEnd <= h.HopStart {
		t.Fatal("独享公网实例没有分配跳跃范围")
	}
	hopUsable = func() bool { return false }
	h = &Hy2{}
	setHy2Range(h, st.PortMode)
	if h.HopStart != 0 {
		t.Fatal("加不了 nat 规则时不该分配跳跃范围")
	}
}

func TestPortMode(t *testing.T) {
	const ip = "203.0.113.5"
	private := &net.IPNet{IP: net.ParseIP("10.0.0.7")}
	public := &net.IPNet{IP: net.ParseIP(ip)}
	tests := []struct {
		name  string
		state State
		addrs []net.Addr
		input string
		want  string
	}{
		{"公网网卡同时有私网地址", State{IP4: ip}, []net.Addr{private, public}, "", portDirect},
		{"纯 IPv6", State{IP6: "2001:db8::7"}, nil, "", portDirect},
		{"一对一映射", State{IP4: ip}, []net.Addr{private}, "\n", portDirect},
		{"服务商只分配几个端口", State{IP4: ip}, []net.Addr{private}, "2\n", portMapped},
		{"读取网卡失败仍可选映射", State{IP4: ip}, nil, "2\n", portMapped},
		{"已有端口翻译默认保留", State{IP4: ip, Reality: &Reality{Port: 443, PubPort: 30443}}, []net.Addr{private}, "\n", portMapped},
	}
	old := in
	t.Cleanup(func() { in = old })
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in = nil
			if tc.input != "" {
				in = bufio.NewReader(strings.NewReader(tc.input))
			}
			if got := selectPortMode(&tc.state, tc.addrs); got != tc.want {
				t.Fatalf("端口方式 = %q，预期 %q", got, tc.want)
			}
		})
	}
}

func TestLimitedUDPPorts(t *testing.T) {
	old := in
	t.Cleanup(func() { in = old })
	st := &State{IP4: "203.0.113.5"}
	in = bufio.NewReader(strings.NewReader("2\n30443\n\n"))
	if got := askPubPort(st, 443); got != 30443 {
		t.Fatalf("映射端口 = %d", got)
	}
	if got := askPubPort(st, 8443); got != 8443 {
		t.Fatalf("同号映射端口 = %d", got)
	}
	h := &Hy2{HopStart: 20000, HopEnd: 21000}
	setHy2Range(h, st.PortMode)
	if h.HopStart != 0 || h.HopEnd != 0 {
		t.Fatal("受限映射启用了跳跃")
	}
}

func TestHy2RangeFollowsProbeAndMode(t *testing.T) {
	oldHop := hopUsable
	t.Cleanup(func() { hopUsable = oldHop })

	// 已有范围，换到加不了 nat 规则的环境：回落单端口
	hopUsable = func() bool { return false }
	h := &Hy2{Port: 443, HopStart: 20000, HopEnd: 21000}
	setHy2Range(h, portDirect)
	if h.HopStart != 0 || h.HopEnd != 0 {
		t.Fatal("探测失败时没清掉已有的跳跃范围")
	}
	// 已有范围、探测成功：范围不变
	hopUsable = func() bool { return true }
	h = &Hy2{Port: 443, HopStart: 20000, HopEnd: 21000}
	setHy2Range(h, portDirect)
	if h.HopStart != 20000 || h.HopEnd != 21000 {
		t.Fatal("探测成功却换了跳跃范围")
	}
}

// 改别的协议时选了映射端口：内存里 Hy2 跟着走单端口，别的协议端口一个不动；
// 规则一条都不删，用户这时取消，旧规则原样留着，等 applyAll 成功后 fwPrune 才回收
func TestMappedCancelKeepsRules(t *testing.T) {
	hop := "-A INPUT -p udp -m udp --dport 20000:21000 -m comment --comment dun-allow -j ACCEPT"
	cmds := fakeFw(t, hop, func([]string) bool { return false })
	p := fakeRulesFile(t, hop)
	before, _ := os.ReadFile(p)
	oldHop := hopUsable
	t.Cleanup(func() { hopUsable = oldHop })
	hopUsable = func() bool { t.Fatal("切映射不该探测"); return false }

	st := &State{Reality: &Reality{Port: 443, PubPort: 443}, AnyTLS: &AnyTLS{Port: 8443, PubPort: 30001},
		WS: &WS{Port: 2053, PubPort: 2053}, Hy2: &Hy2{Port: 5443, PubPort: 5443, HopStart: 20000, HopEnd: 21000}}
	st.setPortMode(portMapped)
	if st.PortMode != portMapped || st.Hy2.HopStart != 0 || st.Hy2.HopEnd != 0 {
		t.Fatal("映射端口模式下 Hy2 还留着跳跃范围")
	}
	if st.Reality.Port != 443 || st.Reality.PubPort != 443 || st.AnyTLS.Port != 8443 || st.AnyTLS.PubPort != 30001 ||
		st.WS.Port != 2053 || st.WS.PubPort != 2053 || st.Hy2.Port != 5443 || st.Hy2.PubPort != 5443 {
		t.Fatal("切端口方式动了已有协议的端口")
	}
	if after, _ := os.ReadFile(p); len(*cmds) != 0 || string(after) != string(before) {
		t.Fatalf("还没应用就删了规则：%q", *cmds)
	}
	fwPrune(st) // 应用成功之后才回收
	if after, _ := os.ReadFile(p); len(*cmds) != 1 || strings.Contains(string(after), "20000:21000") {
		t.Fatalf("应用成功后没回收旧跳跃范围：%q", *cmds)
	}
}

// applyAll 的 sing-box 配置检查不过时 die 退出，旧端口规则不能被删
func TestApplyFailKeepsRules(t *testing.T) {
	old := "-A INPUT -p tcp -m tcp --dport 8443 -m comment --comment dun-allow -j ACCEPT"
	cmds := fakeFw(t, old, func([]string) bool { return false })
	p := fakeRulesFile(t, old)
	before, _ := os.ReadFile(p)
	ob, oc, os_, oe := sbBin, sbConf, statePath, dieExit
	t.Cleanup(func() { sbBin, sbConf, statePath, dieExit = ob, oc, os_, oe })
	dir := t.TempDir()
	sbBin, sbConf, statePath = dir+"/no-sing-box", dir+"/sing-box.json", dir+"/state.json"
	dieExit = func(int) { panic("die") }

	// Reality 从 8443 换到 443，新配置检查失败
	st := &State{TLS: &TLSHost{Host: "a.example.com"}, Reality: &Reality{Port: 443, PubPort: 443, Fallback: 21003}}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("检查失败却没 die")
			}
		}()
		applyAll(st)
	}()
	if after, _ := os.ReadFile(p); len(*cmds) != 0 || string(after) != string(before) {
		t.Fatalf("新配置没通过却删了旧规则：%q", *cmds)
	}
}

// 服务启动时跳跃规则加不上：范围写回状态，任何进程从磁盘读出来生成的链接和订阅都不带跳跃
func TestHopApplyFailPersists(t *testing.T) {
	fakeFw(t, "", func(a []string) bool { return len(a) > 2 && a[1] == "nat" && a[2] == "-A" })
	os_ := statePath
	t.Cleanup(func() { statePath = os_ })
	statePath = t.TempDir() + "/state.json"
	st := &State{IP4: "203.0.113.5", TLS: &TLSHost{Host: "a.example.com"},
		Hy2: &Hy2{Port: 5443, PubPort: 5443, HopStart: 20000, HopEnd: 21000, HopSec: 30}}
	st.save()
	if !strings.Contains(linkHy2(st, "x"), "mport=20000-21000") || !strings.Contains(subClash(st), "20000-21000") {
		t.Fatal("跳跃生效时链接或订阅里没带范围")
	}
	hopApply(st)
	fresh := loadState() // 相当于另一个进程：dun links、dun mihomo、订阅请求
	if fresh.Hy2.HopStart != 0 || strings.Contains(linkHy2(fresh, "x"), "mport") || strings.Contains(subClash(fresh), "20000-21000") {
		t.Fatal("跳跃规则没加上，磁盘上的状态还带着范围")
	}
}
