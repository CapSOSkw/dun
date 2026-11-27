package main

import (
	"bufio"
	"encoding/json"
	"net"
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
