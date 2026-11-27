package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fork v1.1.2 写出的 state.json 格式，值全是虚构的。nat 是旧字段，argo、cfip 是 fork 专有字段
const v112State = `{
  "ip4": "203.0.113.5",
  "nat": true,
  "zone": {"id": "zone-id-test", "name": "example.com", "account": "acct-id-test"},
  "tls": {"host": "a.r4nd.example.com", "cert_name": "*.r4nd.example.com", "record_id": "rec-tls"},
  "reality": {"port": 443, "pub_port": 443, "fallback": 21003, "uuid": "11111111-2222-4333-8444-555555555555",
    "private_key": "test-private-key", "public_key": "test-public-key", "short_id": "0123abcd"},
  "anytls": {"port": 45678, "pub_port": 45678, "password": "test-pass", "padding": ["stop=8", "0=30-30"]},
  "ws": {"host": "w.example.com", "record_id": "rec-ws", "port": 8443, "pub_port": 8443, "inner": 21004,
    "uuid": "66666666-7777-4888-9999-000000000000", "path": "/wspath"},
  "argo": {"host": "xh.example.com", "record_id": "rec-argo", "tunnel": "c1744f8b-faa1-48a4-9e5c-02ac921467fa",
    "tunnel_name": "dun-test", "external": true, "inner": 21001, "web": 21002, "metrics": 21005,
    "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "path": "/abc123xyz0", "http2": true},
  "disguise": {"seed": 42},
  "token": "sub-token-test",
  "cfip": {"no_tokyo": true, "wetest": true, "v6": true, "no_h3": true}
}`

func TestV112StateRoundTrip(t *testing.T) {
	var st State
	if err := json.Unmarshal([]byte(v112State), &st); err != nil {
		t.Fatal(err)
	}
	if st.PortMode != "" {
		t.Fatalf("旧文件没有 port_mode，读出来却是 %q", st.PortMode)
	}
	// 跟 save() 一样序列化，再和原文件逐字段比：除了废弃的 nat，什么都不能丢、不能变
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var orig, saved map[string]any
	json.Unmarshal([]byte(v112State), &orig)
	json.Unmarshal(b, &saved)
	delete(orig, "nat")
	for _, k := range []string{"argo", "cfip", "reality", "anytls", "ws", "zone", "tls", "token", "disguise", "ip4"} {
		if !reflect.DeepEqual(orig[k], saved[k]) {
			t.Fatalf("%s 往返后变了：\n原 %v\n现 %v", k, orig[k], saved[k])
		}
	}
	var again State
	if err := json.Unmarshal(b, &again); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st, again) {
		t.Fatal("再读一遍和第一次读的不一样")
	}

	// 现有三个协议的内外端口都一样，没有映射痕迹；Argo 不占公网端口，不参与判断
	if again.hasMappedPorts() {
		t.Fatal("内外端口相同的旧配置被当成了映射端口")
	}
	old := in
	t.Cleanup(func() { in = old })
	private := []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.7")}}
	// 公网地址没绑网卡（Azure 这类），会问一次，默认选 1：独享公网 IP，端口照旧
	in = bufio.NewReader(strings.NewReader("\n"))
	if got := selectPortMode(&again, private); got != portDirect {
		t.Fatalf("默认端口方式 = %q", got)
	}
	in = bufio.NewReader(strings.NewReader("\n"))
	if got := askPubPort(&again, 45679); got != 45679 || again.PortMode != portDirect {
		t.Fatalf("新协议外网端口 = %d，端口方式 %q", got, again.PortMode)
	}
	if again.Reality.Port != 443 || again.Reality.PubPort != 443 || again.AnyTLS.PubPort != 45678 || again.WS.PubPort != 8443 {
		t.Fatal("选端口方式时动了已有协议的端口")
	}

	// 旧版填过不同外网端口的，默认保留映射方式
	var mapped State
	json.Unmarshal([]byte(v112State), &mapped)
	mapped.AnyTLS.PubPort = 30001
	in = bufio.NewReader(strings.NewReader("\n"))
	if got := selectPortMode(&mapped, private); got != portMapped {
		t.Fatalf("有映射端口的旧配置默认端口方式 = %q", got)
	}
}

// 走真正的 loadState、save 落盘：nat 为 true、false、省略三种旧文件，读→存→再读后端口和 fork 字段都不变
func TestV112StateOnDisk(t *testing.T) {
	old := statePath
	t.Cleanup(func() { statePath = old })
	for _, tc := range []struct{ name, json string }{
		{"nat=true", v112State},
		{"nat=false", strings.Replace(v112State, `"nat": true`, `"nat": false`, 1)},
		{"省略nat", strings.Replace(v112State, `"nat": true,`, "", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath = filepath.Join(t.TempDir(), "dun", "state.json")
			os.MkdirAll(filepath.Dir(statePath), 0700)
			if err := os.WriteFile(statePath, []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			loadState().save()
			st := loadState()
			b, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			var orig, saved map[string]any
			if json.Unmarshal([]byte(tc.json), &orig) != nil || json.Unmarshal(b, &saved) != nil {
				t.Fatal("JSON 解不开")
			}
			for _, k := range []string{"reality", "anytls", "ws", "argo", "cfip", "zone", "tls", "token", "disguise", "ip4"} {
				if !reflect.DeepEqual(orig[k], saved[k]) {
					t.Fatalf("%s 落盘往返后变了：\n原 %v\n现 %v", k, orig[k], saved[k])
				}
			}
			if _, has := saved["nat"]; has || st.PortMode != "" {
				t.Fatalf("旧文件不该凭空多出端口方式：nat 留着=%v，port_mode=%q", has, st.PortMode)
			}
			if st.Reality.Port != 443 || st.Reality.PubPort != 443 || st.AnyTLS.Port != 45678 || st.AnyTLS.PubPort != 45678 ||
				st.WS.Port != 8443 || st.WS.PubPort != 8443 || st.WS.Inner != 21004 {
				t.Fatal("Reality / AnyTLS / CF WS 端口变了")
			}
			a := st.Argo
			if a.Inner != 21001 || a.Web != 21002 || a.Metrics != 21005 || !a.External || !a.HTTP2 || a.Tunnel != "c1744f8b-faa1-48a4-9e5c-02ac921467fa" {
				t.Fatalf("Argo 字段变了：%+v", a)
			}
			if st.CFIP != (CFIPOpt{NoTokyo: true, Wetest: true, V6: true, NoH3: true}) {
				t.Fatalf("CFIP 变了：%+v", st.CFIP)
			}
		})
	}
}
