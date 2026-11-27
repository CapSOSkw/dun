package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	wetestV4 = "https://www.wetest.vip/page/cloudflare/address_v4.html"
	wetestV6 = "https://www.wetest.vip/page/cloudflare/address_v6.html"
)

// 和 yx-auto 内置的优选域名一致
var builtinDomains = []string{
	"cloudflare.182682.xyz", "freeyx.cloudflare88.eu.org", "bestcf.top", "cdn.2020111.xyz",
	"cf.0sm.com", "cf.090227.xyz", "cf.zhetengsha.eu.org", "cfip.1323123.xyz",
	"cloudflare-ip.mofashi.ltd", "cf.877771.xyz", "xn--b6gac.eu.org",
}

type CFAddr struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	Name string `json:"name"`
}

type wetestCache struct {
	Time    time.Time `json:"time"`
	Items   []CFAddr  `json:"items"`
	Domains []string  `json:"domains"` // 检查过、确实解析到 CF 的内置域名
	Checked bool      `json:"checked"`
}

var cfNets = func() []*net.IPNet {
	var ns []*net.IPNet
	for _, c := range strings.Fields(`173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
		108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15
		104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32
		2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`) {
		_, n, _ := net.ParseCIDR(c)
		ns = append(ns, n)
	}
	return ns
}()

func isCFIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// 优选域名会过期、被抢注，解析不到 CF 的一律不用
func aliveDomains() []string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	alive := map[string]bool{}
	for _, d := range builtinDomains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupHost(ctx, d)
			if err != nil || len(ips) == 0 {
				return
			}
			for _, ip := range ips {
				if !isCFIP(ip) {
					return
				}
			}
			mu.Lock()
			alive[d] = true
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	var res []string
	for _, d := range builtinDomains {
		if alive[d] {
			res = append(res, d)
		}
	}
	return res
}

var (
	reRow  = regexp.MustCompile(`(?s)<tr.*?</tr>`)
	reCell = regexp.MustCompile(`(?s)data-label="线路名称">(.+?)</td>.*?data-label="优选地址">([\d.:a-fA-F]+)</td>.*?data-label="数据中心">(.+?)</td>`)
	reTag  = regexp.MustCompile(`<[^>]*>`)
	reHost = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]*$`)
)

func fetchWetest(u string) ([]CFAddr, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var res []CFAddr
	count := map[string]int{}
	for _, row := range reRow.FindAllString(string(b), -1) {
		m := reCell.FindStringSubmatch(row)
		if m == nil {
			continue
		}
		isp := strings.TrimSpace(reTag.ReplaceAllString(m[1], ""))
		colo := strings.TrimSpace(reTag.ReplaceAllString(m[3], ""))
		key := isp
		if colo != "" {
			key += "-" + colo
		}
		count[key]++
		res = append(res, CFAddr{Addr: m[2], Port: 443, Name: fmt.Sprintf("优选-%s-%02d", key, count[key])})
	}
	return res, nil
}

func refreshWetest(st *State) (int, error) {
	c := loadWetest()
	c.Domains, c.Checked = aliveDomains(), true
	items, err := fetchWetest(wetestV4)
	if err == nil && st.CFIP.V6 {
		if v6, e := fetchWetest(wetestV6); e == nil {
			items = append(items, v6...)
		}
	}
	var good []CFAddr
	for _, it := range items {
		if isCFIP(it.Addr) {
			good = append(good, it)
		}
	}
	if err == nil && len(good) == 0 {
		err = fmt.Errorf("页面里没解析出地址")
	}
	if err == nil {
		c.Items, c.Time = good, time.Now()
	}
	b, _ := json.Marshal(c)
	writeFileAtomic(wetestPath, b, 0600)
	return len(good), err
}

func loadWetest() wetestCache {
	var c wetestCache
	if b, err := os.ReadFile(wetestPath); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

// 自选地址一行一个：地址[:端口][#备注]
func customAddrs() []CFAddr {
	f, err := os.Open(customPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var res []CFAddr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if a, ok := parseAddr(sc.Text()); ok {
			res = append(res, a)
		}
	}
	return res
}

func parseAddr(line string) (CFAddr, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return CFAddr{}, false
	}
	name := ""
	if i := strings.Index(line, "#"); i >= 0 {
		name = strings.TrimSpace(line[i+1:])
		line = strings.TrimSpace(line[:i])
	}
	addr, port := line, 443
	if strings.HasPrefix(line, "[") {
		if j := strings.Index(line, "]"); j > 0 {
			addr = line[1:j]
			if p, err := strconv.Atoi(strings.TrimPrefix(line[j+1:], ":")); err == nil {
				port = p
			}
		}
	} else if strings.Count(line, ":") == 1 {
		h, p, _ := strings.Cut(line, ":")
		if n, err := strconv.Atoi(p); err == nil {
			addr, port = h, n
		}
	}
	if port < 1 || port > 65535 || (net.ParseIP(addr) == nil && !reHost.MatchString(addr)) {
		return CFAddr{}, false
	}
	if name == "" {
		name = addr
	}
	return CFAddr{Addr: addr, Port: port, Name: "自选-" + name}, true
}

// 东京（NRT）的 CF IP，都是 2026-11 从上海电信实测过的：走 Argo 落在东京，晚高峰 20-40 MB/s；
// 同期新加坡的 IP 走 Argo 延迟 2 秒左右、只有 0.2 MB/s。
// 别的运营商、别的地区落在哪个机房可能不一样，在菜单「优选地址」里可以关掉它、改用 wetest
var tokyoIPs = []string{
	"108.162.198.174", "108.162.198.101", "108.162.198.167", "108.162.198.31", "108.162.198.223",
	"172.64.52.178", "172.64.52.113", "172.64.229.218",
}

// 普通橙云域名（CF WS 用的就是这种）在 108.162.198.x、172.64.52.x 上会被 CF 拒绝，返回 403 错误 1034；
// 隧道域名（Argo）不受这个限制。实测东京段里普通域名只能用 172.64.229.x
var tokyoWSIPs = []string{"172.64.229.218", "172.64.229.21"}

// 优选地址池。argo 为 true 时给 Argo 用，否则给 CF WS 用：两边能用的东京 IP 不一样
func cfAddrs(st *State, argo bool) []CFAddr {
	var res []CFAddr
	if !st.CFIP.NoTokyo {
		ips := tokyoWSIPs
		if argo {
			ips = tokyoIPs
		}
		for _, ip := range ips {
			res = append(res, CFAddr{Addr: ip, Port: 443, Name: "东京-" + ip})
		}
	}
	if st.CFIP.Wetest {
		res = append(res, loadWetest().Items...)
	}
	if st.CFIP.Domains {
		ds := builtinDomains
		if c := loadWetest(); c.Checked {
			ds = c.Domains
		}
		for _, d := range ds {
			res = append(res, CFAddr{Addr: d, Port: 443, Name: "优选-" + d})
		}
	}
	return append(res, customAddrs()...)
}

// ── 链接 ─────────────────────────────────────────────
func nodeName() string {
	h, _ := os.Hostname()
	h = strings.Split(h, ".")[0]
	if h == "" {
		h = "vps"
	}
	return h
}

func hostPort(a string, p int) string {
	if strings.Contains(a, ":") && !strings.HasPrefix(a, "[") {
		a = "[" + a + "]"
	}
	return a + ":" + strconv.Itoa(p)
}

func frag(s string) string { return url.PathEscape(s) }

func linkReality(st *State, name string) string {
	r := st.Reality
	return fmt.Sprintf("vless://%s@%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s",
		r.UUID, hostPort(strings.Trim(st.srvAddr(), "[]"), r.PubPort), st.TLS.Host, r.PublicKey, r.ShortID, frag(name))
}

func linkAnyTLS(st *State, name string) string {
	a := st.AnyTLS
	return fmt.Sprintf("anytls://%s@%s/?sni=%s#%s", a.Password, hostPort(st.TLS.Host, a.PubPort), st.TLS.Host, frag(name))
}

func linkHy2(st *State, name string) string {
	h := st.Hy2
	v := url.Values{}
	v.Set("sni", st.TLS.Host)
	v.Set("obfs", "gecko")
	v.Set("obfs-password", h.Obfs)
	if h.HopStart > 0 {
		v.Set("mport", fmt.Sprintf("%d-%d", h.HopStart, h.HopEnd))
	}
	return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", h.Password, hostPort(st.TLS.Host, h.PubPort), v.Encode(), frag(name))
}

// tuic://uuid:password@host:port?...，uuid 和密码按 userinfo 转义
func linkTUIC(st *State, name string) string {
	t := st.TUIC
	v := url.Values{}
	v.Set("congestion_control", t.cc())
	v.Set("alpn", "h3")
	v.Set("sni", st.TLS.Host)
	v.Set("udp_relay_mode", "native")
	return fmt.Sprintf("tuic://%s@%s?%s#%s", url.UserPassword(t.UUID, t.Password), hostPort(st.TLS.Host, t.PubPort), v.Encode(), frag(name))
}

func linkWS(st *State, a CFAddr) string {
	w := st.WS
	return fmt.Sprintf("vless://%s@%s?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#%s",
		w.UUID, hostPort(a.Addr, a.Port), w.Host, w.Host, url.QueryEscape(w.Path), frag(a.Name))
}

// 经过 Argo 只有 packet-up 能通；h2 走 TCP，h3 走 UDP（QUIC）
func linkArgo(st *State, a CFAddr, h3 bool) string {
	g := st.Argo
	alpn := "h2"
	if h3 {
		alpn = "h3"
	}
	return fmt.Sprintf("vless://%s@%s?encryption=none&security=tls&sni=%s&fp=chrome&alpn=%s&type=xhttp&host=%s&path=%s&mode=packet-up#%s",
		g.UUID, hostPort(a.Addr, a.Port), g.Host, alpn, g.Host, url.QueryEscape(g.Path), frag(a.Name))
}

type node struct {
	name, link, clash string
}

func q(s string) string { return strconv.Quote(s) }

// 节点名进 YAML 和链接，去掉引号和反斜杠；重名的加序号
func uniqName(seen map[string]int, s string) string {
	s = strings.NewReplacer(`"`, "", `\`, "").Replace(s)
	seen[s]++
	if c := seen[s]; c > 1 {
		s = fmt.Sprintf("%s-%d", s, c)
	}
	return s
}

// Argo 节点：隧道域名本身加上优选地址池（和 CF WS 共用），每个地址出 TCP 和 UDP 两个
func argoNodes(st *State, base string) []node {
	g := st.Argo
	addrs := []CFAddr{{Addr: g.Host, Port: 443, Name: base + "-Argo"}}
	for _, a := range cfAddrs(st, true) {
		a.Name = "Argo-" + a.Name
		addrs = append(addrs, a)
	}
	var ns []node
	seen := map[string]int{}
	for _, a := range addrs {
		a.Name = uniqName(seen, a.Name)
		for _, h3 := range []bool{false, true} {
			if h3 && st.CFIP.NoH3 {
				continue
			}
			x, alpn := a, "h2"
			if h3 {
				x.Name, alpn = a.Name+"-UDP", "h3"
			}
			ns = append(ns, node{x.Name, linkArgo(st, x, h3), fmt.Sprintf(`  - name: %s
    type: vless
    server: %s
    port: %d
    uuid: %s
    network: xhttp
    tls: true
    udp: true
    servername: %s
    client-fingerprint: chrome
    alpn: [%s]
    xhttp-opts:
      path: %s
      host: %s
      mode: packet-up
`, q(x.Name), q(x.Addr), x.Port, g.UUID, g.Host, alpn, q(g.Path), g.Host)})
		}
	}
	return ns
}

func buildNodes(st *State) []node {
	var ns []node
	base := nodeName()
	if st.Reality != nil {
		n := base + "-Reality"
		r := st.Reality
		ns = append(ns, node{n, linkReality(st, n), fmt.Sprintf(`  - name: %s
    type: vless
    server: %s
    port: %d
    uuid: %s
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: %s
    client-fingerprint: chrome
    reality-opts:
      public-key: %s
      short-id: %s
`, q(n), strings.Trim(st.srvAddr(), "[]"), r.PubPort, r.UUID, st.TLS.Host, r.PublicKey, q(r.ShortID))})
	}
	if st.AnyTLS != nil {
		n := base + "-AnyTLS"
		a := st.AnyTLS
		ns = append(ns, node{n, linkAnyTLS(st, n), fmt.Sprintf(`  - name: %s
    type: anytls
    server: %s
    port: %d
    password: %s
    sni: %s
    client-fingerprint: chrome
    udp: true
`, q(n), st.TLS.Host, a.PubPort, q(a.Password), st.TLS.Host)})
	}
	if h := st.Hy2; h != nil {
		n := base + "-Hy2"
		extra := ""
		if h.HopStart > 0 {
			extra += fmt.Sprintf("    ports: %d-%d\n    hop-interval: %d\n", h.HopStart, h.HopEnd, h.HopSec)
		}
		extra += fmt.Sprintf("    obfs: gecko\n    obfs-password: %s\n    obfs-min-packet-size: %d\n    obfs-max-packet-size: %d\n",
			q(h.Obfs), h.CMinPkt, h.CMaxPkt)
		ns = append(ns, node{n, linkHy2(st, n), fmt.Sprintf(`  - name: %s
    type: hysteria2
    server: %s
    port: %d
%s    password: %s
    sni: %s
    alpn: [h3]
`, q(n), st.TLS.Host, h.PubPort, extra, q(h.Password), st.TLS.Host)})
	}
	if t := st.TUIC; t != nil {
		n := base + "-TUIC"
		ns = append(ns, node{n, linkTUIC(st, n), fmt.Sprintf(`  - name: %s
    type: tuic
    server: %s
    port: %d
    uuid: %s
    password: %s
    alpn: [h3]
    sni: %s
    congestion-controller: %s
    udp-relay-mode: native
    reduce-rtt: false
`, q(n), q(st.TLS.Host), t.PubPort, q(t.UUID), q(t.Password), q(st.TLS.Host), t.cc())})
	}
	if st.Argo != nil {
		ns = append(ns, argoNodes(st, base)...)
	}
	if st.WS != nil {
		w := st.WS
		addrs := append([]CFAddr{{Addr: w.Host, Port: 443, Name: base + "-CF-WS"}}, cfAddrs(st, false)...)
		seen := map[string]int{}
		for _, a := range addrs {
			a.Name = uniqName(seen, a.Name)
			ns = append(ns, node{a.Name, linkWS(st, a), fmt.Sprintf(`  - name: %s
    type: vless
    server: %s
    port: %d
    uuid: %s
    network: ws
    tls: true
    udp: true
    servername: %s
    client-fingerprint: chrome
    ws-opts:
      path: %s
      headers:
        Host: %s
`, q(a.Name), q(a.Addr), a.Port, w.UUID, w.Host, q(w.Path), w.Host)})
		}
	}
	return ns
}

func subV2ray(st *State) string {
	var ls []string
	for _, n := range buildNodes(st) {
		ls = append(ls, n.link)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(ls, "\n")))
}

const clashHead = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: strict

geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
  asn: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb

sniffer:
  enable: true
  parse-pure-ip: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]

# 防 DNS 泄露：
# 默认上游是国外 DoH，respect-rules 让它按分流规则走代理出去，
# 国内 DNS 只用来解析国内域名、节点域名和直连流量
dns:
  enable: true
  ipv6: true
  respect-rules: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
    - "time.*.com"
    - "ntp.*.com"
    - "+.stun.*.*"
    - "geosite:private"
    - "geosite:connectivity-check"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  nameserver-policy:
    "geosite:cn,private":
      - https://223.5.5.5/dns-query
      - https://1.12.12.12/dns-query
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  direct-nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
`

// 分组：名字、默认第一项
var clashGroups = []struct{ name, first string }{
	{"AI", "节点选择"},
	{"Telegram", "节点选择"},
	{"YouTube", "节点选择"},
	{"流媒体", "节点选择"},
	{"谷歌", "节点选择"},
	{"微软", "DIRECT"},
	{"苹果", "DIRECT"},
	{"漏网之鱼", "节点选择"},
}

const clashRules = `rules:
  - GEOSITE,private,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,category-ads-all,广告拦截
  - GEOSITE,category-ai-!cn,AI
  - GEOSITE,telegram,Telegram
  - GEOIP,telegram,Telegram,no-resolve
  - GEOSITE,youtube,YouTube
  - GEOSITE,netflix,流媒体
  - GEOSITE,disney,流媒体
  - GEOSITE,hbo,流媒体
  - GEOSITE,primevideo,流媒体
  - GEOSITE,spotify,流媒体
  - GEOIP,netflix,流媒体,no-resolve
  - GEOSITE,google,谷歌
  - GEOIP,google,谷歌,no-resolve
  - GEOSITE,microsoft,微软
  - GEOSITE,apple,苹果
  - GEOSITE,geolocation-!cn,节点选择
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,漏网之鱼
`

func subClash(st *State) string {
	ns := buildNodes(st)
	var b strings.Builder
	b.WriteString(clashHead)
	b.WriteString("proxies:\n")
	for _, n := range ns {
		b.WriteString(n.clash)
	}
	b.WriteString("\nproxy-groups:\n")
	b.WriteString("  - name: 节点选择\n    type: select\n    proxies: [自动选择, DIRECT]\n    include-all-proxies: true\n")
	b.WriteString("  - name: 自动选择\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    include-all-proxies: true\n")
	for _, g := range clashGroups {
		opts := []string{"节点选择", "自动选择", "DIRECT"}
		if g.first == "DIRECT" {
			opts = []string{"DIRECT", "节点选择", "自动选择"}
		}
		fmt.Fprintf(&b, "  - name: %s\n    type: select\n    proxies: [%s]\n    include-all-proxies: true\n", g.name, strings.Join(opts, ", "))
	}
	b.WriteString("  - name: 广告拦截\n    type: select\n    proxies: [REJECT, DIRECT]\n\n")
	b.WriteString(clashRules)
	return b.String()
}

func subBase(st *State) string {
	if st.Token == "" {
		return ""
	}
	// 走 Argo 隧道最稳：VPS 的 IP 被墙了也能更新，还不暴露 IP
	if st.Argo != nil {
		return "https://" + st.Argo.Host + "/" + st.Token
	}
	if st.WS != nil {
		return "https://" + st.WS.Host + "/" + st.Token
	}
	if st.Reality != nil && st.TLS != nil {
		h := st.TLS.Host
		if st.Reality.PubPort != 443 {
			h += ":" + strconv.Itoa(st.Reality.PubPort)
		}
		return "https://" + h + "/" + st.Token
	}
	return ""
}
