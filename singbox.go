package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

func sbArch() string {
	switch runtime.GOARCH {
	case "arm":
		return "armv7"
	default:
		return runtime.GOARCH
	}
}

// 跟 releases/latest 的跳转拿版本号，不走 API，免得被限流
func ghLatest(repo string) string {
	c := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get("https://github.com/" + repo + "/releases/latest")
	if err != nil {
		return ""
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		return strings.TrimPrefix(loc[i+5:], "v")
	}
	return ""
}

func sbVersion() string {
	out, err := runOut(sbBin, "version")
	if err != nil {
		return ""
	}
	f := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if len(f) >= 3 {
		return f[2]
	}
	return ""
}

func sbInstall(ver string) {
	if ver == "" {
		ver = ghLatest("SagerNet/sing-box")
	}
	if ver == "" {
		die("拿不到 sing-box 最新版本号，检查能不能访问 GitHub")
	}
	u := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", ver, ver, sbArch())
	info("下载 sing-box %s (%s)", ver, sbArch())
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(u)
	if err != nil || resp.StatusCode != 200 {
		die("sing-box 下载失败: %s", u)
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		die("sing-box 包解不开: %v", err)
	}
	tr := tar.NewReader(gz)
	os.MkdirAll(path.Dir(sbBin), 0755)
	for {
		h, err := tr.Next()
		if err != nil {
			die("包里没找到 sing-box")
		}
		if path.Base(h.Name) != "sing-box" || h.Typeflag != tar.TypeReg {
			continue
		}
		f, err := os.OpenFile(sbBin+".new", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			die("%v", err)
		}
		_, err = io.Copy(f, tr)
		f.Close()
		if err != nil {
			die("sing-box 下载不完整: %v", err)
		}
		break
	}
	if exists(sbBin) {
		os.Rename(sbBin, sbBin+".old")
	}
	os.Rename(sbBin+".new", sbBin)
	if sbVersion() == "" {
		die("sing-box 跑不起来")
	}
	ok("sing-box %s", sbVersion())
}

func sbConfig(st *State) (map[string]any, int) {
	var inb []any
	user := "dun"
	if r := st.Reality; r != nil {
		inb = append(inb, map[string]any{
			"type": "vless", "tag": "reality", "listen": listenAll(), "listen_port": r.Port,
			"users": []any{map[string]any{"name": user, "uuid": r.UUID, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{"enabled": true, "server_name": st.TLS.Host,
				"reality": map[string]any{"enabled": true,
					"handshake":   map[string]any{"server": "127.0.0.1", "server_port": r.Fallback},
					"private_key": r.PrivateKey, "short_id": []string{r.ShortID}}},
		})
	}
	if a := st.AnyTLS; a != nil {
		in := map[string]any{
			"type": "anytls", "tag": "anytls", "listen": listenAll(), "listen_port": a.Port,
			"users": []any{map[string]any{"name": user, "password": a.Password}},
			"tls": map[string]any{"enabled": true, "server_name": st.TLS.Host, "alpn": []string{"h2", "http/1.1"},
				"certificate_path": certFile, "key_path": keyFile},
		}
		if len(a.Padding) > 0 {
			in["padding_scheme"] = a.Padding
		}
		inb = append(inb, in)
	}
	if h := st.Hy2; h != nil {
		in := map[string]any{
			"type": "hysteria2", "tag": "hy2", "listen": listenAll(), "listen_port": h.Port,
			"users": []any{map[string]any{"name": user, "password": h.Password}},
			"tls": map[string]any{"enabled": true, "server_name": st.TLS.Host, "alpn": []string{"h3"},
				"certificate_path": certFile, "key_path": keyFile},
		}
		in["obfs"] = map[string]any{"type": "gecko", "password": h.Obfs,
			"min_packet_size": h.MinPkt, "max_packet_size": h.MaxPkt}
		inb = append(inb, in)
	}
	if w := st.WS; w != nil {
		inb = append(inb, map[string]any{
			"type": "vless", "tag": "ws", "listen": "127.0.0.1", "listen_port": w.Inner,
			"users":     []any{map[string]any{"name": user, "uuid": w.UUID}},
			"transport": map[string]any{"type": "ws", "path": w.Path},
		})
	}
	return map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  inb,
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		// 服务端只拦两样：BT（商家看到会封机）和访问内网地址
		"route": map[string]any{"rules": []any{
			map[string]any{"action": "sniff"},
			map[string]any{"protocol": "bittorrent", "action": "reject"},
			map[string]any{"ip_is_private": true, "action": "reject"},
		}},
	}, len(inb)
}

// 先 check 再替换，检查不过旧配置不动
func applyAll(st *State) {
	st.save()
	cfg, n := sbConfig(st)
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if n == 0 {
		writeFileAtomic(sbConf, b, 0600)
		svcDisable(svcBox)
	} else {
		tmp := sbConf + ".check"
		os.WriteFile(tmp, b, 0600)
		if out, err := runOut(sbBin, "check", "-c", tmp); err != nil {
			os.Remove(tmp)
			die("sing-box 配置检查不通过，旧配置没动:\n%s", out)
		}
		os.Rename(tmp, sbConf)
		svcEnable(svcBox)
		svcDo("restart", svcBox)
	}
	hopApply(st)
	xrayApply(st)
	if st.installed() {
		svcEnable(svcWeb)
		svcDo("restart", svcWeb)
	} else {
		svcDisable(svcWeb)
	}
	if !st.installed() {
		info("没有协议了，服务已停")
		return
	}
	// 等端口起来再报成功
	want := []int{}
	if st.Reality != nil {
		want = append(want, st.Reality.Port, st.Reality.Fallback)
	}
	if st.AnyTLS != nil {
		want = append(want, st.AnyTLS.Port)
	}
	if st.WS != nil {
		want = append(want, st.WS.Port, st.WS.Inner)
	}
	if st.Argo != nil {
		want = append(want, st.Argo.Inner, st.Argo.Web)
	}
	for i := 0; i < 20; i++ {
		bad := 0
		for _, p := range want {
			if portOwner(p) != "ours" {
				bad = p
			}
		}
		if st.Hy2 != nil && udpOwner(st.Hy2.Port) != "ours" {
			bad = st.Hy2.Port
		}
		if bad == 0 {
			ok("服务已运行")
			return
		}
		if i == 19 {
			svcLog(30, false)
			die("端口 %d 没起来，看上面的日志", bad)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// ── Hysteria2 端口跳跃 ───────────────────────────────
// 把一段 UDP 端口转到 hy2 端口上；dun 服务启动时会重新加一遍，重启机器也不丢
const hopTag = "dun-hy2"

func hopClear() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !have(bin) {
			continue
		}
		out, _ := runOut(bin, "-t", "nat", "-S", "PREROUTING")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "-A ") && strings.Contains(l, hopTag) {
				run(bin, append([]string{"-t", "nat", "-D"}, strings.Fields(l)[1:]...)...)
			}
		}
	}
}

func hopApply(st *State) {
	hopClear()
	h := st.Hy2
	if h == nil || h.HopStart == 0 {
		return
	}
	rng := fmt.Sprintf("%d:%d", h.HopStart, h.HopEnd)
	added := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		if have(bin) && run(bin, "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", rng,
			"-m", "comment", "--comment", hopTag, "-j", "REDIRECT", "--to-ports", fmt.Sprint(h.Port)) == nil {
			added = true
		}
	}
	if !added {
		warn("端口跳跃规则加不上，只能用单端口 %d", h.Port)
	}
}
