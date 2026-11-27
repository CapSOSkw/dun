package main

import (
	"archive/tar"
	"bytes"
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

// 不带版本安装时装的内核版本，都是验证过的；菜单 15 可以换成上游最新的正式版
const (
	sbPinned   = "1.14.5"
	xrayPinned = "26.11.9"
	cfdPinned  = "2026.11.2"
)

// 测试里换成替身，不联网
var dlVerified = downloadVerified

// 跟 releases/latest 的跳转拿版本号，不走 API，免得被限流。releases/latest 只指向正式版
var ghLatest = func(repo string) string {
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

// 第一行形如 sing-box version 1.14.5
func sbVersionAt(bin string) string { return binVersion(bin, 2, "version") }
func sbVersion() string             { return sbVersionAt(sbBin) }

// 版本号按数字段比较："1.14.5" < "1.15.0"，"2026.9.1" < "2026.11.2"。空串比谁都小
func vcmp(a, b string) int {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	seg := func(p []string, i int) int {
		n := 0
		if i < len(p) {
			for _, c := range p[i] {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
			}
		}
		return n
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		if x, y := seg(pa, i), seg(pb, i); x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// 菜单 15：列出当前、推荐、上游最新正式版，问装哪个；返回 "" = 不更新
func pickVersion(name, cur, pinned, latest string) string {
	show := cur
	if show == "" {
		show = "未知"
	}
	if latest == "" {
		info("%s 当前 %s，推荐 %s；拿不到上游最新版本号", name, show, pinned)
		if cur == pinned {
			warn("%s 已经是推荐版本，先不更新", name)
			return ""
		}
		if confirm(fmt.Sprintf("装推荐版本 %s？", pinned), vcmp(cur, pinned) < 0) {
			return pinned
		}
		return ""
	}
	info("%s 当前 %s，推荐 %s，上游最新正式版 %s", name, show, pinned, latest)
	switch {
	case vcmp(cur, pinned) < 0 && vcmp(latest, pinned) > 0:
		switch choose([]string{"升到推荐版本 " + pinned, "升到最新正式版 " + latest, "不更新"}, 1) {
		case 0:
			return pinned
		case 1:
			return latest
		}
		return ""
	case vcmp(cur, latest) >= 0:
		if confirm(name+" 已经是最新 "+cur+"，还要重装？", false) {
			return latest
		}
		return ""
	case vcmp(cur, pinned) < 0:
		if confirm(fmt.Sprintf("升到推荐版本 %s？", pinned), true) {
			return pinned
		}
		return ""
	}
	if confirm(fmt.Sprintf("升到最新正式版 %s？", latest), false) {
		return latest
	}
	return ""
}

func sbInstall(ver string) {
	if ver == "" {
		ver = sbPinned
	}
	name := fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", ver, sbArch())
	info("下载 sing-box %s (%s)", ver, sbArch())
	os.MkdirAll(path.Dir(sbBin), 0755)
	tgz := sbBin + ".tar.gz"
	defer os.Remove(tgz)
	if err := dlVerified("SagerNet/sing-box", "v"+ver, name, tgz, 0600); err != nil {
		die("sing-box 下载失败：%v", err)
	}
	pkg, err := os.Open(tgz)
	if err != nil {
		die("%v", err)
	}
	defer pkg.Close()
	gz, err := gzip.NewReader(pkg)
	if err != nil {
		die("sing-box 包解不开: %v", err)
	}
	tr := tar.NewReader(gz)
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
			os.Remove(sbBin + ".new")
			die("sing-box 下载不完整: %v", err)
		}
		break
	}
	placeBin(sbBin, "sing-box", sbVersionAt)
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
	if t := st.TUIC; t != nil {
		inb = append(inb, map[string]any{
			"type": "tuic", "tag": "tuic", "listen": listenAll(), "listen_port": t.Port,
			"users":              []any{map[string]any{"name": user, "uuid": t.UUID, "password": t.Password}},
			"congestion_control": t.cc(), "zero_rtt_handshake": false,
			"tls": map[string]any{"enabled": true, "server_name": st.TLS.Host, "alpn": []string{"h3"},
				"certificate_path": certFile, "key_path": keyFile},
		})
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

// applyAll 的外部副作用，测试里换成替身
var (
	portReady  = func(p int) bool { return portOwner(p) == "ours" }
	udpReady   = udpListening
	applyPrune = fwPrune
	applyHop   = hopApply
	applyLog   = func() { svcLog(30, false) }
	readyWait  = 300 * time.Millisecond
)

// 新配置写到临时文件检查，检查完临时文件删掉
func checkConf(tmp string, b []byte, bin string, args ...string) (string, error) {
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err.Error(), err
	}
	out, err := runOut(bin, append(args, tmp)...)
	if err != nil && out == "" { // 没输出（比如内核文件不在）就把错误本身打出来
		out = err.Error()
	}
	return out, err
}

type fileSnap struct {
	path string
	data []byte
	had  bool
}

// 应用前的磁盘原样；原来不存在的文件回滚时删掉
func snapFiles(paths ...string) []fileSnap {
	var snap []fileSnap
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			die("读不到 %s，没动任何配置: %v", p, err)
		}
		snap = append(snap, fileSnap{p, b, err == nil})
	}
	return snap
}

// 分两步，不留半态：
//  1. 新配置写到临时文件检查，不过就退出，磁盘上的状态、配置和正在跑的服务都不动
//  2. 记下旧文件，换上新状态和新配置再起服务、等端口；中途失败就换回旧文件、按旧状态恢复服务再退出。
//     旧的放行规则只在全部就绪后才回收
func applyAll(st *State) {
	cfg, n := sbConfig(st)
	sbNew, _ := json.MarshalIndent(cfg, "", "  ")
	stNew, _ := json.MarshalIndent(st, "", "  ")
	var xrNew []byte
	xrChanged := false
	if st.Argo != nil {
		xrNew, _ = json.MarshalIndent(xrayConfig(st), "", "  ")
		cur, _ := os.ReadFile(xrayConf)
		xrChanged = !bytes.Equal(cur, xrNew)
	}
	if n > 0 {
		if out, err := checkConf(sbConf+".check", sbNew, sbBin, "check", "-c"); err != nil {
			die("sing-box 配置检查不通过，旧配置没动:\n%s", out)
		}
	}
	if xrChanged { // Xray 按扩展名认格式，临时文件得是 .json
		if out, err := checkConf(strings.TrimSuffix(xrayConf, ".json")+".check.json", xrNew, xrayBin, "run", "-test", "-c"); err != nil {
			die("Xray 配置检查不通过，旧配置没动:\n%s", out)
		}
	}

	old := snapFiles(statePath, sbConf, xrayConf)
	fail := func(f string, a ...any) {
		warn(f, a...)
		applyRollback(old, xrChanged)
		die("没应用成功，已换回原来的配置")
	}
	// dun serve 启动时按 state.json 定监听端口，所以先换状态再重启服务
	err := writeFileAtomic(statePath, stNew, 0600)
	if err == nil {
		err = writeFileAtomic(sbConf, sbNew, 0600)
	}
	if err == nil && xrChanged {
		err = writeFileAtomic(xrayConf, xrNew, 0600)
	}
	if err != nil {
		fail("写配置失败: %v", err)
	}
	if err := startServices(st, xrChanged); err != nil {
		fail("%v", err)
	}
	if !st.installed() {
		applyPrune(st)
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
	var udp []int
	if st.Hy2 != nil {
		udp = append(udp, st.Hy2.Port)
	}
	if st.TUIC != nil {
		udp = append(udp, st.TUIC.Port)
	}
	bad := 0
	for i := 0; i < 20; i++ {
		if i > 0 {
			time.Sleep(readyWait)
		}
		bad = 0
		for _, p := range want {
			if !portReady(p) {
				bad = p
			}
		}
		for _, p := range udp {
			if !udpReady(p) {
				bad = p
			}
		}
		if bad == 0 {
			applyPrune(st)
			ok("服务已运行")
			return
		}
	}
	applyLog()
	fail("端口 %d 没起来，看上面的日志", bad)
}

// 按 st 起停所有服务；applyAll 和回滚共用
func startServices(st *State, xrChanged bool) error {
	if _, n := sbConfig(st); n == 0 {
		svcDisable(svcBox)
	} else {
		svcEnable(svcBox)
		if err := svcDo("restart", svcBox); err != nil {
			return fmt.Errorf("sing-box 服务起不来: %v", err)
		}
	}
	applyHop(st)
	if err := xrayApply(st, xrChanged); err != nil {
		return err
	}
	if !st.installed() {
		svcDisable(svcWeb)
		return nil
	}
	svcEnable(svcWeb)
	if err := svcDo("restart", svcWeb); err != nil {
		return fmt.Errorf("dun 服务起不来: %v", err)
	}
	return nil
}

// 换回 applyAll 之前的文件，按旧状态重新加跳跃规则、起停服务。不回收放行规则
func applyRollback(old []fileSnap, xrChanged bool) {
	prev := &State{}
	for _, f := range old {
		var err error
		if f.had {
			err = writeFileAtomic(f.path, f.data, 0600)
		} else if err = os.Remove(f.path); os.IsNotExist(err) {
			err = nil
		}
		if err != nil {
			warn("还原 %s 失败: %v", f.path, err)
		}
		if f.path == statePath && f.had {
			if err := json.Unmarshal(f.data, prev); err != nil {
				warn("旧状态文件解析不了: %v", err)
			}
		}
	}
	if err := startServices(prev, xrChanged); err != nil {
		warn("按原来的配置恢复服务也失败了: %v", err)
	}
}

// ── Hysteria2 端口跳跃 ───────────────────────────────
// 把一段 UDP 端口转到 hy2 端口上；dun 服务启动时会重新加一遍，重启机器也不丢
const hopTag = "dun-hy2"

func hopClear() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !fwHave(bin) {
			continue
		}
		out, _ := fwOut(bin, "-t", "nat", "-S", "PREROUTING")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "-A ") && strings.Contains(l, hopTag) {
				fwCmd(bin, append([]string{"-t", "nat", "-D"}, strings.Fields(l)[1:]...)...)
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
	// 纯 IPv6 的机器得 ip6tables 加上才算数
	need := map[string]bool{"iptables": st.IP4 != "" || st.IP6 == "", "ip6tables": st.IP6 != ""}
	added := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		if fwHave(bin) && fwCmd(bin, "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", rng,
			"-m", "comment", "--comment", hopTag, "-j", "REDIRECT", "--to-ports", fmt.Sprint(h.Port)) == nil && need[bin] {
			added = true
		}
	}
	if !added {
		start, end := h.HopStart, h.HopEnd
		h.HopStart, h.HopEnd = 0, 0
		// 写回状态，所有进程（订阅、dun links、dun mihomo）都不再发跳不过去的范围。
		// 基于磁盘上最新的状态只改这两个字段，别拿启动时的旧快照整份覆盖别的进程刚存的设置
		cur := loadState()
		if cur.Hy2 == nil || cur.Hy2.HopStart != start || cur.Hy2.HopEnd != end {
			warn("端口跳跃规则加不上，状态文件里的跳跃配置已经改过了，没有写回")
			return
		}
		cur.Hy2.HopStart, cur.Hy2.HopEnd = 0, 0
		cur.save()
		warn("端口跳跃规则加不上，已关掉跳跃，Hy2 走单端口 %d；以后能加了，进菜单 11 改 Hy2 端口时会重新开", h.Port)
	}
}
