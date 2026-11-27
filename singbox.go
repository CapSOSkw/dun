package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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

// 菜单 15：列出当前、推荐、上游最新正式版，问装哪个；返回 "" = 不更新。
// 回车、读到头都算不更新；比当前旧的版本写明「降级到」，还要再确认一次
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
	} else {
		info("%s 当前 %s，推荐 %s，上游最新正式版 %s", name, show, pinned, latest)
	}
	var vers []string
	add := func(v, what string) {
		if v == "" || slices.Contains(vers, v) {
			return
		}
		verb := "升到"
		if c := vcmp(v, cur); c == 0 {
			verb = "重装"
		} else if c < 0 {
			verb = "降级到"
		}
		vers = append(vers, v)
		fmt.Fprintf(os.Stderr, "  %d. %s%s %s\n", len(vers), verb, what, v)
	}
	add(pinned, "推荐版本")
	add(latest, "最新正式版")
	a, full := askLine("装哪个（回车不更新）")
	n, err := strconv.Atoi(a)
	if !full || err != nil || n < 1 || n > len(vers) {
		info("不更新 %s", name)
		return ""
	}
	v := vers[n-1]
	if vcmp(v, cur) < 0 {
		a, full = askLine(fmt.Sprintf("%s 会从 %s 降级到 %s，确定？(y/n) [n]", name, show, v))
		if a = strings.ToLower(a); !full || (a != "y" && a != "yes") {
			info("不更新 %s", name)
			return ""
		}
	}
	return v
}

// 菜单 15 专用：读一整行；没读到换行（读到头、只有半行）返回 false，调用者当作取消
func askLine(prompt string) (string, bool) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	s, err := in.ReadString('\n')
	eofIn = nil
	if err != nil {
		eofIn = in
		fmt.Fprintln(os.Stderr)
		return "", false
	}
	return strings.TrimSpace(s), true
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
	placeBin(sbBin, svcBox, "sing-box", sbVersionAt)
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
	applyHop   = hopRules
	applyLog   = func() { svcLog(30, false) }
	applyWrite = writeFileAtomic
	readyWait  = 300 * time.Millisecond
)

// 新配置写到同目录的独立临时文件里检查，用完删掉
func checkConf(dir, pattern string, b []byte, bin string, args ...string) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err.Error(), err
	}
	tmp := f.Name()
	defer func() {
		if err := os.Remove(tmp); err != nil {
			warn("临时文件 %s 删不掉: %v", tmp, err)
		}
	}()
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
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

// 预检：新配置写临时文件检查，不过就退出，磁盘上的状态、配置和正在跑的服务都不动。
// 没有入站时不跑 sing-box，不用检查；sbConf 照旧写一份空入站的配置（和以前一样），回滚时一起还原
func applyCheck(st *State) (sbNew, xrNew []byte, xrChanged bool) {
	cfg, n := sbConfig(st)
	sbNew, _ = json.MarshalIndent(cfg, "", "  ")
	if st.Argo != nil {
		xrNew, _ = json.MarshalIndent(xrayConfig(st), "", "  ")
		cur, _ := os.ReadFile(xrayConf)
		xrChanged = !bytes.Equal(cur, xrNew)
	}
	if n > 0 {
		if out, err := checkConf(filepath.Dir(sbConf), "sing-box-check-*.json", sbNew, sbBin, "check", "-c"); err != nil {
			die("sing-box 配置检查不通过，旧配置没动:\n%s", out)
		}
	}
	if xrChanged { // Xray 按扩展名认格式，临时文件得是 .json
		if out, err := checkConf(filepath.Dir(xrayConf), "xray-check-*.json", xrNew, xrayBin, "run", "-test", "-c"); err != nil {
			die("Xray 配置检查不通过，旧配置没动:\n%s", out)
		}
	}
	return
}

// 分两步，不留半态：
//  1. applyCheck 预检
//  2. 记下旧文件，换上新状态和新配置再起服务、等端口；中途失败就换回旧文件、按旧状态恢复服务再退出。
//     旧的放行规则只在全部就绪后才回收
func applyAll(st *State) {
	sbNew, xrNew, xrChanged := applyCheck(st)
	stNew, _ := json.MarshalIndent(st, "", "  ")
	old := snapFiles(statePath, sbConf, xrayConf)
	fail := func(err error) {
		warn("%v", err)
		if rerr := applyRollback(old, xrChanged); rerr != nil {
			die("没应用成功，回滚未完全成功：\n%v", rerr)
		}
		die("没应用成功，已回滚到原来的配置")
	}
	// dun serve 启动时按 state.json 定监听端口，所以先换状态再重启服务
	err := applyWrite(statePath, stNew, 0600)
	if err == nil {
		err = applyWrite(sbConf, sbNew, 0600)
	}
	if err == nil && xrChanged {
		err = applyWrite(xrayConf, xrNew, 0600)
	}
	if err != nil {
		fail(fmt.Errorf("写配置失败: %v", err))
	}
	// 没有协议了也一样：停不掉就回滚，调用者后面的清理（比如删 CF 上的隧道）不会再做
	if err := startServices(st, xrChanged, false); err != nil {
		fail(err)
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
	bad := ""
	for i := 0; i < 20; i++ {
		if i > 0 {
			time.Sleep(readyWait)
		}
		bad = ""
		for _, p := range want {
			if !portReady(p) {
				bad = fmt.Sprintf("TCP 端口 %d", p)
			}
		}
		for _, p := range udp {
			if !udpReady(p) {
				bad = fmt.Sprintf("UDP 端口 %d", p)
			}
		}
		if st.Argo != nil && !st.Argo.External && !svcActive(svcArgo) {
			bad = "cloudflared 服务 " + svcArgo
		}
		if bad == "" {
			applyPrune(st)
			ok("服务已运行")
			return
		}
	}
	applyLog()
	fail(fmt.Errorf("%s 没起来，看上面的日志", bad))
}

// 按 st 起停所有服务；一步出错也接着做完，错误汇总返回。applyAll 和回滚共用。
// 回滚时跳跃规则加不上只记错误，不改状态文件（刚还原的字节要保持原样）
func startServices(st *State, xrChanged, rollback bool) error {
	var errs []error
	add := func(err error, what string) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", what, err))
		}
	}
	if _, n := sbConfig(st); n == 0 {
		add(svcDisable(svcBox), "sing-box 服务停不掉")
	} else {
		add(svcEnable(svcBox), "sing-box 设不了开机启动")
		add(svcDo("restart", svcBox), "sing-box 服务起不来")
	}
	// 旧规则列不出、删不掉都算失败（没有 iptables 的机器 hopClear 直接跳过）
	clearErr, addErr := applyHop(st)
	if rollback {
		add(clearErr, "清掉新的端口跳跃规则")
		add(addErr, "按原来的配置加端口跳跃")
	} else {
		add(clearErr, "清旧的端口跳跃规则")
		if addErr != nil {
			add(hopOff(st), "关掉端口跳跃")
		}
	}
	if err := xrayApply(st, xrChanged); err != nil {
		errs = append(errs, err)
	}
	if st.installed() {
		add(svcEnable(svcWeb), "dun 服务设不了开机启动")
		add(svcDo("restart", svcWeb), "dun 服务起不来")
	} else {
		add(svcDisable(svcWeb), "dun 服务停不掉")
	}
	return errors.Join(errs...)
}

// 换回 applyAll 之前的文件，按旧状态重新加跳跃规则、起停服务；每一步都做，错误汇总返回。
// 不回收放行规则，也不调用会 die 的 loadState / save
func applyRollback(old []fileSnap, xrChanged bool) error {
	var errs []error
	prev := &State{}
	for _, f := range old {
		var err error
		if f.had {
			err = applyWrite(f.path, f.data, 0600)
		} else if err = os.Remove(f.path); os.IsNotExist(err) {
			err = nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("还原 %s: %v", f.path, err))
		}
		if f.path == statePath && f.had {
			if err := json.Unmarshal(f.data, prev); err != nil {
				errs = append(errs, fmt.Errorf("旧状态文件解析不了: %v", err))
			}
		}
	}
	if err := startServices(prev, xrChanged, true); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ── Hysteria2 端口跳跃 ───────────────────────────────
// 把一段 UDP 端口转到 hy2 端口上；dun 服务启动时会重新加一遍，重启机器也不丢
const hopTag = "dun-hy2"

// 删掉 dun 加的跳跃规则；列不出、删不掉的都返回
func hopClear() error {
	var errs []error
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !fwHave(bin) {
			continue
		}
		out, err := fwOut(bin, "-t", "nat", "-S", "PREROUTING")
		if err != nil {
			errs = append(errs, fmt.Errorf("%s 列不出 nat 规则: %v", bin, err))
			continue
		}
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "-A ") && strings.Contains(l, hopTag) {
				if err := fwCmd(bin, append([]string{"-t", "nat", "-D"}, strings.Fields(l)[1:]...)...); err != nil {
					errs = append(errs, fmt.Errorf("%s 删不掉 %s: %v", bin, l, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// 服务启动时用：规则加不上就关掉跳跃并写回状态
func hopApply(st *State) {
	clearErr, addErr := hopRules(st)
	if clearErr != nil {
		warn("清旧的端口跳跃规则出错: %v", clearErr)
	}
	if addErr != nil {
		if err := hopOff(st); err != nil {
			die("%v", err)
		}
	}
}

// 先清掉旧规则，再按 st 加跳跃规则；两步的错误分开返回，不碰状态文件
func hopRules(st *State) (clearErr, addErr error) {
	clearErr = hopClear()
	h := st.Hy2
	if h == nil || h.HopStart == 0 {
		return clearErr, nil
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
		return clearErr, fmt.Errorf("端口跳跃规则 %s 加不上", rng)
	}
	return clearErr, nil
}

// 跳跃规则加不上：关掉跳跃写回状态，所有进程（订阅、dun links、dun mihomo）都不再发跳不过去的范围。
// 基于磁盘上最新的状态只改这两个字段，别拿启动时的旧快照整份覆盖别的进程刚存的设置
func hopOff(st *State) error {
	h := st.Hy2
	start, end := h.HopStart, h.HopEnd
	h.HopStart, h.HopEnd = 0, 0
	cur, err := readState()
	if err != nil {
		return err
	}
	if cur.Hy2 == nil || cur.Hy2.HopStart != start || cur.Hy2.HopEnd != end {
		warn("端口跳跃规则加不上，状态文件里的跳跃配置已经改过了，没有写回")
		return nil
	}
	cur.Hy2.HopStart, cur.Hy2.HopEnd = 0, 0
	if err := cur.write(); err != nil {
		return fmt.Errorf("保存状态失败: %v", err)
	}
	warn("端口跳跃规则加不上，已关掉跳跃，Hy2 走单端口 %d；以后能加了，进菜单 11 改 Hy2 端口时会重新开", h.Port)
	return nil
}
