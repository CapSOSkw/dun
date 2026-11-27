package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	initSys string // systemd / openrc
	pkgMgr  string
)

func detectOS() {
	switch {
	case have("apt-get"):
		pkgMgr = "apt"
	case have("dnf"):
		pkgMgr = "dnf"
	case have("yum"):
		pkgMgr = "yum"
	case have("apk"):
		pkgMgr = "apk"
	}
	if have("systemctl") && isDir("/run/systemd/system") {
		initSys = "systemd"
	} else if have("rc-service") {
		initSys = "openrc"
	}
}

func have(c string) bool   { _, err := exec.LookPath(c); return err == nil }
func isDir(p string) bool  { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// 跑外部命令；测试里换成替身，不真跑 systemctl、sing-box
var run = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

var runOut = func(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func runTTY(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if ttyFile != nil {
		c.Stdin = ttyFile
	}
	return c.Run()
}

func pkgInstall(pkgs ...string) error {
	switch pkgMgr {
	case "apt":
		if exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...).Run() == nil {
			return nil
		}
		run("apt-get", "update", "-q")
		c := exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
		c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		return c.Run()
	case "dnf", "yum":
		return run(pkgMgr, append([]string{"install", "-y", "-q"}, pkgs...)...)
	case "apk":
		return run("apk", append([]string{"add", "--no-cache", "-q"}, pkgs...)...)
	}
	return fmt.Errorf("不认识的包管理器")
}

// 极简系统可能没有根证书，访问 GitHub 和 CF 会失败
func ensureCA() {
	if p, err := x509.SystemCertPool(); err == nil && p != nil && !p.Equal(x509.NewCertPool()) {
		return
	}
	info("安装根证书 ca-certificates")
	pkgInstall("ca-certificates")
}

// ── 服务 ─────────────────────────────────────────────
func writeServices() {
	if initSys == "systemd" {
		box := fmt.Sprintf(`[Unit]
Description=dun sing-box
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, sbBin, sbConf)
		web := fmt.Sprintf(`[Unit]
Description=dun 伪装站、订阅和证书续期
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, selfPath)
		xray := fmt.Sprintf(`[Unit]
Description=dun Xray（Argo 的 XHTTP 入站）
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, xrayBin, xrayConf)
		// dun tunnel 读状态拼好参数再换成 cloudflared，切换隧道协议不用改服务文件
		argo := fmt.Sprintf(`[Unit]
Description=dun Argo 隧道（cloudflared）
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s tunnel
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, selfPath)
		os.WriteFile("/etc/systemd/system/"+svcBox+".service", []byte(box), 0644)
		os.WriteFile("/etc/systemd/system/"+svcWeb+".service", []byte(web), 0644)
		os.WriteFile("/etc/systemd/system/"+svcXray+".service", []byte(xray), 0644)
		os.WriteFile("/etc/systemd/system/"+svcArgo+".service", []byte(argo), 0644)
		run("systemctl", "daemon-reload")
		return
	}
	if initSys == "openrc" {
		tpl := `#!/sbin/openrc-run
name="%s"
command="%s"
command_args="%s"
supervisor=supervise-daemon
respawn_delay=3
output_log="/var/log/%s.log"
error_log="/var/log/%s.log"
depend() { need net; after firewall; }
`
		os.WriteFile("/etc/init.d/"+svcBox, []byte(fmt.Sprintf(tpl, svcBox, sbBin, "run -c "+sbConf, svcBox, svcBox)), 0755)
		os.WriteFile("/etc/init.d/"+svcWeb, []byte(fmt.Sprintf(tpl, svcWeb, selfPath, "serve", svcWeb, svcWeb)), 0755)
		os.WriteFile("/etc/init.d/"+svcXray, []byte(fmt.Sprintf(tpl, svcXray, xrayBin, "run -c "+xrayConf, svcXray, svcXray)), 0755)
		os.WriteFile("/etc/init.d/"+svcArgo, []byte(fmt.Sprintf(tpl, svcArgo, selfPath, "tunnel", svcArgo, svcArgo)), 0755)
	}
}

// 老版本升级上来没有 Xray 和隧道的服务文件，也要补写一遍
func servicesWritten() bool {
	return svcExists(svcWeb) && svcExists(svcArgo)
}

func svcDo(action, name string) error {
	if initSys == "systemd" {
		return run("systemctl", action, name)
	}
	return run("rc-service", name, action)
}

func svcEnable(name string) {
	if initSys == "systemd" {
		run("systemctl", "enable", name)
	} else {
		run("rc-update", "add", name, "default")
	}
}

func svcDisable(name string) {
	if initSys == "systemd" {
		run("systemctl", "disable", "--now", name)
	} else {
		run("rc-service", name, "stop")
		run("rc-update", "del", name, "default")
	}
}

func svcActive(name string) bool {
	if initSys == "systemd" {
		return run("systemctl", "is-active", "--quiet", name) == nil
	}
	return run("rc-service", name, "status") == nil
}

func svcLog(n int, follow bool) {
	all := []string{svcBox, svcWeb, svcXray, svcArgo}
	if initSys == "systemd" {
		args := []string{"--no-pager", "-o", "short", "-n", strconv.Itoa(n)}
		for _, s := range all {
			args = append(args, "-u", s)
		}
		if follow {
			args = append(args, "-f")
		}
		runTTY("journalctl", args...)
		return
	}
	args := []string{"-n", strconv.Itoa(n)}
	if follow {
		args = append(args, "-f")
	}
	files := 0
	for _, s := range all {
		if f := "/var/log/" + s + ".log"; exists(f) {
			args = append(args, f)
			files++
		}
	}
	if files == 0 {
		warn("还没有日志")
		return
	}
	runTTY("tail", args...)
}

// OpenRC 下服务的输出直接写 /var/log，没人轮转。超过 20MB 就只留最后 2MB，免得把小鸡的硬盘写满；
// systemd 下日志进 journald，由它自己轮转，用不着这个
func trimLogs() {
	for _, s := range []string{svcBox, svcWeb, svcXray, svcArgo} {
		trimLog("/var/log/"+s+".log", 20<<20, 2<<20)
	}
}

func logTrimLoop() {
	for {
		time.Sleep(6 * time.Hour)
		trimLogs()
	}
}

// 原地截断，supervise-daemon 是追加写的，截完接着往末尾写。
// shortcut: 读尾部到截断之间服务新写的几行会丢（copytruncate 的固有限制），要一行不丢得换成服务配合的轮转
func trimLog(p string, max, keep int64) {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() <= max {
		return
	}
	buf := make([]byte, keep)
	if n, err := f.ReadAt(buf, fi.Size()-keep); err != nil || int64(n) != keep {
		return // 尾巴没读全就不截，免得把日志清空
	}
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	if err := f.Truncate(0); err != nil {
		warn("截断 %s 失败：%v", p, err)
		return
	}
	if _, err := f.WriteAt(buf, 0); err != nil {
		warn("%s 截断后写回最后 %d 字节失败：%v", p, len(buf), err)
	}
}

// ── 端口 ─────────────────────────────────────────────
func listenInodes(port int) []string { return sockInodes(port, false) }

var procDir = "/proc" // 测试里指到临时目录

// UDP 没有监听状态：未连接的套接字是 07，绑了端口再 connect 的是 01，都占着端口。states 不填就是这两种（TCP 是 0A）
func sockInodes(port int, udp bool, states ...string) []string {
	files := []string{"tcp", "tcp6"}
	if udp {
		files = []string{"udp", "udp6"}
	}
	if len(states) == 0 {
		states = []string{"0A"}
		if udp {
			states = []string{"07", "01"}
		}
	}
	var res []string
	for _, f := range files {
		b, err := os.ReadFile(procDir + "/net/" + f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 || !slices.Contains(states, fs[3]) {
				continue
			}
			idx := strings.LastIndex(fs[1], ":")
			if p, err := strconv.ParseUint(fs[1][idx+1:], 16, 32); err == nil && int(p) == port {
				res = append(res, fs[9])
			}
		}
	}
	return res
}

// 返回占用端口的进程名；空 = 空闲，ours = 本程序或它管的 sing-box
func portOwner(port int) string { return sockOwner(port, false) }
func udpOwner(port int) string  { return sockOwner(port, true) }

// applyAll 的就绪检查：本脚本的进程在这个 UDP 端口上真的在收包（07）。自家已连接的 01 不算，和 v1.2.0 一样
func udpListening(port int) bool {
	inodes := sockInodes(port, true, "07")
	return len(inodes) > 0 && inodeOwner(inodes, true) == "ours"
}

func sockOwner(port int, udp bool) string {
	inodes := sockInodes(port, udp)
	if len(inodes) == 0 {
		if udp {
			return ""
		}
		if !exists("/proc/net/tcp") {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				return "未知进程"
			}
			ln.Close()
		}
		return ""
	}
	return inodeOwner(inodes, udp)
}

// 找出持有这些套接字的进程。TCP 和 v1.2.0 一样认第一个匹配的进程；
// UDP（preferOurs）同一端口可能还挂着别的进程的已连接套接字，只要有一个是自家的就算 ours，别让排在前面的外部进程盖过去
func inodeOwner(inodes []string, preferOurs bool) string {
	want := map[string]bool{}
	for _, i := range inodes {
		want["socket:["+i+"]"] = true
	}
	other := ""
	procs, _ := os.ReadDir(procDir)
	for _, p := range procs {
		if !p.IsDir() || p.Name()[0] < '0' || p.Name()[0] > '9' {
			continue
		}
		dir := procDir + "/" + p.Name()
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !want[l] {
				continue
			}
			cmd, _ := os.ReadFile(dir + "/cmdline")
			c := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
			if strings.Contains(c, sbConf) || strings.Contains(c, xrayConf) || strings.HasSuffix(c, "dun serve") {
				return "ours"
			}
			name := "未知进程"
			if comm, _ := os.ReadFile(dir + "/comm"); len(strings.TrimSpace(string(comm))) > 0 {
				name = strings.TrimSpace(string(comm))
			}
			if !preferOurs {
				return name
			}
			if other == "" {
				other = name
			}
		}
	}
	if other != "" {
		return other
	}
	return "未知进程"
}

func (s *State) usedPorts(skip string) map[int]string {
	m := map[int]string{}
	if s.Reality != nil {
		m[s.Reality.Fallback] = "reality"
		if skip != "reality" {
			m[s.Reality.Port] = "reality"
		}
	}
	if s.AnyTLS != nil && skip != "anytls" {
		m[s.AnyTLS.Port] = "anytls"
	}
	if s.WS != nil {
		m[s.WS.Inner] = "ws"
		if skip != "ws" {
			m[s.WS.Port] = "ws"
		}
	}
	if s.Argo != nil {
		m[s.Argo.Inner] = "argo"
		m[s.Argo.Web] = "argo"
		m[s.Argo.Metrics] = "argo"
	}
	return m
}

func randPort(st *State, avoid ...int) int {
	used := st.usedPorts("")
	for _, a := range avoid {
		used[a] = "x"
	}
	for i := 0; i < 100; i++ {
		p := 20000 + rand.IntN(40000)
		if p >= 20241 && p <= 20245 { // 别的 cloudflared 默认拿这几个做监控端口，开机时可能抢先占掉
			continue
		}
		if _, u := used[p]; !u && portOwner(p) == "" {
			return p
		}
	}
	die("找不到空闲端口")
	return 0
}

func curPorts(st *State, key string) (int, int) {
	switch {
	case key == "reality" && st.Reality != nil:
		return st.Reality.Port, st.Reality.PubPort
	case key == "anytls" && st.AnyTLS != nil:
		return st.AnyTLS.Port, st.AnyTLS.PubPort
	case key == "ws" && st.WS != nil:
		return st.WS.Port, st.WS.PubPort
	case key == "hy2" && st.Hy2 != nil:
		return st.Hy2.Port, st.Hy2.PubPort
	case key == "tuic" && st.TUIC != nil:
		return st.TUIC.Port, st.TUIC.PubPort
	}
	return 0, 0
}

func askPort(st *State, prompt string, def int, key string) int {
	used := st.usedPorts(key)
	current, _ := curPorts(st, key)
	for {
		p := askInt(prompt, def, 1, 65535)
		if _, u := used[p]; u {
			reask("%d 已经分给本脚本的其他协议了", p)
			continue
		}
		if o := portOwner(p); o != "" && o != "ours" && p != current {
			reask("%d 被 %s 占用，换一个", p, o)
			continue
		}
		return p
	}
}

const (
	portDirect = "direct"
	portMapped = "mapped"
)

func hasLocalIP(ip string, addrs []net.Addr) bool {
	want := net.ParseIP(ip)
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && want.Equal(n.IP) {
			return true
		}
	}
	return false
}

func (st *State) hasMappedPorts() bool {
	for _, key := range []string{"reality", "anytls", "ws", "hy2", "tuic"} {
		port, pub := curPorts(st, key)
		if pub > 0 && pub != port {
			return true
		}
	}
	return false
}

func selectPortMode(st *State, addrs []net.Addr) string {
	mapped := st.hasMappedPorts()
	if !mapped && st.PortMode != portMapped && (st.IP4 == "" || hasLocalIP(st.IP4, addrs)) {
		return portDirect
	}
	def := 1
	if st.PortMode == portMapped || (st.PortMode == "" && mapped) {
		def = 2
	}
	info("请选择服务商给这台机器分配端口的方式")
	info("1. 独享公网 IP，可以自行开放端口，比如绑定公网 IP 的甲骨文实例")
	info("2. 只能用服务商分配的映射端口，包括内外端口号相同的情况")
	if askInt("端口方式", def, 1, 2) == 2 {
		return portMapped
	}
	return portDirect
}

// 端口方式是全局的：换成映射端口后，已装的 Hy2 也只能走单端口；别的协议端口不动
func (st *State) setPortMode(mode string) {
	st.PortMode = mode
	if h := st.Hy2; h != nil && mode == portMapped && h.HopStart > 0 {
		setHy2Range(h, mode) // 只改内存，旧范围的放行规则等 applyAll 成功后由 fwPrune 回收
	}
}

func askPubPort(st *State, p int) int {
	if st.PortMode != portDirect && st.PortMode != portMapped {
		addrs, _ := net.InterfaceAddrs()
		st.setPortMode(selectPortMode(st, addrs))
	}
	if st.PortMode == portMapped {
		return askInt("  服务商分配的外网端口", p, 1, 65535)
	}
	return p
}

// ── 公网 IP ──────────────────────────────────────────
func traceIP(network, u string) string {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "ip=") {
			return strings.TrimSpace(l[3:])
		}
	}
	return ""
}

func detectIP(st *State) {
	oldIP4 := st.IP4
	st.IP4 = traceIP("tcp4", "https://1.1.1.1/cdn-cgi/trace")
	st.IP6 = traceIP("tcp6", "https://[2606:4700:4700::1111]/cdn-cgi/trace")
	if st.IP4 == "" && st.IP6 == "" {
		die("拿不到公网 IP，检查网络")
	}
	if oldIP4 != st.IP4 {
		st.PortMode = ""
	}
	st.save()
}

func (s *State) srvAddr() string {
	if s.IP4 != "" {
		return s.IP4
	}
	return "[" + s.IP6 + "]"
}

func listenAll() string {
	if exists("/proc/net/if_inet6") {
		return "::"
	}
	return "0.0.0.0"
}

func enableBBR() {
	cur, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if strings.TrimSpace(string(cur)) == "bbr" {
		ok("BBR 已经开着")
		return
	}
	run("modprobe", "tcp_bbr")
	f := "/etc/sysctl.d/99-dun-bbr.conf"
	os.WriteFile(f, []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"), 0644)
	run("sysctl", "-p", f)
	cur, _ = os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if strings.TrimSpace(string(cur)) == "bbr" {
		ok("BBR 已开启")
		return
	}
	os.Remove(f)
	warn("这台机器开不了 BBR，内核太老或者容器不让改")
}
