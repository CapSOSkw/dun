package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"time"
)

var version = "dev"

func usage() {
	fmt.Printf(`dun %s：Reality 偷自己 / AnyTLS / CF WS / Argo 隧道 一键节点
  dun                          打开管理菜单
  dun install <reality|anytls|ws|all|hy2|argo>
  dun remove  <reality|anytls|ws|hy2|argo>
  dun links                    查看订阅和链接
  dun mihomo                   输出 mihomo / Clash 配置
  dun cfip                     立即刷新优选 IP
  dun restart|stop|start|log
  dun update                   更新内核（sing-box，装了 Argo 还有 Xray、cloudflared）
  dun upgrade                  更新 dun 自己
  dun renew                    立即续期证书（平时会自动续）
  dun bbr                      开启 BBR
  dun syncip                   IP 变了以后同步解析
  dun rehost                   更换节点域名（证书一起换）
  dun uninstall                全部卸载
`, version)
}

func download(u, dst string, mode os.FileMode) error {
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	return err
}

// 把自己装到 /usr/local/bin/dun；先写临时文件再改名，正在运行的服务不受影响
func installSelf() {
	exe, err := os.Executable()
	if err != nil || exe == selfPath {
		return
	}
	src, err := os.Open(exe)
	if err != nil {
		return
	}
	defer src.Close()
	dst, err := os.OpenFile(selfPath+".new", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	io.Copy(dst, src)
	dst.Close()
	os.Rename(selfPath+".new", selfPath)
}

func firstSetup() *State {
	os.MkdirAll(baseDir, 0700)
	os.Chmod(baseDir, 0700)
	ensureCA()
	installSelf()
	st := loadState()
	if !exists(sbBin) {
		sbInstall("")
	}
	if !servicesWritten() {
		writeServices()
	}
	if st.Argo != nil {
		ensureArgoBins(!st.Argo.External)
	}
	if st.IP4 == "" && st.IP6 == "" {
		detectIP(st)
	}
	// 老版本装的 AnyTLS 用的是官方默认填充，补一份随机的
	if st.AnyTLS != nil && len(st.AnyTLS.Padding) == 0 {
		st.AnyTLS.Padding = randPadding()
		applyAll(st)
		ok("AnyTLS 已换成随机填充方案，密码不变")
	}
	if st.Disguise.Seed == 0 {
		st.Disguise.Seed = mrand.Uint64() | 1
		st.save()
		if st.installed() {
			svcDo("restart", svcWeb)
		}
	}
	if configStale(st) {
		applyAll(st)
		ok("配置已按 dun %s 更新", version)
	}
	return st
}

// 升级 dun 以后配置格式可能变了，和按新版本生成的对不上就要重新应用
func configStale(st *State) bool {
	if cfg, n := sbConfig(st); n > 0 {
		want, _ := json.MarshalIndent(cfg, "", "  ")
		if cur, _ := os.ReadFile(sbConf); !bytes.Equal(cur, want) {
			return true
		}
	}
	if st.Argo != nil {
		want, _ := json.MarshalIndent(xrayConfig(st), "", "  ")
		if cur, _ := os.ReadFile(xrayConf); !bytes.Equal(cur, want) {
			return true
		}
	}
	return false
}

func main() {
	args := append(os.Args[1:], "", "")
	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println("dun", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	case "serve":
		serve()
		return
	case "tunnel": // dun-argo 服务用
		runTunnel()
		return
	}
	if runtime.GOOS != "linux" {
		die("只支持 Linux")
	}
	if os.Geteuid() != 0 {
		die("请用 root 运行")
	}
	initTTY()
	detectOS()
	if initSys == "" {
		die("没找到 systemd 或 OpenRC，这个系统用不了")
	}
	st := firstSetup()
	switch args[0] {
	case "":
		menu(st)
	case "apply": // 升级后由 dun upgrade 调用，配置同步在 firstSetup 里已经做了
		if st.installed() {
			svcDo("restart", svcWeb)
		}
	case "install":
		switch args[1] {
		case "reality":
			installReality(st)
		case "anytls":
			installAnyTLS(st)
		case "ws":
			installWS(st)
		case "hy2":
			installHy2(st)
		case "argo":
			installArgo(st)
		case "all":
			installReality(st)
			installAnyTLS(st)
			installWS(st)
		default:
			usage()
			os.Exit(1)
		}
		showLinks(st)
	case "remove":
		switch args[1] {
		case "reality":
			removeReality(st)
		case "anytls":
			removeAnyTLS(st)
		case "ws":
			removeWS(st)
		case "hy2":
			removeHy2(st)
		case "argo":
			removeArgo(st)
		default:
			usage()
			os.Exit(1)
		}
	case "links":
		showLinks(st)
	case "mihomo":
		showMihomo(st)
	case "cfip":
		if n, err := refreshWetest(st); err != nil {
			die("刷新失败: %v", err)
		} else {
			ok("拉到 %d 个优选 IP", n)
		}
	case "restart", "stop", "start":
		for _, s := range activeSvcs() {
			svcDo(args[0], s)
		}
	case "log":
		svcLog(100, false)
	case "update":
		updateCore(st)
	case "upgrade":
		updateSelf()
	case "renew":
		if st.TLS == nil || st.Zone == nil {
			die("没有用到证书的协议")
		}
		info("重新申请 %s 的证书", st.TLS.Host)
		if err := issueCert(st, cfLogin()); err != nil {
			die("续期失败：%v", err)
		}
		if st.AnyTLS != nil {
			svcDo("restart", svcBox)
		}
		exp, _ := certExpiry()
		ok("证书已更新，到期时间 %s", exp.Local().Format("2006-01-02"))
	case "bbr":
		enableBBR()
	case "syncip":
		syncIP(st)
	case "rehost":
		changeNodeHost(st)
	case "uninstall":
		uninstallAll(st)
	default:
		usage()
		os.Exit(1)
	}
}
