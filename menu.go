package main

import (
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

func protoLabel(k string) string {
	return map[string]string{"reality": "Reality 偷自己", "anytls": "AnyTLS", "ws": "CF WS", "hy2": "Hysteria2",
		"tuic": "TUIC v5", "argo": "Argo 隧道"}[k]
}

func pickProto(st *State) string {
	var ks []string
	if st.Reality != nil {
		ks = append(ks, "reality")
	}
	if st.AnyTLS != nil {
		ks = append(ks, "anytls")
	}
	if st.WS != nil {
		ks = append(ks, "ws")
	}
	if st.Hy2 != nil {
		ks = append(ks, "hy2")
	}
	if st.TUIC != nil {
		ks = append(ks, "tuic")
	}
	if st.Argo != nil {
		ks = append(ks, "argo")
	}
	if len(ks) == 0 {
		warn("还没装任何协议")
		return ""
	}
	var ls []string
	for _, k := range ks {
		ls = append(ls, protoLabel(k))
	}
	i := choose(ls, 1)
	if i < 0 {
		return ""
	}
	return ks[i]
}

func showLinks(st *State) {
	if !st.installed() {
		warn("还没装任何协议")
		return
	}
	if (st.WS != nil || st.Argo != nil) && len(loadWetest().Items) == 0 && st.CFIP.Wetest {
		refreshWetest(st)
	}
	var b strings.Builder
	var qrs []string
	if base := subBase(st); base != "" {
		b.WriteString("【订阅】v2rayN / Shadowrocket / NekoBox / 小火箭\n" + base + "/sub\n\n")
		b.WriteString("【订阅】Clash Verge / FlClash / mihomo\n" + base + "/clash\n\n")
		qrs = append(qrs, base+"/sub")
	} else {
		b.WriteString("【订阅】没有在线订阅：它由 Reality 偷自己、CF WS 或 Argo 隧道的域名提供。只装 Hy2 / TUIC 时导入下面的单个链接，Clash 配置用 dun mihomo 导出\n\n")
	}
	base := nodeName()
	if st.Reality != nil {
		l := linkReality(st, base+"-Reality")
		b.WriteString("【Reality 偷自己】直连，速度最好\n" + l + "\n\n")
		qrs = append(qrs, l)
	}
	if st.AnyTLS != nil {
		l := linkAnyTLS(st, base+"-AnyTLS")
		b.WriteString("【AnyTLS】直连，客户端要支持 AnyTLS\n" + l + "\n\n")
		qrs = append(qrs, l)
	}
	if st.Argo != nil {
		a := CFAddr{Addr: st.Argo.Host, Port: 443, Name: base + "-Argo"}
		l := linkArgo(st, a, false)
		b.WriteString("【Argo 隧道】VLESS + XHTTP，VPS 不开端口，IP 被墙也能用\n" + l + "\n")
		qrs = append(qrs, l)
		n := len(cfAddrs(st, true))
		if !st.CFIP.NoH3 {
			a.Name += "-UDP"
			lu := linkArgo(st, a, true)
			b.WriteString(lu + "\n")
			b.WriteString("上面两个一个走 TCP（h2）、一个走 UDP（h3），晚高峰 UDP 往往更稳，UDP 被限速时用 TCP\n")
			qrs = append(qrs, lu)
			n *= 2
		}
		b.WriteString(fmt.Sprintf("订阅里另外带了 %d 个优选地址的 Argo 节点\n", n))
		b.WriteString("要 v2rayN、Shadowrocket 2.2.66 以上（UDP 版要 2.2.78 以上）或新版 mihomo 客户端；NekoBox 这类 sing-box 内核的用不了\n\n")
	}
	if st.WS != nil {
		l := linkWS(st, CFAddr{Addr: st.WS.Host, Port: 443, Name: base + "-CF-WS"})
		b.WriteString("【CF WS】走 Cloudflare，IP 被墙也能用\n" + l + "\n")
		b.WriteString(fmt.Sprintf("订阅里另外带了 %d 个优选地址的 CF WS 节点\n\n", len(cfAddrs(st, false))))
		qrs = append(qrs, l)
	}
	if st.Hy2 != nil {
		l := linkHy2(st, base+"-Hy2")
		if st.Hy2.HopStart > 0 {
			b.WriteString("【Hysteria2】UDP，gecko 混淆 + 端口跳跃，线路差的机器用\n" + l + "\n")
			b.WriteString(fmt.Sprintf("端口跳跃 %d-%d，订阅里已经带上\n", st.Hy2.HopStart, st.Hy2.HopEnd))
		} else {
			b.WriteString("【Hysteria2】UDP，gecko 混淆，单端口，线路差的机器用\n" + l + "\n")
		}
		b.WriteString("要 mihomo 1.19.34、sing-box 1.14 以上的客户端，老版本不认 gecko\n")
		b.WriteString("\n")
		qrs = append(qrs, l)
	}
	if st.TUIC != nil {
		l := linkTUIC(st, base+"-TUIC")
		b.WriteString("【TUIC v5】UDP（QUIC），bbr 拥塞控制，线路差的机器用\n" + l + "\n")
		b.WriteString("Mihomo / Clash Verge Rev / FlClash、v2rayN、Shadowrocket、Stash、SFA 都能用；v2rayNG 稳定版的常规入口暂时没有 TUIC\n")
		b.WriteString(fmt.Sprintf("云安全组（比如 Azure NSG）要放行 UDP %d\n\n", st.TUIC.PubPort))
		qrs = append(qrs, l)
	}

	writeFileAtomic(linksPath, []byte(b.String()), 0600)
	hr()
	fmt.Print(b.String())
	hr()
	if confirm("显示二维码？", false) {
		for _, s := range qrs {
			fmt.Println(s[:min(len(s), 60)] + "…")
			printQR(s)
			fmt.Println()
		}
	}
	info("链接也存在 %s", linksPath)
	if st.PortMode == portMapped {
		info("链接里用的是你填的外网端口")
	}
	info("甲骨文、谷歌云、AWS 这类机器，记得在云后台的安全组也放行端口")
}

func showMihomo(st *State) {
	if !st.installed() {
		warn("还没装任何协议")
		return
	}
	if base := subBase(st); base != "" {
		info("Clash 客户端直接导入订阅更省事：%s/clash", base)
	}
	fmt.Print(subClash(st))
}

func changePort(st *State) {
	k := pickProto(st)
	if k == "" {
		return
	}
	if k == "argo" {
		warn("Argo 隧道不占公网端口，没有要改的")
		return
	}
	oldPort, oldPub := curPorts(st, k)
	var port int
	if k == "hy2" || k == "tuic" {
		port = askUDPPort(st, k, oldPort)
	} else {
		port = askPort(st, protoLabel(k)+" 新端口", oldPort, k)
	}
	addrs, _ := net.InterfaceAddrs()
	st.setPortMode(selectPortMode(st, addrs))
	pub := port
	if st.PortMode == portMapped && port == oldPort && oldPub > 0 {
		pub = oldPub
	}
	if k == "hy2" || k == "tuic" {
		port, pub = askUDPPub(st, k, port, pub)
	} else {
		pub = askPubPort(st, pub)
	}
	switch k {
	case "hy2":
		st.Hy2.Port, st.Hy2.PubPort = port, pub
		fwOpenProto(fmt.Sprint(port), "udp")
		setHy2Range(st.Hy2, st.PortMode, st.tuicPorts()...)
		if st.Hy2.HopStart > 0 {
			fwOpenProto(fmt.Sprintf("%d:%d", st.Hy2.HopStart, st.Hy2.HopEnd), "udp")
			info("云安全组请放行 UDP %d 和 %d-%d", pub, st.Hy2.HopStart, st.Hy2.HopEnd)
		}
		applyAll(st)
		ok("Hy2 监听 UDP %d，外网端口 %d", port, pub)
		return
	case "tuic":
		st.TUIC.Port, st.TUIC.PubPort = port, pub
		fwOpenProto(fmt.Sprint(port), "udp")
		applyAll(st)
		ok("TUIC 监听 UDP %d，外网端口 %d；云安全组请放行 UDP %d", port, pub, pub)
		return

	case "reality":
		st.Reality.Port, st.Reality.PubPort = port, pub
	case "anytls":
		st.AnyTLS.Port, st.AnyTLS.PubPort = port, pub
	case "ws":
		st.WS.Port, st.WS.PubPort = port, pub
	}
	fwOpen(port)
	applyAll(st)
	if k == "ws" {
		wsRules(st, cfLogin())
		ok("CF 回源端口已同步成 %d；客户端还是连 CF 的 443，链接不用换", pub)
		return
	}
	ok("端口已改成 %d，订阅会自动更新，单独导入的链接要重新导入", port)
}

func resetSecret(st *State) {
	k := pickProto(st)
	if k == "" {
		return
	}
	switch k {
	case "reality":
		st.Reality.PrivateKey, st.Reality.PublicKey = realityKeys()
		st.Reality.UUID, st.Reality.ShortID = newUUID(), randHex(8)
	case "anytls":
		st.AnyTLS.Password, st.AnyTLS.Padding = newUUID(), randPadding()
	case "ws":
		st.WS.UUID, st.WS.Path = newUUID(), "/"+randLabel(10)
	case "hy2":
		fresh := newHy2(st.Hy2.Port, st.Hy2.PubPort)
		fresh.HopStart, fresh.HopEnd = st.Hy2.HopStart, st.Hy2.HopEnd
		st.Hy2 = fresh
	case "tuic":
		st.TUIC.UUID, st.TUIC.Password = newUUID(), randLabel(32)
	case "argo":
		st.Argo.UUID, st.Argo.Path = newUUID(), "/"+randLabel(10)
		// 隧道路由按路径把 XHTTP 分给 Xray，路径换了要同步；同步不上也能用，会经 dun 转一手
		if err := argoSyncIngress(st, cfLogin()); err != nil {
			warn("隧道路由没同步上：%v。节点照样能用，只是多经过 dun 转一次", err)
		}
	}
	applyAll(st)
	ok("%s 的凭据已重置，旧链接作废", protoLabel(k))
	showLinks(st)
}

func removeOne(st *State) {
	k := pickProto(st)
	if k == "" || !confirm("确定卸载 "+protoLabel(k)+"？", false) {
		return
	}
	map[string]func(*State){"reality": removeReality, "anytls": removeAnyTLS, "ws": removeWS,
		"hy2": removeHy2, "tuic": removeTUIC, "argo": removeArgo}[k](st)
}

func serviceMenu() {
	i := choose([]string{"重启", "停止", "启动", "看最近日志", "实时日志（Ctrl+C 退出）"}, 1)
	switch i {
	case 0, 2:
		for _, s := range activeSvcs() {
			svcDo("restart", s)
		}
		ok("已重启")
	case 1:
		for _, s := range activeSvcs() {
			svcDo("stop", s)
		}
		ok("已停止，开机还会自动启动；要彻底停用就卸载")
	case 3:
		svcLog(80, false)
	case 4:
		svcLog(30, true)
	}
}

func disguiseMenu(st *State) {
	if st.Reality == nil && st.WS == nil && st.Argo == nil {
		warn("伪装站是给 Reality、CF WS 和 Argo 用的，先装其中一个")
		return
	}
	cur := "伪装登录页"
	if st.Disguise.Mode == "proxy" {
		cur = "反代 " + st.Disguise.URL
	}
	info("现在：%s", cur)
	info("别人直接打开你的域名，看到的就是这个页面")
	i := choose([]string{"伪装登录页（默认）", "反代一个网站", "换一个登录页样式（重新随机）"}, 1)
	switch i {
	case 0:
		st.Disguise = Disguise{Seed: st.Disguise.Seed}
	case 2:
		st.Disguise = Disguise{Seed: mrand.Uint64() | 1}
	case 1:
		for {
			raw := strings.TrimSpace(ask("要反代的网址，比如 https://www.example.com", ""))
			if !strings.Contains(raw, "://") {
				raw = "https://" + raw
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				warn("网址格式不对")
				continue
			}
			raw = u.Scheme + "://" + u.Host
			if u.Path != "" && u.Path != "/" {
				info("只反代整个站点，路径 %s 会去掉", u.Path)
			}
			info("测试能不能打开 %s", raw)
			req, _ := http.NewRequest("GET", raw, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				warn("打不开：%v", err)
				if !confirm("还是要用它？", false) {
					continue
				}
			} else {
				resp.Body.Close()
				if resp.StatusCode >= 400 {
					warn("能连上，但对方返回 %d，访客看到的可能也是这个错误页", resp.StatusCode)
				} else {
					ok("能打开，状态码 %d", resp.StatusCode)
				}
			}
			st.Disguise = Disguise{Mode: "proxy", URL: raw, Seed: st.Disguise.Seed}
			break
		}
	default:
		return
	}
	applyAll(st)
	ok("伪装站已切换")
}

func cfipMenu(st *State) {
	if st.WS == nil && st.Argo == nil {
		warn("优选地址是给 CF WS 和 Argo 用的，先装其中一个")
		return
	}
	for {
		wc := loadWetest()
		onoff := func(b bool) string {
			if b {
				return "开"
			}
			return "关"
		}
		upd := "从没刷新过"
		if !wc.Time.IsZero() {
			upd = wc.Time.Local().Format("01-02 15:04")
		}
		fmt.Fprintf(os.Stderr, "  东京优选 IP（内置）：%s，Argo %d 个、CF WS %d 个   自选：%d 个\n",
			onoff(!st.CFIP.NoTokyo), len(tokyoIPs), len(tokyoWSIPs), len(customAddrs()))
		fmt.Fprintf(os.Stderr, "  wetest 三网优选 IP：%s，%d 个，更新于 %s\n", onoff(st.CFIP.Wetest), len(wc.Items), upd)
		nd := len(builtinDomains)
		if wc.Checked {
			nd = len(wc.Domains)
		}
		fmt.Fprintf(os.Stderr, "  内置优选域名：%s，%d/%d 个能用   IPv6 优选：%s\n",
			onoff(st.CFIP.Domains), nd, len(builtinDomains), onoff(st.CFIP.V6))
		var parts []string
		if st.WS != nil {
			parts = append(parts, fmt.Sprintf("CF WS %d 个", len(cfAddrs(st, false))+1))
		}
		if st.Argo != nil {
			m := len(cfAddrs(st, true)) + 1
			if !st.CFIP.NoH3 {
				m *= 2
			}
			parts = append(parts, fmt.Sprintf("Argo %d 个（UDP 版：%s）", m, onoff(!st.CFIP.NoH3)))
		}
		fmt.Fprintf(os.Stderr, "  订阅里的节点：%s\n", strings.Join(parts, "，"))
		i := choose([]string{"立即刷新 wetest 和内置域名", "查看全部优选地址", "添加自选地址", "清空自选地址",
			"开关 wetest 三网优选 IP（默认关：电信多半落新加坡）", "开关 内置优选域名（默认关）", "开关 IPv6 优选 IP",
			"开关 Argo 的 UDP（h3）版节点", "重置订阅地址（旧订阅失效）", "开关 东京优选 IP（内置）"}, 1)
		switch i {
		case -1:
			return
		case 0:
			if n, err := refreshWetest(st); err != nil {
				warn("刷新失败：%v", err)
			} else {
				ok("拉到 %d 个优选 IP", n)
			}
		case 1:
			if st.Argo != nil {
				fmt.Println("  Argo 用的：")
				for _, a := range cfAddrs(st, true) {
					fmt.Printf("    %-42s %-5d %s\n", a.Addr, a.Port, a.Name)
				}
			}
			if st.WS != nil {
				fmt.Println("  CF WS 用的（东京段里普通橙云域名只能用 172.64.229.x）：")
				for _, a := range cfAddrs(st, false) {
					fmt.Printf("    %-42s %-5d %s\n", a.Addr, a.Port, a.Name)
				}
			}
		case 2:
			info("一行一个，格式：地址[:端口][#备注]，比如 104.16.1.1:2053#家里最快。空行结束")
			info("CF 能用的 HTTPS 端口：443 2053 2083 2087 2096 8443")
			f, _ := os.OpenFile(customPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			n := 0
			for {
				l := ask("地址", "")
				if l == "" {
					break
				}
				a, good := parseAddr(l)
				if !good {
					warn("格式不对，跳过")
					continue
				}
				if !strings.Contains(" 443 2053 2083 2087 2096 8443 ", fmt.Sprintf(" %d ", a.Port)) {
					warn("端口 %d 不是 CF 的 HTTPS 端口，大概率连不上，还是加上了", a.Port)
				}
				fmt.Fprintln(f, l)
				n++
			}
			f.Close()
			ok("加了 %d 个，订阅马上生效", n)
		case 3:
			os.Remove(customPath)
			ok("已清空")
		case 4, 5:
			if i == 4 {
				st.CFIP.Wetest = !st.CFIP.Wetest
			} else {
				st.CFIP.Domains = !st.CFIP.Domains
			}
			st.save()
			if st.CFIP.fetches() { // 刚打开就马上拉一次，不用等 3 小时
				if n, err := refreshWetest(st); err != nil {
					warn("刷新失败：%v", err)
				} else {
					ok("拉到 %d 个优选 IP", n)
				}
			}
		case 6:
			st.CFIP.V6 = !st.CFIP.V6
			st.save()
			refreshWetest(st)
		case 7:
			st.CFIP.NoH3 = !st.CFIP.NoH3
			st.save()
		case 8:
			st.Token = randLabel(16)
			applyAll(st)
			ok("新订阅地址：%s/sub", subBase(st))
		case 9:
			st.CFIP.NoTokyo = !st.CFIP.NoTokyo
			st.save()
		}
	}
}

func syncIP(st *State) {
	o4, o6 := st.IP4, st.IP6
	detectIP(st)
	info("公网 IP：%s %s", st.IP4, st.IP6)
	if o4 == st.IP4 && o6 == st.IP6 && !confirm("IP 没变，还要重写解析？", false) {
		return
	}
	c := cfLogin()
	if st.TLS != nil {
		st.TLS.RecordID = dnsSet(st, c, st.TLS.Host, false)
		ok("%s 已指向新 IP", st.TLS.Host)
	}
	if st.WS != nil {
		st.WS.RecordID = dnsSet(st, c, st.WS.Host, true)
		ok("%s 已指向新 IP", st.WS.Host)
	}
	st.save()
	showLinks(st)
}

func changeCF(st *State) {
	if st.TLS != nil || st.WS != nil || st.Argo != nil {
		warn("已装协议的解析（还有 Argo 隧道）在旧账号里，换账号只影响以后的操作；卸载前记得换回来")
		if !confirm("继续？", false) {
			return
		}
	}
	os.Remove(cfPath)
	cfCur = nil
	cfLogin()
	if st.TLS == nil && st.WS == nil && st.Argo == nil {
		st.Zone = nil
		st.save()
	}
}

func updateCore(st *State) {
	updateSingBox(st)
	if st.Argo != nil {
		updateXray()
		if !st.Argo.External {
			updateCfd()
		}
	}
}

func updateSingBox(st *State) {
	had, goOn := prepOld(sbBin, svcBox)
	if !goOn {
		return
	}
	cur := sbVersion()
	ver := pickVersion("sing-box", cur, sbPinned, ghLatest("SagerNet/sing-box"))
	if ver == "" {
		return
	}
	sbInstall(ver)
	if _, n := sbConfig(st); n > 0 {
		out, err := runOut(sbBin, "check", "-c", sbConf)
		if err == nil {
			err = restartCheck(svcBox, 2*time.Second)
		}
		if err != nil {
			warn("新版本跑不起来，回退到 %s: %v\n%s", cur, err, out)
			rollbackBin(sbBin, svcBox, had)
			return
		}
	}
	os.Remove(sbBin + ".old")
	ok("sing-box 已更新到 %s", ver)
}

func updateSelf() {
	latest := ghLatest(repo)
	if latest == "" {
		warn("拿不到 dun 的最新版本")
		return
	}
	if latest == version && !confirm("已经是最新 "+version+"，还要重装？", false) {
		return
	}
	if err := downloadVerified(repo, "v"+latest, "dun-linux-"+runtime.GOARCH, selfPath+".new", 0755); err != nil {
		warn("下载失败：%v", err)
		return
	}
	if out, err := runOut(selfPath+".new", "version"); err != nil || !strings.Contains(out, latest) {
		os.Remove(selfPath + ".new")
		warn("新版本跑不起来，没换")
		return
	}
	os.Rename(selfPath+".new", selfPath)
	runTTY(selfPath, "apply")
	ok("dun 已更新到 %s，重新输入 dun 打开", latest)
	os.Exit(0)
}

func uninstallAll(st *State) {
	if !confirm("卸载全部协议，删掉解析、CF 规则、隧道、证书和内核？", false) {
		return
	}
	if (st.TLS != nil || st.WS != nil || st.Argo != nil) && cfLoad() == nil {
		warn("没有 CF 凭据，CF 上的解析、规则和隧道要自己删")
	}
	if st.Argo != nil {
		removeArgo(st)
	}
	if st.Hy2 != nil {
		removeHy2(st)
	}
	if st.TUIC != nil {
		removeTUIC(st)
	}
	if st.WS != nil {
		removeWS(st)
	}
	if st.AnyTLS != nil {
		removeAnyTLS(st)
	}
	if st.Reality != nil {
		removeReality(st)
	}
	for _, s := range []string{svcBox, svcWeb, svcXray, svcArgo} {
		svcDisable(s)
		os.Remove("/etc/systemd/system/" + s + ".service")
		os.Remove("/etc/init.d/" + s)
		os.Remove("/var/log/" + s + ".log")
	}
	if initSys == "systemd" {
		run("systemctl", "daemon-reload")
	}
	fwCleanup()
	os.RemoveAll(baseDir)
	os.Remove(selfPath)
	ok("已全部卸载，BBR 设置保留")
	os.Exit(0)
}

func statusLine(st *State) {
	run := func(n string) string {
		if svcActive(n) {
			return "\033[32m运行中\033[0m"
		}
		return "\033[33m未运行\033[0m"
	}
	p := func(installed bool, s string) string {
		if installed {
			return s
		}
		return "未装"
	}
	fmt.Printf("  sing-box %s %s   dun 服务 %s\n", sbVersion(), run(svcBox), run(svcWeb))
	if a := st.Argo; a != nil && a.External {
		fmt.Printf("  Xray %s %s   隧道：复用 %s\n", xrayVersion(), run(svcXray), a.tunnelLabel())
	} else if a != nil {
		fmt.Printf("  Xray %s %s   cloudflared %s %s\n", xrayVersion(), run(svcXray), cfdVersion(), run(svcArgo))
	}
	r, a, w := "", "", ""
	if st.Reality != nil {
		r = fmt.Sprintf("端口 %d", st.Reality.Port)
	}
	if st.AnyTLS != nil {
		a = fmt.Sprintf("端口 %d", st.AnyTLS.Port)
	}
	if st.WS != nil {
		w = st.WS.Host
	}
	fmt.Printf("  Reality 偷自己: %s   AnyTLS: %s   CF WS: %s\n", p(st.Reality != nil, r), p(st.AnyTLS != nil, a), p(st.WS != nil, w))
	h := ""
	if st.Hy2 != nil {
		h = fmt.Sprintf("UDP %d", st.Hy2.Port)
		if st.Hy2.HopStart > 0 {
			h += fmt.Sprintf("（跳跃 %d-%d）", st.Hy2.HopStart, st.Hy2.HopEnd)
		}
	}
	t, g := "", ""
	if st.TUIC != nil {
		t = fmt.Sprintf("UDP %d", st.TUIC.Port)
	}
	if st.Argo != nil {
		g = st.Argo.Host
	}
	fmt.Printf("  Hysteria2: %s   TUIC v5: %s   Argo 隧道: %s\n", p(st.Hy2 != nil, h), p(st.TUIC != nil, t), p(st.Argo != nil, g))
	if st.TLS != nil {
		fmt.Printf("  节点域名: %s\n", st.TLS.Host)
	}
	if st.Reality != nil || st.WS != nil || st.Argo != nil {
		d := "伪装登录页"
		if st.Disguise.Mode == "proxy" {
			d = "反代 " + st.Disguise.URL
		}
		fmt.Printf("  伪装站: %s\n", d)
	}
}

func menu(st *State) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("════════════════ dun %s ════════════════\n", version)
		statusLine(st)
		fmt.Print(`────────────────────────────────────────────
  1. 安装 Reality 偷自己
  2. 安装 AnyTLS
  3. 安装 CF WS（套 Cloudflare）
  4. 三个一起装
  5. 安装 HY2 | TUIC5（UDP，线路差的机器用）
  6. Argo 隧道（VLESS + XHTTP，VPS 不开端口）
────────────────────────────────────────────
  7. 查看订阅和节点链接
  8. 查看 mihomo / Clash 配置
  9. 优选地址和订阅
 10. 伪装站：登录页 / 反代网站
 11. 修改端口
 12. 重置密码 / UUID
 13. 卸载单个协议
 14. 服务：重启 / 停止 / 日志
 15. 更新内核（sing-box / Xray / cloudflared）
 16. 开启 BBR
 17. IP 变了：同步解析
 18. 更换节点域名
 19. 更换 CF 账号
 20. 更新 dun
 21. 全部卸载
  0. 退出
`)
		switch ask("请选择", "") {
		case "1":
			installReality(st)
			showLinks(st)
		case "2":
			installAnyTLS(st)
			showLinks(st)
		case "3":
			installWS(st)
			showLinks(st)
		case "4":
			installReality(st)
			installAnyTLS(st)
			installWS(st)
			showLinks(st)
		case "5":
			installUDP(st)
			showLinks(st)
		case "6":
			argoMenu(st)
		case "7":
			showLinks(st)
		case "8":
			showMihomo(st)
		case "9":
			cfipMenu(st)
		case "10":
			disguiseMenu(st)
		case "11":
			changePort(st)
		case "12":
			resetSecret(st)
		case "13":
			removeOne(st)
		case "14":
			serviceMenu()
		case "15":
			updateCore(st)
		case "16":
			enableBBR()
		case "17":
			syncIP(st)
		case "18":
			changeNodeHost(st)
			showLinks(st)
		case "19":
			changeCF(st)
		case "20":
			updateSelf()
		case "21":
			uninstallAll(st)
		case "0", "q":
			return
		default:
			continue
		}
		pause()
	}
}

func activeSvcs() []string {
	st := loadState()
	var ss []string
	if _, n := sbConfig(st); n > 0 {
		ss = append(ss, svcBox)
	}
	if st.installed() {
		ss = append(ss, svcWeb)
	}
	if st.Argo != nil {
		ss = append(ss, svcXray)
		if !st.Argo.External {
			ss = append(ss, svcArgo)
		}
	}
	return ss
}
