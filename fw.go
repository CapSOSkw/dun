package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ── 防火墙 ───────────────────────────────────────────
// 只放行 dun 自己用的端口。ufw、firewalld 开着就交给它们。
// iptables 默认拦截时只插一条带 dun-allow 标记的放行，开机规则文件里也只加这一行，
// 别的规则原样保留，不再把整套实时规则写回去。
const fwTag = "dun-allow"

type fwFamily struct{ bin, restore, file string }

var fwFamilies = []fwFamily{
	{"iptables", "iptables-restore", "/etc/iptables/rules.v4"},
	{"ip6tables", "ip6tables-restore", "/etc/iptables/rules.v6"},
}

func fwOpen(p int) { fwOpenProto(strconv.Itoa(p), "tcp") }

// ps 可以是单个端口，也可以是 20000:21000 这样的范围
func fwOpenProto(ps, proto string) {
	managed := false
	if have("ufw") {
		if out, _ := runOut("ufw", "status"); strings.Contains(out, "Status: active") {
			managed = true
			if run("ufw", "allow", ps+"/"+proto) == nil {
				info("ufw 已放行 %s/%s", ps, proto)
			}
		}
	}
	if have("firewall-cmd") && run("firewall-cmd", "--state") == nil {
		managed = true
		run("firewall-cmd", "-q", "--permanent", "--add-port="+strings.ReplaceAll(ps, ":", "-")+"/"+proto)
		run("firewall-cmd", "-q", "--reload")
		info("firewalld 已放行 %s/%s", ps, proto)
	}
	for _, fam := range fwFamilies {
		fwAllow(fam, ps, proto, managed)
	}
}

func fwAllow(fam fwFamily, ps, proto string, managed bool) {
	if !have(fam.bin) {
		return
	}
	out, err := runOut(fam.bin, "-S", "INPUT")
	if err != nil {
		return
	}
	pos, need := fwInsertPos(strings.Split(out, "\n"), managed)
	if !need {
		return
	}
	plain := []string{"-p", proto, "-m", proto, "--dport", ps, "-j", "ACCEPT"}
	if run(fam.bin, append([]string{"-C", "INPUT"}, plain...)...) == nil {
		// 已经有不带标记的同一条，旧版 dun 或者用户自己加的，开机文件也由当初加它的人管
		info("%s 已放行 %s/%s", fam.bin, ps, proto)
		return
	}
	spec := []string{"-p", proto, "-m", proto, "--dport", ps, "-m", "comment", "--comment", fwTag, "-j", "ACCEPT"}
	if run(fam.bin, append([]string{"-C", "INPUT"}, spec...)...) != nil {
		where := []string{"-A", "INPUT"}
		if pos > 0 {
			where = []string{"-I", "INPUT", strconv.Itoa(pos)}
		}
		if run(fam.bin, append(where, spec...)...) != nil {
			// 有的容器内核没有 comment 模块，退回不带标记的写法，这种卸载时认不出来，留着
			spec = plain
			if run(fam.bin, append(where, spec...)...) != nil {
				warn("%s 放行 %s/%s 失败，请自己放行", fam.bin, ps, proto)
				return
			}
		}
	}
	info("%s 已放行 %s/%s", fam.bin, ps, proto)
	fwPersist(fam, "-A INPUT "+strings.Join(spec, " "))
}

// 看 iptables -S INPUT 的输出，判断 INPUT 链会不会挡住新连接，返回放行规则该插在第几条前面，0 表示加在最后。
// 只认兜底的 REJECT、DROP，比如甲骨文镜像最后那条；封某个 IP、某个端口的规则不算，放行插在它们后面。
// ufw、firewalld 管着时 DROP 策略交给它们，但兜底规则照样要让开：甲骨文的 REJECT 排在 ufw 的链前面。
func fwInsertPos(lines []string, managed bool) (int, bool) {
	n, policyDrop := 0, false
	for _, l := range lines {
		f := fwFields(l)
		switch {
		case len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT":
			policyDrop = f[2] == "DROP"
		case len(f) >= 2 && f[0] == "-A" && f[1] == "INPUT":
			n++
			if fwCatchAll(f[2:]) {
				return n, true
			}
		}
	}
	return 0, policyDrop && !managed
}

// 兜底规则：除了协议、网卡和注释没有别的匹配条件，目标是 REJECT 或 DROP
func fwCatchAll(f []string) bool {
	target := ""
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "-p", "-i", "--comment", "--reject-with":
			i++
		case "-m":
			if i+1 >= len(f) {
				return false
			}
			switch f[i+1] {
			case "comment", "tcp", "udp", "icmp", "icmp6", "ipv6-icmp":
				i++
			default:
				return false
			}
		case "-j":
			if i+1 < len(f) {
				target = f[i+1]
			}
			i++
		default:
			return false
		}
	}
	return target == "REJECT" || target == "DROP"
}

// 按空格拆 iptables -S、iptables-save 的一行，双引号里的空格不拆
func fwFields(l string) []string {
	var f []string
	var b strings.Builder
	inQ, esc, quoted := false, false, false
	flush := func() {
		if quoted || b.Len() > 0 {
			f = append(f, b.String())
		}
		b.Reset()
		quoted = false
	}
	for _, r := range l {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\' && inQ:
			esc = true
		case r == '"':
			inQ, quoted = !inQ, true
		case (r == ' ' || r == '\t' || r == '\r') && !inQ:
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return f
}

func fwTagged(l string) bool {
	f := fwFields(l)
	if len(f) < 2 || f[0] != "-A" || f[1] != "INPUT" {
		return false
	}
	for i := 2; i+1 < len(f); i++ {
		if f[i] == "--comment" && f[i+1] == fwTag {
			return true
		}
	}
	return false
}

// 在规则文件的 *filter 段里插一行：插在兜底拦截前面，没有就跟在最后一条 INPUT 规则后面，再没有就放在 COMMIT 前面。
// 已经有一模一样的行，或者文件里没有完整的 *filter 段，就不动。
func fwInsertLine(content, line string) (string, bool) {
	ls := strings.Split(content, "\n")
	start, end := -1, -1
	for i, l := range ls {
		t := strings.TrimSpace(l)
		if start < 0 {
			if t == "*filter" {
				start = i
			}
			continue
		}
		if t == "COMMIT" {
			end = i
			break
		}
		if strings.HasPrefix(t, "*") {
			return content, false
		}
	}
	if start < 0 || end < 0 {
		return content, false
	}
	at, last := -1, -1
	for i := start + 1; i < end; i++ {
		t := strings.TrimSpace(ls[i])
		if t == line {
			return content, false
		}
		if f := fwFields(t); len(f) >= 2 && f[0] == "-A" && f[1] == "INPUT" {
			last = i
			if at < 0 && fwCatchAll(f[2:]) {
				at = i
			}
		}
	}
	switch {
	case at >= 0:
	case last >= 0:
		at = last + 1
	default:
		at = end
	}
	out := make([]string, 0, len(ls)+1)
	out = append(out, ls[:at]...)
	out = append(out, line)
	out = append(out, ls[at:]...)
	return strings.Join(out, "\n"), true
}

// 去掉规则文件里带 dun-allow 标记的行，别的行一个字节都不动
func fwStripTagged(content string) (string, bool) {
	ls := strings.Split(content, "\n")
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		if !fwTagged(l) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n"), len(out) != len(ls)
}

// 把放行规则写进开机规则文件。没有这个文件就不替它建一个
func fwPersist(fam fwFamily, line string) {
	b, err := os.ReadFile(fam.file)
	if err != nil {
		return
	}
	nb, changed := fwInsertLine(string(b), line)
	if !changed {
		return
	}
	if bak := fam.file + ".dun.bak"; !exists(bak) {
		if os.WriteFile(bak, b, 0600) != nil {
			warn("备份 %s 失败，放行规则没写进去，机器重启后要重新放行", fam.file)
			return
		}
	}
	if !fwWriteRules(fam, nb) {
		warn("放行规则没写进 %s，机器重启后要重新放行", fam.file)
	}
}

// 先用 iptables-restore --test 过一遍，过不了就不写；权限照原文件
func fwWriteRules(fam fwFamily, content string) bool {
	if !have(fam.restore) {
		return false
	}
	c := exec.Command(fam.restore, "--test")
	c.Stdin = strings.NewReader(content)
	if c.Run() != nil {
		return false
	}
	mode := os.FileMode(0640)
	if fi, err := os.Stat(fam.file); err == nil {
		mode = fi.Mode().Perm()
	}
	return writeFileAtomic(fam.file, []byte(content), mode) == nil
}

// 卸载时删掉 dun 加的放行规则，实时的和开机文件里的都删。ufw、firewalld 里的不动
func fwCleanup() {
	for _, fam := range fwFamilies {
		if !have(fam.bin) {
			continue
		}
		out, _ := runOut(fam.bin, "-S", "INPUT")
		for _, l := range strings.Split(out, "\n") {
			if fwTagged(l) {
				run(fam.bin, append([]string{"-D"}, fwFields(l)[1:]...)...)
			}
		}
		b, err := os.ReadFile(fam.file)
		if err != nil {
			continue
		}
		nb, changed := fwStripTagged(string(b))
		if !changed {
			continue
		}
		if !fwWriteRules(fam, nb) {
			warn("%s 里带 %s 标记的放行规则没删掉，可以自己删", fam.file, fwTag)
			continue
		}
		bak := fam.file + ".dun.bak"
		if ob, err := os.ReadFile(bak); err == nil {
			if string(ob) == nb {
				os.Remove(bak)
			} else {
				info("%s 和 dun 改动前不一样了，改动前的备份留在 %s", fam.file, bak)
			}
		}
	}
}
