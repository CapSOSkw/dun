package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// 部署目录下的路径都指到 dir，测试不碰真机上的 /etc/dun
func setPaths(dir string) {
	baseDir, cfPath, certDir = dir, dir+"/cf.json", dir+"/cert"
	certFile, keyFile, acmeKeyPath = certDir+"/fullchain.pem", certDir+"/key.pem", dir+"/acme-account.key"
	linksPath, customPath, wetestPath, argoToken = dir+"/links.txt", dir+"/cfip.txt", dir+"/cfip-wetest.json", dir+"/argo.token"
	statePath, sbBin, sbConf = dir+"/state.json", dir+"/bin/sing-box", dir+"/sing-box.json"
	xrayConf, xrayBin, cfdBin = dir+"/xray.json", dir+"/bin/xray", dir+"/bin/cloudflared"
}

// 本测试的部署目录换成 t.TempDir()，结束时还原
func isolatePaths(t *testing.T) string {
	t.Helper()
	ps := []*string{&baseDir, &cfPath, &certDir, &certFile, &keyFile, &acmeKeyPath, &linksPath, &customPath,
		&wetestPath, &argoToken, &statePath, &sbBin, &sbConf, &xrayConf, &xrayBin, &cfdBin}
	old := make([]string, len(ps))
	for i, p := range ps {
		old[i] = *p
	}
	t.Cleanup(func() {
		for i, p := range ps {
			*p = old[i]
		}
	})
	dir := t.TempDir()
	setPaths(dir)
	return dir
}

// 兜底：整个包的测试都不读真凭据、不联网、不碰部署目录；需要的测试自己换替身
// 也不碰真实防火墙：没换替身的用例走到 iptables / ip6tables 都直接跳过，端口跳跃探测当作失败
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dun-test-")
	if err != nil {
		panic(err)
	}
	setPaths(dir)
	fwHave = func(string) bool { return false } // 不碰真机的 iptables
	hopUsable = func() bool { return false }
	ghLatest = func(string) string { return "" }
	dlVerified = func(string, string, string, string, os.FileMode) error { return errors.New("测试里不联网") }
	argoCF = func() *CF { return nil }
	argoCFCleanup = func(*State, *CF, Argo) { panic("测试里不该清 CF") }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// applyAll 的替身：外部命令只记下来，不真跑 systemctl、sing-box、xray、iptables
type applyRec struct {
	cmds     []string               // run 跑过的命令（svcDo / svcEnable / svcDisable / svcActive）
	hops     []int                  // 每次加跳跃规则时 Hy2 的跳跃起点
	writes   map[string]int         // applyWrite 每个文件写了几次
	prunes   int                    // fwPrune 调了几次
	tcp, udp func(port int) bool    // 端口就绪
	check    func(bin string) error // sing-box check / xray run -test 的结果
	fail     func(cmd string, nth int) error
	writeErr func(path string, nth int) error
	hopErr   func(nth int) error
	onCmd    func(cmd string)
}

func fakeApply(t *testing.T) *applyRec {
	t.Helper()
	r := &applyRec{writes: map[string]int{}, tcp: func(int) bool { return true }, udp: func(int) bool { return true },
		check: func(string) error { return nil }}
	oe, oi := dieExit, initSys
	orun, oout, oex := run, runOut, svcExists
	opr, oudp, oprune, ohop, olog, owr, ow := portReady, udpReady, applyPrune, applyHop, applyLog, applyWrite, readyWait
	t.Cleanup(func() {
		dieExit, initSys = oe, oi
		run, runOut, svcExists = orun, oout, oex
		portReady, udpReady, applyPrune, applyHop, applyLog, applyWrite, readyWait = opr, oudp, oprune, ohop, olog, owr, ow
	})
	isolatePaths(t)
	dieExit = func(int) { panic("die") }
	initSys = "systemd"
	svcExists = func(string) bool { return false }
	run = func(name string, args ...string) error {
		c := name + " " + strings.Join(args, " ")
		r.cmds = append(r.cmds, c)
		if r.onCmd != nil {
			r.onCmd(c)
		}
		if r.fail != nil {
			return r.fail(c, r.has(c))
		}
		return nil
	}
	runOut = func(name string, args ...string) (string, error) {
		if err := r.check(name); err != nil {
			return "bad config", err
		}
		return "", nil
	}
	portReady = func(p int) bool { return r.tcp(p) }
	udpReady = func(p int) bool { return r.udp(p) }
	applyPrune = func(*State) { r.prunes++ }
	applyHop = func(st *State) (error, error) {
		h := 0
		if st.Hy2 != nil {
			h = st.Hy2.HopStart
		}
		r.hops = append(r.hops, h)
		if r.hopErr != nil {
			return nil, r.hopErr(len(r.hops))
		}
		return nil, nil
	}
	applyWrite = func(p string, b []byte, m os.FileMode) error {
		r.writes[p]++
		if r.writeErr != nil {
			if err := r.writeErr(p, r.writes[p]); err != nil {
				return err
			}
		}
		return writeFileAtomic(p, b, m)
	}
	applyLog = func() {}
	readyWait = 0
	return r
}

func (r *applyRec) has(cmd string) int {
	n := 0
	for _, c := range r.cmds {
		if c == cmd {
			n++
		}
	}
	return n
}

// 跑 applyAll，返回有没有 die
func runApply(st *State) (died bool, out string) {
	out = captureStderr(func() {
		defer func() { died = recover() != nil }()
		applyAll(st)
	})
	return
}

// 旧状态：Reality + Hy2（带跳跃）+ dun 自己跑 cloudflared 的 Argo
func oldApplyState() *State {
	return &State{IP4: "203.0.113.5", TLS: &TLSHost{Host: "n.r4nd.example.com"},
		Reality: &Reality{Port: 8443, PubPort: 8443, Fallback: 21003},
		Hy2:     &Hy2{Port: 5443, PubPort: 5443, Password: "p", Obfs: "o", HopStart: 20000, HopEnd: 21000, HopSec: 30},
		Argo:    &Argo{Host: "a.example.com", Inner: 21010, Web: 21011, UUID: "u", Path: "/old"},
		Zone:    &Zone{ID: "z", Name: "example.com"}}
}

// 新状态：Reality 换端口、Hy2 换跳跃范围、Argo 换路径（Xray 配置也要重写）
func newApplyState() *State {
	st := oldApplyState()
	st.Reality.Port = 443
	st.Hy2.HopStart, st.Hy2.HopEnd = 30000, 31000
	st.Argo.Path = "/new"
	return st
}

// 把旧状态、旧 sing-box 配置、旧 Xray 配置放到磁盘上，返回三份原字节
func seedOld(t *testing.T) (st, sb, xr []byte) {
	t.Helper()
	return seedState(t, oldApplyState())
}

func seedState(t *testing.T, old *State) (st, sb, xr []byte) {
	t.Helper()
	old.save()
	st, _ = os.ReadFile(statePath)
	sb, xr = []byte(`{"old":"sing-box"}`), []byte(`{"old":"xray"}`)
	os.WriteFile(sbConf, sb, 0600)
	os.WriteFile(xrayConf, xr, 0600)
	return
}

func assertBytes(t *testing.T, what, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if want == nil {
		if err == nil {
			t.Fatalf("%s 应该不存在，实际是：%s", what, got)
		}
		return
	}
	if string(got) != string(want) {
		t.Fatalf("%s 变了：\n%s\n应为：\n%s", what, got, want)
	}
}

// 回滚后：三份文件是旧字节，没回收放行规则，提示已回滚
func assertRolledBack(t *testing.T, r *applyRec, out string, st, sb, xr []byte) {
	t.Helper()
	assertBytes(t, "state.json", statePath, st)
	assertBytes(t, "sing-box 配置", sbConf, sb)
	assertBytes(t, "Xray 配置", xrayConf, xr)
	if r.prunes != 0 {
		t.Fatal("没应用成功却回收了放行规则")
	}
	if !strings.Contains(out, "已回滚到原来的配置") {
		t.Fatalf("没提示已回滚：\n%s", out)
	}
}

// 新配置检查不过（sing-box 或 Xray）：磁盘上的状态和配置一个字节都不动，不碰服务，不回收放行规则，不留临时文件
func TestApplyCheckFailLeavesDisk(t *testing.T) {
	for _, bad := range []string{"sing-box", "xray"} {
		t.Run(bad, func(t *testing.T) {
			r := fakeApply(t)
			st0, sb0, xr0 := seedOld(t)
			badBin := map[string]string{"sing-box": sbBin, "xray": xrayBin}[bad]
			r.check = func(bin string) error {
				if bin == badBin {
					return errors.New("exit 1")
				}
				return nil
			}
			died, out := runApply(newApplyState())
			if !died || !strings.Contains(out, "检查不通过") {
				t.Fatalf("检查不过应该 die：\n%s", out)
			}
			assertBytes(t, "state.json", statePath, st0)
			assertBytes(t, "sing-box 配置", sbConf, sb0)
			assertBytes(t, "Xray 配置", xrayConf, xr0)
			if len(r.cmds) != 0 || len(r.hops) != 0 || r.prunes != 0 || len(r.writes) != 0 {
				t.Fatalf("检查不过却动了服务、规则或文件：%q hop=%v prune=%d write=%v", r.cmds, r.hops, r.prunes, r.writes)
			}
			if left, _ := os.ReadDir(strings.TrimSuffix(statePath, "/state.json")); len(left) != 3 {
				t.Fatalf("临时文件没删干净：%v", left)
			}
		})
	}
}

// 就绪检查不过（TCP 端口、UDP 端口、托管的 cloudflared）：三份文件换回旧字节，
// 按旧状态重启服务、重加旧的跳跃规则，不回收放行规则
func TestApplyReadyFailRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name, msg string
		set       func(r *applyRec)
	}{
		{"TCP", "TCP 端口 443 没起来", func(r *applyRec) { r.tcp = func(p int) bool { return p != 443 } }},
		{"UDP", "UDP 端口 5443 没起来", func(r *applyRec) { r.udp = func(p int) bool { return p != 5443 } }},
		{"cloudflared", "cloudflared 服务 dun-argo 没起来", func(r *applyRec) {
			r.fail = func(c string, _ int) error {
				if c == "systemctl is-active --quiet dun-argo" {
					return errors.New("inactive")
				}
				return nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeApply(t)
			st0, sb0, xr0 := seedOld(t)
			tc.set(r)
			webSawNew := false
			r.onCmd = func(c string) {
				if c == "systemctl restart dun" && !webSawNew {
					// dun serve 按 state.json 定端口，重启它之前新状态必须已经落盘
					webSawNew = loadState().Reality.Port == 443
				}
			}
			died, out := runApply(newApplyState())
			if !died || !strings.Contains(out, tc.msg) {
				t.Fatalf("应该报 %q 后 die：\n%s", tc.msg, out)
			}
			if !webSawNew {
				t.Fatal("重启 dun 服务时 state.json 还是旧的")
			}
			assertRolledBack(t, r, out, st0, sb0, xr0)
			if !reflect.DeepEqual(r.hops, []int{30000, 20000}) {
				t.Fatalf("跳跃规则应先按新状态、再按旧状态加：%v", r.hops)
			}
			for _, c := range []string{"systemctl restart dun-sb", "systemctl restart dun", "systemctl restart dun-xray"} {
				if r.has(c) != 2 {
					t.Fatalf("%q 应该新旧各一次：%q", c, r.cmds)
				}
			}
		})
	}
}

// 写配置失败：已经写下的新 state.json 换回去，按旧状态恢复服务
func TestApplyWriteFailRollsBack(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	r.writeErr = func(p string, n int) error {
		if p == sbConf && n == 1 {
			return errors.New("disk full")
		}
		return nil
	}
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "写配置失败") {
		t.Fatalf("写失败应该 die：\n%s", out)
	}
	assertRolledBack(t, r, out, st0, sb0, xr0)
	if r.has("systemctl restart dun-sb") != 1 || !reflect.DeepEqual(r.hops, []int{20000}) {
		t.Fatalf("应该只按旧状态起一次服务：%q hop=%v", r.cmds, r.hops)
	}
}

// 服务起不来：回滚。原来没有的 Xray 配置被删掉
func TestApplyStartFailRollsBack(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, _ := seedOld(t)
	os.Remove(xrayConf)
	r.fail = func(c string, n int) error {
		if c == "systemctl restart dun-sb" && n == 1 {
			return errors.New("exit 1")
		}
		return nil
	}
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "sing-box 服务起不来") {
		t.Fatalf("起不来应该 die：\n%s", out)
	}
	assertRolledBack(t, r, out, st0, sb0, nil)
	if r.has("systemctl restart dun-sb") != 2 {
		t.Fatalf("回滚时应该按旧状态再起 sing-box：%q", r.cmds)
	}
}

// 非空状态下要停的服务停不掉：算失败，回滚
func TestApplyStopFailRollsBack(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	r.fail = func(c string, n int) error {
		if c == "systemctl disable --now dun-sb" {
			return errors.New("exit 1")
		}
		return nil
	}
	st := oldApplyState()
	st.Reality, st.Hy2 = nil, nil // 只剩 Argo，sing-box 要停
	died, out := runApply(st)
	if !died || !strings.Contains(out, "sing-box 服务停不掉") {
		t.Fatalf("停不掉应该 die：\n%s", out)
	}
	assertRolledBack(t, r, out, st0, sb0, xr0)
	if r.has("systemctl restart dun-sb") != 1 {
		t.Fatalf("回滚时应该按旧状态起 sing-box：%q", r.cmds)
	}
}

// 回滚时跳跃规则加不上：只记进错误，刚还原的 state.json 字节不变（不走关掉跳跃的写回）
func TestApplyRollbackHopFailKeepsState(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	fakeFw(t, "", func(a []string) bool { return len(a) > 2 && a[1] == "nat" && a[2] == "-A" })
	applyHop = hopRules
	r.tcp = func(p int) bool { return p != 443 }
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "回滚未完全成功") || !strings.Contains(out, "端口跳跃规则 20000:21000 加不上") {
		t.Fatalf("应该报回滚时跳跃加不上：\n%s", out)
	}
	assertBytes(t, "state.json", statePath, st0)
	assertBytes(t, "sing-box 配置", sbConf, sb0)
	assertBytes(t, "Xray 配置", xrayConf, xr0)
}

// 回滚中一步失败，其余步骤照做，错误汇总
func TestApplyRollbackKeepsGoing(t *testing.T) {
	r := fakeApply(t)
	st0, _, xr0 := seedOld(t)
	r.tcp = func(p int) bool { return p != 443 }
	r.writeErr = func(p string, n int) error {
		if p == sbConf && n == 2 {
			return errors.New("ro fs")
		}
		return nil
	}
	r.fail = func(c string, n int) error {
		if c == "systemctl restart dun-sb" && n == 2 {
			return errors.New("exit 1")
		}
		return nil
	}
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "回滚未完全成功") || !strings.Contains(out, "ro fs") || !strings.Contains(out, "sing-box 服务起不来") {
		t.Fatalf("应该汇总两个回滚错误：\n%s", out)
	}
	assertBytes(t, "state.json", statePath, st0)
	assertBytes(t, "Xray 配置", xrayConf, xr0)
	if len(r.hops) != 2 || r.has("systemctl restart dun") != 2 || r.has("systemctl restart dun-xray") != 2 || r.prunes != 0 {
		t.Fatalf("回滚出错后其余步骤没做完：%q hop=%v prune=%d", r.cmds, r.hops, r.prunes)
	}
}

// 旧状态没有协议：回滚时按旧状态把服务停掉，不再重启
func TestApplyRollbackToEmpty(t *testing.T) {
	r := fakeApply(t)
	r.tcp = func(int) bool { return false }
	st := oldApplyState()
	st.Argo = nil
	died, _ := runApply(st)
	if !died {
		t.Fatal("端口没起来应该 die")
	}
	assertBytes(t, "state.json", statePath, nil)
	assertBytes(t, "sing-box 配置", sbConf, nil)
	if r.has("systemctl restart dun-sb") != 1 || r.has("systemctl disable --now dun-sb") != 1 ||
		r.has("systemctl disable --now dun") != 1 || r.prunes != 0 {
		t.Fatalf("回滚后服务状态不对：%q prune=%d", r.cmds, r.prunes)
	}
}

// 卸到没有协议：停得掉就回收规则；停不掉也回滚，不回收规则
func TestApplyEmpty(t *testing.T) {
	r := fakeApply(t)
	seedOld(t)
	if died, out := runApply(&State{}); died || !strings.Contains(out, "没有协议了") || r.prunes != 1 {
		t.Fatalf("空状态应该停服务、回收规则：die=%v prune=%d\n%s", died, r.prunes, out)
	}
	r = fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	r.fail = func(c string, _ int) error {
		if c == "systemctl disable --now dun" {
			return errors.New("exit 1")
		}
		return nil
	}
	died, out := runApply(&State{})
	if !died || !strings.Contains(out, "dun 服务停不掉") {
		t.Fatalf("空状态停不掉也该回滚后 die：\n%s", out)
	}
	assertRolledBack(t, r, out, st0, sb0, xr0)
}

// 都起来了：新配置落盘，放行规则回收一次
func TestApplySuccess(t *testing.T) {
	r := fakeApply(t)
	seedOld(t)
	if died, out := runApply(newApplyState()); died || !strings.Contains(out, "服务已运行") {
		t.Fatalf("应该成功：\n%s", out)
	}
	if r.prunes != 1 || loadState().Reality.Port != 443 || !reflect.DeepEqual(r.hops, []int{30000}) {
		t.Fatalf("成功后状态不对：prune=%d hop=%v", r.prunes, r.hops)
	}
	if b, _ := os.ReadFile(xrayConf); !strings.Contains(string(b), `"/new"`) {
		t.Fatal("Xray 配置没换上")
	}
	if b, _ := os.ReadFile(sbConf); !strings.Contains(string(b), `"listen_port": 443`) {
		t.Fatal("sing-box 配置没换上")
	}
}

// 新内核文件跑不起来：原来的不动，不留 .new；换上去以后跑不起来：换回原来的，不留 .old
func TestPlaceBinKeepsOld(t *testing.T) {
	oe, oout := dieExit, runOut
	t.Cleanup(func() { dieExit, runOut = oe, oout })
	dieExit = func(int) { panic("die") }
	for _, tc := range []struct {
		name    string
		badPath func(bin string) string // 版本自检失败的路径
		want    string
		died    bool
	}{
		{"新文件跑不起来", func(b string) string { return b + ".new" }, "OLD", true},
		{"换上去跑不起来", func(b string) string { return b }, "OLD", true},
		{"正常换上", func(string) string { return "" }, "NEW", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir() + "/sing-box"
			os.WriteFile(bin, []byte("OLD"), 0755)
			os.WriteFile(bin+".new", []byte("NEW"), 0755)
			bad := tc.badPath(bin)
			runOut = func(name string, args ...string) (string, error) {
				if name == bad {
					return "", errors.New("exec format error")
				}
				return "sing-box version 1.14.5", nil
			}
			var died bool
			captureStderr(func() {
				defer func() { died = recover() != nil }()
				placeBin(bin, "sing-box", sbVersionAt) // sbInstall 走的就是这条
			})
			assertBytes(t, "内核", bin, []byte(tc.want))
			assertBytes(t, ".new", bin+".new", nil)
			if died != tc.died {
				t.Fatalf("die=%v，应为 %v", died, tc.died)
			}
			if tc.died {
				assertBytes(t, ".old", bin+".old", nil)
			} else {
				assertBytes(t, ".old", bin+".old", []byte("OLD"))
			}
		})
	}
}

// 原来没有内核（首次安装）：换上去跑不起来就删掉，不会凭空冒出一个 .old 顶上
func TestPlaceBinFreshFail(t *testing.T) {
	oe, oout := dieExit, runOut
	t.Cleanup(func() { dieExit, runOut = oe, oout })
	dieExit = func(int) { panic("die") }
	bin := t.TempDir() + "/xray"
	os.WriteFile(bin+".new", []byte("NEW"), 0755)
	runOut = func(name string, args ...string) (string, error) {
		if name == bin {
			return "", errors.New("bad")
		}
		return "Xray 26.11.9 (Xray, Penetrates Everything.)", nil
	}
	captureStderr(func() {
		defer func() { recover() }()
		placeBin(bin, "Xray", xrayVersionAt)
	})
	assertBytes(t, "内核", bin, nil)
	assertBytes(t, ".new", bin+".new", nil)
}

// 换回 .old 失败：不重启服务（免得起坏的），.old 留着，打出手动恢复的命令
func TestRollbackBinRenameFail(t *testing.T) {
	r := fakeApply(t)
	bin := t.TempDir() + "/sing-box"
	os.MkdirAll(bin+"/busy", 0755) // bin 是个非空目录，.old 改不过去
	os.WriteFile(bin+".old", []byte("OLD"), 0755)
	out := captureStderr(func() { rollbackBin(bin, svcBox, true) })
	if len(r.cmds) != 0 || !strings.Contains(out, restoreCmd(bin, svcBox)) || !strings.Contains(restoreCmd(bin, svcBox),
		"mv "+bin+" "+bin+".bad.$(date +%s); } && mv "+bin+".old "+bin+" && systemctl restart dun-sb") {
		t.Fatalf("换不回去时不该重启，要给出手动命令：%q\n%s", r.cmds, out)
	}
	assertBytes(t, ".old", bin+".old", []byte("OLD"))
}

// 菜单 15 更新 cloudflared 的回退：
//   - 有原文件时换回去再重启
//   - 原来没有时把新装的坏文件删掉，不重启
//   - 有上次留下的 .old：不论现在的能不能跑，都不删、不下载，打出手动命令
func TestUpdateCfdRollback(t *testing.T) {
	for _, tc := range []struct {
		name                string
		bin, old            string // 开始时的 bin 和 .old，"" = 不存在；BROKEN 跑不起来
		failRestart, failUp bool
		wantBin, wantOld    string // 结束后
		restarts            int
		downloaded          bool
	}{
		{"重启失败换回旧的", "OLD", "", true, false, "OLD", "", 2, true},
		{"起来又停了换回旧的", "OLD", "", false, true, "OLD", "", 2, true},
		{"首次装坏的删掉", "", "", false, true, "", "", 1, true},
		{"能跑也有 old 不更新", "OLD", "STALE", false, false, "OLD", "STALE", 0, false},
		{"跑不起来又有 old 不更新", "BROKEN", "STALE", false, false, "BROKEN", "STALE", 0, false},
		{"没装又有 old 不更新", "", "STALE", false, false, "", "STALE", 0, false},
		{"成功", "OLD", "", false, false, "NEW", "", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeApply(t)
			fakeInstall(t)
			osl, oin, oeof := sleep, in, eofIn
			t.Cleanup(func() { sleep, in, eofIn = osl, oin, oeof })
			sleep = func(time.Duration) {}
			if tc.bin != "" {
				os.WriteFile(cfdBin, []byte(tc.bin), 0755)
			}
			if tc.old != "" {
				os.WriteFile(cfdBin+".old", []byte(tc.old), 0755)
			}
			ghLatest = func(string) string { return "2026.12.0" }
			downloaded := false
			dlVerified = func(repo, tag, name, dst string, mode os.FileMode) error {
				downloaded = true
				return os.WriteFile(dst, []byte("NEW"), mode)
			}
			runOut = func(name string, args ...string) (string, error) {
				if b, err := os.ReadFile(name); err != nil || string(b) == "BROKEN" {
					return "", errors.New("not runnable")
				}
				return "cloudflared version 2026.11.2 (built 2026-11-01)", nil
			}
			r.fail = func(c string, n int) error {
				if tc.failRestart && c == "systemctl restart dun-argo" && n == 1 ||
					tc.failUp && c == "systemctl is-active --quiet dun-argo" {
					return errors.New("exit 1")
				}
				return nil
			}
			in = bufio.NewReader(strings.NewReader("2\n"))
			out := captureStderr(func() {
				defer func() { recover() }()
				updateCfd()
			})
			want := func(v string) []byte {
				if v == "" {
					return nil
				}
				return []byte(v)
			}
			assertBytes(t, "cloudflared", cfdBin, want(tc.wantBin))
			assertBytes(t, ".old", cfdBin+".old", want(tc.wantOld))
			assertBytes(t, ".new", cfdBin+".new", nil)
			if r.has("systemctl restart dun-argo") != tc.restarts || downloaded != tc.downloaded {
				t.Fatalf("重启 %d 次、下载 %v 不对：%q\n%s", r.has("systemctl restart dun-argo"), downloaded, r.cmds, out)
			}
			if !tc.downloaded && (!strings.Contains(out, "这次不更新") || !strings.Contains(out, restoreCmd(cfdBin, svcArgo))) {
				t.Fatalf("没提示先恢复：\n%s", out)
			}
		})
	}
}

// 替身：记下下载的版本，下载直接失败（die），不联网
func fakeInstall(t *testing.T) *[]string {
	t.Helper()
	var got []string
	od, ol, oe, ob, ox, oc := dlVerified, ghLatest, dieExit, sbBin, xrayBin, cfdBin
	t.Cleanup(func() { dlVerified, ghLatest, dieExit, sbBin, xrayBin, cfdBin = od, ol, oe, ob, ox, oc })
	dir := t.TempDir()
	sbBin, xrayBin, cfdBin = dir+"/sing-box", dir+"/xray", dir+"/cloudflared"
	dieExit = func(int) { panic("die") }
	ghLatest = func(repo string) string { t.Fatalf("不该查上游版本：%s", repo); return "" }
	dlVerified = func(repo, tag, name, dst string, mode os.FileMode) error {
		got = append(got, repo+" "+tag)
		return errors.New("offline")
	}
	return &got
}

func TestInstallPinned(t *testing.T) {
	got := fakeInstall(t)
	for _, f := range []func(string){sbInstall, xrayInstall, cfdInstall} {
		captureStderr(func() {
			defer func() { recover() }()
			f("")
		})
	}
	want := []string{"SagerNet/sing-box v1.14.5", "XTLS/Xray-core v26.11.9", "cloudflare/cloudflared 2026.11.2"}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("默认安装的版本 %q，应为 %q", *got, want)
	}
}

func TestVcmp(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.14.5", "1.15.0", -1}, {"1.9.0", "1.14.5", -1}, {"1.14.5", "1.14.5", 0},
		{"26.11.9", "26.9.10", 1}, {"2026.11.2", "2026.9.30", 1}, {"2026.11.2", "2026.11.10", -1},
		{"", "1.0.0", -1}, {"v1.2", "1.2.0", 0},
	} {
		if got := vcmp(tc.a, tc.b); got != tc.want {
			t.Fatalf("vcmp(%q, %q) = %d，应为 %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// 菜单 15：只用 ghLatest 查上游正式版，按当前、推荐、最新列选项；回车和读到头都不更新；
// 比当前旧的写明「降级到」，还要再确认一次
func TestUpdateCorePick(t *testing.T) {
	oin, oeof, oout := in, eofIn, runOut
	t.Cleanup(func() { in, eofIn, runOut = oin, oeof, oout })
	type core struct {
		update      func()
		repo, ver   string // ver 输出的格式
		pinned, tag string // tag 前缀
	}
	cores := map[string]core{
		"sing-box":    {func() { updateSingBox(&State{}) }, "SagerNet/sing-box", "sing-box version %s", sbPinned, "v"},
		"Xray":        {updateXray, "XTLS/Xray-core", "Xray %s (Xray, Penetrates Everything.)", xrayPinned, "v"},
		"cloudflared": {updateCfd, "cloudflare/cloudflared", "cloudflared version %s (built 2026-11-01)", cfdPinned, ""},
	}
	older := map[string]string{"sing-box": "1.13.2", "Xray": "25.12.8", "cloudflared": "2025.11.1"}
	newer := map[string]string{"sing-box": "1.15.0", "Xray": "26.12.1", "cloudflared": "2026.12.0"}
	top := map[string]string{"sing-box": "1.16.0", "Xray": "27.1.1", "cloudflared": "2027.1.0"}
	for name, c := range cores {
		for _, tc := range []struct {
			cur, latest, input string
			want               string // 装的版本，空 = 不装
			shows              string // 输出里要有的选项
		}{
			{"older", "newer", "\n", "", "1. 升到推荐版本"}, // 当前 < 推荐 < 最新：回车不更新
			{"older", "newer", "", "", "2. 升到最新正式版"},  // 读到头不更新
			{"older", "newer", "1\n", "pinned", ""},
			{"older", "newer", "1", "", ""}, // 只有半行：读到头，不更新
			{"older", "newer", "2\n", "newer", ""},
			{"older", "newer", "3\n", "", ""},
			{"older", "newer", "x\n", "", ""},
			{"pinned", "newer", "\n", "", "1. 重装推荐版本"}, // 当前 == 推荐 < 最新
			{"pinned", "newer", "2\n", "newer", ""},
			{"newer", "newer", "\n", "", "2. 重装最新正式版"}, // 已是最新
			{"newer", "newer", "2\n", "newer", ""},
			{"newer", "newer", "1\n", "", "1. 降级到推荐版本"}, // 降级要再确认，默认否
			{"newer", "newer", "1\n\n", "", ""},
			{"newer", "newer", "1\ny\n", "pinned", ""},
			{"newer", "newer", "1\ny", "", ""},         // 降级确认只有半行 y：不降级
			{"top", "newer", "2\n", "", "2. 降级到最新正式版"}, // 当前比上游最新还新
			{"top", "newer", "2\ny\n", "newer", ""},
			{"older", "pinned", "1\n", "pinned", "1. 升到推荐版本"}, // 最新就是推荐，只列一项
			{"older", "", "\n", "", "1. 升到推荐版本"},              // 查不到上游：还能装推荐版
			{"older", "", "", "", ""},
			{"older", "", "1\n", "pinned", ""},
			{"top", "", "1\n", "", "1. 降级到推荐版本"},
			{"top", "", "1\ny\n", "pinned", ""},
			{"pinned", "", "1\n", "", "已经是推荐版本"},
		} {
			v := map[string]string{"older": older[name], "newer": newer[name], "top": top[name], "pinned": c.pinned, "": ""}
			got := fakeInstall(t)
			var asked []string
			ghLatest = func(repo string) string { asked = append(asked, repo); return v[tc.latest] }
			runOut = func(string, ...string) (string, error) {
				return fmt.Sprintf(c.ver, v[tc.cur]), nil
			}
			in = bufio.NewReader(strings.NewReader(tc.input))
			out := captureStderr(func() {
				defer func() { recover() }()
				c.update()
			})
			var want []string
			if tc.want != "" {
				want = []string{c.repo + " " + c.tag + v[tc.want]}
			}
			if !reflect.DeepEqual(*got, want) || !reflect.DeepEqual(asked, []string{c.repo}) {
				t.Fatalf("%s 当前 %s 最新 %q 输入 %q：装了 %q 查了 %q，应装 %q\n%s",
					name, tc.cur, v[tc.latest], tc.input, *got, asked, want, out)
			}
			if !strings.Contains(out, "推荐 "+c.pinned) || !strings.Contains(out, "当前 "+v[tc.cur]) || !strings.Contains(out, tc.shows) {
				t.Fatalf("%s 当前 %s 最新 %q：输出里没有当前、推荐版本或 %q：\n%s", name, tc.cur, v[tc.latest], tc.shows, out)
			}
			if tc.latest == "" && strings.Contains(out, "最新正式版") {
				t.Fatalf("查不到上游时不该列最新正式版：\n%s", out)
			}
		}
	}
}

// 卸载 Argo：只预检一次；停 Xray 和隧道在 applyAll 可回滚的阶段里，停不掉就换回原来的配置
func TestRemoveArgoStopInTxn(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprint("停不掉=", fail), func(t *testing.T) {
			r := fakeApply(t)
			st0, sb0, xr0 := seedOld(t)
			cleaned := fakeArgoCF(t)
			svcExists = func(string) bool { return true }
			checks := 0
			r.check = func(string) error { checks++; return nil }
			stateAtStop := ""
			r.onCmd = func(c string) {
				if c == "systemctl disable --now dun-argo" && stateAtStop == "" {
					b, _ := os.ReadFile(statePath)
					stateAtStop = string(b)
				}
			}
			r.fail = func(c string, n int) error {
				if fail && c == "systemctl disable --now dun-argo" {
					return errors.New("exit 1")
				}
				return nil
			}
			var died bool
			out := captureStderr(func() {
				defer func() { died = recover() != nil }()
				removeArgo(loadState())
			})
			if checks != 1 {
				t.Fatalf("预检应该只做一次，做了 %d 次", checks)
			}
			if stateAtStop == "" || strings.Contains(stateAtStop, `"argo"`) {
				t.Fatalf("停隧道时新状态还没落盘，不在可回滚阶段：\n%s", stateAtStop)
			}
			if !fail {
				if died || loadState().Argo != nil || *cleaned != 1 || exists(argoToken) {
					t.Fatalf("应该卸载成功并清掉 CF 和 token：清了 %d 次\n%s", *cleaned, out)
				}
				return
			}
			if !died || !strings.Contains(out, "dun-argo 停不掉") || *cleaned != 0 || !exists(argoToken) {
				t.Fatalf("停不掉应该 die，不清 CF、不删 token：清了 %d 次\n%s", *cleaned, out)
			}
			assertRolledBack(t, r, out, st0, sb0, xr0)
		})
	}
}

// 回滚时清跳跃规则出错（列不出、删不掉）：记进汇总，后面的步骤照做。旧状态没有跳跃也要清、要查
func TestApplyRollbackNATClearFail(t *testing.T) {
	for _, mode := range []string{"列不出", "删不掉"} {
		t.Run(mode, func(t *testing.T) {
			r := fakeApply(t)
			old := oldApplyState()
			old.Hy2.HopStart, old.Hy2.HopEnd = 0, 0
			old.save()
			cmds := fakeFw(t, "", func(a []string) bool { return mode == "删不掉" && a[2] == "-D" })
			fwOut = func(name string, args ...string) (string, error) {
				if r.has("systemctl restart dun-sb") < 2 { // 正向应用时照常，回滚（已按旧状态重启 sing-box）时出错
					return "", nil
				}
				if mode == "列不出" {
					return "", errors.New("nat table missing")
				}
				return "-A PREROUTING -p udp -m udp --dport 30000:31000 -m comment --comment dun-hy2 -j REDIRECT --to-ports 5443", nil
			}
			applyHop = hopRules
			r.tcp = func(p int) bool { return p != 443 }
			died, out := runApply(newApplyState())
			if !died || !strings.Contains(out, "回滚未完全成功") || !strings.Contains(out, "清掉新的端口跳跃规则") {
				t.Fatalf("应该把清规则的错误汇总进回滚结果：\n%s", out)
			}
			if r.has("systemctl restart dun") != 2 || r.has("systemctl restart dun-xray") != 2 {
				t.Fatalf("清规则出错后其余步骤没做：%q", r.cmds)
			}
			if mode == "删不掉" && !strings.Contains(strings.Join(*cmds, "\n"), "-t nat -D PREROUTING") {
				t.Fatalf("没去删新规则：%q", *cmds)
			}
		})
	}
}

// 正向应用里跳跃加不上要写回状态，这时读不了状态文件：按失败回滚
func TestApplyHopOffReadFailRollsBack(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	r.hopErr = func(n int) error {
		if n == 1 {
			os.WriteFile(statePath, []byte("{坏的"), 0600) // 另一个进程写坏了
			return errors.New("加不上")
		}
		return nil
	}
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "关掉端口跳跃") || !strings.Contains(out, "损坏") {
		t.Fatalf("读不了状态应该算失败：\n%s", out)
	}
	assertRolledBack(t, r, out, st0, sb0, xr0)
}

// readState：文件不存在 = 空状态；读不了、解析不了都是错误
func TestReadStateErrors(t *testing.T) {
	os_ := statePath
	t.Cleanup(func() { statePath = os_ })
	dir := t.TempDir()
	statePath = dir + "/none.json"
	if st, err := readState(); err != nil || st.installed() {
		t.Fatalf("文件不存在应该是空状态：%v", err)
	}
	statePath = dir // 目录读不了
	if _, err := readState(); err == nil || !strings.Contains(err.Error(), "读不了") {
		t.Fatalf("读错误要返回：%v", err)
	}
	statePath = dir + "/bad.json"
	os.WriteFile(statePath, []byte("{"), 0600)
	if _, err := readState(); err == nil || !strings.Contains(err.Error(), "损坏") {
		t.Fatalf("解析错误要返回：%v", err)
	}
}

// OpenRC：stop 报错时只有 status 明确是 stopped 才不算失败
func TestSvcDisableOpenRC(t *testing.T) {
	oi, orun, oout := initSys, run, runOut
	t.Cleanup(func() { initSys, run, runOut = oi, orun, oout })
	initSys = "openrc"
	for _, tc := range []struct {
		status string
		err    bool
	}{
		{" * status: stopped", false},
		{" * status: started", true},
		{"", true}, // status 自己也出错，没法确认
	} {
		run = func(name string, args ...string) error {
			if strings.Join(args, " ") == "dun-sb stop" {
				return errors.New("exit 1")
			}
			return nil
		}
		runOut = func(name string, args ...string) (string, error) { return tc.status, errors.New("exit 3") }
		if err := svcDisable(svcBox); (err != nil) != tc.err {
			t.Fatalf("status %q：错误 %v，应为 %v", tc.status, err, tc.err)
		}
	}
}

// 卸载 Argo 用的 CF：替身账号，清理只计数，不读真凭据、不发请求。顺手放一个 token 文件
func fakeArgoCF(t *testing.T) *int {
	t.Helper()
	oc, ocl := argoCF, argoCFCleanup
	t.Cleanup(func() { argoCF, argoCFCleanup = oc, ocl })
	n := 0
	argoCF = func() *CF { return &CF{} }
	argoCFCleanup = func(*State, *CF, Argo) { n++ }
	os.WriteFile(argoToken, []byte("tok"), 0600)
	return &n
}

// 卸载最后一个协议 Argo 时停不掉：回滚后 die，不回收规则、不清 CF、不删 token，三份文件是旧字节
func TestRemoveLastArgoStopFail(t *testing.T) {
	r := fakeApply(t)
	old := oldApplyState()
	old.Reality, old.Hy2, old.TLS = nil, nil, nil
	st0, sb0, xr0 := seedState(t, old)
	cleaned := fakeArgoCF(t)
	svcExists = func(string) bool { return true }
	r.fail = func(c string, _ int) error {
		if c == "systemctl disable --now dun-argo" {
			return errors.New("exit 1")
		}
		return nil
	}
	var died bool
	out := captureStderr(func() {
		defer func() { died = recover() != nil }()
		removeArgo(loadState())
	})
	if !died || *cleaned != 0 || !exists(argoToken) {
		t.Fatalf("停不掉应该 die，不清 CF、不删 token：die=%v 清了 %d 次\n%s", died, *cleaned, out)
	}
	assertRolledBack(t, r, out, st0, sb0, xr0)
}

// 正向应用时旧跳跃规则删不掉（新规则加得上）：算失败，回滚，不回收规则
func TestApplyNATClearFailForward(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, xr0 := seedOld(t)
	fakeFw(t, "-A PREROUTING -p udp -m udp --dport 20000:21000 -m comment --comment dun-hy2 -j REDIRECT --to-ports 5443",
		func(a []string) bool { return a[2] == "-D" })
	applyHop = hopRules
	died, out := runApply(newApplyState())
	if !died || !strings.Contains(out, "清旧的端口跳跃规则") {
		t.Fatalf("旧规则删不掉应该回滚：\n%s", out)
	}
	assertBytes(t, "state.json", statePath, st0)
	assertBytes(t, "sing-box 配置", sbConf, sb0)
	assertBytes(t, "Xray 配置", xrayConf, xr0)
	if r.prunes != 0 {
		t.Fatal("没应用成功却回收了放行规则")
	}
}
