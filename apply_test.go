package main

import (
	"bufio"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// applyAll 的替身：外部命令只记下来，不真跑 systemctl、sing-box、xray、iptables
type applyRec struct {
	cmds   []string // run 跑过的命令（svcDo / svcEnable / svcDisable / svcActive）
	hops   []int    // 每次 hopApply 时 Hy2 的跳跃起点
	prunes int
	ready  func(port int) bool
	check  func(bin string) error // sing-box check / xray run -test 的结果
	onCmd  func(cmd string)
}

func fakeApply(t *testing.T) *applyRec {
	t.Helper()
	r := &applyRec{ready: func(int) bool { return true }, check: func(string) error { return nil }}
	ob, oc, ox, oxb, os_, oe, oi := sbBin, sbConf, xrayConf, xrayBin, statePath, dieExit, initSys
	orun, oout := run, runOut
	opr, oudp, oprune, ohop, olog, ow := portReady, udpReady, applyPrune, applyHop, applyLog, readyWait
	t.Cleanup(func() {
		sbBin, sbConf, xrayConf, xrayBin, statePath, dieExit, initSys = ob, oc, ox, oxb, os_, oe, oi
		run, runOut = orun, oout
		portReady, udpReady, applyPrune, applyHop, applyLog, readyWait = opr, oudp, oprune, ohop, olog, ow
	})
	dir := t.TempDir()
	sbBin, sbConf, xrayConf, xrayBin, statePath = dir+"/sing-box", dir+"/sing-box.json", dir+"/xray.json", dir+"/xray", dir+"/state.json"
	dieExit = func(int) { panic("die") }
	initSys = "systemd"
	run = func(name string, args ...string) error {
		c := name + " " + strings.Join(args, " ")
		r.cmds = append(r.cmds, c)
		if r.onCmd != nil {
			r.onCmd(c)
		}
		return nil
	}
	runOut = func(name string, args ...string) (string, error) {
		if err := r.check(name); err != nil {
			return "bad config", err
		}
		return "", nil
	}
	portReady = func(p int) bool { return r.ready(p) }
	udpReady = func(p int) bool { return r.ready(p) }
	applyPrune = func(*State) { r.prunes++ }
	applyHop = func(st *State) {
		h := 0
		if st.Hy2 != nil {
			h = st.Hy2.HopStart
		}
		r.hops = append(r.hops, h)
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

func oldApplyState() *State {
	return &State{IP4: "203.0.113.5", TLS: &TLSHost{Host: "n.r4nd.example.com"},
		Reality: &Reality{Port: 8443, PubPort: 8443, Fallback: 21003},
		Hy2:     &Hy2{Port: 5443, PubPort: 5443, Password: "p", Obfs: "o", HopStart: 20000, HopEnd: 21000, HopSec: 30},
		Argo:    &Argo{Host: "a.example.com", Inner: 21010, Web: 21011, UUID: "u", Path: "/old"}}
}

// 把旧状态和旧配置放到磁盘上，返回三份原字节
func seedOld(t *testing.T) (st, sb, xr []byte) {
	t.Helper()
	oldApplyState().save()
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
			st := oldApplyState()
			st.Reality.Port = 443
			st.Argo.Path = "/new" // Xray 配置也变了，两样都要检查
			died, out := runApply(st)
			if !died || !strings.Contains(out, "检查不通过") {
				t.Fatalf("检查不过应该 die：\n%s", out)
			}
			assertBytes(t, "state.json", statePath, st0)
			assertBytes(t, "sing-box 配置", sbConf, sb0)
			assertBytes(t, "Xray 配置", xrayConf, xr0)
			if len(r.cmds) != 0 || len(r.hops) != 0 || r.prunes != 0 {
				t.Fatalf("检查不过却动了服务或规则：%q hop=%v prune=%d", r.cmds, r.hops, r.prunes)
			}
			if left, _ := os.ReadDir(strings.TrimSuffix(statePath, "/state.json")); len(left) != 3 {
				t.Fatalf("临时文件没删干净：%v", left)
			}
		})
	}
}

// 端口等不到：三份文件换回旧字节（原来没有的删掉），按旧状态重启服务、重加旧的跳跃规则，不回收放行规则
func TestApplyReadyFailRollsBack(t *testing.T) {
	r := fakeApply(t)
	st0, sb0, _ := seedOld(t)
	os.Remove(xrayConf) // 原来没有 Xray 配置：回滚时要删掉新写的
	webSawNew := false
	r.onCmd = func(c string) {
		if c == "systemctl restart dun" && !webSawNew {
			// dun serve 按 state.json 定端口，重启它之前新状态必须已经落盘
			webSawNew = loadState().Reality.Port == 443
		}
	}
	r.ready = func(p int) bool { return p != 443 }
	st := oldApplyState()
	st.Reality.Port = 443
	st.Hy2.HopStart, st.Hy2.HopEnd = 30000, 31000
	died, out := runApply(st)
	if !died || !strings.Contains(out, "端口 443 没起来") || !strings.Contains(out, "已换回原来的配置") {
		t.Fatalf("端口没起来应该回滚后 die：\n%s", out)
	}
	if !webSawNew {
		t.Fatal("重启 dun 服务时 state.json 还是旧的")
	}
	assertBytes(t, "state.json", statePath, st0)
	assertBytes(t, "sing-box 配置", sbConf, sb0)
	assertBytes(t, "Xray 配置", xrayConf, nil)
	if !reflect.DeepEqual(r.hops, []int{30000, 20000}) {
		t.Fatalf("跳跃规则应先按新状态、再按旧状态加：%v", r.hops)
	}
	for _, c := range []string{"systemctl restart dun-sb", "systemctl restart dun", "systemctl restart dun-xray"} {
		if r.has(c) != 2 {
			t.Fatalf("%q 应该新旧各一次：%q", c, r.cmds)
		}
	}
	if r.prunes != 0 {
		t.Fatal("没应用成功却回收了放行规则")
	}
}

// 旧状态没有协议：回滚时按旧状态把服务停掉，不再重启
func TestApplyRollbackToEmpty(t *testing.T) {
	r := fakeApply(t)
	r.ready = func(int) bool { return false }
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

// 都起来了：新配置落盘，放行规则回收一次
func TestApplySuccess(t *testing.T) {
	r := fakeApply(t)
	seedOld(t)
	st := oldApplyState()
	st.Reality.Port = 443
	st.Argo.Path = "/new"
	if died, out := runApply(st); died || !strings.Contains(out, "服务已运行") {
		t.Fatalf("应该成功：\n%s", out)
	}
	if r.prunes != 1 || loadState().Reality.Port != 443 || !reflect.DeepEqual(r.hops, []int{20000}) {
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

// 菜单 15：只用 ghLatest 查上游正式版，按当前、推荐、最新给选项，最后装的版本对
func TestUpdateCorePick(t *testing.T) {
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
	for name, c := range cores {
		for _, tc := range []struct {
			cur, latest, input string
			want               string // 装的版本，空 = 不装
		}{
			{"older", "newer", "\n", "pinned"}, // 当前 < 推荐 < 最新：默认装推荐
			{"older", "newer", "2\n", "newer"},
			{"older", "newer", "3\n", ""},
			{"older", "newer", "0\n", ""},
			{"pinned", "newer", "\n", ""}, // 当前 == 推荐 < 最新：默认不升
			{"pinned", "newer", "y\n", "newer"},
			{"newer", "newer", "\n", ""}, // 已是最新：默认不重装
			{"newer", "newer", "y\n", "newer"},
			{"older", "pinned", "\n", "pinned"}, // 最新就是推荐
			{"older", "", "\n", "pinned"},       // 查不到上游：还能装推荐版
			{"pinned", "", "\n", ""},
		} {
			v := map[string]string{"older": older[name], "newer": newer[name], "pinned": c.pinned, "": ""}
			got := fakeInstall(t)
			var asked []string
			ghLatest = func(repo string) string { asked = append(asked, repo); return v[tc.latest] }
			oout, oin := runOut, in
			runOut = func(string, ...string) (string, error) {
				return strings.Replace(c.ver, "%s", v[tc.cur], 1), nil
			}
			in = bufio.NewReader(strings.NewReader(tc.input))
			out := captureStderr(func() {
				defer func() { recover() }()
				c.update()
			})
			runOut, in = oout, oin
			var want []string
			if tc.want != "" {
				want = []string{c.repo + " " + c.tag + v[tc.want]}
			}
			if !reflect.DeepEqual(*got, want) || !reflect.DeepEqual(asked, []string{c.repo}) {
				t.Fatalf("%s 当前 %s 最新 %q 输入 %q：装了 %q 查了 %q，应装 %q\n%s",
					name, tc.cur, v[tc.latest], tc.input, *got, asked, want, out)
			}
			if !strings.Contains(out, "推荐 "+c.pinned) || !strings.Contains(out, "当前 "+v[tc.cur]) {
				t.Fatalf("%s 没列出当前和推荐版本：\n%s", name, out)
			}
		}
	}
}
