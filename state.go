package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	baseDir     = "/etc/dun"
	cfPath      = baseDir + "/cf.json"
	certDir     = baseDir + "/cert"
	certFile    = certDir + "/fullchain.pem"
	keyFile     = certDir + "/key.pem"
	acmeKeyPath = baseDir + "/acme-account.key"
	linksPath   = baseDir + "/links.txt"
	customPath  = baseDir + "/cfip.txt"
	wetestPath  = baseDir + "/cfip-wetest.json"
	selfPath    = "/usr/local/bin/dun"
	svcBox      = "dun-sb"
	svcWeb      = "dun"
	rulePrefix  = "dun ws "
	xrayBin     = baseDir + "/bin/xray"
	xrayConf    = baseDir + "/xray.json"
	cfdBin      = baseDir + "/bin/cloudflared"
	argoToken   = baseDir + "/argo.token"
	svcXray     = "dun-xray"
	svcArgo     = "dun-argo"
	argoPrefix  = "dun argo "
)

// 测试里指到临时目录
var (
	statePath = baseDir + "/state.json"
	sbBin     = baseDir + "/bin/sing-box"
	sbConf    = baseDir + "/sing-box.json"
)

// dun upgrade 从这个仓库的 Release 拉新版本；发版时 workflow 会用 -X main.repo 注入当前仓库
var repo = "CapSOSkw/dun"

type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type Zone struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	NS      []string `json:"ns,omitempty"`
	Account string   `json:"account,omitempty"` // CF 账户 ID，建 Argo 隧道要用
}

type TLSHost struct {
	Host     string      `json:"host"`
	CertName string      `json:"cert_name,omitempty"` // *.<随机>.<域名>，空 = 老版本的单域名证书
	RecordID string      `json:"record_id"`
	Backup   []DNSRecord `json:"backup,omitempty"`
}

type Reality struct {
	Port       int    `json:"port"`
	PubPort    int    `json:"pub_port"`
	Fallback   int    `json:"fallback"`
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}

type AnyTLS struct {
	Port     int      `json:"port"`
	PubPort  int      `json:"pub_port"`
	Password string   `json:"password"`
	Padding  []string `json:"padding,omitempty"` // 每台机器随机生成的填充方案
}

// 一律 gecko 混淆 + 端口跳跃，包长、端口段、跳跃间隔每台机器随机
type Hy2 struct {
	Port     int    `json:"port"` // UDP
	PubPort  int    `json:"pub_port"`
	Password string `json:"password"`
	Obfs     string `json:"obfs"` // gecko 密码
	MinPkt   int    `json:"min_pkt"`
	MaxPkt   int    `json:"max_pkt"`
	CMinPkt  int    `json:"cmin_pkt"` // 客户端用的另一组
	CMaxPkt  int    `json:"cmax_pkt"`
	HopStart int    `json:"hop_start,omitempty"`
	HopEnd   int    `json:"hop_end,omitempty"`
	HopSec   int    `json:"hop_sec"`
}

// TUIC v5：单用户 uuid + 密码，不开 0-RTT（会被重放）
type TUIC struct {
	Port     int    `json:"port"` // UDP
	PubPort  int    `json:"pub_port"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	CC       string `json:"cc"` // 拥塞控制，默认 bbr
}

// 只认 sing-box 支持的三种，state 里的别的值一律当 bbr，免得写进配置和链接
func (t *TUIC) cc() string {
	switch t.CC {
	case "cubic", "new_reno", "bbr":
		return t.CC
	}
	return "bbr"
}

type WS struct {
	Host     string      `json:"host"`
	RecordID string      `json:"record_id"`
	Port     int         `json:"port"`
	PubPort  int         `json:"pub_port"`
	Inner    int         `json:"inner"`
	UUID     string      `json:"uuid"`
	Path     string      `json:"path"`
	Backup   []DNSRecord `json:"backup,omitempty"`
}

// Argo 隧道：cloudflared 从 VPS 主动连 CF，VPS 不开公网端口。
// 隧道路由由 dun 用 API 写在 CF 上，token 单独存在 argoToken 里。
// XHTTP 只有 Xray 支持（sing-box 没有），所以这一个入站由 Xray 跑
type Argo struct {
	Host     string      `json:"host"` // 只能是一级子域名，CF 的免费证书只覆盖一级
	RecordID string      `json:"record_id"`
	Backup   []DNSRecord `json:"backup,omitempty"`
	Tunnel   string      `json:"tunnel"`
	TName    string      `json:"tunnel_name,omitempty"`
	Manual   bool        `json:"manual,omitempty"`   // 隧道是用户在 CF 后台手动建的，cloudflared 由 dun 跑
	External bool        `json:"external,omitempty"` // 复用已有隧道：cloudflared 由这台机器上别的程序跑，dun 只往里加路由
	Inner    int         `json:"inner"`              // Xray，只监听 127.0.0.1
	Web      int         `json:"web"`                // dun 的伪装站和订阅，只监听 127.0.0.1
	Metrics  int         `json:"metrics"`            // cloudflared 的指标端口，固定下来免得占到 dun 的端口
	UUID     string      `json:"uuid"`
	Path     string      `json:"path"`
	HTTP2    bool        `json:"http2,omitempty"` // 隧道协议：默认 auto（QUIC 优先），UDP 出不去的机器改 http2
}

// Mode 为空是假登录页，proxy 是反代 URL
type Disguise struct {
	Mode string `json:"mode,omitempty"`
	URL  string `json:"url,omitempty"`
	Seed uint64 `json:"seed,omitempty"` // 伪装登录页的随机种子
}

// 零值就是默认：只用内置的东京 IP；wetest 三网 IP 和内置优选域名默认关（实测从上海电信多半落新加坡、美西，走 Argo 很慢）；
// 不要 IPv6；Argo 节点带 UDP（h3）版
type CFIPOpt struct {
	NoTokyo bool `json:"no_tokyo,omitempty"`
	Wetest  bool `json:"wetest,omitempty"`
	Domains bool `json:"domains,omitempty"`
	V6      bool `json:"v6,omitempty"`
	NoH3    bool `json:"no_h3,omitempty"`
}

// wetest 和内置域名都要定时去外面拉、去解析；两个都关着就不用刷新
func (o CFIPOpt) fetches() bool { return o.Wetest || o.Domains }

type State struct {
	IP4      string   `json:"ip4,omitempty"`
	IP6      string   `json:"ip6,omitempty"`
	PortMode string   `json:"port_mode,omitempty"` // direct 或 mapped，旧版 nat 只反映地址是否一致
	Zone     *Zone    `json:"zone,omitempty"`
	TLS      *TLSHost `json:"tls,omitempty"`
	Reality  *Reality `json:"reality,omitempty"`
	AnyTLS   *AnyTLS  `json:"anytls,omitempty"`
	WS       *WS      `json:"ws,omitempty"`
	Hy2      *Hy2     `json:"hy2,omitempty"`
	TUIC     *TUIC    `json:"tuic,omitempty"`
	Argo     *Argo    `json:"argo,omitempty"`
	Disguise Disguise `json:"disguise"`
	Token    string   `json:"token,omitempty"`
	CFIP     CFIPOpt  `json:"cfip"`
}

func loadState() *State {
	st := &State{}
	if b, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(b, st); err != nil {
			die("状态文件 %s 损坏: %v", statePath, err)
		}
	}
	return st
}

func (s *State) save() {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := writeFileAtomic(statePath, b, 0600); err != nil {
		die("保存状态失败: %v", err)
	}
}

func (s *State) installed() bool {
	return s.Reality != nil || s.AnyTLS != nil || s.WS != nil || s.Hy2 != nil || s.TUIC != nil || s.Argo != nil
}

// 节点域名和证书被谁用着
func (s *State) needTLS() bool { return s.Reality != nil || s.certInBox() }

// sing-box 自己加载证书文件的协议，续期后要重启 sing-box；Reality 的伪装站由 dun 每次握手现读
func (s *State) certInBox() bool { return s.AnyTLS != nil || s.Hy2 != nil || s.TUIC != nil }

// 证书续期成功后要重启的服务，renewLoop 和 dun renew 共用
func renewRestarts(st *State) []string {
	if st.certInBox() {
		return []string{svcBox}
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// 同目录独占的临时文件，rename 才是原子的，同时写也不会互相覆盖临时文件
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
