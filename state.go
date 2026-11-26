package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	baseDir     = "/etc/dun"
	statePath   = baseDir + "/state.json"
	cfPath      = baseDir + "/cf.json"
	sbBin       = baseDir + "/bin/sing-box"
	sbConf      = baseDir + "/sing-box.json"
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
	ID   string   `json:"id"`
	Name string   `json:"name"`
	NS   []string `json:"ns,omitempty"`
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

// Mode 为空是假登录页，proxy 是反代 URL
type Disguise struct {
	Mode string `json:"mode,omitempty"`
	URL  string `json:"url,omitempty"`
	Seed uint64 `json:"seed,omitempty"` // 伪装登录页的随机种子
}

// 零值就是默认：开 wetest、开内置域名、不要 IPv6
type CFIPOpt struct {
	NoWetest  bool `json:"no_wetest,omitempty"`
	NoDomains bool `json:"no_domains,omitempty"`
	V6        bool `json:"v6,omitempty"`
}

type State struct {
	IP4      string   `json:"ip4,omitempty"`
	IP6      string   `json:"ip6,omitempty"`
	NAT      bool     `json:"nat,omitempty"`
	Zone     *Zone    `json:"zone,omitempty"`
	TLS      *TLSHost `json:"tls,omitempty"`
	Reality  *Reality `json:"reality,omitempty"`
	AnyTLS   *AnyTLS  `json:"anytls,omitempty"`
	WS       *WS      `json:"ws,omitempty"`
	Hy2      *Hy2     `json:"hy2,omitempty"`
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
	return s.Reality != nil || s.AnyTLS != nil || s.WS != nil || s.Hy2 != nil
}

// 节点域名和证书被谁用着
func (s *State) needTLS() bool { return s.Reality != nil || s.AnyTLS != nil || s.Hy2 != nil }

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
