# dun 盾

一条命令装好三种节点：Reality 偷自己、AnyTLS、套 Cloudflare 的 VLESS + WS；线路差的机器还可以加装 Hysteria2，或者装一条 Argo 隧道（VLESS + XHTTP），VPS 一个公网端口都不用开。装完输入 `dun` 就能管理。

dun 是一个 Go 写的单文件程序。节点由官方 sing-box 跑，Argo 的 XHTTP 由 Xray 跑、隧道由 cloudflared 跑，伪装站、订阅和证书续期由 dun 自己的后台服务负责。

> 本仓库 fork 自 [byJoey/dun](https://github.com/byJoey/dun)，在它的基础上加了 Argo 隧道。

## 快速开始

准备三样东西：

- 一台 VPS，root 登录。带 systemd 的 Linux 都行，比如 Debian、Ubuntu、CentOS、Alma、Rocky，amd64 和 arm64 都支持
- 一个已经接入 Cloudflare 的域名
- Cloudflare 的 Global API Key。在 CF 后台点右上角头像，进「我的个人资料」→「API 令牌」，Global API Key 那一栏点「查看」

登录 VPS，执行：

```bash
bash <(curl -fsSL https://github.com/CapSOSkw/dun/releases/latest/download/install.sh)
```

菜单里选 `4` 三个一起装。中间会问 CF 邮箱和 Key，让你选一个域名，其他问题一路回车用默认值就行。装完屏幕上会打出订阅地址，复制进客户端就能用。想要 Argo 隧道，再选 `6`。

以后再管理，输入：

```bash
dun
```

不想进菜单也可以直接敲命令：

```bash
dun install reality      # 只装一个，reality / anytls / ws / all / hy2 / argo
dun links                # 再看一遍订阅和链接
dun log                  # 看日志
dun syncip               # 机器换了 IP 以后同步解析
dun uninstall            # 全部卸载
```

## 订阅

装完会给两个订阅地址，装了的协议的节点都在里面：

- `…/sub`：v2rayN、Shadowrocket、NekoBox 用
- `…/clash`：Clash Verge、FlClash 这类 mihomo 客户端用，自带「自动选择」分组

订阅地址优先走 Argo 隧道的域名，没装 Argo 就走 CF WS 的域名，VPS 的 IP 被墙了也能更新。订阅里除了原始的 CF WS、Argo 节点，还会带上一批优选地址：

- wetest 的三网优选 IP，每 3 小时自动刷新
- 内置优选域名，刷新时逐个解析，解析不到 Cloudflare 的自动剔除
- 你自己加的地址，菜单「优选地址和订阅」里添加，格式是 `地址[:端口][#备注]`

这些都在你自己的 VPS 上生成，不经过任何第三方订阅服务。订阅地址里带一段随机字符，泄露了就在菜单里重置。

## 分流

Clash 订阅自带分流规则，导入就能用：

| 分组 | 默认 | 管哪些 |
|---|---|---|
| 广告拦截 | 拦截 | 常见广告和跟踪域名 |
| AI | 走代理 | ChatGPT、Claude、Gemini 等 |
| Telegram / YouTube / 流媒体 / 谷歌 | 走代理 | 各自的域名和 IP |
| 微软 / 苹果 | 直连 | 下载更新走国内更快 |
| 国内网站和 IP | 直连 | |
| 漏网之鱼 | 走代理 | 上面都没匹配到的 |

每个分组都能在客户端里单独切换节点或改成直连。规则库用的是 MetaCubeX 的 geosite 和 geoip，从 jsDelivr 下载，每天自动更新。

DNS 防泄露也配好了。常见的泄露是这样来的：一个国外域名不在规则列表里，客户端为了判断它是不是国内 IP，会先拿国内 DNS 解析一次，这时国内 DNS 就看到了你访问的域名。dun 的订阅默认用国外 DoH，并让 DNS 请求跟着分流规则走代理，国内 DNS 只用来解析国内域名和直连流量。用 DNS 泄露测试网站测，看不到国内的 DNS 服务器。

v2rayN、Shadowrocket 用的 `/sub` 订阅装不下规则，用客户端自带的分流就行，比如 v2rayN 的「绕过大陆」。

服务端另外拦两样：BT 下载，VPS 商家看到了会封机；通过节点访问内网地址，免得别人借你的节点摸进机器本地的服务。

## 抗封锁做了什么

- **Reality 偷自己**：用你自己域名的真证书和伪装站，Vision 流控，chrome 指纹
- **证书不暴露节点域名**：证书签成 `*.<随机>.<你的域名>`，证书公开日志里只有通配符，扫描器拿不到真正的节点域名。觉得域名被盯上了，`dun rehost` 一键换
- **AnyTLS**：填充方案每台机器随机生成，不用官方默认那套
- **Hysteria2**：gecko 混淆，握手包切成随机大小；端口跳跃的范围和间隔每台机器随机；没有密码的探测一律不回应
- **CF WS**：回源端口只回应 Cloudflare 的 IP，别人直连就是一个没开的端口；路径随机
- **Argo 隧道**：VPS 不开公网端口，GFW 只看到你在连 Cloudflare；XHTTP 路径随机；隧道 token 只放在 root 能读的文件里，不出现在进程列表
- **伪装站**：登录页每台机器随机生成，标题、文案、配色、页面结构、登录接口和报错都不一样
- **客户端**：DNS 防泄露，分流规则

## Hysteria2

菜单第 5 项单独装，不在「三个一起装」里。走 UDP，丢包多、晚高峰拥堵的线路上明显比 TCP 协议快，适合线路不好的机器。

默认就是最抗封锁的配置：gecko 混淆、端口跳跃，参数每台机器随机，不用自己选。客户端要求 mihomo 1.19.34、sing-box 1.14 以上，老版本不认 gecko。云厂商的安全组记得放行 UDP。

## Argo 隧道

菜单第 6 项单独装，不在「三个一起装」里。VPS 上的 cloudflared 主动连到 Cloudflare，客户端连 Cloudflare 的优选 IP，流量走 Cloudflare 自己的网络进隧道：

```
客户端 ──TLS──> CF 优选 IP ══CF 网络══> 隧道 ══> cloudflared ──> Xray（只听 127.0.0.1）
```

VPS 不开任何公网端口，也不暴露 IP，IP 被墙了照样能用；NAT 小鸡、纯 IPv6 的机器也能装。

- 隧道、路由、解析都由 dun 用 API 建好，不用进 Zero Trust 后台。万一你的账号不让 API 建隧道，dun 会教你在后台手动建一条，把 token 粘回来。手动建的隧道卸载时 dun 不删，留给你自己处理；已经给别的域名用着的隧道，dun 不收它的 token
- 账号里已经有隧道的话，安装时会问你**新建一条**（推荐）还是**复用已有的**。复用有个前提：这条隧道是远程管理的（用 token 跑），而且它的 cloudflared 就跑在这台机器上。原因是一条隧道的路由所有连接器共用，CF 会把请求分给任意一个连接器，而 dun 的路由指向本机 127.0.0.1。连接器在别的机器上，请求就会被送错地方。复用时 dun 只往隧道里加两条路由，放在最前面，原有路由一条都不动，也不另跑 cloudflared；卸载时只删这两条路由和 dun 建的解析，隧道留着。代价是那个 cloudflared 停了，Argo 节点也跟着断，隧道协议也由它说了算
- 装完会从外面实际打开一次 Argo 域名，确认 CF → 隧道 → 本机这一路是通的
- 协议是 VLESS + XHTTP，由 Xray 跑，sing-box 不支持 XHTTP。经过 Argo 只有 `packet-up` 模式能通，订阅里已经写好
- 每个地址出两个节点：`…-Argo` 走 TCP（h2），`…-Argo-UDP` 走 UDP（h3）。晚高峰运营商常对单条 TCP 连接限速，这时 UDP 版往往更稳；UDP 被限速时就用 TCP 版。嫌节点太多，可以在「优选地址和订阅」里关掉 UDP 版
- 隧道协议默认 `auto`：优先 QUIC，UDP 出不去自动退回 http2；机器有 IPv4 就固定用 IPv4 连 Cloudflare。菜单「Argo 隧道」里可以切成 http2
- 优选地址和 CF WS 共用一个池子，你自己测出来好用的 IP 加进「自选地址」就行
- Argo 的域名只能是一级子域名（`xxx.你的域名`），Cloudflare 免费证书只覆盖一级。证书由 Cloudflare 签发和续期，不用管

客户端要支持 XHTTP：v2rayN（Xray 内核）、Shadowrocket 2.2.66 以上（UDP 版要 2.2.78 以上）、新版 mihomo 内核的 Clash Verge Rev / FlClash。NekoBox、sing-box 官方客户端这类 sing-box 内核的用不了。

还要知道一点：TLS 在 Cloudflare 边缘就解开了，VLESS 本身不加密，所以 Cloudflare 能看到你访问的是哪个网站，网页内容是 HTTPS 的，它看不到。GFW 什么都看不到。

## 伪装站

别人直接打开你的节点域名，看到的是一个登录页。随便输账号密码，都会提示用户名或密码错误。每台机器的登录页长得都不一样，想换个样子，在「伪装站」里选「换一个登录页样式」。

想换成别的网站，在菜单「伪装站」里选「反代一个网站」，填个网址就行。Reality 偷自己、CF WS 和 Argo 的域名会一起换过去。CF WS 的回源端口只认 Cloudflare，直接连 IP 什么都看不到。反代只在 HTTP 这一层，TLS 握手用的还是你自己域名的真证书。

## 菜单能做什么

| 序号 | 功能 |
|---|---|
| 1-4 | 单独装某个协议，或者三个一起装 |
| 5 | 装 Hysteria2 |
| 6 | Argo 隧道：没装就装（可以新建隧道，也可以复用这台机器上已有的）；装了可以看状态、切换隧道协议、重启、卸载 |
| 7 / 8 | 看订阅、链接和二维码，看 mihomo 配置 |
| 9 | 优选地址：刷新、看列表、加自选、开关来源、开关 Argo 的 UDP 版、重置订阅地址 |
| 10 | 伪装站：登录页、反代网站、换登录页样式 |
| 11 / 12 | 改端口，重置密码和 UUID |
| 13 | 卸载单个协议，顺带删掉它的解析、CF 规则和隧道 |
| 14 | 重启、停止、看日志 |
| 15 / 20 | 更新内核（sing-box，装了 Argo 还有 Xray、cloudflared），更新 dun |
| 16 | 开 BBR |
| 17 | IP 变了，同步解析 |
| 18 | 更换节点域名，证书一起换 |
| 19 | 换 CF 账号 |
| 21 | 全部卸载 |

## 常见问题

**三个协议该用哪个？**

优先用 Reality 偷自己，直连，速度最好。AnyTLS 也是直连，换个协议换个特征，当备用。CF WS 走 Cloudflare 中转，速度一般，但 VPS 的 IP 被墙了它照样能用，属于保底。直接导入订阅，三个都有，客户端里切换最省心。

Argo 隧道也是保底，而且在很多线路上比 CF WS 快：CF WS 要 Cloudflare 从公网回源到你的 VPS，这一段经常很慢；Argo 走的是 Cloudflare 自己的网络，还能复用连接，打开网页更快。

**为什么要 Global API Key，安全吗？**

用 Global Key 是因为小白只要复制一串字符，不用自己建令牌、勾权限。代价是这把 Key 权限很大，能管你整个 CF 账号。dun 把它存在 VPS 的 `/etc/dun/cf.json`，只有 root 能读，续期证书要用，所以会一直留着，卸载时一起删掉。VPS 要是被人拿下，Key 也就跟着泄露了。介意的话，单独注册一个 CF 账号放节点用的域名。

**会动我域名的哪些设置？**

只加这几样：

- 两条解析。一条给 Reality、AnyTLS、Hysteria2 用，只解析不开代理；另一条给 CF WS 用，开橙云
- CF WS 那个子域名一条回源规则，把 CF 回源的端口改成节点端口
- CF WS 那个子域名一条配置规则，单独把 SSL 设成 Flexible，安全级别调低，免得订阅和连接被拦

装了 Argo 隧道还会加：

- 一条隧道，和指向它的一条解析（开橙云）。选了复用已有隧道的话不新建，只在那条隧道里加两条路由
- Argo 那个子域名一条配置规则（安全级别调低、关浏览器完整性检查）和一条缓存规则（不缓存）
- 整个域名的 HTTP/3 开关，没开就打开，UDP 版节点要用
- Bot Fight Mode 开着的话会问你要不要关。它只能整个域名一起开关，开着可能把代理流量当成机器人拦掉

整个域名的 SSL 模式不改，你原来的规则也不碰。子域名要是已经有解析，dun 会先问你，覆盖前会备份，卸载时还原。

**443 被占了怎么办？**

Reality 和 AnyTLS 默认用 443，被占了会提示换个端口，填别的也能用。机器上原来的网站不受影响，dun 的伪装站只监听本机 127.0.0.1，80 端口空着才会用来做跳转。

**装完连不上？**

按这个顺序查：

1. 云厂商后台的安全组有没有放行端口。甲骨文、谷歌云、AWS 都要在网页上单独放行，dun 只能处理机器里面的防火墙
2. CF WS、Argo 刚装好，解析可能要一两分钟才生效
3. 客户端是不是太老。AnyTLS 要新版客户端，见下一条；Argo 的要求见上面「Argo 隧道」一节
4. 输入 `dun log` 看日志，有报错截图发到群里

**AnyTLS 和官方默认有什么不一样？**

AnyTLS 靠填充打乱包长，但官方默认的填充方案人人都在用，包长分布本身就成了特征，比如认证包永远是同一个长度。dun 每台机器装的时候随机生成一份自己的方案，客户端连上以后由服务端下发，从第二条连接开始就按你的方案走。重置 AnyTLS 密码时方案也会一起换。

**哪些客户端能用 AnyTLS？**

sing-box 官方客户端、Clash Verge Rev、FlClash 这类 mihomo 内核的客户端，还有新版的 v2rayN、Shadowrocket。Reality 和 WS 基本所有客户端都支持。

**CF WS 很慢？**

导入订阅后，在客户端里给 CF WS 那一组测个速，挑最快的。也可以把你自己测出来的好 IP 加进「自选地址」，订阅马上就有。

**NAT 小鸡能用吗？**

能。dun 发现是 NAT 机器，会多问一句外网端口，填服务商给你映射的那个端口就行。甲骨文这种内外端口一样的，直接回车。Argo 隧道不用开端口，NAT 机器装它最省事。

**证书会过期吗？**

不会。后台服务每 12 小时检查一次，剩不到 30 天就自动续，续完自动生效。想手动续就敲 `dun renew`。Argo 和 CF WS 用的是 Cloudflare 的边缘证书，Cloudflare 自己续。

**机器换 IP 了怎么办？**

输入 `dun syncip`，解析改成新 IP。订阅会自动跟着变，客户端更新一下订阅就行。Argo 隧道不受 IP 影响。

**怎么卸载干净？**

输入 `dun uninstall`。dun 加的解析、CF 规则、隧道、证书、sing-box、Xray、cloudflared 和它自己全删掉，BBR 设置会保留。

## 自己编译

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=dev" -o dun .
```

打 `v*` 的 tag 推上去，GitHub Actions 会自动编译 amd64、arm64 两个版本并发布 Release。仓库名会在编译时注入，`dun upgrade` 和 install.sh 都从发版的这个仓库拉，fork 出去的仓库不会跑回上游。fork 的仓库第一次用，要先在 Actions 页面启用 workflow。
