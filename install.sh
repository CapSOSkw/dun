#!/usr/bin/env bash
# dun 一键安装：下载对应架构的二进制，然后打开菜单
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "暂不支持 $(uname -m)"; exit 1 ;;
esac
url="https://github.com/CapSOSkw/dun/releases/latest/download/dun-linux-$arch"
echo "下载 dun ($arch)"
curl -fL --progress-bar "$url" -o /usr/local/bin/dun.new
chmod +x /usr/local/bin/dun.new
mv -f /usr/local/bin/dun.new /usr/local/bin/dun
exec /usr/local/bin/dun "$@" </dev/tty
