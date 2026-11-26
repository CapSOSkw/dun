#!/usr/bin/env bash
# dun 一键安装：下载对应架构的二进制，核对 SHA-256，然后打开菜单
set -e
# 发版时 workflow 会把这两行改成发布这个版本的仓库和 tag；tag 为空时用最新版
repo="CapSOSkw/dun"
tag=""
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "暂不支持 $(uname -m)"; exit 1 ;;
esac
command -v sha256sum >/dev/null || { echo "缺少 sha256sum，没法校验下载的文件"; exit 1; }
if [ -n "$tag" ]; then
    base="https://github.com/$repo/releases/download/$tag"
else
    base="https://github.com/$repo/releases/latest/download"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "下载 dun ${tag:-最新版} ($arch)"
curl -fL --progress-bar "$base/dun-linux-$arch" -o "$tmp/dun"
curl -fsSL "$base/sha256sums.txt" -o "$tmp/sums"
want=$(awk -v f="dun-linux-$arch" '$2 == f || $2 == "*" f { print $1 }' "$tmp/sums")
got=$(sha256sum "$tmp/dun" | awk '{ print $1 }')
if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "SHA-256 校验失败：下载的文件和 Release 里的校验值对不上，没装"
    exit 1
fi
echo "SHA-256 校验通过"
install -m 755 "$tmp/dun" /usr/local/bin/dun.new
mv -f /usr/local/bin/dun.new /usr/local/bin/dun
exec /usr/local/bin/dun "$@" </dev/tty
