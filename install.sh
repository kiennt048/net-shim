#!/bin/sh

# Dừng script ngay lập tức nếu bất kỳ lệnh nào bị lỗi
set -e

GITHUB_USER="kiennt048"
GITHUB_REPO="net-shim"
BRANCH="main"
TOKEN="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"

BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH"
HEADER="Authorization: token $TOKEN"

echo ">>> [1/4] Dang tai file..."

# Sử dụng -S để hiện lỗi nếu tải thất bại
curl -H "$HEADER" -SL -o /usr/local/sbin/net-shim "$BASE_URL/net-shim"
curl -H "$HEADER" -SL -o /usr/local/etc/rc.d/net-shim "$BASE_URL/net-shim.rc"

echo ">>> [2/4] Phan quyen..."
chmod +x /usr/local/sbin/net-shim
chmod +x /usr/local/etc/rc.d/net-shim

echo ">>> [3/4] Dang ky service..."
sysrc -f /etc/rc.conf.local net_shim_enable="YES"

echo ">>> [4/4] Khoi chay..."
service net-shim restart || service net-shim start

echo ">>> TRIEN KHAI HOAN TAT!"
