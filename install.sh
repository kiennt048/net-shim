#!/bin/sh

# Dừng script ngay nếu có lỗi
set -e

# CẤU HÌNH
GITHUB_USER="kiennt048"
GITHUB_REPO="net-shim"
BRANCH="main"
TOKEN="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"

BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH"
HEADER="Authorization: token $TOKEN"

echo ">>> [1/4] Dang tai file..."

# Tải Binary và kiểm tra ngay lập tức
curl -H "$HEADER" -sSL -o /usr/local/sbin/net-shim "$BASE_URL/net-shim"
if [ ! -s /usr/local/sbin/net-shim ]; then
    echo "LOI: Khong tai được file binary hoac file rong!"
    exit 1
fi

# Tải Service Script
curl -H "$HEADER" -sSL -o /usr/local/etc/rc.d/net-shim "$BASE_URL/net-shim.rc"

echo ">>> [2/4] Phan quyen..."
chmod +x /usr/local/sbin/net-shim
chmod +x /usr/local/etc/rc.d/net-shim

echo ">>> [3/4] Dang ky service..."
# Kiểm tra xem dòng config đã tồn tại chưa để tránh trùng lặp
if ! grep -q 'net_shim_enable="YES"' /etc/rc.conf.local 2>/dev/null; then
    sysrc -f /etc/rc.conf.local net_shim_enable="YES"
fi

echo ">>> [4/4] Khoi chay..."
service net-shim restart || service net-shim start

echo ">>> KIEM TRA TRANG THAI:"
ls -lh /usr/local/sbin/net-shim
pgrep -lf net-shim || echo "Canh bao: App chua chay, hay kiem tra log."

echo ">>> TRIEN KHAI HOAN TAT!"
