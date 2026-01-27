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

echo ">>> [1/4] Dang tai file tu GitHub..."
# Tải Binary
curl -H "$HEADER" -sSL -o /usr/local/sbin/net-shim "$BASE_URL/net-shim"
# Tải Service Script
curl -H "$HEADER" -sSL -o /usr/local/etc/rc.d/net-shim "$BASE_URL/net-shim.rc"

echo ">>> [2/4] Phan quyen thuc thi..."
chmod +x /usr/local/sbin/net-shim
chmod +x /usr/local/etc/rc.d/net-shim

echo ">>> [3/4] Kich hoat dich vu (System Enable)..."
# Ghi vao rc.conf.local de tu chay khi boot
sysrc -f /etc/rc.conf.local net_shim_enable="YES"
# Lenh xac nhan kich hoat tren pfSense
service net-shim enable

echo ">>> [4/4] Khoi chay ung dung (System Start/Restart)..."
# Restart de cap nhat binary moi neu dang chay, neu chua chay thi se start
service net-shim restart || service net-shim start

echo ">>> KIEM TRA KET QUA:"
if pgrep -f "net-shim" > /dev/null; then
    echo "THANH CONG: net-shim dang chay."
    pgrep -lf "net-shim"
else
    echo "CANH BAO: net-shim chua chay. Hay kiem tra file log hoac chay truc tiep de debug."
fi

echo ">>> TRIEN KHAI HOAN TAT!"
