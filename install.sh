#!/bin/sh

# THÔNG TIN CẤU HÌNH
GITHUB_USER="kiennt048"
GITHUB_REPO="net-shim"
BRANCH="main"
TOKEN="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"

BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH"
HEADER="Authorization: token $TOKEN"

echo ">>> [1/4] Dang tai file tu GitHub qua curl..."

# Tai Binary
curl -H "$HEADER" -sSfL -o /usr/local/sbin/net-shim "$BASE_URL/net-shim"

# Tai Service Script
curl -H "$HEADER" -sSfL -o /usr/local/etc/rc.d/net-shim "$BASE_URL/net-shim.rc"

echo ">>> [2/4] Phan quyen thuc thi..."
chmod +x /usr/local/sbin/net-shim
chmod +x /usr/local/etc/rc.d/net-shim

echo ">>> [3/4] Dang ky service..."
sysrc -f /etc/rc.conf.local net_shim_enable="YES"

echo ">>> [4/4] Khoi chay ung dung..."
service net-shim restart || service net-shim start

echo ">>> TRIEN KHAI HOAN TAT!"
