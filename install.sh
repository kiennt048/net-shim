#!/bin/sh

# CẤU HÌNH GITHUB
GITHUB_USER="TenUserCuaAnh"
GITHUB_REPO="TenRepo"
BRANCH="main"
# Token dạng ghp_xxxxxxxxxxxxxxx
GITHUB_TOKEN="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"

# Đường dẫn Raw của GitHub
BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH"

# ĐƯỜNG DẪN TRÊN PFSENSE
BIN_PATH="/usr/local/sbin/net-shim"
RC_PATH="/usr/local/etc/rc.d/net-shim"

echo ">>> [1/4] Downloading files from GitHub..."
# Lưu ý Header khác: "Authorization: token ..." thay vì "PRIVATE-TOKEN"
fetch -q -o $BIN_PATH --no-verify-peer --header "Authorization: token $GITHUB_TOKEN" "$BASE_URL/net-shim"
fetch -q -o $RC_PATH --no-verify-peer --header "Authorization: token $GITHUB_TOKEN" "$BASE_URL/net-shim.rc"

echo ">>> [2/4] Setting permissions..."
chmod +x $BIN_PATH
chmod +x $RC_PATH

echo ">>> [3/4] Enabling service..."
sysrc -f /etc/rc.conf.local net_shim_enable="YES"

echo ">>> [4/4] Starting service..."
service net-shim restart || service net-shim start