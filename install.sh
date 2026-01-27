#!/bin/sh

# THÔNG TIN CẤU HÌNH
GITHUB_USER="kiennt048"
GITHUB_REPO="net-shim"
BRANCH="main"
TOKEN="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"

# Cấu trúc URL có nhúng Token để bypass lỗi --header
BASE_URL="https://$TOKEN@raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH"

echo ">>> Dang tai file tu GitHub cho pfSense 2.8.1..."

# Tai Binary
fetch -q -o /usr/local/sbin/net-shim "$BASE_URL/net-shim"

# Tai Service Script
fetch -q -o /usr/local/etc/rc.d/net-shim "$BASE_URL/net-shim.rc"

# Phan quyen
chmod +x /usr/local/sbin/net-shim
chmod +x /usr/local/etc/rc.d/net-shim

# Kich hoat va Chay (Dùng sysrc để đảm bảo an toàn cho rc.conf.local)
sysrc -f /etc/rc.conf.local net_shim_enable="YES"
service net-shim restart || service net-shim start

echo ">>> Hoan tat trien khai net-shim!"
