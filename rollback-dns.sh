#!/bin/bash
# WLoc DNS 秒级回滚：恢复到 asyncio 重构之前（ThreadingUDPServer 版本）
# 用法： sudo /opt/wloc-web/rollback-dns.sh
set -e

ORIG=/opt/wloc-web/wloc_dns.py.sync-orig
DEST=/opt/wloc-web/wloc_dns.py
EXPECT=75ea58b2d929290e4c393e6b9042df6d

if [ ! -f "$ORIG" ]; then
    echo "错误：找不到原始文件 $ORIG"
    exit 1
fi

GOT=$(md5sum "$ORIG" | awk '{print $1}')
echo "原始文件 MD5: $GOT"
if [ "$GOT" != "$EXPECT" ]; then
    echo "警告：原始文件 MD5 与预期不符（期望 $EXPECT），仍继续回滚"
fi

cp -a "$ORIG" "$DEST"
chown wloc:wloc-web "$DEST"
systemctl restart wloc-dns
sleep 1
systemctl is-active wloc-dns
echo "已回滚到同步版： $DEST"
md5sum "$DEST"
