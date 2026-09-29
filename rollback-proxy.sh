#!/bin/bash
# WLoc 代理秒级回滚脚本
# 用法: sudo /opt/wloc-web/rollback-proxy.sh
set -e

SRC=/opt/wloc-web/wloc_proxy.py.sync-orig
DST=/opt/wloc-web/wloc_proxy.py

if [ ! -f "$SRC" ]; then
    echo "❌ 原版备份不存在: $SRC"
    echo "   请用完整备份恢复: sudo /opt/wloc-backup/restore_wloc.sh <备份包>"
    exit 1
fi

echo "回滚 wloc-proxy 到重构前版本..."
cp "$SRC" "$DST"
chown wloc:wloc-web "$DST"
systemctl restart wloc-proxy
sleep 3

echo
echo "=== 回滚后状态 ==="
systemctl is-active wloc-proxy
echo "MD5（应为 909faa523a5cfa6e0dc84635012a15db）:"
md5sum "$DST"
echo
ss -tlnp | grep -E ':9999|10.10.1.1:443' || echo "⚠️ 端口未监听"
