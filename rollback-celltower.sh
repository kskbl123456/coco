#!/bin/bash
# 基站（CellTower）改写修复 —— 秒级回滚
# 用法： sudo bash rollback-celltower.sh
set -euo pipefail

DST='/opt/wloc-web/wloc_proxy.py'
BAK_DIR='/opt/wloc-backup/pre-celltower'
SRC="$BAK_DIR/wloc_proxy.py.rollback"
VENV='/opt/wloc-web/venv/bin/python'

echo '=========================================='
echo ' 基站改写修复 · 回滚'
echo '=========================================='

if [ ! -f "$SRC" ]; then
    echo "❌ 找不到回滚源：$SRC"; exit 1
fi

echo "回滚源 MD5: $(md5sum "$SRC" | awk '{print $1}')"
echo "当前生产 MD5: $(md5sum "$DST" | awk '{print $1}')"

cp "$SRC" "$DST.staged"
chown wloc:wloc-web "$DST.staged"
chmod 644 "$DST.staged"
mv "$DST.staged" "$DST"

"$VENV" -m py_compile "$DST"
systemctl restart wloc-proxy
sleep 2

STATE=$(systemctl is-active wloc-proxy || true)
echo "服务状态: $STATE"
echo "回滚后生产 MD5: $(md5sum "$DST" | awk '{print $1}')"

if [ "$STATE" = 'active' ]; then
    echo '✅ 回滚完成'
else
    echo '❌ 回滚后服务仍未起来，请人工介入'
    exit 1
fi
