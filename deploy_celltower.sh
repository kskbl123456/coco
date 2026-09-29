#!/bin/bash
# 基站（CellTower）改写修复 —— 上线脚本
# 用法： sudo bash deploy_celltower.sh [源文件路径]
set -euo pipefail

EXPECT_MD5='95d41e4727c4aec2fa1f80175465d566'
SRC="${1:-/tmp/wloc_proxy.py.new}"
DST='/opt/wloc-web/wloc_proxy.py'
BAK_DIR='/opt/wloc-backup/pre-celltower'
VENV='/opt/wloc-web/venv/bin/python'

echo '=========================================='
echo ' 基站改写修复 · 上线'
echo '=========================================='

# ---- 0. 源文件存在 ----
if [ ! -f "$SRC" ]; then
    echo "❌ 源文件不存在：$SRC"; exit 1
fi

# ---- 1. MD5 校验（防传错文件）----
ACTUAL=$(md5sum "$SRC" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECT_MD5" ]; then
    echo "❌ MD5 不符！"
    echo "   期望：$EXPECT_MD5"
    echo "   实际：$ACTUAL"
    exit 1
fi
echo "✅ [1/6] MD5 校验通过：$ACTUAL"

# ---- 2. 语法检查 ----
if ! "$VENV" -m py_compile "$SRC" 2>/dev/null; then
    echo "❌ [2/6] 语法检查失败"; exit 1
fi
echo "✅ [2/6] 语法检查通过"

# ---- 3. 备份当前生产版本（回滚源）----
mkdir -p "$BAK_DIR"
if [ ! -f "$BAK_DIR/wloc_proxy.py.rollback" ]; then
    cp "$DST" "$BAK_DIR/wloc_proxy.py.rollback"
    echo "✅ [3/6] 已留存回滚源：$BAK_DIR/wloc_proxy.py.rollback"
else
    echo "✅ [3/6] 回滚源已存在（保留首次版本，不覆盖）"
fi
cp "$DST" "$BAK_DIR/wloc_proxy.py.before-$(date +%Y%m%d-%H%M%S)"
echo "        另存本次改动前副本"

# ---- 4. 原子替换 ----
cp "$SRC" "$DST.staged"
chown wloc:wloc-web "$DST.staged"
chmod 644 "$DST.staged"
mv "$DST.staged" "$DST"
NEW_MD5=$(md5sum "$DST" | awk '{print $1}')
echo "✅ [4/6] 已替换，生产 MD5 = $NEW_MD5"

# ---- 5. 重启服务 ----
systemctl restart wloc-proxy
sleep 2
STATE=$(systemctl is-active wloc-proxy || true)
if [ "$STATE" != 'active' ]; then
    echo "❌ [5/6] 服务未起来（$STATE），立即回滚！"
    bash "$(dirname "$0")/rollback-celltower.sh" || \
        cp "$BAK_DIR/wloc_proxy.py.rollback" "$DST" && systemctl restart wloc-proxy
    exit 1
fi
echo "✅ [5/6] wloc-proxy 已重启，状态 active"

# ---- 6. 端口与日志验证 ----
sleep 2
echo "--- 端口检查 ---"
ss -lntp 2>/dev/null | grep -E '10\.10\.1\.1:(443|9999)' || {
    echo "⚠️  端口未监听，请检查"; }

echo "--- 日志尾部 ---"
tail -5 /var/log/wloc-proxy.log 2>/dev/null || true

echo
echo '=========================================='
echo ' 上线完成。回滚： sudo bash rollback-celltower.sh'
echo '=========================================='
