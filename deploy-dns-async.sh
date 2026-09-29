#!/bin/bash
# WLoc DNS asyncio 版上线脚本（带 MD5 校验）
# 在服务器上执行： sudo /opt/wloc-web/deploy-dns-async.sh
set -e

SRC=/tmp/wloc_dns.py.async
DEST=/opt/wloc-web/wloc_dns.py
EXPECT=8445ab27b58e6ca21ab7665be5d21d5e

if [ ! -f "$SRC" ]; then
    echo "错误：找不到待部署文件 $SRC"
    exit 1
fi

GOT=$(md5sum "$SRC" | awk '{print $1}')
echo "源文件 MD5: $GOT"
if [ "$GOT" != "$EXPECT" ]; then
    echo "错误：MD5 不匹配（期望 $EXPECT）"
    exit 1
fi

# 再次确认原件已保存
if [ ! -f /opt/wloc-web/wloc_dns.py.sync-orig ]; then
    echo "错误：缺少回滚用原件 wloc_dns.py.sync-orig"
    exit 1
fi

# 就地备份当前生产文件（若它已是 asyncio 版，说明是重复部署）
CUR=$(md5sum "$DEST" | awk '{print $1}')
echo "当前生产文件 MD5: $CUR"
cp -a "$DEST" "$DEST.prev-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

# 部署
cp -a "$SRC" "$DEST"
chown wloc:wloc-web "$DEST"
chmod 644 "$DEST"
sed -i 's/\r$//' "$DEST"

# 语法检查（用服务同一解释器）
/opt/wloc-web/venv/bin/python -m py_compile "$DEST"
echo "语法检查通过"

systemctl restart wloc-dns
sleep 2
systemctl is-active wloc-dns
echo "已上线： $DEST"
md5sum "$DEST"
systemctl status wloc-dns --no-pager | head -6
