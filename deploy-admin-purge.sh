#!/bin/bash
# 部署「删除老管理面板」后的 app.py
# 用法：bash deploy_admin_purge.sh
set -e

NEW=/tmp/app.py.new
DST=/opt/wloc-web/app.py
EXPECT_MD5='b0133b433fec92ca0461aca6ede32dcc'

echo '=== 1. 校验待部署文件 ==='
ACTUAL=$(md5sum "$NEW" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECT_MD5" ]; then
    echo "❌ MD5 不匹配！期望 $EXPECT_MD5，实际 $ACTUAL"
    exit 1
fi
echo "✅ MD5 校验通过: $ACTUAL"

echo
echo '=== 2. 语法检查 ==='
python3 -c "import ast; ast.parse(open('$NEW', encoding='utf-8-sig').read())"
echo '✅ 语法检查通过'

echo
echo '=== 3. 备份当前版本 ==='
sudo mkdir -p /opt/wloc-backup/pre-admin-purge
sudo cp -a "$DST" /opt/wloc-backup/pre-admin-purge/app.py.before-purge
echo "✅ 已备份到 /opt/wloc-backup/pre-admin-purge/app.py.before-purge"

echo
echo '=== 4. 部署 ==='
sudo cp "$NEW" "$DST"
sudo chown wloc:wloc-web "$DST"
sudo chmod 644 "$DST"
echo "✅ 已写入 $DST"

echo
echo '=== 5. 重启服务 ==='
sudo systemctl restart wloc-web
sleep 2
systemctl is-active wloc-web

echo
echo '=== 6. 验证路由 ==='
for p in / /health; do
    printf '  %-24s -> ' "$p"
    curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 15.164.220.99' "http://127.0.0.1$p"
done
echo '  以下应全部 404：'
for p in /login /logout /admin /api/mobileconfig /api/status /api/location; do
    printf '  %-24s -> ' "$p"
    curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: 15.164.220.99' "http://127.0.0.1$p"
done

echo
echo '✅ 部署完成。回滚请执行: sudo /opt/wloc-web/rollback-admin-purge.sh'
