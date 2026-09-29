#!/bin/bash
# 秒级回滚：恢复清理前的 app.py（含 /admin /login 老面板）
set -e
SRC=/opt/wloc-backup/pre-admin-purge/app.py.before-purge
DST=/opt/wloc-web/app.py
echo "回滚前: $(md5sum $DST)"
sudo cp -a $SRC $DST
echo "回滚后: $(md5sum $DST)"
sudo systemctl restart wloc-web
sleep 1
systemctl is-active wloc-web && echo '✅ wloc-web 已恢复'
