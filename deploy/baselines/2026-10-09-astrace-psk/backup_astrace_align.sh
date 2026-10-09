#!/bin/bash
# ============================================================
# WLoc「astrace 完全对齐 + 双端 PSK」版本 基线备份
# 覆盖：ipsec 双端 PSK / app.py PAC http / tunnel 证书新 SAN
#       nginx 隧道内 :80 / 探针脚本动态目标 / 全量 systemd / PAC
# 在服务器上以 root 执行
# ============================================================
set -e

TS=$(date +%Y%m%d-%H%M%S)
TAG="astrace-psk-20261009"
STAGE=/tmp/wloc-baseline/staging
OUT=/tmp/wloc-baseline/wloc-baseline-$TAG-$TS.tar.gz

rm -rf /tmp/wloc-baseline
mkdir -p "$STAGE"
cd "$STAGE"
mkdir -p opt-wloc-web etc-ipsec etc-nginx systemd sbin etc-wloc-web var-www

echo "== 1/8 应用代码 /opt/wloc-web（排除 venv/pycache/db 的 wal）=="
rsync -a --exclude 'venv' --exclude '__pycache__' --exclude '.gunicorn' \
      --exclude '*.pyc' --exclude '*.log' \
      /opt/wloc-web/ opt-wloc-web/

echo "== 2/8 ipsec 配置与会话密钥（敏感）=="
cp -a /etc/ipsec.conf            etc-ipsec/ 2>/dev/null || true
cp -a /etc/ipsec.secrets         etc-ipsec/ 2>/dev/null || true
rsync -a /etc/ipsec.d/           etc-ipsec/ipsec.d/

echo "== 3/8 nginx 站点 + 全部证书（含 tunnel 新 SAN，敏感）=="
rsync -a /etc/nginx/sites-available/ etc-nginx/sites-available/ 2>/dev/null || true
rsync -a /etc/nginx/sites-enabled/   etc-nginx/sites-enabled/   2>/dev/null || true
cp -a /etc/nginx/nginx.conf      etc-nginx/ 2>/dev/null || true
rsync -a /etc/nginx/ssl/         etc-nginx/ssl/

echo "== 4/8 systemd 单元（全量 wloc-* + strongswan + nginx）=="
cp -a /etc/systemd/system/wloc-* systemd/ 2>/dev/null || true
cp -a /etc/systemd/system/strongswan-starter.service systemd/ 2>/dev/null || true
cp -a /etc/systemd/system/nginx.service systemd/ 2>/dev/null || true

echo "== 5/8 探针脚本（动态目标版）=="
cp -a /usr/local/bin/wloc-external-probe.py  sbin/ 2>/dev/null || true
cp -a /usr/local/bin/wloc-ikev2-probe.sh     sbin/ 2>/dev/null || true
cp -a /usr/local/bin/wloc-*.bak-orig         sbin/ 2>/dev/null || true

echo "== 6/8 运行时配置 /etc/wloc-web（含密钥，敏感）=="
rsync -a /etc/wloc-web/ etc-wloc-web/

echo "== 7/8 PAC 托管文件 =="
rsync -a /var/www/wloc-pac/ var-www/wloc-pac/ 2>/dev/null || true

echo "== 8/8 SQLite 数据库一致性快照 =="
mkdir -p etc-wloc-web/db
if [ -f /opt/wloc-web/wloc.db ]; then
  sqlite3 /opt/wloc-web/wloc.db ".backup '/$STAGE/etc-wloc-web/db/wloc.db'" 2>/dev/null \
    || cp -a /opt/wloc-web/wloc.db etc-wloc-web/db/
  sqlite3 /opt/wloc-web/wloc.db "PRAGMA integrity_check;" > etc-wloc-web/db/integrity.txt 2>/dev/null || true
fi

echo "== 生成清单与校验 =="
cd "$STAGE"
find . -type f ! -name 'MANIFEST*' -exec md5sum {} \; | sort -k2 > MANIFEST.md5
{
  echo "WLoc 基线备份（astrace 完全对齐 + 双端 PSK）"
  echo "生成时间: $(date -Is)"
  echo "主机: $(hostname)  公网IP: 18.179.53.219"
  echo "--- 关键文件 MD5 ---"
  md5sum /etc/ipsec.conf /opt/wloc-web/app.py /opt/wloc-web/wloc_proxy.py \
         /opt/wloc-web/wloc_dns.py /opt/wloc-web/vpn_sync.py \
         /etc/nginx/sites-available/wloc /etc/nginx/ssl/tunnel.pem \
         /usr/local/bin/wloc-external-probe.py /usr/local/bin/wloc-ikev2-probe.sh \
         /var/www/wloc-pac/proxy.pac 2>/dev/null
  echo "--- 版本 ---"
  ipsec version 2>/dev/null | head -1
  nginx -v 2>&1 | head -1
  lsb_release -ds 2>/dev/null
  echo "--- systemd 各 unit 状态 ---"
  systemctl is-active wloc-loopback-ip wloc-dns wloc-proxy wloc-web \
    strongswan-starter nginx wloc-vpn-sync.timer \
    wloc-ikev2-probe.timer wloc-external-probe.timer 2>/dev/null | tr '\n' ' '
  echo
} > BACKUP-INFO.txt

echo "== 打包 =="
cd /tmp/wloc-baseline
tar czf "$OUT" -C staging .
chmod 600 "$OUT"
chown ubuntu:ubuntu "$OUT"
ls -lh "$OUT"
echo "BACKUP_PATH=$OUT"
sha256sum "$OUT" | tee "$OUT.sha256"
chown ubuntu:ubuntu "$OUT.sha256"
