#!/bin/bash
# ============================================================
# WLoc 部署到国内 PoC 服务器（117.72.208.23 / 京东云）
#
# 前置：代码已上传到 /tmp/wloc-src/，且同目录下有 units/ 和 env-cn、nginx-wloc.conf
# 用法： sudo bash deploy.sh
# ============================================================
set -uo pipefail

SRC=/tmp/wloc-src
WEB=/opt/wloc-web
CONF=/etc/wloc-web
BAK=/opt/wloc-backup
TS=$(date +%Y%m%d-%H%M%S)
CA_CERT=/etc/ipsec.d/cacerts/wloc-cn-poc-ca-cert.pem
CA_KEY=/etc/ipsec.d/private/wloc-cn-poc-ca-key.pem
SECRETS_FILE=/etc/ipsec.d/wloc-users.secrets
PIP_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple

step() { echo; echo "========== $* =========="; }
die()  { echo "❌ $*"; exit 1; }

step "0. 备份当前状态（回滚基线）"
mkdir -p "$BAK/pre-cn-migration"
tar czf "$BAK/pre-cn-migration/ipsec-and-system-$TS.tar.gz" \
    /etc/ipsec.conf /etc/ipsec.secrets /etc/ipsec.d \
    /etc/systemd/system/x-ui.service 2>/dev/null
echo "已备份 -> $BAK/pre-cn-migration/ipsec-and-system-$TS.tar.gz"
ipsec statusall > "$BAK/pre-cn-migration/ipsec-statusall-$TS.txt" 2>&1
ss -tulnp > "$BAK/pre-cn-migration/listen-ports-$TS.txt" 2>&1
dpkg -l > "$BAK/pre-cn-migration/dpkg-list-$TS.txt" 2>&1
echo "已记录：ipsec 状态 / 端口 / 软件清单"

step "1. 安装依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx python3-venv python3-pip openssl || die "apt 安装失败"
echo "nginx: $(nginx -v 2>&1)"

step "2. 建立 wloc 系统用户"
if id wloc >/dev/null 2>&1; then
    echo "用户 wloc 已存在"
else
    useradd --system --shell /usr/sbin/nologin --home-dir "$WEB" wloc
    echo "已创建用户 wloc"
fi

step "3. 部署代码到 $WEB"
mkdir -p "$WEB" "$CONF"
cp -f "$SRC"/app.py "$SRC"/wloc_proxy.py "$SRC"/wloc_dns.py \
      "$SRC"/wloc_users.py "$SRC"/wloc_vpn.py "$SRC"/wloc_keygen.py "$WEB/"
cp -f "$SRC"/vpn_sync.py "$WEB/"
mkdir -p "$WEB/static"
cp -f "$SRC"/static/index.html "$WEB/static/"
[ -f "$SRC/生产部署文档.md" ] && cp -f "$SRC/生产部署文档.md" "$WEB/"
echo "已部署文件："
ls -1 "$WEB" | sed 's/^/    /'

step "4. 建 venv 并装 Python 依赖"
if [ ! -x "$WEB/venv/bin/python3" ]; then
    python3 -m venv "$WEB/venv" || die "venv 创建失败"
fi
"$WEB/venv/bin/pip" install -q --upgrade pip -i "$PIP_MIRROR" 2>&1 | tail -2
"$WEB/venv/bin/pip" install -q flask gunicorn cryptography requests -i "$PIP_MIRROR" || die "pip 安装失败"
echo "已装："
"$WEB/venv/bin/pip" list 2>/dev/null | grep -iE "flask|gunicorn|cryptography|requests" | sed 's/^/    /'

step "5. 生成代理的 TLS 中间人证书（由 PoC CA 签发）"
[ -f "$CA_CERT" ] || die "找不到 PoC CA 证书：$CA_CERT"
[ -f "$CA_KEY" ]  || die "找不到 PoC CA 私钥：$CA_KEY"
openssl req -newkey rsa:2048 -nodes -keyout /tmp/proxy.key -out /tmp/proxy.csr \
    -subj "/CN=gs-loc.apple.com" 2>/dev/null || die "生成 CSR 失败"
cat > /tmp/proxy.ext <<'EXTEOF'
subjectAltName=DNS:gs-loc.apple.com,DNS:gs-loc-cn.apple.com,DNS:gs-loc.ls-apple.com,DNS:gs-loc-cn.ls-apple.com
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXTEOF
openssl x509 -req -in /tmp/proxy.csr -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$WEB/AppWLocProxy.pem" -days 825 -extfile /tmp/proxy.ext 2>/dev/null \
    || die "签发代理证书失败"
cp -f /tmp/proxy.key "$WEB/AppWLocProxy.key"
install -m 644 "$WEB/AppWLocProxy.pem" /etc/ipsec.d/certs/AppWLocProxy.pem
install -m 600 "$WEB/AppWLocProxy.key" /etc/ipsec.d/private/AppWLocProxy.key
rm -f /tmp/proxy.key /tmp/proxy.csr /tmp/proxy.ext
echo "证书已签发："
openssl x509 -in /etc/ipsec.d/certs/AppWLocProxy.pem -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null | sed 's/^/    /'

step "6. 安装环境变量与服务单元"
# ★★ 环境变量文件【只在新装时写入】，已存在就保留不覆盖。
#   它属于「部署状态」而不是「代码」—— 上线后手工调过的东西
#   （比如把 WLOC_REMOTE_ID 从 IP 改成域名）不能被模板冲掉。
#   2026-10-02 实际踩过：用过期模板覆盖 → 描述文件 RemoteIdentifier 变回 IP
#   → 与 ipsec.conf 的 leftid 不匹配 → 手机连 VPN 秒断
#   （日志特征：`no matching peer config found` + `N(AUTH_FAILED)`）
if [ -f "$CONF/env" ]; then
    echo "⚠️  $CONF/env 已存在 → 保留不覆盖"
    echo "    如需更新请手工编辑（模板参考 $SRC/env-cn）"
    echo "    当前关键项："
    grep -E "WLOC_REMOTE_ID|WLOC_VPN_ADDRESS" "$CONF/env" | sed 's/^/      /'
else
    install -m 600 "$SRC/env-cn" "$CONF/env"
    echo "已写入初始 $CONF/env"
fi

install -m 644 "$SRC/units/"*.service /etc/systemd/system/
install -m 644 "$SRC/units/"*.timer   /etc/systemd/system/
install -m 644 "$SRC/nginx-wloc.conf" /etc/nginx/sites-available/wloc
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/wloc /etc/nginx/sites-enabled/wloc
echo "nginx 站点："
ls -l /etc/nginx/sites-enabled/ | sed 's/^/    /'

step "7. 目录权限与凭据密钥"
# ★ 预生成 Fernet 密钥：面板（wloc 用户）与 vpn_sync（root）必须用同一把，
#   否则面板加密的密码、同步脚本解不开。
#   （wloc_vpn.get_fernet() 在文件不存在时会自己生成，但面板进程受
#     ProtectSystem=full 限制写不了 /etc，所以必须在这里先建好。）
if [ ! -f "$CONF/vpn-identity.env" ]; then
    KEY=$("$WEB/venv/bin/python3" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
    printf 'WLOC_VPN_CREDENTIAL_KEY=%s\n' "$KEY" > "$CONF/vpn-identity.env"
    echo "已生成凭据密钥 -> $CONF/vpn-identity.env"
else
    echo "凭据密钥已存在，保留不覆盖"
fi
chmod 640 "$CONF/vpn-identity.env"
chown root:wloc "$CONF/vpn-identity.env"

chown -R wloc:wloc "$WEB"
chown root:root "$WEB/vpn_sync.py" 2>/dev/null || true
# 代理和 DNS 以 root 跑，需要读私钥；面板以 wloc 跑，需要写数据库
chmod 640 "$WEB/wloc.db" 2>/dev/null || true
touch /var/log/wloc-proxy.log /var/log/wloc-dns.log /var/log/wloc-vpn-sync.log
chmod 644 /var/log/wloc-*.log
echo "完成"

step "8. 校验配置"
nginx -t || die "nginx 配置校验失败"
systemctl daemon-reload

# ★ 检查 ipsec.conf 的 leftsubnet：少了它隧道能建但 0 字节流量，定位完全不生效
if ! grep -qE "^\s*leftsubnet=" /etc/ipsec.conf; then
    echo "⚠️  /etc/ipsec.conf 缺少 leftsubnet —— 隧道会建立但一个字节都不走！"
    echo "    正在自动补上 leftsubnet=10.10.1.1/32 ..."
    cp -a /etc/ipsec.conf "/etc/ipsec.conf.bak-$(date +%Y%m%d-%H%M%S)"
    sed -i 's|^\(\s*\)rightauth=eap-mschapv2|\1rightauth=eap-mschapv2\n    leftsubnet=10.10.1.1/32|' /etc/ipsec.conf
    echo "    已补上（稍后会重启 strongSwan 生效）"
else
    echo "leftsubnet 已配置："
    grep -E "^\s*leftsubnet=" /etc/ipsec.conf | sed 's/^/    /'
fi

# ★ 检查 ipsec.secrets 有没有 include 我们生成的账号文件
if ! grep -qF "$SECRETS_FILE" /etc/ipsec.secrets 2>/dev/null; then
    echo "⚠️  /etc/ipsec.secrets 未 include $SECRETS_FILE —— 账号加载不进去！"
    echo "    正在自动补上 ..."
    cp -a /etc/ipsec.secrets "/etc/ipsec.secrets.bak-$(date +%Y%m%d-%H%M%S)"
    printf '\n# --- WLoc 用户账号（由 wloc-vpn-sync 自动生成，勿手工编辑）---\ninclude %s\n' "$SECRETS_FILE" >> /etc/ipsec.secrets
    echo "    已补上"
else
    echo "ipsec.secrets 已 include 账号文件"
fi

echo "systemd / nginx / ipsec 配置校验通过"

step "9. 启动服务"
systemctl enable --now wloc-loopback-ip.service
systemctl enable --now wloc-proxy.service
systemctl enable --now wloc-dns.service
systemctl enable --now wloc-web.service
systemctl enable --now nginx
systemctl enable --now wloc-vpn-sync.timer
# ★ 必须显式 reload：apt 装 nginx 时它已带着默认站点启动了，
#   之后只写配置不 reload 的话，nginx 内存里还是旧配置（会继续服务默认页）。
systemctl reload nginx
sleep 4

echo
echo "========== 启动结果 =========="
for s in wloc-loopback-ip wloc-proxy wloc-dns wloc-web nginx wloc-vpn-sync.timer strongswan-starter; do
    printf "  %-24s %s / %s\n" "$s" "$(systemctl is-active $s)" "$(systemctl is-enabled $s 2>/dev/null)"
done
echo
echo "========== 监听端口 =========="
ss -tulnp | grep -E ":(80|443|5000|9999|53|500|4500)\s" || echo "（无）"
echo
echo "========== lo 地址 =========="
ip -4 addr show lo | grep inet
echo
echo "========== 首次账户同步 =========="
"$WEB/venv/bin/python3" "$WEB/vpn_sync.py" 2>&1 | sed 's/^/  /'
echo
echo "部署完成。日志：/var/log/wloc-proxy.log /var/log/wloc-dns.log /var/log/wloc-vpn-sync.log"
