import os
import json
import uuid
import sqlite3
import secrets
import functools
import wloc_vpn
import wloc_users
from datetime import datetime, timezone
from flask import (Flask, request, Response, jsonify, send_from_directory)

def get_vpn_address():
    """VPN 服务器地址：可以是 IP，也可以是域名。

    用域名的好处：换服务器 IP 时只改 DNS 解析，用户无需重新安装描述文件。
    读取优先级：环境变量 > 配置文件 > 内置默认值。
    """
    for env_key in ('WLOC_VPN_ADDRESS', 'WLOC_PUBLIC_IP'):
        value = os.environ.get(env_key)
        if value and value.strip():
            return value.strip()
    for path in ('/etc/wloc-web/vpn-address', '/etc/wloc-web/public-ip'):
        try:
            with open(path, 'r') as fh:
                value = fh.read().strip()
                if value:
                    return value
        except Exception:
            pass
    return 'ios.819263.xyz'


# ==================== 部署相关可配置项 ====================
# 2026-10-02 新增：让同一份代码能同时部署在「境外机」与「国内机」，
# 靠环境变量区分。★ 所有默认值 = 首尔生产环境的原行为，不设变量时行为完全不变。
#
#   WLOC_TUNNEL_CIDR    主 IP 池（写进描述文件的 IncludedRoutes）
#   WLOC_TUNNEL_CIDR_2  第二个 IP 池（留空则不在描述文件里写这条路由）
#   WLOC_PROXY_ADDR     隧道内代理 / DNS 地址（设备连它，代理做 TLS 中间人）
#   WLOC_REMOTE_ID      IKEv2 服务端身份，必须与 strongSwan 的 leftid 一致
#   WLOC_CA_CERT        根证书路径（要内嵌进描述文件、并让设备完全信任）
TUNNEL_CIDR = os.environ.get('WLOC_TUNNEL_CIDR', '10.10.0.0/24')
TUNNEL_CIDR_2 = os.environ.get('WLOC_TUNNEL_CIDR_2', '10.10.4.0/22')
PROXY_ADDR = os.environ.get('WLOC_PROXY_ADDR', '10.10.0.1')
# 代理所在网段（写进 IncludedRoutes；留空则退化为 PROXY_ADDR/32 单主机路由）
PROXY_CIDR = os.environ.get('WLOC_PROXY_CIDR', '10.10.0.0/24')
# PAC 托管域名（同时也是代理 SupplementalMatchDomains 的一员，对齐 astrace）
PAC_HOST = os.environ.get('WLOC_PAC_HOST', 'apple.819263.xyz')
REMOTE_ID = os.environ.get('WLOC_REMOTE_ID', 'gs-loc.apple.com')
CA_CERT_PATH = os.environ.get('WLOC_CA_CERT',
                              '/etc/ipsec.d/cacerts/AppWLocRootCA.pem')


def _cidr_to_addr_mask(cidr):
    """'10.10.0.0/24' -> ('10.10.0.0', '255.255.255.0')；非法则返回 None"""
    if not cidr or not cidr.strip():
        return None
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        return str(net.network_address), str(net.netmask)
    except Exception as _e:
        print('[warn] WLOC_TUNNEL_CIDR 解析失败(%s): %s' % (cidr, _e))
        return None


def _build_included_routes():
    """按配置生成 IncludedRoutes 的 XML 片段

    顺序刻意与原版保持一致：主池 → 代理地址 → 第二池。
    （路由顺序对 iOS 无实际影响，但保持逐字节一致便于前后比对。）
    """
    t5 = '\t' * 5

    def _item(addr, mask):
        return (t5 + '<dict>\n'
                + t5 + '\t<key>Address</key>\n'
                + t5 + '\t<string>%s</string>\n' % addr
                + t5 + '\t<key>SubnetMask</key>\n'
                + t5 + '\t<string>%s</string>\n' % mask
                + t5 + '</dict>')

    # ★ 2026-10-09 对齐 astrace：IncludedRoutes **只保留一条** ——
    #   服务端隧道网段（PROXY_CIDR，即代理/网关所在的 10.10.0.0/24）。
    #   astrace 实测只有 1 条 10.10.0.0/24，其代理在 10.10.0.1，正好落在该网段内。
    #   原先额外写的 VPN 池网段属于多余（池内流量无需经隧道回环），已移除。
    items = []
    am_proxy = _cidr_to_addr_mask(PROXY_CIDR)
    if am_proxy:
        items.append(_item(am_proxy[0], am_proxy[1]))
    else:
        items.append(_item(PROXY_ADDR, '255.255.255.255'))

    # 每项自带缩进（5 个 tab），直接换行拼接即可；模板里 {_included_routes} 位于行首
    return '\n'.join(items)


app = Flask(__name__)


# ==================== 隧道内 API（2026-10-02）====================
# 敏感接口（设点、查状态、取地图 Key）只允许**从 VPN 隧道内**访问：
# 设备必须先连上 VPN 才能操作。这样「能连上隧道」本身就是身份证明，
# 而且这些接口在公网上根本不存在（扫描器扫不到）。
# 设计参考同类服务 astrace 的 VPN-gated API。
#
# 判定依据：来源 IP 属于 VPN 地址池。依赖 nginx 传的 X-Real-IP
# （隧道那份 nginx 配置里 proxy_set_header X-Real-IP $remote_addr 不能少，
#  否则后端看到 127.0.0.1，判定永远失败）。
VPN_POOL = os.environ.get('WLOC_VPN_POOL', '10.20.0.0/24')
TUNNEL_ORIGIN = os.environ.get('WLOC_TUNNEL_ORIGIN', 'https://10.10.1.1:8443')
CORS_ORIGINS = {o.strip() for o in
                os.environ.get('WLOC_CORS_ORIGINS', '').split(',') if o.strip()}

# ── 品牌信息（后台可改）──
# 配置 /etc/wloc-web/brand.json：
#   {"platformName":"coco","logoURL":"","announcement":"","lockNotice":""}
# 做成可配置是为了「多站点复用同一套代码」时不用改前端。
# 公告为空时前端不显示公告条。
BRAND_PATH = os.environ.get('WLOC_BRAND_CONFIG', '/etc/wloc-web/brand.json')
BRAND_DEFAULTS = {
    'platformName': 'coco',
    'logoURL': '',
    'announcement': '',
    'lockNotice': '',
}


def _load_brand():
    b = dict(BRAND_DEFAULTS)
    try:
        with open(BRAND_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for k in BRAND_DEFAULTS:
                v = data.get(k)
                if isinstance(v, str) and v.strip():
                    b[k] = v.strip()
    except Exception:
        pass
    return b


def _in_vpn_pool(ip):
    """来源 IP 是否属于 VPN 隧道地址池"""
    if not ip:
        return False
    try:
        import ipaddress
        return ipaddress.ip_address(ip.strip()) in ipaddress.ip_network(
            VPN_POOL, strict=False)
    except Exception:
        return False


def require_tunnel(view):
    """敏感接口装饰器：来源必须是隧道内地址，否则 403。"""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not _in_vpn_pool(_client_ip()):
            return jsonify({'ok': False,
                            'error': '该操作需要先连接 VPN，请连上后重试'}), 403
        return view(*args, **kwargs)
    return wrapper

# ==================== 用户体系 API（阶段 1）====================

# 启动时确保表结构存在
try:
    wloc_users.init_user_tables()
except Exception as _e:
    print('[warn] 用户表初始化失败: %s' % _e)


def _client_ip():
    """优先取 Cloudflare 传来的真实 IP。"""
    return (request.headers.get('CF-Connecting-IP')
            or request.headers.get('X-Real-IP')
            or request.remote_addr or '')


@app.after_request
def _add_cors_headers(resp):
    """隧道内接口的跨源支持。

    页面在公网 origin（如 https://117.72.208.23），而敏感接口在隧道 origin
    （https://10.10.1.1:8443）—— 属于跨源请求，必须回 CORS 头。

    OPTIONS 预检由 Flask 自动处理（自动 OPTIONS 不会走 view 函数，
    所以 require_user / require_tunnel 都不会拦它），这里只负责加头。
    """
    origin = request.headers.get('Origin', '')
    if origin and origin in CORS_ORIGINS:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        resp.headers['Access-Control-Max-Age'] = '86400'
        resp.headers['Vary'] = 'Origin'
    return resp


@app.route('/api/tunnel/ping', methods=['GET'])
@require_tunnel
def tunnel_ping():
    """隧道探针：前端用它判断「现在能不能走隧道」。

    这个接口只在隧道内可达（公网访问会 403），所以前端拿到 200
    就等于确认「设备已连 VPN 且隧道可用」。
    """
    return jsonify({'ok': True, 'tunnel': True, 'clientIp': _client_ip()})


@app.route('/api/public/content', methods=['GET'])
def public_content():
    """品牌信息（平台名 / Logo / 公告 / 锁定提示）—— 公网接口，无需登录。

    前端在登录页和控制台展示。做成可配置是为了「多站点复用同一套代码」，
    以及运营时能不发版就改公告。
    """
    return jsonify({'ok': True, 'content': _load_brand()})


def _bearer_token():
    """从 Authorization 头或 token 查询参数取令牌。"""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return (request.args.get('token') or '').strip()


def _current_user():
    """按 Bearer token 解析当前用户，失败返回 None。"""
    return wloc_users.resolve_token(_bearer_token())


def require_user(view):
    """用户级鉴权装饰器：未登录返回 401。"""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user:
            return jsonify({'ok': False, 'error': '未登录或授权已失效'}), 401
        request.wloc_user = user
        return view(*args, **kwargs)
    return wrapper


@app.route('/api/user/login', methods=['POST'])
def user_login():
    data = request.get_json(silent=True) or {}
    code = data.get('code') or data.get('authCode') or ''
    machine = data.get('machineCode') or ''
    ok, result = wloc_users.login(code, machine, client_ip=_client_ip())
    if not ok:
        return jsonify({'ok': False, 'error': result.get('error', '登录失败')}), 401
    return jsonify({'ok': True, 'token': result['token'], 'userId': result['user_id']})


@app.route('/api/user/me', methods=['GET'])
@require_user
def user_me():
    info = wloc_users.user_public_info(request.wloc_user)
    info['ok'] = True
    # 告诉前端「隧道内 API 的地址」—— 敏感接口（设点/状态/地图 Key）
    # 只能从这个 origin 访问，前端据此切换。
    info['tunnelOrigin'] = TUNNEL_ORIGIN
    info['onTunnel'] = _in_vpn_pool(_client_ip())
    return jsonify(info)


@app.route('/api/user/auth-status', methods=['GET'])
def user_auth_status():
    status = wloc_users.check_auth_status(_bearer_token())
    return jsonify({'ok': True, 'status': status})


@app.route('/api/user/logout', methods=['POST'])
@require_user
def user_logout():
    wloc_users.revoke_tokens(request.wloc_user['user_id'])
    return jsonify({'ok': True})


wloc_vpn.init_db()

def init_location_db(db_path='/opt/wloc-web/wloc.db'):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS device_locations (
            user_id INTEGER PRIMARY KEY,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            coordinate_system TEXT NOT NULL DEFAULT 'wgs84',
            updated_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_location_db()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "stage": "5E/6"})

def _build_mobileconfig(user_id):
    """生成 iOS 描述文件响应。user_id 的合法性由调用方负责校验。"""
    identity = wloc_vpn.get_or_create_identity(user_id)
    if identity['status'] != 'active':
        return jsonify({"error": f"Identity status '{identity['status']}' not active"}), 403

    try:
        with open('/opt/wloc-web/sync.marker', 'w') as f:
            f.write(f"sync {user_id}\n")
    except Exception:
        pass

    decrypted_password = wloc_vpn.decrypt_password(identity['password_ciphertext'])
    vpn_username = identity['vpn_username']
    profile_scope = identity['profile_scope']

    base_uuid = uuid.UUID(profile_scope)
    ca_uuid = str(uuid.uuid5(base_uuid, "ca")).lower()
    vpn_uuid = str(uuid.uuid5(base_uuid, "vpn")).lower()
    main_uuid = str(base_uuid).lower()

    ca_cert_path = CA_CERT_PATH
    ca_data = ""
    if os.path.exists(ca_cert_path):
        import base64
        with open(ca_cert_path, "rb") as f:
            raw = f.read()
        # 证书 payload 必须是 DER（Apple 惯例）：PEM 文本先剥掉头尾再解 base64
        if raw.lstrip().startswith(b'-----BEGIN'):
            body = b''.join(
                ln for ln in raw.splitlines()
                if ln.strip() and not ln.startswith(b'-----')
            )
            raw = base64.b64decode(body)
        if raw[:1] != b'\x30':
            raise RuntimeError('根证书不是有效的 DER 结构（应为 0x30 SEQUENCE）')
        ca_data = base64.b64encode(raw).decode("ascii")

    public_ip = get_vpn_address()
    # ── 代理模式（2026-10-09 对齐 astrace：改回 PAC）──
    #   'pac'    = PAC：设备连上后从 https://<PAC_HOST>/proxy.pac 取规则
    #   'manual' = 手动代理：代理地址直接写进描述文件（已废弃，保留作回滚）
    #   回滚：把下面这行改成 'manual' → 重启 wloc-web → 让设备重装描述文件
    # ★ 2026-10-09 对齐 astrace：改用 PSK（SharedSecret）认证
    #   PSK 直接复用用户密码，base64 后写进描述文件的 <data>
    psk_b64 = base64.b64encode(decrypted_password.encode('utf-8')).decode('ascii')
    _PROXY_MODE = 'pac'
    _t = '\t' * 4
    _included_routes = _build_included_routes()
    if _PROXY_MODE == 'manual':
        # ★ 2026-10-09：手动代理模式必须**显式关闭 PAC**（ProxyAutoConfigEnable=0），
        #   否则 iOS 会优先尝试 PAC，而 PAC 下载/解析失败会导致整个 Proxies 段被忽略。
        #   FallBackAllowed 只在 PAC 模式有意义，手动模式写它可能让 iOS 拒绝启用代理 → 移除。
        _proxies_mode_block = (
            _t + '<key>HTTPEnable</key>\n' + _t + '<integer>1</integer>\n'
            + _t + '<key>HTTPProxy</key>\n' + _t + '<string>%s</string>\n' % PROXY_ADDR
            + _t + '<key>HTTPPort</key>\n' + _t + '<integer>8888</integer>\n'
            + _t + '<key>HTTPSEnable</key>\n' + _t + '<integer>1</integer>\n'
            + _t + '<key>HTTPSProxy</key>\n' + _t + '<string>%s</string>\n' % PROXY_ADDR
            + _t + '<key>HTTPSPort</key>\n' + _t + '<integer>8888</integer>\n'
            + _t + '<key>ProxyAutoConfigEnable</key>\n' + _t + '<integer>0</integer>'
        )
    else:
        _proxies_mode_block = (
            _t + '<key>ProxyAutoConfigEnable</key>\n' + _t + '<integer>1</integer>\n'
            + _t + '<key>ProxyAutoConfigURLString</key>\n'
            + _t + '<string>http://%s/proxy.pac</string>\n' % PAC_HOST
            + _t + '<key>FallBackAllowed</key>\n' + _t + '<integer>0</integer>'
        )

    mobileconfig_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>WLocRootCA</string>
			<key>PayloadContent</key>
			<data>{ca_data}</data>
			<key>PayloadDisplayName</key>
			<string>coco</string>
			<key>PayloadIdentifier</key>
			<string>com.wloc.profile.ca.{profile_scope}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{ca_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>PayloadDisplayName</key>
			<string>coco</string>
			<key>PayloadIdentifier</key>
			<string>com.wloc.profile.vpn.{profile_scope}</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>{vpn_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>UserDefinedName</key>
			<string>coco</string>
			<key>VPNType</key>
			<string>IKEv2</string>
			<key>DNS</key>
			<dict>
				<key>SearchDomains</key>
				<array/>
				<key>SupplementalMatchDomains</key>
				<array>
					<string>gs-loc-cn.apple.com</string>
					<string>gs-loc.apple.com</string>
					<string>gs-loc-cn.ls-apple.com</string>
					<string>gs-loc.ls-apple.com</string>
					<string>{PAC_HOST}</string>
				</array>
				<key>SupplementalMatchDomainsNoSearch</key>
				<integer>0</integer>
			</dict>
			<key>IKEv2</key>
			<dict>
				<key>RemoteAddress</key>
				<string>{public_ip}</string>
				<key>RemoteIdentifier</key>
				<string>{REMOTE_ID}</string>
				<key>LocalIdentifier</key>
				<string>{vpn_username}</string>
				<key>AuthenticationMethod</key>
				<string>SharedSecret</string>
				<key>SharedSecret</key>
				<data>{psk_b64}</data>
				<key>OnDemandEnabled</key>
				<integer>0</integer>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>1</integer>
				<key>EnableFallback</key>
				<integer>0</integer>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
			</dict>
			<key>Proxies</key>
			<dict>
{_proxies_mode_block}
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>0</integer>
				<key>IncludedRoutes</key>
				<array>
{_included_routes}
				</array>
			</dict>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>coco</string>
	<key>PayloadIdentifier</key>
	<string>com.wloc.profile.main.{profile_scope}</string>
	<key>PayloadOrganization</key>
	<string>coco</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{main_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>TargetDeviceType</key>
	<integer>1</integer>
</dict>
</plist>'''

    resp = Response(mobileconfig_xml, mimetype='application/x-apple-aspen-config')
    resp.headers['Cache-Control'] = 'private, no-store, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

@app.route('/api/user/download', methods=['GET'])
def user_download():
    """用户端下载描述文件：token 走 query，便于 iOS Safari 直接导航下载"""
    user = _current_user()
    if not user:
        return jsonify({"ok": False, "error": "未登录或授权已失效"}), 401
    wloc_users.audit('download', user['user_id'], 'ip=%s' % _client_ip(),
                     _client_ip())
    return _build_mobileconfig(user['user_id'])


@app.route('/api/user/status', methods=['GET'])
@require_user
@require_tunnel
def user_status():
    """用户自己的状态：锁定坐标 + VPN 连接状态 + 授权信息"""
    user = request.wloc_user
    user_id = user['user_id']
    identity = wloc_vpn.get_or_create_identity(user_id)
    vpn_user = identity['vpn_username']

    conn = sqlite3.connect('/opt/wloc-web/wloc.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM vpn_active_sessions WHERE vpn_username = ?", (vpn_user,))
    session_row = cur.fetchone()
    cur.execute("SELECT * FROM device_locations WHERE user_id = ?", (user_id,))
    loc = cur.fetchone()
    conn.close()

    loc_dict = None
    if loc:
        loc_dict = {
            'latitude': loc['latitude'],
            'longitude': loc['longitude'],
            'coordinateSystem': loc['coordinate_system'],
            'updatedAt': loc['updated_at'],
        }

    return jsonify({
        'ok': True,
        'userId': user_id,
        'authCode': user['auth_code'],
        'validUntil': user['valid_until'],
        'connected': session_row is not None,
        'vpnIp': session_row['vpn_ip'] if session_row else None,
        'location': loc_dict,
    })


@app.route('/api/user/map-bootstrap', methods=['GET'])
@require_user
@require_tunnel
def user_map_bootstrap():
    """下发高德地图 Key + 当前锁定坐标。

    ★ 为什么要这个接口：高德 Key 和 securityJsCode 如果**写在前端 HTML 里**，
      任何人查看网页源码就能拿到并盗用配额。必须登录后由服务端下发。
      （这个设计参考同类服务 astrace 的 /api/user/map-bootstrap）
    """
    user_id = request.wloc_user['user_id']
    conn = sqlite3.connect('/opt/wloc-web/wloc.db')
    conn.row_factory = sqlite3.Row
    try:
        loc = conn.execute(
            "SELECT latitude, longitude FROM device_locations WHERE user_id = ?",
            (user_id,)).fetchone()
    finally:
        conn.close()

    target = None
    if loc:
        target = {'latitude': loc['latitude'], 'longitude': loc['longitude']}

    try:
        import wloc_amap
        k = wloc_amap.get_active()
    except Exception as exc:
        print('[warn] 高德配置读取失败: %s' % exc)
        k = None

    if not k:
        return jsonify({'ok': False,
                        'error': '地图服务暂未配置，请联系管理员'}), 503

    return jsonify({
        'ok': True,
        'amapKey': k['key'],
        'securityJsCode': k.get('securityJsCode', ''),
        'amapAccountId': k.get('accountId', ''),
        'target': target,
        'targetSaved': target is not None,
    })


@app.route('/api/user/map-key/failure', methods=['POST'])
@require_user
@require_tunnel
def user_map_key_failure():
    """前端上报高德 Key 失效（配额用尽 / Key 无效），服务端据此轮换到下一个账号。

    高德个人开发者「搜索类」配额只有 100 次/日，必须靠多账号轮换。
    """
    data = request.get_json(silent=True) or {}
    acc = (data.get('accountId') or '').strip()
    reason = (data.get('reason') or '')[:120]
    try:
        import wloc_amap
        switched, _ = wloc_amap.report_failure(account_id=acc, reason=reason)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)[:120]}), 500

    try:
        wloc_users.audit('map_key_failure', request.wloc_user['user_id'],
                         'acc=%s reason=%s' % (acc, reason), _client_ip())
    except Exception:
        pass
    return jsonify({'ok': True, 'switched': switched})


# ==================== 位置收藏 ====================
# 数据层在 wloc_users.py（list_favorites / add_favorite / delete_favorite），
# 这里只是薄薄的 HTTP 包装。敏感操作 → 走隧道（require_tunnel）。

@app.route('/api/user/favorites', methods=['GET'])
@require_user
@require_tunnel
def user_favorites_list():
    """列出当前用户的收藏位置"""
    favs = wloc_users.list_favorites(request.wloc_user['user_id'])
    return jsonify({'ok': True, 'favorites': favs})


@app.route('/api/user/favorites', methods=['POST'])
@require_user
@require_tunnel
def user_favorites_add():
    """收藏一个位置。body: {name, latitude, longitude}（WGS-84）"""
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get('latitude'))
        lng = float(data.get('longitude'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': '经纬度格式不正确'}), 400
    if not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
        return jsonify({'ok': False, 'error': '经纬度超出范围'}), 400

    name = (data.get('name') or '').strip()[:40] or '收藏位置'
    try:
        fid = wloc_users.add_favorite(request.wloc_user['user_id'], name, lat, lng)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)[:120]}), 500
    return jsonify({'ok': True, 'id': fid})


@app.route('/api/user/favorites/<int:fav_id>', methods=['DELETE'])
@require_user
@require_tunnel
def user_favorites_delete(fav_id):
    """删除一条收藏（只能删自己的 —— 数据层带 user_id 条件）"""
    ok = wloc_users.delete_favorite(request.wloc_user['user_id'], fav_id)
    if not ok:
        return jsonify({'ok': False, 'error': '收藏不存在'}), 404
    return jsonify({'ok': True})


@app.route('/api/user/target', methods=['POST'])
@require_user
@require_tunnel
def user_target():
    """保存锁定坐标"""
    data = request.get_json(silent=True) or {}
    lat = data.get('latitude')
    lng = data.get('longitude')
    acc = data.get('accuracy', 25)

    if lat is None or lng is None:
        return jsonify({'ok': False, 'error': '缺少经纬度'}), 400
    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': '经纬度格式不正确'}), 400
    if not (-90 <= lat <= 90):
        return jsonify({'ok': False, 'error': '纬度需在 -90 到 90 之间'}), 400
    if not (-180 <= lng <= 180):
        return jsonify({'ok': False, 'error': '经度需在 -180 到 180 之间'}), 400

    user_id = request.wloc_user['user_id']
    conn = sqlite3.connect('/opt/wloc-web/wloc.db')
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cur.execute("""
        INSERT INTO device_locations (user_id, latitude, longitude, coordinate_system, updated_at)
        VALUES (?, ?, ?, 'wgs84', ?)
        ON CONFLICT(user_id) DO UPDATE SET
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            coordinate_system = excluded.coordinate_system,
            updated_at = excluded.updated_at
    """, (user_id, lat, lng, now))
    conn.commit()
    conn.close()

    wloc_users.audit('lock', user_id, '%s,%s acc=%s' % (lat, lng, acc),
                     _client_ip())
    return jsonify({'ok': True, 'latitude': lat, 'longitude': lng,
                    'accuracy': acc})


@app.route('/api/user/target', methods=['DELETE'])
@require_user
@require_tunnel
def user_clear_target():
    """解除锁定，恢复真实定位"""
    user_id = request.wloc_user['user_id']
    conn = sqlite3.connect('/opt/wloc-web/wloc.db')
    cur = conn.cursor()
    cur.execute("DELETE FROM device_locations WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    wloc_users.audit('unlock', user_id, '', _client_ip())
    return jsonify({'ok': True})


@app.route('/')
def index():
    """用户界面：授权码登录 → 下载配置 → 地图选点"""
    resp = send_from_directory('/opt/wloc-web/static', 'index.html')
    # 前端迭代频繁，禁止浏览器缓存，保证每次都拿到最新版
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


if __name__ == '__main__':
    import sys as _sys
    if '--create-user' in _sys.argv:
        _idx = _sys.argv.index('--create-user')
        _name = _sys.argv[_idx + 1] if _idx + 1 < len(_sys.argv) else None
        _days = None
        if '--days' in _sys.argv:
            _days = int(_sys.argv[_sys.argv.index('--days') + 1])
        _u = wloc_users.create_user(display_name=_name, valid_days=_days)
        print('✅ 用户已创建')
        print('   授权码: %s' % _u['auth_code'])
        print('   user_id: %d' % _u['user_id'])
        print('   到期: %s' % (_u['valid_until'] or '永久有效'))
        _sys.exit(0)
    if '--list-users' in _sys.argv:
        _us = wloc_users.list_users()
        if not _us:
            print('(暂无用户)')
        for _u in _us:
            print('  #%-4d %-16s %-8s %s' % (
                _u['user_id'], _u['auth_code'], _u['status'],
                _u['valid_until'] or '永久'))
        _sys.exit(0)
    app.run(host='127.0.0.1', port=5000)
