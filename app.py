import os
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
    return '47.129.138.117'


app = Flask(__name__)

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

    ca_cert_path = "/etc/ipsec.d/cacerts/AppWLocRootCA.pem"
    ca_data = ""
    if os.path.exists(ca_cert_path):
        import base64
        with open(ca_cert_path, "rb") as f:
            ca_data = base64.b64encode(f.read()).decode("ascii")

    public_ip = get_vpn_address()
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
				<key>ServerAddresses</key>
				<array>
					<string>10.10.1.1</string>
				</array>
				<key>SearchDomains</key>
				<array/>
				<key>SupplementalMatchDomains</key>
				<array>
					<string>gs-loc-cn.apple.com</string>
					<string>gs-loc.apple.com</string>
					<string>gs-loc-cn.ls-apple.com</string>
					<string>gs-loc.ls-apple.com</string>
				</array>
				<key>SupplementalMatchDomainsNoSearch</key>
				<integer>0</integer>
			</dict>
			<key>IKEv2</key>
			<dict>
				<key>RemoteAddress</key>
				<string>{public_ip}</string>
				<key>RemoteIdentifier</key>
				<string>gs-loc.apple.com</string>
				<key>LocalIdentifier</key>
				<string>{vpn_username}</string>
				<key>AuthenticationMethod</key>
				<string>None</string>
				<key>ExtendedAuthEnabled</key>
				<integer>1</integer>
				<key>AuthName</key>
				<string>{vpn_username}</string>
				<key>AuthPassword</key>
				<string>{decrypted_password}</string>
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
				<key>ProxyAutoConfigEnable</key>
				<integer>1</integer>
				<key>ProxyAutoConfigURLString</key>
				<string>http://10.10.1.1:8888/network/route.pac</string>
				<key>SupplementalMatchDomains</key>
				<array>
					<string>gs-loc.apple.com</string>
					<string>gs-loc-cn.apple.com</string>
					<string>gs-loc.ls-apple.com</string>
					<string>gs-loc-cn.ls-apple.com</string>
				</array>
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>0</integer>
				<key>IncludedRoutes</key>
				<array>
					<dict>
						<key>Address</key>
						<string>10.10.0.0</string>
						<key>SubnetMask</key>
						<string>255.255.255.0</string>
					</dict>
					<dict>
						<key>Address</key>
						<string>10.10.1.1</string>
						<key>SubnetMask</key>
						<string>255.255.255.255</string>
					</dict>
					<dict>
						<key>Address</key>
						<string>10.10.4.0</string>
						<key>SubnetMask</key>
						<string>255.255.252.0</string>
					</dict>
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


@app.route('/api/user/target', methods=['POST'])
@require_user
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
