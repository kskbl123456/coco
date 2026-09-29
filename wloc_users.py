#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WLoc 用户体系模块

设计要点（参考同类服务 astrace）：
  - 授权码登录，一码一设备（绑定机器码）
  - 签发 Bearer Token，可单独撤销（支持服务端踢人）
  - 授权可设到期时间，也可永久
  - 全操作写审计日志

表结构：
  users        用户（授权码、状态、到期、绑定设备）
  api_tokens   访问令牌
  audit_log    审计日志
  favorites    位置收藏
"""

import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta

DB_PATH = '/opt/wloc-web/wloc.db'

# 授权码字符集：去掉易混淆的 0/O/1/I/L
CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
CODE_LENGTH = 12          # 4-4-4 分组
TOKEN_TTL_DAYS = 90       # Token 自身有效期（授权到期另行判断）


# ==================== 工具 ====================

def _now():
    return datetime.now(timezone.utc).isoformat()


def _conn(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10)

    # PRAGMA_FOR_WAL：WAL 模式下 synchronous=NORMAL 是标准搭配，
    # 既保证崩溃安全（不会损坏库），又避免每次提交都 fsync。
    try:
        conn.execute('PRAGMA busy_timeout=10000')
        conn.execute('PRAGMA synchronous=NORMAL')
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    return conn


def _parse_dt(value):
    """把 ISO 字符串解析成带时区的 datetime；解析失败返回 None。"""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def is_expired(valid_until):
    """valid_until 为空表示永久有效。"""
    dt = _parse_dt(valid_until)
    if dt is None:
        return False
    return datetime.now(timezone.utc) > dt


# ==================== 建表 ====================

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_code    TEXT UNIQUE NOT NULL,
    display_name TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    valid_until  TEXT,
    machine_code TEXT,
    note         TEXT,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    license_id   TEXT
);

CREATE TABLE IF NOT EXISTS api_tokens (
    token        TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    expires_at   TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    user_id   INTEGER,
    action    TEXT NOT NULL,
    detail    TEXT,
    client_ip TEXT
);

CREATE TABLE IF NOT EXISTS favorites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    name       TEXT NOT NULL,
    latitude   REAL NOT NULL,
    longitude  REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_user   ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_favorites_uid ON favorites(user_id);
"""


def init_user_tables(db_path=None):
    with _conn(db_path) as conn:
        conn.executescript(SCHEMA)
        # 兼容旧库：补 license_id 列（必须在建索引之前）
        cols = [r[1] for r in conn.execute('PRAGMA table_info(users)').fetchall()]
        if 'license_id' not in cols:
            conn.execute('ALTER TABLE users ADD COLUMN license_id TEXT')
        # 列就位后再建索引
        conn.execute('CREATE INDEX IF NOT EXISTS idx_users_license '
                     'ON users(license_id)')
    return True


# ==================== 授权码 ====================

def generate_auth_code():
    """生成形如 K7M2-P9X4-TW3N 的授权码。"""
    raw = ''.join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return '%s-%s-%s' % (raw[0:4], raw[4:8], raw[8:12])


def normalize_code(code):
    """去掉空格、横线，统一大写。"""
    return ''.join(ch for ch in str(code or '').upper() if ch.isalnum())


# ==================== 审计 ====================

def audit(action, user_id=None, detail=None, client_ip=None, db_path=None):
    try:
        with _conn(db_path) as conn:
            conn.execute(
                'INSERT INTO audit_log (ts, user_id, action, detail, client_ip) '
                'VALUES (?,?,?,?,?)',
                (_now(), user_id, action, detail, client_ip))
    except Exception:
        pass


# ==================== 用户管理 ====================

def create_user(display_name=None, valid_days=None, note=None, db_path=None):
    """新建用户。valid_days=None 表示永久有效。返回用户 dict。"""
    valid_until = None
    if valid_days:
        valid_until = (datetime.now(timezone.utc)
                       + timedelta(days=int(valid_days))).isoformat()

    for _ in range(10):                     # 防授权码碰撞
        code = generate_auth_code()
        try:
            with _conn(db_path) as conn:
                cur = conn.execute(
                    'INSERT INTO users (auth_code, display_name, status, valid_until, '
                    'note, created_at) VALUES (?,?,?,?,?,?)',
                    (code, display_name, 'active', valid_until, note, _now()))
                user_id = cur.lastrowid
            audit('user_create', user_id, 'code=%s valid_until=%s' % (code, valid_until),
                  db_path=db_path)
            return get_user(user_id, db_path)
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError('授权码生成失败（多次碰撞）')


def get_user(user_id, db_path=None):
    with _conn(db_path) as conn:
        row = conn.execute('SELECT * FROM users WHERE user_id=?', (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_code(code, db_path=None):
    norm = normalize_code(code)
    if not norm:
        return None
    with _conn(db_path) as conn:
        rows = conn.execute('SELECT * FROM users').fetchall()
    for row in rows:
        if normalize_code(row['auth_code']) == norm:
            return dict(row)
    return None


def get_user_by_license(license_id, db_path=None):
    """按 Keygen 的 license_id 查本地映射记录。"""
    if not license_id:
        return None
    with _conn(db_path) as conn:
        row = conn.execute('SELECT * FROM users WHERE license_id=? LIMIT 1',
                           (license_id,)).fetchone()
    return dict(row) if row else None


def list_users(db_path=None):
    with _conn(db_path) as conn:
        rows = conn.execute('SELECT * FROM users ORDER BY user_id DESC').fetchall()
    return [dict(r) for r in rows]


def update_user(user_id, db_path=None, **fields):
    allowed = {'display_name', 'status', 'valid_until', 'machine_code', 'note'}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append('%s=?' % k)
            vals.append(v)
    if not sets:
        return False
    vals.append(user_id)
    with _conn(db_path) as conn:
        conn.execute('UPDATE users SET %s WHERE user_id=?' % ','.join(sets), vals)
    return True


def delete_user(user_id, db_path=None):
    with _conn(db_path) as conn:
        conn.execute('DELETE FROM api_tokens WHERE user_id=?', (user_id,))
        conn.execute('DELETE FROM favorites WHERE user_id=?', (user_id,))
        conn.execute('DELETE FROM users WHERE user_id=?', (user_id,))
    audit('user_delete', user_id, db_path=db_path)
    return True


# ==================== 登录 ====================

def _issue_token(user_id, db_path=None):
    """为用户签发一个 WLoc 会话 token。"""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc)
                  + timedelta(days=TOKEN_TTL_DAYS)).isoformat()
    with _conn(db_path) as conn:
        conn.execute(
            'INSERT INTO api_tokens (token, user_id, created_at, expires_at) '
            'VALUES (?,?,?,?)', (token, user_id, _now(), expires_at))
        conn.execute('UPDATE users SET last_seen_at=? WHERE user_id=?',
                     (_now(), user_id))
    return token


def _login_via_keygen(code, machine_code, client_ip=None, db_path=None):
    """走 Keygen 校验（与安卓软件统一授权）。"""
    import wloc_keygen

    ok, res = wloc_keygen.validate_or_activate(
        code, machine_code, machine_name='WLoc Web')

    if not ok:
        audit('login_fail', None,
              'keygen=%s %s' % (res.get('code'), (res.get('message') or '')[:80]),
              client_ip, db_path)
        return False, {
            'error': res.get('message') or '授权失败',
            'code': res.get('code'),
        }

    license_id = res.get('license_id')
    expiry = res.get('expiry')

    user = get_user_by_license(license_id, db_path)
    if user:
        # 已存在映射 → 同步最新状态
        update_user(user['user_id'], db_path,
                    auth_code=code,
                    machine_code=machine_code,
                    valid_until=expiry)
        user = get_user(user['user_id'], db_path)
    else:
        # 首次登录 → 建立映射记录
        try:
            with _conn(db_path) as conn:
                cur = conn.execute(
                    'INSERT INTO users (auth_code, display_name, status, '
                    'valid_until, machine_code, note, created_at, license_id) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (code, None, 'active', expiry, machine_code,
                     'keygen', _now(), license_id))
                user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            # auth_code 已存在（可能是旧记录）→ 直接更新它
            user = get_user_by_code(code, db_path)
            if not user:
                return False, {'error': '本地记录冲突，请联系管理员'}
            update_user(user['user_id'], db_path,
                        license_id=license_id, machine_code=machine_code,
                        valid_until=expiry)
            user = get_user(user['user_id'], db_path)
        else:
            user = get_user(user_id, db_path)
        audit('user_create', user['user_id'],
              'license=%s source=keygen' % license_id, client_ip, db_path)

    # 本地状态检查（管理员可在本地停用）
    if user['status'] != 'active':
        audit('login_fail', user['user_id'], 'local_status=%s' % user['status'],
              client_ip, db_path)
        return False, {'error': '该授权已被停用'}

    token = _issue_token(user['user_id'], db_path)
    audit('login_ok', user['user_id'],
          'source=keygen activated=%s ip=%s' % (res.get('activated'), client_ip),
          client_ip, db_path)
    return True, {'token': token, 'user_id': user['user_id'],
                  'license_id': license_id, 'expiry': expiry,
                  'activated': bool(res.get('activated'))}


def _login_local(code, machine_code, client_ip=None, db_path=None):
    """回退方案：仅用本地记录校验（Keygen 不可用时）。"""
    user = get_user_by_code(code, db_path)
    if not user:
        audit('login_fail', None, 'code_not_found(local) ip=%s' % client_ip,
              client_ip, db_path)
        return False, {'error': '授权码不存在'}

    if user['status'] != 'active':
        audit('login_fail', user['user_id'], 'status=%s' % user['status'],
              client_ip, db_path)
        return False, {'error': '该授权已被停用'}

    if is_expired(user['valid_until']):
        audit('login_fail', user['user_id'], 'expired(local)', client_ip, db_path)
        return False, {'error': '授权已过期'}

    bound = (user['machine_code'] or '').strip()
    if not bound:
        update_user(user['user_id'], db_path, machine_code=machine_code)
        audit('device_bind', user['user_id'], 'machine=%s' % machine_code[:16],
              client_ip, db_path)
    elif bound != machine_code:
        audit('login_fail', user['user_id'], 'device_mismatch(local)',
              client_ip, db_path)
        return False, {'error': '该授权码已绑定其他设备，请联系管理员解绑'}

    token = _issue_token(user['user_id'], db_path)
    audit('login_ok', user['user_id'], 'source=local ip=%s' % client_ip,
          client_ip, db_path)
    return True, {'token': token, 'user_id': user['user_id']}


def login(code, machine_code, client_ip=None, db_path=None, allow_local_fallback=True):
    """
    授权码登录。

    优先走 Keygen（与安卓软件统一授权）；Keygen 未配置或不可用时，
    回退到本地记录校验（保证 Keygen 宕机时服务不中断）。

    返回 (ok: bool, data: dict)；成功含 token / user_id，失败含 error
    """
    norm = normalize_code(code)
    if not norm:
        return False, {'error': '请输入授权码'}

    mc = (machine_code or '').strip()
    if not mc:
        return False, {'error': '缺少设备标识，请更换浏览器后重试'}

    try:
        import wloc_keygen
        configured = wloc_keygen.is_configured()
    except Exception:
        configured = False

    if configured:
        try:
            return _login_via_keygen(code, mc, client_ip, db_path)
        except Exception as exc:
            audit('keygen_error', None, str(exc)[:200], client_ip, db_path)
            if not allow_local_fallback:
                return False, {'error': '授权服务暂时不可用，请稍后重试'}

    return _login_local(code, mc, client_ip, db_path)


def revalidate_user(user_id, db_path=None):
    """
    重新校验某个用户的卡密（供后台定时任务用）。
    返回 (state, detail)
    """
    user = get_user(user_id, db_path)
    if not user or not user.get('auth_code'):
        return 'unknown', 'no local record'
    try:
        import wloc_keygen
        if not wloc_keygen.is_configured():
            return 'unknown', 'keygen not configured'
        ok, res = wloc_keygen.validate_key(user['auth_code'],
                                           fingerprint=user.get('machine_code'))
    except Exception as exc:
        return 'unavailable', str(exc)[:120]

    if ok:
        update_user(user_id, db_path, valid_until=res.get('expiry'))
        return 'active', res.get('code') or 'VALID'

    code = res.get('code') or ''
    if code in ('EXPIRED', 'OVERDUE'):
        update_user(user_id, db_path, status='expired')
    elif code in ('SUSPENDED', 'BANNED'):
        update_user(user_id, db_path, status='disabled')
    elif code in ('NOT_FOUND', 'NO_MATCH'):
        update_user(user_id, db_path, status='disabled')
    audit('revalidate', user_id, 'code=%s' % code, db_path=db_path)
    return code.lower() or 'invalid', res.get('message') or code


# ==================== Token ====================

def resolve_token(token, db_path=None, touch=True):
    """校验 token，返回 user dict；无效返回 None。"""
    if not token:
        return None
    with _conn(db_path) as conn:
        row = conn.execute('SELECT * FROM api_tokens WHERE token=?', (token,)).fetchone()
        if not row:
            return None
        row = dict(row)
        if row['revoked']:
            return None
        exp = _parse_dt(row['expires_at'])
        if exp and datetime.now(timezone.utc) > exp:
            return None
        user = conn.execute('SELECT * FROM users WHERE user_id=?',
                            (row['user_id'],)).fetchone()
        if not user:
            return None
        if touch:
            conn.execute('UPDATE api_tokens SET last_used_at=? WHERE token=?',
                         (_now(), token))
            conn.execute('UPDATE users SET last_seen_at=? WHERE user_id=?',
                         (_now(), row['user_id']))
    return dict(user)


def revoke_tokens(user_id, db_path=None):
    """撤销某用户的全部 token（用于踢下线）。"""
    with _conn(db_path) as conn:
        cur = conn.execute('UPDATE api_tokens SET revoked=1 WHERE user_id=?',
                           (user_id,))
        n = cur.rowcount
    audit('revoke_tokens', user_id, 'count=%d' % n, db_path=db_path)
    return n


def check_auth_status(token, db_path=None):
    """
    供前端轮询的授权状态。
    state: active / revoked / expired / disabled / invalid
    """
    if not token:
        return {'state': 'invalid', 'message': '未登录'}

    with _conn(db_path) as conn:
        row = conn.execute('SELECT * FROM api_tokens WHERE token=?', (token,)).fetchone()
        if not row:
            return {'state': 'revoked', 'message': '授权已失效，请重新登录'}
        row = dict(row)
        if row['revoked']:
            return {'state': 'revoked', 'message': '授权已被管理员撤销'}
        user = conn.execute('SELECT * FROM users WHERE user_id=?',
                            (row['user_id'],)).fetchone()
    if not user:
        return {'state': 'revoked', 'message': '用户不存在'}

    user = dict(user)
    if user['status'] != 'active':
        return {'state': 'disabled', 'message': '授权已被停用',
                'validUntil': user['valid_until']}
    if is_expired(user['valid_until']):
        return {'state': 'expired', 'message': '授权已过期',
                'validUntil': user['valid_until']}

    return {'state': 'active', 'message': '', 'validUntil': user['valid_until'],
            'userId': user['user_id'], 'displayName': user['display_name']}


def user_public_info(user):
    """返回给前端的用户信息（脱敏）。"""
    return {
        'userId': user['user_id'],
        'authCode': user['auth_code'],
        'displayName': user['display_name'],
        'status': user['status'],
        'validUntil': user['valid_until'],
        'deviceBound': bool((user['machine_code'] or '').strip()),
    }


# ==================== 收藏 ====================

def list_favorites(user_id, db_path=None):
    with _conn(db_path) as conn:
        rows = conn.execute(
            'SELECT * FROM favorites WHERE user_id=? ORDER BY id DESC',
            (user_id,)).fetchall()
    return [dict(r) for r in rows]


def add_favorite(user_id, name, latitude, longitude, db_path=None):
    with _conn(db_path) as conn:
        cur = conn.execute(
            'INSERT INTO favorites (user_id, name, latitude, longitude, created_at) '
            'VALUES (?,?,?,?,?)',
            (user_id, name or '收藏位置', float(latitude), float(longitude), _now()))
        fid = cur.lastrowid
    audit('favorite_add', user_id, '%s %s,%s' % (name, latitude, longitude), db_path=db_path)
    return fid


def delete_favorite(user_id, fav_id, db_path=None):
    with _conn(db_path) as conn:
        cur = conn.execute('DELETE FROM favorites WHERE id=? AND user_id=?',
                           (fav_id, user_id))
    return cur.rowcount > 0


# ==================== 自检 ====================

if __name__ == '__main__':
    import sys
    if '--selftest' in sys.argv:
        import tempfile
        tmp = os.path.join(tempfile.mkdtemp(), 'test.db')
        init_user_tables(tmp)
        u = create_user('测试用户', valid_days=30, note='selftest', db_path=tmp)
        assert u and u['auth_code'], '创建用户失败'
        print('  创建用户: %s (id=%d, 到期 %s)' % (u['auth_code'], u['user_id'], u['valid_until'][:10]))

        ok, d = login(u['auth_code'], 'machine-aaa', db_path=tmp)
        assert ok, '首次登录应成功: %s' % d
        print('  首次登录: OK，token 长度 %d' % len(d['token']))
        tok = d['token']

        ok2, d2 = login(u['auth_code'], 'machine-bbb', db_path=tmp)
        assert not ok2, '换设备应被拒绝'
        print('  换设备登录: 已拒绝（%s）' % d2['error'])

        ok3, _ = login(u['auth_code'], 'machine-aaa', db_path=tmp)
        assert ok3, '同设备应可再登录'
        print('  同设备再登录: OK')

        uu = resolve_token(tok, db_path=tmp)
        assert uu and uu['user_id'] == u['user_id'], 'token 解析失败'
        print('  解析 token: OK (user_id=%d)' % uu['user_id'])

        st = check_auth_status(tok, db_path=tmp)
        assert st['state'] == 'active', '状态应为 active，实际 %s' % st['state']
        print('  授权状态: %s' % st['state'])

        revoke_tokens(u['user_id'], db_path=tmp)
        st2 = check_auth_status(tok, db_path=tmp)
        assert st2['state'] == 'revoked', '撤销后应为 revoked'
        assert resolve_token(tok, db_path=tmp) is None, '撤销后 token 应失效'
        print('  撤销后状态: %s，token 已失效' % st2['state'])

        add_favorite(u['user_id'], '天安门', 39.9087, 116.3975, db_path=tmp)
        favs = list_favorites(u['user_id'], db_path=tmp)
        assert len(favs) == 1, '收藏失败'
        print('  收藏夹: %d 条' % len(favs))

        print('SELFTEST PASS')
