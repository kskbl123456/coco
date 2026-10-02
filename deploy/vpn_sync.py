#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WLoc VPN 账户 / 会话同步器

★ 本脚本在原仓库中缺失（只存在于首尔生产机上），此处按接口契约重建。

它做两件事：

  1. 【账户同步】把 vpn_identities 表里的账户写进 strongSwan 的 EAP 凭据文件
     （默认 /etc/ipsec.d/wloc-users.secrets），内容变化时执行 ipsec rereadsecrets。
     没有这一步，面板新建的用户在 VPN 上登不进来。

  2. 【会话同步】读 `ipsec leases` 拿到「隧道 IP → EAP 身份」的在线映射，
     写进 vpn_active_sessions 表。
     没有这一步，wloc_proxy 的 lookup_locked_location() 查不到用户 →
     改写失效（设备显示真实位置）。

用法：
    vpn_sync.py            同步一次
    vpn_sync.py --check    只检查，不写任何东西

环境变量：
    WLOC_DB_PATH        默认 /opt/wloc-web/wloc.db
    WLOC_SECRETS_FILE   默认 /etc/ipsec.d/wloc-users.secrets
    WLOC_SYNC_LOG       默认 /var/log/wloc-vpn-sync.log
"""
import os
import re
import sys
import time
import sqlite3
import subprocess

DB_PATH = os.environ.get('WLOC_DB_PATH', '/opt/wloc-web/wloc.db')
SECRETS_FILE = os.environ.get('WLOC_SECRETS_FILE', '/etc/ipsec.d/wloc-users.secrets')
SECRETS_MAIN = os.environ.get('WLOC_IPSEC_SECRETS', '/etc/ipsec.secrets')
LOG_FILE = os.environ.get('WLOC_SYNC_LOG', '/var/log/wloc-vpn-sync.log')

CHECK_ONLY = '--check' in sys.argv


def log(msg):
    line = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
    print(line)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as fh:
            fh.write(line + '\n')
    except Exception:
        pass


# ---------------------------------------------------------------- 接线检查
def ensure_include():
    """确保 /etc/ipsec.secrets 里 include 了我们生成的账号文件。

    ★★ 这一步不能少！strongSwan 只读 /etc/ipsec.secrets，
       include 进来才会读 wloc-users.secrets。
       少了它：账号写进去了但 charon 不知道 →
       手机连 VPN 时报 EAP-MSCHAPv2 校验失败，
       日志里是 `no EAP key found for hosts ...`。
       （2026-10-02 实际踩过，用户手机上表现为「连不上」）
    """
    if not os.path.exists(SECRETS_MAIN):
        log('主凭据文件不存在，跳过 include 检查：%s' % SECRETS_MAIN)
        return
    try:
        with open(SECRETS_MAIN, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except Exception as exc:
        log('读主凭据文件失败：%s' % exc)
        return

    if SECRETS_FILE in content:
        return  # 已经 include 过了

    if CHECK_ONLY:
        log('[check] 主凭据文件缺少 include：%s' % SECRETS_FILE)
        return

    try:
        with open(SECRETS_MAIN, 'a', encoding='utf-8') as fh:
            fh.write('\n# --- WLoc 用户账号（由 wloc-vpn-sync 自动生成，勿手工编辑）---\n'
                     'include %s\n' % SECRETS_FILE)
        log('已在 %s 中追加 include %s' % (SECRETS_MAIN, SECRETS_FILE))
    except Exception as exc:
        log('追加 include 失败：%s' % exc)


# ---------------------------------------------------------------- 账户同步
def build_secrets_content():
    """从 vpn_identities 生成 strongSwan EAP 凭据文件内容。

    格式（legacy ipsec.secrets）：
        wloc_xxxxxxxxxxxx : EAP "password"
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import wloc_vpn

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT vpn_username, password_ciphertext, status "
            "FROM vpn_identities WHERE status = 'active' "
            "ORDER BY user_id"
        ).fetchall()
    finally:
        conn.close()

    lines = [
        '# 由 wloc-vpn-sync 自动生成，请勿手工编辑',
        '# 账户来源：wloc.db 的 vpn_identities 表（status=active）',
        '',
    ]
    ok = 0
    for r in rows:
        try:
            pwd = wloc_vpn.decrypt_password(r['password_ciphertext'])
        except Exception as exc:
            log('跳过 %s：密码解密失败（%s）' % (r['vpn_username'], exc))
            continue
        lines.append('%s : EAP "%s"' % (r['vpn_username'], pwd))
        ok += 1
    lines.append('')
    return '\n'.join(lines), ok


def sync_secrets():
    if not os.path.exists(DB_PATH):
        log('数据库不存在，跳过账户同步：%s' % DB_PATH)
        return
    try:
        content, count = build_secrets_content()
    except Exception as exc:
        log('账户同步失败（读库异常）：%s' % exc)
        return

    old = ''
    if os.path.exists(SECRETS_FILE):
        try:
            with open(SECRETS_FILE, 'r', encoding='utf-8') as fh:
                old = fh.read()
        except Exception:
            old = ''

    if old == content:
        return  # 无变化，不打扰 strongSwan

    if CHECK_ONLY:
        log('[check] 凭据文件需要更新（%d 个账户）' % count)
        return

    tmp = SECRETS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(content)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRETS_FILE)

    r = subprocess.run(['ipsec', 'rereadsecrets'], capture_output=True, text=True)
    if r.returncode == 0:
        log('凭据文件已更新并重载：%d 个账户' % count)
    else:
        log('凭据文件已写入，但 rereadsecrets 失败：%s'
            % (r.stderr or r.stdout).strip()[:200])


# ---------------------------------------------------------------- 会话同步
LEASE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(online|offline)\s+'([^']*)'",
    re.MULTILINE)


def parse_leases():
    """解析 `ipsec leases`，返回 {ip: identity}（只要 online 的）"""
    try:
        r = subprocess.run(['ipsec', 'leases'], capture_output=True, text=True, timeout=15)
    except Exception as exc:
        log('执行 ipsec leases 失败：%s' % exc)
        return {}
    if r.returncode != 0:
        log('ipsec leases 返回 %d：%s' % (r.returncode, (r.stderr or '').strip()[:200]))
        return {}

    leases = {}
    for m in LEASE_RE.finditer(r.stdout):
        ip, state, identity = m.group(1), m.group(2), m.group(3)
        if state == 'online':
            leases[ip] = identity
    return leases


def sync_sessions():
    if not os.path.exists(DB_PATH):
        log('数据库不存在，跳过会话同步：%s' % DB_PATH)
        return
    leases = parse_leases()

    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute('PRAGMA busy_timeout=5000')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vpn_active_sessions (
                vpn_username TEXT PRIMARY KEY,
                vpn_ip       TEXT,
                session_id   TEXT,
                updated_at   TEXT
            )
        ''')
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime())

        # 先清掉已下线的
        if leases:
            marks = ','.join('?' * len(leases))
            conn.execute('DELETE FROM vpn_active_sessions WHERE vpn_ip NOT IN (%s)' % marks,
                         tuple(leases.keys()))
        else:
            conn.execute('DELETE FROM vpn_active_sessions')

        for ip, identity in leases.items():
            conn.execute('''
                INSERT INTO vpn_active_sessions (vpn_username, vpn_ip, session_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(vpn_username) DO UPDATE SET
                    vpn_ip     = excluded.vpn_ip,
                    session_id = excluded.session_id,
                    updated_at = excluded.updated_at
            ''', (identity, ip, identity, now))
        conn.commit()

        # 顺带汇报「有租约但库里没这个账户」的情况（配置不一致的信号）
        if leases:
            known = {r[0] for r in conn.execute(
                'SELECT vpn_username FROM vpn_identities').fetchall()}
            for ip, identity in leases.items():
                if identity not in known:
                    log('⚠️ 租约身份 %s (%s) 在 vpn_identities 中不存在' % (identity, ip))
    finally:
        conn.close()

    if leases:
        log('会话已同步：%d 个在线 —— %s'
            % (len(leases), ', '.join('%s→%s' % (i, u) for i, u in leases.items())))
    else:
        log('会话已同步：当前无在线租约')


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('需要 root 权限（要读写 ipsec 凭据）')
    ensure_include()
    sync_secrets()
    sync_sessions()
