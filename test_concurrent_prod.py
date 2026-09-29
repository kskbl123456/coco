#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生产环境并发压测（在服务器本机运行）。

直接打真实代理 10.10.1.1:443（DNS 直连模式），
用真实 AppWLocRootCA 校验服务端证书，验证改写是否生效。

用法: sudo -u wloc ./venv/bin/python test_concurrent_prod.py [并发数] [进程名]
"""
import os
import ssl
import sys
import time
import socket
import asyncio

PROXY_HOST = '10.10.1.1'
PROXY_PORT = 443
CA_FILE = '/etc/ipsec.d/cacerts/AppWLocRootCA.pem'
TARGET_LAT, TARGET_LNG = 41.7963, 123.4528

# 构造一个带 2 个 WifiDevice 的合法 WLoc 请求（对齐 test_e2e.py 的构造方式）
def build_request():
    def varint(v):
        out = b''
        while True:
            b = v & 0x7F
            v >>= 7
            out += bytes([b | (0x80 if v else 0)])
            if not v:
                return out

    def vf(t, v):
        return varint((t << 3) | 0) + varint(v)

    def bf(t, p):
        return varint((t << 3) | 2) + varint(len(p)) + p

    bssids = [b'aa:bb:cc:dd:ee:ff', b'11:22:33:44:55:66']
    parts = [bf(2, bf(1, b)) for b in bssids]
    parts.append(vf(3, len(bssids)))
    parts.append(vf(4, len(bssids)))
    payload = b''.join(parts)

    def pascal(text):
        raw = text.encode()
        return len(raw).to_bytes(2, 'big') + raw

    out = bytearray()
    out += (1).to_bytes(2, 'big')
    out += pascal('en_US')
    out += pascal('com.apple.locationd')
    out += pascal('17.5.1')
    out += (1).to_bytes(4, 'big')
    out += len(payload).to_bytes(4, 'big')
    out += payload
    outer = bytes(out)

    head = ('POST /clls/wloc HTTP/1.1\r\nHost: gs-loc.apple.com\r\n'
            'Content-Type: application/octet-stream\r\n'
            'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(outer))
    return head.encode() + outer


def parse_latlng(body):
    def rv(b, p):
        s = v = 0
        while True:
            x = b[p]; p += 1
            v |= (x & 0x7F) << s
            if not (x & 0x80):
                return v, p
            s += 7

    def fs(b):
        p, o = 0, []
        while p < len(b):
            try:
                k, p = rv(b, p)
            except IndexError:
                break
            t, w = k >> 3, k & 7
            if w == 0:
                v, p = rv(b, p); o.append((t, w, v))
            elif w == 2:
                n, p = rv(b, p); o.append((t, w, b[p:p + n])); p += n
            elif w == 5:
                p += 4
            elif w == 1:
                p += 8
            else:
                break
        return o

    if b'\r\n\r\n' not in body:
        return None, None
    _, _, b = body.partition(b'\r\n\r\n')
    if len(b) < 10:
        return None, None
    for t, w, v in fs(b[10:]):
        if t == 2 and w == 2:
            loc = None
            for t2, w2, v2 in fs(v):
                if t2 == 2 and w2 == 2:
                    loc = fs(v2)
            if loc:
                d = {t2: v2 for t2, w2, v2 in loc if w2 == 0}
                if 1 in d and 2 in d:
                    return d[1] / 1e8, d[2] / 1e8
    return None, None


def rss_mb(pid):
    try:
        with open('/proc/%d/status' % pid) as fh:
            for line in fh:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) / 1024
    except Exception:
        return None
    return None


def find_pid(name='wloc_proxy.py'):
    import subprocess
    out = subprocess.run(['pgrep', '-f', name], capture_output=True, text=True).stdout
    pids = [int(x) for x in out.split() if x.strip()]
    return pids[0] if pids else None


def one_client(ca_file, timeout=20):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(ca_file)
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
        conn = ctx.wrap_socket(s, server_hostname='gs-loc.apple.com')
        req = build_request()
        conn.sendall(req)
        data = b''
        conn.settimeout(timeout)
        while True:
            try:
                c = conn.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            data += c
        conn.close()
        if not data:
            return False, 'empty'
        lat, lng = parse_latlng(data)
        if lat is None:
            return False, 'no coords (%d bytes)' % len(data)
        if abs(lat - TARGET_LAT) < 1e-3 and abs(lng - TARGET_LNG) < 1e-3:
            return True, 'ok'
        return False, 'wrong %.4f,%.4f' % (lat, lng)
    except Exception as exc:
        return False, '%s' % type(exc).__name__


async def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000

    # ---- 准备测试数据（让 10.10.1.1 这个源 IP 命中锁定坐标）----
    import sqlite3
    import datetime
    DB = '/opt/wloc-web/wloc.db'
    TEST_USER_ID, TEST_VPN_USER, TEST_SESSION_ID = 9998, 'wloc_conctest', 'conctest'
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = sqlite3.connect(DB, timeout=10)
    cur = conn.cursor()
    cur.execute(
        'INSERT OR REPLACE INTO vpn_identities '
        '(user_id, vpn_username, password_ciphertext, profile_scope, status, '
        ' secret_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
        (TEST_USER_ID, TEST_VPN_USER, 'conctest', 'conctest-scope', 'active', now, now))
    cur.execute(
        'INSERT OR REPLACE INTO device_locations '
        '(user_id, latitude, longitude, coordinate_system, updated_at) VALUES (?, ?, ?, ?, ?)',
        (TEST_USER_ID, TARGET_LAT, TARGET_LNG, 'gcj02', now))
    cur.execute(
        'INSERT OR REPLACE INTO vpn_active_sessions '
        '(vpn_username, vpn_ip, session_id, updated_at) VALUES (?, ?, ?, ?)',
        (TEST_VPN_USER, PROXY_HOST, TEST_SESSION_ID, now))
    conn.commit()
    conn.close()
    print('已写入测试数据：%s → %.4f,%.4f' % (PROXY_HOST, TARGET_LAT, TARGET_LNG))

    try:
        await run_load(n)
    finally:
        conn = sqlite3.connect(DB, timeout=10)
        cur = conn.cursor()
        cur.execute('DELETE FROM vpn_active_sessions WHERE vpn_username = ?', (TEST_VPN_USER,))
        cur.execute('DELETE FROM device_locations WHERE user_id = ?', (TEST_USER_ID,))
        cur.execute('DELETE FROM vpn_identities WHERE user_id = ?', (TEST_USER_ID,))
        conn.commit()
        conn.close()
        print('已清理测试数据')


async def run_load(n):
    pid = find_pid()
    print('代理进程 PID = %s' % pid)
    base = rss_mb(pid) if pid else None
    if base:
        print('压测前代理 RSS = %.1f MB' % base)

    loop = asyncio.get_running_loop()
    print('\n开始 %d 并发...' % n)
    t0 = time.time()
    tasks = [loop.run_in_executor(None, one_client, CA_FILE) for _ in range(n)]
    res = await asyncio.gather(*tasks)
    elapsed = time.time() - t0

    ok = sum(1 for r, _ in res if r)
    fails = [m for r, m in res if not r]
    peak = rss_mb(pid) if pid else None

    print('\n总请求 %d，成功 %d，失败 %d，耗时 %.2fs（%.0f req/s）'
          % (n, ok, len(fails), elapsed, n / elapsed if elapsed else 0))
    if fails:
        from collections import Counter
        for msg, cnt in Counter(fails).most_common(8):
            print('  %5d ×  %s' % (cnt, msg))
    if base and peak:
        print('代理 RSS：%.1f MB → %.1f MB（增量 %.1f MB）' % (base, peak, peak - base))
    print('\n%s' % ('✅ PROD 并发 PASS' if ok == n else '⚠️  部分失败，见上'))

asyncio.run(main())
