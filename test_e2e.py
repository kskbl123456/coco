#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端测试：在本机模拟一个 VPN 客户端，走完整链路验证改写是否生效。

链路：TCP → CONNECT → TLS(信任 AppWLocRootCA) → POST /clls/wloc → 检查返回坐标
测试期间会临时写入 3 条测试数据（user_id=9999），结束后清理。
"""

import os
import sys
import ssl
import socket
import sqlite3
import binascii
import datetime

sys.path.insert(0, '/opt/wloc-web')

from wloc_proxy import (  # noqa: E402
    encode_varint_field, encode_bytes_field, parse_fields,
    RESPONSE_PREFIX, COORD_SCALE,
)

DB = '/opt/wloc-web/wloc.db'
PROXY_HOST = '10.10.1.1'
PROXY_PORT = 9999
CA_FILE = '/etc/ipsec.d/cacerts/AppWLocRootCA.pem'
WLOC_PATH = '/clls/wloc'
SERVER_NAME = 'gs-loc.apple.com'

TEST_USER_ID = 9999
TEST_VPN_USER = 'wloc_selftest'
TEST_SESSION_ID = 'selftest'
TEST_CLIENT_IP = '10.10.1.1'
TARGET_LAT, TARGET_LNG = 41.7963, 123.4528

BSSIDS = ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']


def to_signed(value):
    return value - (1 << 64) if value >= (1 << 63) else value


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def setup_test_rows():
    conn = sqlite3.connect(DB, timeout=10)
    cur = conn.cursor()
    cur.execute(
        'INSERT OR REPLACE INTO vpn_identities '
        '(user_id, vpn_username, password_ciphertext, profile_scope, status, '
        ' secret_version, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
        (TEST_USER_ID, TEST_VPN_USER, 'selftest', 'selftest-scope',
         'active', now_iso(), now_iso()),
    )
    cur.execute(
        'INSERT OR REPLACE INTO device_locations '
        '(user_id, latitude, longitude, coordinate_system, updated_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (TEST_USER_ID, TARGET_LAT, TARGET_LNG, 'gcj02', now_iso()),
    )
    cur.execute(
        'INSERT OR REPLACE INTO vpn_active_sessions '
        '(vpn_username, vpn_ip, session_id, updated_at) VALUES (?, ?, ?, ?)',
        (TEST_VPN_USER, TEST_CLIENT_IP, TEST_SESSION_ID, now_iso()),
    )
    conn.commit()
    conn.close()
    print('已写入测试数据：user_id=%d, vpn_ip=%s, 目标坐标 %.4f,%.4f'
          % (TEST_USER_ID, TEST_CLIENT_IP, TARGET_LAT, TARGET_LNG))


def teardown_test_rows():
    conn = sqlite3.connect(DB, timeout=10)
    cur = conn.cursor()
    cur.execute('DELETE FROM vpn_active_sessions WHERE vpn_username = ?', (TEST_VPN_USER,))
    cur.execute('DELETE FROM device_locations WHERE user_id = ?', (TEST_USER_ID,))
    cur.execute('DELETE FROM vpn_identities WHERE user_id = ?', (TEST_USER_ID,))
    conn.commit()
    conn.close()
    print('已清理测试数据')


def build_apple_wloc():
    parts = []
    for bssid in BSSIDS:
        parts.append(encode_bytes_field(2, encode_bytes_field(1, bssid.encode())))
    parts.append(encode_varint_field(3, len(BSSIDS)))
    parts.append(encode_varint_field(4, len(BSSIDS)))
    return b''.join(parts)


def build_arpc(payload, function_id=1):
    def pascal(text):
        raw = text.encode()
        return len(raw).to_bytes(2, 'big') + raw

    out = bytearray()
    out += (1).to_bytes(2, 'big')
    out += pascal('en_US')
    out += pascal('com.apple.locationd')
    out += pascal('17.5.1')
    out += function_id.to_bytes(4, 'big')
    out += len(payload).to_bytes(4, 'big')
    out += payload
    return bytes(out)


def recv_header(sock, limit=65536):
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        if len(data) > limit:
            break
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def recv_all(sock):
    data = b''
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    setup_test_rows()
    try:
        print('\n--- 1. TCP 连接代理 %s:%d ---' % (PROXY_HOST, PROXY_PORT))
        raw = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=20)
        raw.settimeout(20)
        print('  已连接')

        print('--- 2. 发送 CONNECT ---')
        raw.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n'
                     % (SERVER_NAME, SERVER_NAME)).encode())
        connect_reply = recv_header(raw)
        print('  %s' % connect_reply.split(b'\r\n')[0].decode('latin-1', 'replace'))
        if b' 200 ' not in connect_reply:
            print('FAIL：代理未返回 200')
            return 1

        print('--- 3. TLS 握手（信任 AppWLocRootCA）---')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CA_FILE)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        tls = ctx.wrap_socket(raw, server_hostname=SERVER_NAME)
        cert = tls.getpeercert()
        cert_detail = cert.get('subjectAltName') or cert.get('subject')
        print('  握手成功，对端证书 SAN: %s' % (cert_detail,))
        tls.settimeout(20)

        print('--- 4. POST %s ---' % WLOC_PATH)
        body = build_arpc(build_apple_wloc())
        request = (
            'POST %s HTTP/1.1\r\n'
            'Host: %s\r\n'
            'Content-Type: application/octet-stream\r\n'
            'Accept-Encoding: identity\r\n'
            'Content-Length: %d\r\n'
            'Connection: close\r\n\r\n' % (WLOC_PATH, SERVER_NAME, len(body))
        ).encode() + body
        tls.sendall(request)

        response = recv_all(tls)
        tls.close()
        print('  响应 %d 字节' % len(response))

        head, _, payload = response.partition(b'\r\n\r\n')
        print('  %s' % head.split(b'\r\n')[0].decode('latin-1', 'replace'))

        if not payload:
            print('FAIL：响应体为空')
            return 1
        if payload[:8] != RESPONSE_PREFIX:
            print('FAIL：响应信封前缀不匹配：%s'
                  % binascii.hexlify(payload[:16]).decode())
            return 1
        print('  信封前缀 OK')

        declared = (payload[8] << 8) | payload[9]
        proto = payload[10:10 + declared]
        print('  声明长度 %d，实际 %d' % (declared, len(proto)))

        print('\n--- 5. 校验改写结果 ---')
        top = parse_fields(proto)
        tags = [f[0] for f in top]
        devices = [f for f in top if f[0] == 2]
        print('  WifiDevice 数量: %d' % len(devices))
        if not devices:
            print('FAIL：没有 WifiDevice')
            return 1

        ok = True
        for index, device in enumerate(devices):
            sub = parse_fields(device[2])
            bssid = [f for f in sub if f[0] == 1][0][2].decode()
            loc = [f for f in sub if f[0] == 2]
            if not loc:
                print('  #%d FAIL：无 location' % index)
                ok = False
                continue
            values = {f[0]: to_signed(f[2]) for f in parse_fields(loc[0][2])}
            lat = values[1] / COORD_SCALE
            lng = values[2] / COORD_SCALE
            hit = (values[1] == int(round(TARGET_LAT * COORD_SCALE))
                   and values[2] == int(round(TARGET_LNG * COORD_SCALE)))
            print('  #%d bssid=%s lat=%.4f lng=%.4f %s'
                  % (index, bssid, lat, lng, 'OK' if hit else 'FAIL'))
            if not hit:
                ok = False

        if not ok:
            print('\nE2E FAIL')
            return 1

        print('\nE2E PASS — 代理改写已生效，返回坐标与锁定坐标一致')
        return 0
    finally:
        teardown_test_rows()


if __name__ == '__main__':
    sys.exit(main())
