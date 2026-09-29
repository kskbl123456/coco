#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 DNS 劫持 + 直连 443 TLS 改写这条链路（不依赖 PAC）。"""

import os
import sys
import ssl
import socket
import struct
import sqlite3
import datetime

sys.path.insert(0, '/opt/wloc-web')

from wloc_proxy import (  # noqa: E402
    encode_varint_field, encode_bytes_field, parse_fields,
    RESPONSE_PREFIX, COORD_SCALE,
)

DNS_HOST, DNS_PORT = '10.10.1.1', 53
PROXY_HOST = '10.10.1.1'
TLS_PORT = 443
CA_FILE = '/etc/ipsec.d/cacerts/AppWLocRootCA.pem'
SNI = 'gs-loc.apple.com'
WLOC_PATH = '/clls/wloc'
DB = '/opt/wloc-web/wloc.db'

TEST_USER_ID = 9999
TEST_VPN_USER = 'wloc_selftest'
TEST_CLIENT_IP = '10.10.1.1'
TARGET_LAT, TARGET_LNG = 41.7963, 123.4528
BSSIDS = ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def setup_rows():
    conn = sqlite3.connect(DB, timeout=10)
    cur = conn.cursor()
    cur.execute(
        'INSERT OR REPLACE INTO vpn_identities '
        '(user_id, vpn_username, password_ciphertext, profile_scope, status, '
        ' secret_version, created_at, updated_at) VALUES (?,?,?,?,?,1,?,?)',
        (TEST_USER_ID, TEST_VPN_USER, 'selftest', 'selftest-scope', 'active',
         now_iso(), now_iso()))
    cur.execute(
        'INSERT OR REPLACE INTO device_locations '
        '(user_id, latitude, longitude, coordinate_system, updated_at) VALUES (?,?,?,?,?)',
        (TEST_USER_ID, TARGET_LAT, TARGET_LNG, 'gcj02', now_iso()))
    cur.execute(
        'INSERT OR REPLACE INTO vpn_active_sessions '
        '(vpn_username, vpn_ip, session_id, updated_at) VALUES (?,?,?,?)',
        (TEST_VPN_USER, TEST_CLIENT_IP, 'selftest', now_iso()))
    conn.commit()
    conn.close()


def teardown_rows():
    conn = sqlite3.connect(DB, timeout=10)
    cur = conn.cursor()
    cur.execute('DELETE FROM vpn_active_sessions WHERE vpn_username=?', (TEST_VPN_USER,))
    cur.execute('DELETE FROM device_locations WHERE user_id=?', (TEST_USER_ID,))
    cur.execute('DELETE FROM vpn_identities WHERE user_id=?', (TEST_USER_ID,))
    conn.commit()
    conn.close()


def dns_query(name, qtype=1):
    txid = b'\x12\x34'
    header = txid + b'\x01\x00' + struct.pack('!HHHH', 1, 0, 0, 0)
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    packet = header + qname + struct.pack('!HH', qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(6)
    try:
        sock.sendto(packet, (DNS_HOST, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def parse_dns_answers(data):
    ancount = struct.unpack('!H', data[6:8])[0]
    rcode = data[3] & 0x0F
    if ancount == 0:
        return rcode, []
    # 跳过问题段
    pos = 12
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xC0:
            pos += 2
            break
        pos += 1 + data[pos]
    else:
        pos += 1
    pos += 4
    answers = []
    for _ in range(ancount):
        if pos + 12 > len(data):
            break
        if data[pos] & 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(socket.inet_ntoa(rdata))
        else:
            answers.append('type%d' % rtype)
    return rcode, answers


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


def build_apple_wloc():
    parts = []
    for bssid in BSSIDS:
        parts.append(encode_bytes_field(2, encode_bytes_field(1, bssid.encode())))
    parts.append(encode_varint_field(3, len(BSSIDS)))
    parts.append(encode_varint_field(4, len(BSSIDS)))
    return b''.join(parts)


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
    print('=== 1. DNS 解析测试（目标域名应被劫持到 10.10.1.1）===')
    for name in ('gs-loc.apple.com', 'gs-loc-cn.apple.com', 'gs-loc.ls-apple.com'):
        rcode, answers = parse_dns_answers(dns_query(name))
        status = 'OK' if answers == ['10.10.1.1'] else 'FAIL'
        print('  %-24s → %s (rcode=%d) %s' % (name, answers, rcode, status))
        if status == 'FAIL':
            return 1

    print('\n=== 2. 非目标域名应正常转发 ===')
    rcode, answers = parse_dns_answers(dns_query('www.baidu.com'))
    print('  www.baidu.com → %s (rcode=%d) %s'
          % (answers, rcode, 'OK' if answers and rcode == 0 else 'FAIL'))
    if not answers or rcode != 0:
        return 1

    print('\n=== 3. AAAA 查询应返回空答案（让设备走 IPv4）===')
    rcode, answers = parse_dns_answers(dns_query('gs-loc.apple.com', qtype=28))
    print('  AAAA → %s (rcode=%d) %s' % (answers, rcode, 'OK' if not answers and rcode == 0 else 'FAIL'))

    print('\n=== 4. 直连 10.10.1.1:443 TLS 中间人改写测试 ===')
    setup_rows()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CA_FILE)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        raw = socket.create_connection((PROXY_HOST, TLS_PORT), timeout=20)
        raw.settimeout(20)
        tls = ctx.wrap_socket(raw, server_hostname=SNI)
        cert = tls.getpeercert()
        print('  TLS 握手成功，SAN: %s' % (cert.get('subjectAltName'),))

        body = build_arpc(build_apple_wloc())
        request = (
            'POST %s HTTP/1.1\r\nHost: %s\r\n'
            'Content-Type: application/octet-stream\r\n'
            'Accept-Encoding: identity\r\n'
            'Content-Length: %d\r\nConnection: close\r\n\r\n'
            % (WLOC_PATH, SNI, len(body))
        ).encode() + body
        tls.sendall(request)
        response = recv_all(tls)
        tls.close()

        head, _, payload = response.partition(b'\r\n\r\n')
        print('  %s' % head.split(b'\r\n')[0].decode('latin-1', 'replace'))
        if payload[:8] != RESPONSE_PREFIX:
            print('  FAIL：信封前缀不匹配')
            return 1
        declared = (payload[8] << 8) | payload[9]
        proto = payload[10:10 + declared]
        devices = [f for f in parse_fields(proto) if f[0] == 2]
        print('  WifiDevice 数量: %d' % len(devices))
        ok = True
        for index, device in enumerate(devices):
            sub = parse_fields(device[2])
            loc = [f for f in sub if f[0] == 2]
            values = {f[0]: (f[2] - (1 << 64) if f[2] >= (1 << 63) else f[2])
                      for f in parse_fields(loc[0][2])}
            hit = (values[1] == int(round(TARGET_LAT * COORD_SCALE))
                   and values[2] == int(round(TARGET_LNG * COORD_SCALE)))
            print('  #%d lat=%.4f lng=%.4f %s'
                  % (index, values[1] / COORD_SCALE, values[2] / COORD_SCALE,
                     'OK' if hit else 'FAIL'))
            ok = ok and hit
        if not ok:
            return 1
        print('\nDIRECT-TLS VERIFY PASS — DNS 劫持 + 直连 443 改写链路可用')
        return 0
    finally:
        teardown_rows()


if __name__ == '__main__':
    sys.exit(main())
