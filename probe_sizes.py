#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用不同数量的 BSSID 探测 Apple 端点，定位大响应改写失败的原因。"""

import os
import sys
import random
import binascii

sys.path.insert(0, '/opt/wloc-web')

from wloc_proxy import (
    encode_varint_field, encode_bytes_field, parse_fields,
    rewrite_response, RESPONSE_PREFIX,
)

HOSTS = ['gs-loc.apple.com']
PATH = '/clls/wloc'


def rand_bssid():
    return ':'.join('%02x' % random.randint(0, 255) for _ in range(6))


def build_apple_wloc(bssids):
    parts = []
    for bssid in bssids:
        parts.append(encode_bytes_field(2, encode_bytes_field(1, bssid.encode())))
    parts.append(encode_varint_field(3, len(bssids)))
    parts.append(encode_varint_field(4, len(bssids)))
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


def probe(url, body):
    import requests
    headers = {
        'Content-Type': 'application/octet-stream',
        'Accept-Encoding': 'identity',
        'User-Agent': 'locationd/2896.0.3.5.3 CFNetwork/1494.0.7 Darwin/23.4.0',
        'Accept': '*/*',
        'Connection': 'close',
    }
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.post(url, data=body, headers=headers, timeout=20, verify=True)
        return response.status_code, dict(response.headers), response.content
    finally:
        session.close()


def main():
    counts = [int(x) for x in (sys.argv[1:] or ['2', '10', '30', '60'])]
    for count in counts:
        bssids = [rand_bssid() for _ in range(count)]
        payload = build_apple_wloc(bssids)
        body = build_arpc(payload)
        for host in HOSTS:
            try:
                status, headers, content = probe('https://%s%s' % (host, PATH), body)
            except Exception as exc:
                print('%-3d bssid → %s 请求失败：%s' % (count, host, exc))
                continue

            print('%-3d bssid → HTTP %d | 响应 %d 字节 | 编码=%s | 前16字节=%s'
                  % (count, status, len(content),
                     headers.get('Content-Encoding', '无'),
                     binascii.hexlify(content[:16]).decode()))

            mutated = rewrite_response(content, 41.7963, 123.4528)
            if mutated is None:
                print('      改写：失败')
                if content[:2] == b'\x1f\x8b':
                    print('      ★ 响应是 gzip（未解压）')
                elif len(content) >= 8 and content[:8] == RESPONSE_PREFIX:
                    declared = (content[8] << 8) | content[9]
                    print('      ★ 前缀匹配，声明长度 %d，实际 %d'
                          % (declared, len(content) - 10))
                    try:
                        top = parse_fields(content[10:10 + declared])
                        print('      顶层字段：%s'
                              % ', '.join('f%d(w%d)' % (t, w) for t, w, _v, _r in top))
                    except Exception as exc:
                        print('      载荷解析失败：%s' % exc)
                else:
                    print('      ★ 前缀不匹配。前 32 字节：%s'
                          % binascii.hexlify(content[:32]).decode())
            else:
                print('      改写：成功（%d → %d 字节）' % (len(content), len(mutated)))
        print()


if __name__ == '__main__':
    main()
