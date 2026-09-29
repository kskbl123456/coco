#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向真实 Apple 定位端点探测，尝试拿到一份真实响应用于验证改写逻辑。"""

import sys
import binascii

sys.path.insert(0, '/opt/wloc-web')

from wloc_proxy import (
    encode_varint_field, encode_bytes_field, parse_fields, RESPONSE_PREFIX,
)

HOSTS = ['gs-loc.apple.com', 'gs-loc-cn.apple.com']
PATH = '/clls/wloc'

BSSIDS = ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66', 'de:ad:be:ef:00:01']


def build_apple_wloc(with_bssids=True, with_counts=True, with_bundle=True):
    parts = []
    if with_bssids:
        for bssid in BSSIDS:
            device = encode_bytes_field(1, bssid.encode())
            parts.append(encode_bytes_field(2, device))
    if with_counts:
        parts.append(encode_varint_field(3, len(BSSIDS)))
        parts.append(encode_varint_field(4, len(BSSIDS)))
    if with_bundle:
        parts.append(encode_bytes_field(5, b'com.apple.locationd'))
    return b''.join(parts)


def build_arpc(payload, function_id=0):
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


def probe(url, body, label):
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
        response = session.post(url, data=body, headers=headers, timeout=15, verify=True)
    except Exception as exc:
        print('  [%s] 请求异常：%s' % (label, exc))
        return None
    content = response.content
    print('  [%s] HTTP %d | 请求 %d 字节 | 响应 %d 字节'
          % (label, response.status_code, len(body), len(content)))
    if content:
        print('        hex: %s' % binascii.hexlify(content[:96]).decode())
    return content


def main():
    payload = build_apple_wloc()
    print('AppleWLoc 载荷 %d 字节' % len(payload))

    candidates = [
        ('raw-protobuf', payload),
        ('arpc-fid0', build_arpc(payload, 0)),
        ('arpc-fid1', build_arpc(payload, 1)),
        ('arpc-fid2', build_arpc(payload, 2)),
        ('arpc-fid3', build_arpc(payload, 3)),
    ]

    best = None
    for host in HOSTS:
        url = 'https://%s%s' % (host, PATH)
        print('\n=== %s ===' % host)
        for label, body in candidates:
            content = probe(url, body, label)
            if content and content[:8] == RESPONSE_PREFIX:
                print('        ★ 命中响应信封前缀！')
                best = content
                break
            if content and len(content) > 20:
                if best is None:
                    best = content
        if best is not None and best[:8] == RESPONSE_PREFIX:
            break

    if best is None:
        print('\n未能取得可用样本')
        return

    print('\n=== 最佳样本 %d 字节 ===' % len(best))
    if best[:8] == RESPONSE_PREFIX:
        declared = (best[8] << 8) | best[9]
        print('信封前缀正确，声明长度 %d，实际载荷 %d' % (declared, len(best) - 10))
        payload = best[10:10 + declared]
        try:
            for tag, wire, value, raw in parse_fields(payload):
                if tag == 2 and wire == 2:
                    print('  WifiDevice: %s' % binascii.hexlify(value[:48]).decode())
                else:
                    print('  field %d wire %d raw=%s' % (tag, wire, binascii.hexlify(raw[:32]).decode()))
        except Exception as exc:
            print('  解析失败：%s' % exc)
        with open('/tmp/apple_sample.bin', 'wb') as fh:
            fh.write(best)
        print('样本已保存到 /tmp/apple_sample.bin')


if __name__ == '__main__':
    main()
