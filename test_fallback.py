#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试「构造响应」兜底逻辑。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wloc_proxy import (  # noqa: E402
    build_wloc_response, rewrite_response, parse_arpc_payload, extract_bssids,
    encode_bytes_field, parse_fields, RESPONSE_PREFIX, COORD_SCALE,
)

BSSIDS = ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66', 'de:ad:be:ef:00:01']
LAT, LNG = 41.7963, 123.4528


def pascal(text):
    raw = text.encode()
    return len(raw).to_bytes(2, 'big') + raw


def build_arpc(bssids):
    payload = b''.join(encode_bytes_field(2, encode_bytes_field(1, b.encode()))
                       for b in bssids)
    return ((1).to_bytes(2, 'big') + pascal('en_US')
            + pascal('com.apple.locationd') + pascal('17.5.1')
            + (1).to_bytes(4, 'big') + len(payload).to_bytes(4, 'big') + payload)


def main():
    arpc = build_arpc(BSSIDS)
    payload = parse_arpc_payload(arpc)

    print('1) parse_arpc_payload')
    assert payload is not None and payload[0] == 0x12, 'ARPC 解析失败'
    print('   OK，内层 payload %d 字节，首字段 tag=%d' % (len(payload), payload[0] >> 3))

    print('2) extract_bssids')
    got = [b.decode() for b in extract_bssids(payload)]
    assert got == BSSIDS, 'BSSID 提取失败：%s' % got
    print('   OK，%s' % got)

    print('3) build_wloc_response')
    built = build_wloc_response([b.encode() for b in BSSIDS], LAT, LNG)
    assert built is not None and built[:8] == RESPONSE_PREFIX, '构造响应前缀错误'
    declared = (built[8] << 8) | built[9]
    assert declared == len(built) - 10, '长度字段错误'
    devices = [f for f in parse_fields(built[10:10 + declared]) if f[0] == 2]
    assert len(devices) == 3, '设备数错误'
    for device in devices:
        sub = parse_fields(device[2])
        values = {f[0]: f[2] for f in parse_fields(sub[1][2])}
        assert values[1] == int(round(LAT * COORD_SCALE)), '纬度错误'
        assert values[2] == int(round(LNG * COORD_SCALE)), '经度错误'
        assert values[3] == 39 and values[4] == 3 and values[5] == 480
        assert values[6] == 1000 and values[11] == 63 and values[12] == 467
    print('   OK，%d 字节，%d 个设备，坐标正确' % (len(built), len(devices)))

    print('4) 脏响应 + 有效请求 → 回退到构造')
    out = rewrite_response(b'\x00\x01\x02\x03', LAT, LNG, arpc)
    assert out is not None and out[:8] == RESPONSE_PREFIX, '脏响应未回退到构造'
    print('   OK，构造出 %d 字节' % len(out))

    print('5) 空响应 + 有效请求 → 回退到构造')
    out = rewrite_response(b'', LAT, LNG, arpc)
    assert out is not None and out[:8] == RESPONSE_PREFIX, '空响应未回退到构造'
    print('   OK')

    print('6) 无请求体 → 返回 None')
    assert rewrite_response(b'\x00\x01\x02\x03', LAT, LNG) is None, '应返回 None'
    print('   OK')

    print('7) 正常响应仍走改写（不触发构造）')
    good = build_wloc_response([b.encode() for b in BSSIDS], 39.9, 116.4)
    out = rewrite_response(good, LAT, LNG, arpc)
    assert out is not None, '正常响应改写失败'
    declared = (out[8] << 8) | out[9]
    devices = [f for f in parse_fields(out[10:10 + declared]) if f[0] == 2]
    values = {f[0]: f[2] for f in parse_fields(parse_fields(devices[0][2])[1][2])}
    assert values[1] == int(round(LAT * COORD_SCALE)), '改写后坐标错误'
    print('   OK')

    print('\nFALLBACK TESTS PASS')


if __name__ == '__main__':
    main()
