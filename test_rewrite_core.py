# -*- coding: utf-8 -*-
"""核心改写逻辑验证：直接调用 wloc_proxy.py 的关键函数。

为什么不走真网络：手工构造的极简 protobuf 会被 Apple 拒（400）。
所以直接验证「坐标改写」这条最重要的逻辑，覆盖三条路径：
  A. build_wloc_response —— 从 BSSID 构造响应，坐标必须是锁定值
  B. rewrite_response（正常路径）—— 上游响应含 WifiDevice → 坐标被改写
  C. rewrite_response（fallback）—— 上游响应不含 WifiDevice → 用请求 BSSID 构造
  D. rewrite_response（上游 400/垃圾）—— 同样走 fallback
  E. 信封处理 —— msgtype 00 01 / 00 03 都必须正确保留
"""
import importlib.util
import importlib.machinery
import os
import struct
import sys

# 被测文件：优先命令行参数，其次同目录（本地测试环境），最后服务器路径
def _find_proxy():
    if len(sys.argv) > 1:
        return sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in ('wloc_proxy.py.async', 'wloc_proxy.py'):
        p = os.path.join(here, cand)
        if os.path.exists(p):
            return p
    return '/opt/wloc-web/wloc_proxy.py'

PROXY = _find_proxy()
LAT, LNG = 39.90277525, 116.40114383
BSSIDS = [b'aa:bb:cc:11:22:33', b'de:ad:be:ef:00:01']

print('被测文件: %s' % PROXY)
if not os.path.exists(PROXY):
    sys.exit('找不到被测文件，请传入路径：python test_rewrite_core.py <wloc_proxy.py>')

# 显式指定 loader —— .async 后缀不是合法模块名
_loader = importlib.machinery.SourceFileLoader('wloc_proxy_t', PROXY)
spec = importlib.util.spec_from_loader('wloc_proxy_t', _loader)
m = importlib.util.module_from_spec(spec)
_loader.exec_module(m)

PASS, FAIL = [], []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print('  %s %s%s' % ('[PASS]' if cond else '[FAIL]', name,
                         ('  <- ' + str(detail)) if detail and not cond else ''))


def envelope(msgtype, payload):
    """按实测信封格式打包：00 01 | 00 00 | msgtype | 00 00 | len(u16BE) | payload"""
    return (b'\x00\x01\x00\x00' + msgtype + b'\x00\x00'
            + struct.pack('>H', len(payload)) + payload)


def unwrap(env):
    """返回 (msgtype_hex, payload)"""
    return env[4:6].hex(), env[10:]


def coords_of(payload):
    """用被测模块自己的 parse_fields 抽 (bssid, lat, lng)；自动剥信封。"""
    # build_wloc_response / rewrite_response 的返回值都含信封，先剥掉
    if len(payload) >= 10 and payload[0:4] == b'\x00\x01\x00\x00' \
            and payload[6:8] == b'\x00\x00':
        _, payload = m._parse_envelope(payload)
        if payload is None:
            return []
    out = []
    for tag, wire, value, _raw in m.parse_fields(payload):
        if tag == 2 and wire == 2:            # WifiDevice
            bssid, lat, lng = None, None, None
            for st, sw, sv, _r in m.parse_fields(value):
                if st == 1 and sw == 2:
                    bssid = sv.decode('utf-8', 'replace')
                elif st == 2 and sw == 2:      # Location
                    # ⚠️ 坐标是 varint 定点值（round(x * 1e8)），wire type = 0
                    for lt, lw, lv, lr in m.parse_fields(sv):
                        if lw == 0:
                            if lt == 1:
                                lat = lv / m.COORD_SCALE
                            elif lt == 2:
                                lng = lv / m.COORD_SCALE
            out.append((bssid, lat, lng))
    return out


def build_request_with_bssids(bssids):
    """构造一份含 BSSID 的 AppleWLoc 请求载荷（fallback 需要它）"""
    payload = b''
    for b in bssids:
        loc = m.build_location(0.0, 0.0)
        wd = m.encode_bytes_field(1, b) + m.encode_bytes_field(2, loc)
        payload += m.encode_bytes_field(2, wd)
    return payload


print('=' * 64)
print('核心改写逻辑验证  (锁定值 %.8f, %.8f)' % (LAT, LNG))
print('=' * 64)

# ---------------- A ----------------
print('\n[A] build_wloc_response：从 BSSID 构造响应')
built = m.build_wloc_response(BSSIDS, LAT, LNG)
check('返回非空', built is not None)
if built:
    print('    构造 %d 字节' % len(built))
    cs = coords_of(built)
    print('    解析到 %d 个 WifiDevice' % len(cs))
    hits = 0
    for b, la, ln in cs:
        okk = la is not None and abs(la - LAT) < 1e-4 and abs(ln - LNG) < 1e-4
        hits += 1 if okk else 0
        print('      %-20s lat=%-12s lng=%-12s %s' % (b, la, ln, '✓' if okk else '✗'))
    check('坐标全部 = 锁定值', hits == len(BSSIDS), '%d/%d' % (hits, len(BSSIDS)))
    check('BSSID 全部保留',
          {b for b, _, _ in cs if b} == {x.decode() for x in BSSIDS})

# ---------------- B ----------------
print('\n[B] rewrite_response 正常路径（上游响应含 WifiDevice）')
# build_wloc_response 返回值已含信封 → 取其中的 payload，再用目标 msgtype 重新包
_up = m.build_wloc_response(BSSIDS, 1.0, 2.0)         # 故意用错误坐标
_, upstream_payload = m._parse_envelope(_up)
for mt in (b'\x00\x01', b'\x00\x03'):                 # 两种实测 msgtype
    body = envelope(mt, upstream_payload)
    out = m.rewrite_response(body, LAT, LNG)
    label = 'msgtype=%s' % mt.hex()
    check('%s 有输出' % label, out is not None)
    if not out:
        continue
    mt_out, payload_out = unwrap(out)
    check('%s 信封 msgtype 保留' % label, mt_out == mt.hex(), mt_out)
    check('%s 信封长度重算正确' % label,
          struct.unpack('>H', out[8:10])[0] == len(out) - 10)
    check('%s 前 8 字节前缀不动' % label, out[0:4] == b'\x00\x01\x00\x00'
          and out[6:8] == b'\x00\x00')
    cs = coords_of(payload_out)
    hits = sum(1 for _, la, ln in cs
               if la is not None and abs(la - LAT) < 1e-4 and abs(ln - LNG) < 1e-4)
    check('%s 坐标已改写' % label, hits == len(BSSIDS), '%d/%d' % (hits, len(BSSIDS)))

# ---------------- C ----------------
print('\n[C] rewrite_response fallback（上游响应无 WifiDevice）')
req = build_request_with_bssids(BSSIDS)
junk_payload = b'\x08\x01\x10\x02'                    # 无 f2 字段
body = envelope(b'\x00\x01', junk_payload)
out = m.rewrite_response(body, LAT, LNG, request_body=req)
check('有输出（走了 fallback）', out is not None)
if out:
    _, payload_out = unwrap(out)
    cs = coords_of(payload_out)
    hits = sum(1 for _, la, ln in cs
               if la is not None and abs(la - LAT) < 1e-4 and abs(ln - LNG) < 1e-4)
    print('    fallback 生成 %d 个 WifiDevice，%d 个命中锁定值' % (len(cs), hits))
    check('fallback 坐标 = 锁定值', hits == len(BSSIDS),
          '%d/%d' % (hits, len(BSSIDS)))

# ---------------- D ----------------
print('\n[D] rewrite_response 上游返回 400 文本（如 "Bad Request"）')
body = envelope(b'\x00\x01', b'Bad Request')
out = m.rewrite_response(body, LAT, LNG, request_body=req)
check('有输出（走了 fallback）', out is not None)
if out:
    _, payload_out = unwrap(out)
    cs = coords_of(payload_out)
    hits = sum(1 for _, la, ln in cs
               if la is not None and abs(la - LAT) < 1e-4 and abs(ln - LNG) < 1e-4)
    check('400 文本也能 fallback 出锁定值', hits == len(BSSIDS),
          '%d/%d' % (hits, len(BSSIDS)))

# ---------------- E ----------------
print('\n[E] 边界：无请求体时应返回 None（不崩）')
out = m.rewrite_response(envelope(b'\x00\x01', junk_payload), LAT, LNG,
                         request_body=None)
check('无请求体 → None（设计如此）', out is None, out)

print('\n' + '=' * 64)
print('PASS: %d    FAIL: %d' % (len(PASS), len(FAIL)))
for f in FAIL:
    print('   ✗', f)
print('=' * 64)
sys.exit(1 if FAIL else 0)
