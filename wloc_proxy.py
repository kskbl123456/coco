#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WLoc 服务端 MITM 代理

职责：
  1. 接收 PAC 导向的 CONNECT 请求（仅 gs-loc.apple.com / gs-loc-cn.apple.com）
  2. 用 AppWLocProxy 证书作为服务端完成 TLS 中间人
  3. 对 /clls/wloc 的响应改写经纬度为该客户端锁定的坐标
  4. 其他路径原样透传

协议依据：客户端 WLocCore/AppWLocMutator.swift
（其注释标明「逻辑对齐原 Go 服务里的 buildWLocResponse」）

用法：
  wloc_proxy.py [port] [host]     默认 9999 10.10.0.1
  wloc_proxy.py --selftest        离线自检改写逻辑（不联网）
"""

import os
import sys
import ssl
import time
import socket
import struct
import sqlite3
import asyncio
import binascii
import datetime
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------- 配置

DB_PATH = os.environ.get('WLOC_DB_PATH', '/opt/wloc-web/wloc.db')
CERT_FILE = os.environ.get('WLOC_PROXY_CERT', '/etc/ipsec.d/certs/AppWLocProxy.pem')
KEY_FILE = os.environ.get('WLOC_PROXY_KEY', '/etc/ipsec.d/private/AppWLocProxy.key')
LOG_FILE = os.environ.get('WLOC_PROXY_LOG', '/var/log/wloc-proxy.log')

ALLOWED_HOSTS = {'gs-loc.apple.com', 'gs-loc-cn.apple.com'}
WLOC_PATH = '/clls/wloc'

DEFAULT_PORT = 9999
DEFAULT_HOST = '10.10.0.1'

# 响应信封：8 字节固定前缀 + 2 字节大端长度 + protobuf
RESPONSE_PREFIX = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
MAX_PROTOBUF_LEN = 0xFFFF          # 长度字段只有 2 字节
MAX_HEADER = 64 * 1024
LISTEN_BACKLOG = 4096             # 原为 100，大并发时必须放大
CLIENT_TIMEOUT = 30               # 单连接读写超时（秒）
TLS_HANDSHAKE_TIMEOUT = 15        # TLS 握手超时（秒）
UPSTREAM_POOL_SIZE = 64           # 上游请求线程池（连接数无关）
PEEK_TIMEOUT = 5.0                # 窥探首字节最长等待（秒）
MAX_BODY = 4 * 1024 * 1024

# 写入 Location 的固定字段
COORD_SCALE = 100000000            # 经纬度定点：round(x * 1e8)
H_ACCURACY = int(os.environ.get('WLOC_WIFI_H_ACCURACY', '39'))
# ★ 2026-10-11: 基站定位的水平精度原为 1414(≈1.4km，精度圈很大)；
#   改写为该值（与 WiFi 路径一致）→ 圈变小。设为 0 可关闭本优化。
CELL_H_ACCURACY = int(os.environ.get('WLOC_CELL_H_ACCURACY', '39'))
V_ACCURACY = 1000
ALTITUDE = 480
UNKNOWN_VALUE_4 = 3
MOTION_ACTIVITY_TYPE = 63
MOTION_ACTIVITY_CONFIDENCE = 467

# 顶层需要删除的字段（对齐 Swift 实现）
DROP_TOP_LEVEL_FIELDS = {3, 4, 33}   # numCellResults / numWifiResults / deviceType

# ★ 基站类实体（CellTower 及其同类）所在顶层字段，及其内部 Location 字段号。
#   实测：Apple 在设备只上报基站时返回 f22×N + f24×N，两者结构完全一致，
#   内部 f5(wire2) 就是 Location（子字段 1=纬度 2=经度，定点 ×1e8）。
#   旧版只改写 f2(WifiDevice)，导致基站响应改不动、放行真实坐标。
CELL_ENTITY_FIELDS = (22, 24)
CELL_LOCATION_FIELD = 5

# 转发上游时需要剥离的逐跳头
HOP_BY_HOP = {
    'host', 'connection', 'proxy-connection', 'keep-alive',
    'content-length', 'accept-encoding', 'transfer-encoding', 'te', 'trailer',
    'proxy-authenticate', 'proxy-authorization', 'upgrade',
}



def log(message):
    """写日志。asyncio 单线程事件循环下无需加锁。"""
    line = '[%s] %s' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), message)
    try:
        sys.stdout.write(line + '\n')
        sys.stdout.flush()
    except Exception:
        pass
    try:
        with open(LOG_FILE, 'a') as fh:
            fh.write(line + '\n')
    except Exception:
        pass


# ---------------------------------------------------------------- protobuf 最小实现

def _read_varint(data, pos):
    """读取 varint，返回 (值, 新位置)。"""
    result = 0
    shift = 0
    length = len(data)
    while pos < length:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError('varint too long')
    raise ValueError('truncated varint')


def _write_varint(value):
    """写出 varint（负数按 64 位补码处理）。"""
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def parse_fields(data):
    """
    解析 protobuf 顶层字段，返回 [(tag, wire_type, value, raw_bytes), ...]。
    wire_type 0 → value 为整数；2 → value 为 bytes；1/5 → value 为 None。
    raw_bytes 是原始字节，用于无损保留。
    """
    fields = []
    pos = 0
    length = len(data)
    while pos < length:
        start = pos
        key, pos = _read_varint(data, pos)
        tag = key >> 3
        wire = key & 0x07
        if tag == 0:
            raise ValueError('invalid tag 0')
        if wire == 0:
            value, pos = _read_varint(data, pos)
            fields.append((tag, wire, value, data[start:pos]))
        elif wire == 2:
            size, pos = _read_varint(data, pos)
            end = pos + size
            if end > length:
                raise ValueError('length overflow')
            fields.append((tag, wire, data[pos:end], data[start:end]))
            pos = end
        elif wire == 5:
            end = pos + 4
            if end > length:
                raise ValueError('truncated fixed32')
            fields.append((tag, wire, None, data[start:end]))
            pos = end
        elif wire == 1:
            end = pos + 8
            if end > length:
                raise ValueError('truncated fixed64')
            fields.append((tag, wire, None, data[start:end]))
            pos = end
        else:
            # 3/4 是已废弃的 group，直接放弃
            raise ValueError('unsupported wire type %d' % wire)
    return fields


def encode_varint_field(tag, value):
    return _write_varint((tag << 3) | 0) + _write_varint(value)


def encode_bytes_field(tag, payload):
    return _write_varint((tag << 3) | 2) + _write_varint(len(payload)) + payload


def build_location(latitude, longitude):
    """构造要写入的 Location 消息。"""
    return b''.join([
        encode_varint_field(1, int(round(latitude * COORD_SCALE))),
        encode_varint_field(2, int(round(longitude * COORD_SCALE))),
        encode_varint_field(3, H_ACCURACY),
        encode_varint_field(4, UNKNOWN_VALUE_4),
        encode_varint_field(5, ALTITUDE),
        encode_varint_field(6, V_ACCURACY),
        encode_varint_field(11, MOTION_ACTIVITY_TYPE),
        encode_varint_field(12, MOTION_ACTIVITY_CONFIDENCE),
    ])


def _rewrite_wifi_device(payload, location_bytes):
    """替换 WifiDevice 里的 location（字段 2），其余字段原样保留。"""
    parts = []
    replaced = False
    for tag, wire, _value, raw in parse_fields(payload):
        if tag == 2 and wire == 2:
            parts.append(encode_bytes_field(2, location_bytes))
            replaced = True
        else:
            parts.append(raw)
    if not replaced:
        parts.append(encode_bytes_field(2, location_bytes))
    return b''.join(parts)


def _looks_like_location(msg):
    """
    结构守卫：判断一段字节是否真的是 Location 消息
    （必须含 varint 子字段 1 和 2）。避免误伤同号的其它字段。
    """
    try:
        tags = {t for t, w, _v, _r in parse_fields(msg) if w == 0}
    except Exception:
        return False
    return 1 in tags and 2 in tags


def _replace_coords(loc, latitude, longitude):
    """
    只替换 Location 的经纬度（子字段 1/2），其余子字段原样保留。

    ⚠️ 基站 Location 与 WiFi Location 的 schema 并不相同：
         基站  子字段 3=1414  4=0    无 5/6    11=897/724  12=44/38
         WiFi  子字段 3=39    4=3    5=480 6=1000  11=63   12=467
       因此绝不能照搬 build_location()（会写错 3/4/11/12），必须保守替换。
    """
    lat = int(round(latitude * COORD_SCALE))
    lng = int(round(longitude * COORD_SCALE))
    parts = []
    for tag, wire, _value, raw in parse_fields(loc):
        if tag == 1 and wire == 0:
            parts.append(encode_varint_field(1, lat))
        elif tag == 2 and wire == 0:
            parts.append(encode_varint_field(2, lng))
        elif tag == 3 and wire == 0 and CELL_H_ACCURACY > 0:
            # ★ 2026-10-11: 基站定位精度原为 1414(≈1.4km)；改写为 CELL_H_ACCURACY
            #   与 WiFi 路径(build_location)一致 → 定位圈变小。
            parts.append(encode_varint_field(3, CELL_H_ACCURACY))
        else:
            parts.append(raw)          # 其余子字段逐字节保留
    return b''.join(parts)


def _rewrite_cell_entity(payload, latitude, longitude):
    """
    改写基站实体（顶层 f22/f24）内部的 Location（字段 5），其余字段原样保留。
    返回 (新字节, 是否真的改到了)。
    """
    parts = []
    replaced = False
    for tag, wire, value, raw in parse_fields(payload):
        if tag == CELL_LOCATION_FIELD and wire == 2 and _looks_like_location(value):
            parts.append(encode_bytes_field(
                CELL_LOCATION_FIELD, _replace_coords(value, latitude, longitude)))
            replaced = True
        else:
            parts.append(raw)
    return b''.join(parts), replaced


def rewrite_apple_wloc(payload, latitude, longitude):
    """
    改写 AppleWLoc：
      - f2  WifiDevice  → 内部 f2 Location 换成目标坐标
      - f22/f24 基站实体 → 内部 f5 Location 换成目标坐标
      - 删除 numCellResults / numWifiResults / deviceType
    两种实体都没有时返回 None（调用方回退原始响应）。
    """
    location_bytes = build_location(latitude, longitude)
    parts = []
    device_count = 0
    for tag, wire, value, raw in parse_fields(payload):
        if tag in DROP_TOP_LEVEL_FIELDS:
            continue
        if tag == 2 and wire == 2:
            parts.append(encode_bytes_field(2, _rewrite_wifi_device(value, location_bytes)))
            device_count += 1
        elif tag in CELL_ENTITY_FIELDS and wire == 2:
            new_entity, replaced = _rewrite_cell_entity(value, latitude, longitude)
            parts.append(encode_bytes_field(tag, new_entity))
            if replaced:
                device_count += 1
        else:
            parts.append(raw)
    if device_count == 0:
        return None
    return b''.join(parts)


def parse_arpc_payload(data):
    """从 ARPC 请求中取出内层 protobuf payload。"""
    try:
        pos = 2                                    # version(u16)
        for _ in range(3):                         # locale / appIdentifier / osVersion
            length = struct.unpack('!H', data[pos:pos + 2])[0]
            pos += 2 + length
        pos += 4                                   # functionID(u32)
        payload_len = struct.unpack('!I', data[pos:pos + 4])[0]
        pos += 4
        payload = data[pos:pos + payload_len]
        return payload if len(payload) == payload_len else None
    except Exception:
        return None


def extract_bssids(payload):
    """从 AppleWLoc 请求中提取所有 WifiDevice 的 bssid。"""
    bssids = []
    try:
        for tag, wire, value, _raw in parse_fields(payload):
            if tag == 2 and wire == 2:
                for sub_tag, sub_wire, sub_value, _sub_raw in parse_fields(value):
                    if sub_tag == 1 and sub_wire == 2:
                        bssids.append(sub_value)
                        break
    except Exception:
        pass
    return bssids


def build_wloc_response(bssids, latitude, longitude):
    """
    根据请求中的 BSSID 构造一份全新的 AppleWLoc 响应。
    对齐原 Go 服务的 buildWLocResponse 思路：不依赖上游响应格式。
    """
    if not bssids:
        return None
    location_bytes = build_location(latitude, longitude)
    parts = []
    for bssid in bssids:
        device = encode_bytes_field(1, bssid) + encode_bytes_field(2, location_bytes)
        parts.append(encode_bytes_field(2, device))
    payload = b''.join(parts)
    if not payload or len(payload) > MAX_PROTOBUF_LEN:
        return None
    return RESPONSE_PREFIX + bytes([
        (len(payload) >> 8) & 0xFF,
        len(payload) & 0xFF,
    ]) + payload


_FAIL_DUMP_LIMIT = 5
_fail_dump_count = [0]


def _dump_failure(body, reason):
    """改写失败时记录响应头并保存样本，便于诊断。"""
    try:
        log('改写失败（%s），长度 %d，头部 48 字节：%s'
            % (reason, len(body), binascii.hexlify(body[:48]).decode()))
        if _fail_dump_count[0] < _FAIL_DUMP_LIMIT:
            path = '/tmp/wloc-fail-%d.bin' % _fail_dump_count[0]
            with open(path, 'wb') as fh:
                fh.write(body)
            _fail_dump_count[0] += 1
            log('失败样本已保存：%s（%d 字节）' % (path, len(body)))
    except Exception:
        pass


def _parse_envelope(body):
    """
    解析响应信封，返回 (prefix8, payload) 或 (None, None)。

    信封结构（实测）：
        字节 0-1 : version    固定 00 01
        字节 2-3 : 固定 00 00
        字节 4-5 : **消息类型，会变**（实测见过 00 01 / 00 03）
        字节 6-7 : 固定 00 00
        字节 8-9 : 载荷长度（大端）
        字节 10+ : AppleWLoc protobuf

    注意：早期实现把 8 字节前缀写死成 00 01 00 00 00 01 00 00，
    导致消息类型为 00 03 的响应被判为「前缀不匹配」，改写全部失效。
    """
    if len(body) < 10:
        return None, None
    if body[0:4] != b'\x00\x01\x00\x00' or body[6:8] != b'\x00\x00':
        return None, None
    declared = (body[8] << 8) | body[9]
    payload = body[10:10 + declared]
    if len(payload) != declared:
        return None, None
    return body[:8], payload


def rewrite_response(body, latitude, longitude, request_body=None):
    """
    改写完整响应体（含信封）。
    改写失败时，若给了 request_body，则从请求里的 BSSID 直接构造一份响应（更稳）。
    两者都不行才返回 None，由调用方回退原响应。
    """
    if not body:
        return _build_fallback(request_body, latitude, longitude)
    try:
        prefix, payload = _parse_envelope(body)
        if prefix is not None:
            new_payload = rewrite_apple_wloc(payload, latitude, longitude)
            if new_payload is None:
                _dump_failure(body, '载荷中无 WifiDevice')
                return _build_fallback(request_body, latitude, longitude)
            if len(new_payload) > MAX_PROTOBUF_LEN:
                log('改写后长度 %d 超出 2 字节长度上限，回退' % len(new_payload))
                return _build_fallback(request_body, latitude, longitude)
            # 保留原始信封头（含消息类型），只替换长度与载荷
            return prefix + bytes([
                (len(new_payload) >> 8) & 0xFF,
                len(new_payload) & 0xFF,
            ]) + new_payload
        # 兜底：裸 protobuf
        result = rewrite_apple_wloc(body, latitude, longitude)
        if result is None:
            _dump_failure(body, '信封无法识别且裸 protobuf 解析失败')
            return _build_fallback(request_body, latitude, longitude)
        return result
    except Exception as exc:
        _dump_failure(body, '解析异常 %s' % exc)
        return _build_fallback(request_body, latitude, longitude)


def _build_fallback(request_body, latitude, longitude):
    """改写失败时，从请求 BSSID 构造响应。"""
    if not request_body:
        return None
    payload = parse_arpc_payload(request_body)
    if payload is None:
        payload = request_body
    bssids = extract_bssids(payload)
    if not bssids:
        return None
    built = build_wloc_response(bssids, latitude, longitude)
    if built is not None:
        log('已改用构造方式生成响应（基于请求中 %d 个 BSSID）' % len(bssids))
    return built


# ---------------------------------------------------------------- 锁定坐标查询

def lookup_locked_location(client_ip):
    """按客户端 VPN IP 反查该用户锁定的坐标。"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute('PRAGMA busy_timeout=5000')
            cur.execute('PRAGMA synchronous=NORMAL')
        except Exception:
            pass
        cur.execute('SELECT vpn_username FROM vpn_active_sessions WHERE vpn_ip = ?', (client_ip,))
        session = cur.fetchone()
        if not session:
            # ★ 环回兜底（2026-10-09）：
            # 10.10.0.1 绑在 lo 上，设备发往 10.10.0.1 的包在内核里走 lo 本地投递，
            # 源地址被选成 lo 的地址 -> getpeername() 返回 10.10.0.1（而非设备的 10.20.0.x）。
            # 此时按 vpn_ip 精确匹配必然落空。若当前只有唯一在线会话，则用它兜底。
            if client_ip in ('10.10.0.1', '127.0.0.1', 'unknown'):
                cur.execute('SELECT vpn_username FROM vpn_active_sessions ORDER BY updated_at DESC')
                rows = cur.fetchall()
                if len(rows) == 1:
                    session = rows[0]
                    log('源 IP=%s 为环回/本机，回退到唯一在线会话 %s'
                        % (client_ip, session['vpn_username']))
        if not session:
            conn.close()
            return None
        cur.execute('SELECT user_id FROM vpn_identities WHERE vpn_username = ?',
                    (session['vpn_username'],))
        identity = cur.fetchone()
        if not identity:
            conn.close()
            return None
        cur.execute('SELECT latitude, longitude FROM device_locations WHERE user_id = ?',
                    (identity['user_id'],))
        location = cur.fetchone()
        conn.close()
        if not location:
            return None
        return float(location['latitude']), float(location['longitude'])
    except Exception as exc:
        log('查询锁定坐标失败：%s' % exc)
        return None


# ---------------------------------------------------------------- 异步 IO 层
#
# 本段为 asyncio 重构版本。原实现为「每连接一线程 + 阻塞 recv」，
# 1000 台并发会产生上千线程（约 4GB 内存）。现在改为单事件循环 + 协程。
#
# 关键设计（已通过原型验证）：
#   * 不用 asyncio.start_server —— 它给的 TransportSocket 不支持 MSG_PEEK，
#     而我们必须先窥探首字节来区分 CONNECT 与直连 TLS。
#     因此自行管理裸 socket + loop.sock_accept。
#   * TLS 握手用 loop.start_tls(server_side=True) —— 真异步，无阻塞。
#   * 上游 HTTP（requests 库）与 SQLite 查询无法异步化，放进线程池，
#     线程池容量固定，与连接数解耦。

# 上游/DB 的阻塞操作线程池（模块级，进程内共享）
_BLOCKING_POOL = None          # 由 start_proxy() 初始化


async def _run_blocking(func, *args):
    """在线程池中执行阻塞函数。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_BLOCKING_POOL, func, *args)


async def recv_connect_header(sock, limit=8192):
    """
    逐字节读取 CONNECT 头直到 \\r\\n\\r\\n（异步）。

    必须避免多读：客户端可能在收到 200 后立刻开始 TLS 握手，
    若一次读把 ClientHello 也读进来，握手就会失败。
    """
    data = b''
    loop = asyncio.get_running_loop()
    while not data.endswith(b'\r\n\r\n'):
        if len(data) > limit:
            raise ValueError('CONNECT header too large')
        chunk = await loop.sock_recv(sock, 1)
        if not chunk:
            break
        data += chunk
    return data


def parse_http_request(raw):
    """解析 HTTP 请求头，返回 (method, path, version, headers, leftover)。"""
    head, _, leftover = raw.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    request_line = lines[0].decode('latin-1')
    parts = request_line.split(' ', 2)
    if len(parts) < 2:
        raise ValueError('bad request line: %r' % request_line)
    method = parts[0]
    path = parts[1]
    version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
    headers = {}
    for line in lines[1:]:
        if b':' not in line:
            continue
        name, _, value = line.partition(b':')
        headers[name.decode('latin-1').strip()] = value.decode('latin-1').strip()
    return method, path, version, headers, leftover


STATUS_REASONS = {
    200: 'OK', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found',
    304: 'Not Modified', 400: 'Bad Request', 403: 'Forbidden',
    404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway',
    503: 'Service Unavailable',
}


def build_http_response(status, headers, body):
    reason = STATUS_REASONS.get(status, 'OK')
    lines = ['HTTP/1.1 %d %s' % (status, reason)]
    for name, value in headers.items():
        if name.lower() in ('content-length', 'transfer-encoding',
                            'connection', 'content-encoding'):
            continue
        lines.append('%s: %s' % (name, value))
    lines.append('Content-Length: %d' % len(body))
    lines.append('Connection: close')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1') + body


# ---------------------------------------------------------------- 上游请求

def forward_upstream(host, path, method, headers, body):
    """
    向真实 Apple 端点发起请求，返回 (status, headers, body)。

    ⚠️ 这是阻塞函数，调用方必须用 await _run_blocking(...) 包裹。
    """
    import requests

    forward_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    forward_headers['Host'] = host
    # 关键：必须禁用压缩，否则拿到 gzip 无法解析 protobuf
    forward_headers['Accept-Encoding'] = 'identity'

    session = requests.Session()
    session.trust_env = False          # 忽略环境里的代理设置
    try:
        try:
            response = session.request(
                method, 'https://%s%s' % (host, path),
                data=body, headers=forward_headers, timeout=15, verify=True,
            )
            return response.status_code, dict(response.headers), response.content
        except requests.exceptions.RequestException as exc:
            # 国内端点（高德）从境外常不可达，回退到全球端点
            if host == 'gs-loc-cn.apple.com':
                log('上游 %s 不可达（%s），回退到 gs-loc.apple.com'
                    % (host, type(exc).__name__))
                fallback_headers = dict(forward_headers)
                fallback_headers['Host'] = 'gs-loc.apple.com'
                response = session.request(
                    method, 'https://gs-loc.apple.com%s' % path,
                    data=body, headers=fallback_headers, timeout=15, verify=True,
                )
                return response.status_code, dict(response.headers), response.content
            raise
    finally:
        session.close()


# ---------------------------------------------------------------- 连接处理

def _extract_host_port(target):
    host, _, port = target.partition(':')
    try:
        port = int(port) if port else 443
    except ValueError:
        port = 443
    return host.strip().lower(), port


def parse_sni(client_hello):
    """从 TLS ClientHello 中提取 SNI。"""
    try:
        if len(client_hello) < 44 or client_hello[0] != 0x16:
            return None
        if client_hello[5] != 0x01:                      # 必须是 ClientHello
            return None
        pos = 5 + 4 + 2 + 32                             # record + handshake头 + version + random
        sid_len = client_hello[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack('!H', client_hello[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = client_hello[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack('!H', client_hello[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(client_hello))
        while pos + 4 <= end:
            ext_type = struct.unpack('!H', client_hello[pos:pos + 2])[0]
            ext_len = struct.unpack('!H', client_hello[pos + 2:pos + 4])[0]
            pos += 4
            if ext_type == 0:                            # server_name
                inner = pos + 2                          # 跳过 server_name_list 长度
                if client_hello[inner] == 0:             # host_name 类型
                    name_len = struct.unpack('!H', client_hello[inner + 1:inner + 3])[0]
                    return client_hello[inner + 3:inner + 3 + name_len].decode('ascii', 'replace')
            pos += ext_len
    except Exception:
        return None
    return None


async def peek_client_hello(sock, timeout=PEEK_TIMEOUT):
    """
    窥探连接开头字节，判断是 CONNECT 代理还是直连 TLS。**不消费数据**。

    异步实现：MSG_PEEK 不阻塞地取数据；若尚无数据则让出事件循环等待。
    与原实现的 sleep 轮询不同，这里不占用线程。
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    data = b''
    while True:
        try:
            data = sock.recv(4096, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            if loop.time() >= deadline:
                break
            # 让出事件循环，等 fd 可读（不阻塞、不占线程）
            await asyncio.sleep(0.02)
            continue
        except OSError:
            break

        if not data:
            break
        if data[0] != 0x16:
            return data                                  # 不是 TLS，多半是 CONNECT
        if len(data) >= 5:
            record_len = struct.unpack('!H', data[3:5])[0]
            if len(data) >= 5 + record_len:
                return data[:5 + record_len]
        await asyncio.sleep(0.02)
    return data


async def _serve_over_tls(reader, transport, client_ip, host):
    """
    TLS 握手完成后，处理 HTTP 请求并改写响应。

    ⚠️ 两个关键约束（踩过的坑）：
      1. reader 必须是**原 protocol 持有的那个** reader，
         start_tls 之后数据仍喂给它；这里若新建 StreamReader 会永远读不到数据。
      2. transport 必须是 start_tls **返回的新 transport**（_SSLProtocolTransport），
         用旧的裸 socket transport 写会发不出数据。
    """
    try:
        raw_request = await recv_until_stream(reader, b'\r\n\r\n')
    except Exception as exc:
        log('%s 读取请求失败：%s' % (client_ip, exc))
        return
    if not raw_request:
        return
    method, path, _version, headers, leftover = parse_http_request(raw_request)
    body = await read_request_body_stream(reader, headers, leftover)

    is_wloc = path == WLOC_PATH or path.startswith(WLOC_PATH + '?')
    location = await _run_blocking(lookup_locked_location, client_ip) if is_wloc else None

    try:
        status, resp_headers, resp_body = await _run_blocking(
            forward_upstream, host, path, method, headers, body)
    except Exception as exc:
        log('%s %s %s 上游请求失败：%s' % (client_ip, method, path, exc))
        # 上游不可用时，直接用请求里的 BSSID 构造响应，保证改写仍然生效
        if is_wloc and location is not None:
            built = _build_fallback(body, location[0], location[1])
            if built is not None:
                log('%s 上游失败，已改用构造响应（%.6f,%.6f）'
                    % (client_ip, location[0], location[1]))
                transport.write(build_http_response(
                    200, {'Content-Type': 'application/octet-stream'}, built))
                return
        transport.write(build_http_response(502, {}, b''))
        return

    if is_wloc:
        encoding = '无'
        for key, value in resp_headers.items():
            if key.lower() == 'content-encoding':
                encoding = value
        log('%s %s %s 上游响应：%d 字节，Content-Encoding=%s，头部=%s'
            % (client_ip, method, path, len(resp_body), encoding,
               binascii.hexlify(resp_body[:16]).decode()))
        if location is None:
            log('%s %s %s → 上游 %d，未锁定（IP 无会话或无坐标），原样返回 %d 字节'
                % (client_ip, method, path, status, len(resp_body)))
        else:
            mutated = rewrite_response(resp_body, location[0], location[1], body)
            if mutated is None:
                log('%s %s %s → 上游 %d，改写未生效，原样返回 %d 字节'
                    % (client_ip, method, path, status, len(resp_body)))
            else:
                log('%s %s %s → 上游 %d，已改写为 %.6f,%.6f（%d → %d 字节）'
                    % (client_ip, method, path, status,
                       location[0], location[1], len(resp_body), len(mutated)))
                resp_body = mutated
    else:
        log('%s %s %s → 上游 %d，透传 %d 字节'
            % (client_ip, method, path, status, len(resp_body)))

    payload = build_http_response(status, resp_headers, resp_body)
    transport.write(payload)
    # 关键：必须等 TLS 层把数据（含 close_notify）真正推出去再返回，
    # 否则 handle_client 的 finally 会立即 close，客户端收到 RST 而非正常 EOF。
    try:
        await asyncio.sleep(0.05)
    except Exception:
        pass


async def recv_until_stream(reader, marker, limit=MAX_HEADER):
    """从 StreamReader 读取直到 marker。"""
    data = b''
    while marker not in data:
        if len(data) > limit:
            raise ValueError('header too large')
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
    return data


async def read_request_body_stream(reader, headers, leftover):
    """从 StreamReader 读取请求体。"""
    lowered = {k.lower(): v for k, v in headers.items()}
    if lowered.get('transfer-encoding', '').lower() == 'chunked':
        raise ValueError('chunked body unsupported')
    try:
        length = int(lowered.get('content-length', '0'))
    except ValueError:
        length = 0
    if length > MAX_BODY:
        raise ValueError('body too large')
    body = leftover[:length]
    if len(body) < length:
        need = length - len(body)
        try:
            body += await reader.readexactly(need)
        except asyncio.IncompleteReadError as exc:
            body += exc.partial
    if len(body) != length:
        raise ValueError('incomplete body')
    return body


async def handle_client(client_sock):
    """单连接的协程入口（替代原 handle_client 线程函数）。"""
    loop = asyncio.get_running_loop()
    client_sock.setblocking(False)
    try:
        client_ip = client_sock.getpeername()[0]
    except Exception:
        client_ip = 'unknown'

    transport = None
    sock_handed_over = False        # 一旦交给 connect_accepted_socket，就由 transport 负责关闭
    try:
        head = await peek_client_hello(client_sock)
        if not head:
            return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_FILE, KEY_FILE)

        is_direct_tls = (head[0] == 0x16)
        if is_direct_tls:
            # 直连 TLS 模式（DNS 劫持路径）：设备直接连到 10.10.0.1:443
            host = (parse_sni(head) or 'gs-loc.apple.com').lower()
            if host not in ALLOWED_HOSTS:
                log('%s 直连 TLS 的 SNI=%s 非目标域名，按 gs-loc.apple.com 处理'
                    % (client_ip, host))
                host = 'gs-loc.apple.com'
        else:
            # CONNECT 代理模式（PAC 路径）
            raw_connect = await recv_connect_header(client_sock)
            if not raw_connect:
                return
            first_line = raw_connect.split(b'\r\n', 1)[0].decode('latin-1')
            parts = first_line.split()
            if len(parts) < 2 or parts[0].upper() != 'CONNECT':
                log('%s 非 CONNECT 请求，关闭：%r' % (client_ip, first_line))
                return
            host, _port = _extract_host_port(parts[1])
            if host not in ALLOWED_HOSTS:
                log('%s 请求非目标域名，拒绝：%s' % (client_ip, host))
                return
            await loop.sock_sendall(
                client_sock, b'HTTP/1.1 200 Connection Established\r\n\r\n')

        # ---- 服务端 TLS 握手（真异步）----
        # reader 由 protocol 持有；start_tls 之后数据仍喂给同一个 reader，
        # 因此必须把这个 reader 传下去，不能另建。
        reader = asyncio.StreamReader(limit=MAX_HEADER)
        protocol = asyncio.StreamReaderProtocol(reader)
        base_transport, _ = await loop.connect_accepted_socket(
            lambda: protocol, client_sock)
        # fd 的所有权已转移给 transport：后续不能再直接 client_sock.close()，
        # 否则会和 TLS 层的 flush 竞争，导致客户端收到 RST（ConnectionResetError）。
        sock_handed_over = True

        try:
            new_transport = await asyncio.wait_for(
                loop.start_tls(base_transport, protocol, context, server_side=True),
                timeout=TLS_HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            log('%s TLS 握手超时' % client_ip)
            return
        except ssl.SSLError as exc:
            log('%s TLS 握手失败（可能未信任根证书）：%s' % (client_ip, exc))
            return
        except Exception as exc:
            log('%s TLS 握手异常：%s' % (client_ip, exc))
            return

        if new_transport is None:
            log('%s TLS 握手未完成' % client_ip)
            return
        # 写入必须用 start_tls 返回的新 transport（_SSLProtocolTransport）
        transport = new_transport

        if is_direct_tls:
            log('%s 直连 TLS 命中 %s' % (client_ip, host))

        await _serve_over_tls(reader, transport, client_ip, host)

    except Exception as exc:
        log('%s 连接处理异常：%s' % (client_ip, exc))
    finally:
        if transport is not None:
            # 优雅关闭：让 TLS 层写完缓冲再关（close 前先 pause 写入非必需）。
            try:
                transport.close()
            except Exception:
                pass
        elif not sock_handed_over:
            # 只有在 fd 尚未移交时才自行关闭，避免与 transport 抢同一个 fd
            try:
                client_sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------- 服务启动

async def serve_port(host, port, stop_event):
    """在指定地址/端口上启动异步监听（自行管理裸 socket）。"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((host, port))
        server_sock.listen(LISTEN_BACKLOG)
        server_sock.setblocking(False)
    except OSError as exc:
        # 必须显式记录：否则表现为「服务在跑但端口没监听」
        log('❌ 无法监听 %s:%d —— %s' % (host, port, exc))
        try:
            server_sock.close()
        except Exception:
            pass
        return

    log('wloc-proxy 已监听 %s:%d（asyncio，backlog=%d）'
        % (host, port, LISTEN_BACKLOG))

    loop = asyncio.get_running_loop()
    while not stop_event.is_set():
        try:
            client_sock, client_addr = await loop.sock_accept(server_sock)
        except asyncio.CancelledError:
            break
        except OSError as exc:
            log('accept 失败：%s' % exc)
            await asyncio.sleep(0.1)
            continue
        # 每条连接一个协程（而非线程）
        asyncio.ensure_future(handle_client(client_sock))

    try:
        server_sock.close()
    except Exception:
        pass


async def start_proxy(host, ports):
    """在多个端口上同时监听（9999 走 PAC 代理模式，443 走 DNS 直连模式）。"""
    global _BLOCKING_POOL
    _BLOCKING_POOL = ThreadPoolExecutor(max_workers=UPSTREAM_POOL_SIZE,
                                       thread_name_prefix='wloc-io')

    stop_event = asyncio.Event()
    tasks = [asyncio.ensure_future(serve_port(host, port, stop_event))
             for port in ports]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        stop_event.set()
        raise


# ---------------------------------------------------------------- 自检

def _selftest():
    original_lat, original_lng = 39.9087, 116.3975
    target_lat, target_lng = 41.7963, 123.4528

    original_location = b''.join([
        encode_varint_field(1, int(round(original_lat * COORD_SCALE))),
        encode_varint_field(2, int(round(original_lng * COORD_SCALE))),
        encode_varint_field(3, 65),
        encode_varint_field(5, 44),
    ])
    device_a = encode_bytes_field(1, b'aa:bb:cc:dd:ee:ff') + encode_bytes_field(2, original_location)
    device_b = encode_bytes_field(1, b'11:22:33:44:55:66') + encode_bytes_field(2, original_location)

    payload = b''.join([
        encode_bytes_field(2, device_a),
        encode_bytes_field(2, device_b),
        encode_varint_field(3, 5),
        encode_varint_field(4, 7),
        encode_bytes_field(5, b'com.apple.locationd'),
        encode_varint_field(33, 1),
        encode_varint_field(99, 12345),          # 未知字段，应保留
    ])
    body = RESPONSE_PREFIX + bytes([(len(payload) >> 8) & 0xFF, len(payload) & 0xFF]) + payload

    out = rewrite_response(body, target_lat, target_lng)
    assert out is not None, '改写返回 None'
    assert out[:8] == RESPONSE_PREFIX, '前缀不匹配'
    declared = (out[8] << 8) | out[9]
    new_payload = out[10:10 + declared]
    assert len(new_payload) == declared, '长度字段与实际不符'

    top = parse_fields(new_payload)
    tags = [f[0] for f in top]
    for dropped in (3, 4, 33):
        assert dropped not in tags, '字段 %d 应被删除' % dropped
    assert 5 in tags, '字段 5 应保留'
    assert 99 in tags, '未知字段 99 应保留'

    devices = [f for f in top if f[0] == 2]
    assert len(devices) == 2, 'WifiDevice 数量应为 2，实际 %d' % len(devices)
    for device in devices:
        sub = parse_fields(device[2])
        assert sub[0][0] == 1, 'bssid 字段应为 1'
        assert sub[0][2] in (b'aa:bb:cc:dd:ee:ff', b'11:22:33:44:55:66'), 'bssid 被破坏'
        location = [f for f in sub if f[0] == 2][0][2]
        values = {f[0]: f[2] for f in parse_fields(location)}
        assert values[1] == int(round(target_lat * COORD_SCALE)), '纬度错误：%s' % values[1]
        assert values[2] == int(round(target_lng * COORD_SCALE)), '经度错误：%s' % values[2]
        assert values[3] == H_ACCURACY
        assert values[4] == UNKNOWN_VALUE_4
        assert values[5] == ALTITUDE
        assert values[6] == V_ACCURACY
        assert values[11] == MOTION_ACTIVITY_TYPE
        assert values[12] == MOTION_ACTIVITY_CONFIDENCE

    # 消息类型变体（实测见过 00 01 / 00 03），必须同样能改写
    alt_prefix = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00])
    alt_body = alt_prefix + bytes([(len(payload) >> 8) & 0xFF,
                                   len(payload) & 0xFF]) + payload
    alt_out = rewrite_response(alt_body, target_lat, target_lng)
    assert alt_out is not None, '消息类型 00 03 的响应改写失败'
    assert alt_out[:8] == alt_prefix, '信封头应原样保留（含消息类型）'
    alt_declared = (alt_out[8] << 8) | alt_out[9]
    alt_devices = [f for f in parse_fields(alt_out[10:10 + alt_declared]) if f[0] == 2]
    assert len(alt_devices) == 2, '00 03 变体：WifiDevice 数量不对'
    alt_loc = parse_fields(parse_fields(alt_devices[0][2])[1][2])
    alt_values = {f[0]: f[2] for f in alt_loc}
    assert alt_values[1] == int(round(target_lat * COORD_SCALE)), '00 03 变体：纬度错误'
    print('  消息类型变体 00 03：改写成功，信封头保留')

    # 无 WifiDevice 时应回退
    empty_payload = encode_varint_field(3, 1)
    empty_body = RESPONSE_PREFIX + bytes([(len(empty_payload) >> 8) & 0xFF,
                                          len(empty_payload) & 0xFF]) + empty_payload
    assert rewrite_response(empty_body, target_lat, target_lng) is None, '无设备时应回退'

    # 脏数据不应抛异常
    assert rewrite_response(b'\x00\x01\x02', target_lat, target_lng) is None, '脏数据应回退'
    assert rewrite_response(b'', target_lat, target_lng) is None, '空数据应回退'

    print('SELFTEST PASS')
    print('  原始坐标 %.4f,%.4f → 目标坐标 %.4f,%.4f' % (original_lat, original_lng,
                                                          target_lat, target_lng))
    print('  WifiDevice 数=%d，删除字段 3/4/33，保留字段 5/99' % len(devices))
    print('  载荷 %d 字节 → %d 字节' % (len(payload), len(new_payload)))


# ---------------------------------------------------------------- 入口

def main():
    if '--selftest' in sys.argv:
        _selftest()
        return

    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    ports = [int(p) for p in args[0].split(',')] if args else [DEFAULT_PORT]
    host = args[1] if len(args) > 1 else DEFAULT_HOST

    for path in (CERT_FILE, KEY_FILE):
        if not os.path.exists(path):
            sys.stderr.write('缺少证书文件：%s\n' % path)
            sys.exit(1)

    try:
        asyncio.run(start_proxy(host, ports))
    except KeyboardInterrupt:
        log('收到中断，退出')


if __name__ == '__main__':
    main()
