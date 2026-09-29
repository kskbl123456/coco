#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WLoc 专用 DNS 服务（asyncio 版）

把 Apple 定位域名（gs-loc*.apple.com / gs-loc*.ls-apple.com）解析到本机隧道地址
10.10.1.1，其余域名原样转发给上游解析器。

这样设备会直接连到 10.10.1.1:443，由 wloc_proxy 做 TLS 中间人改写坐标，
完全不依赖 PAC / 代理配置。

用法：
  wloc_dns.py [port] [host]

────────────────────────── 重构说明（2026-09-28）──────────────────────────
原实现用 socketserver.ThreadingUDPServer / ThreadingTCPServer，每个 DNS 请求
起一个线程。1000 台设备同时重连时会瞬间产生上千线程（上游卡顿时更会同时存活），
在 911MB 内存的机器上是唯一的资源单点。

本版本改为单事件循环 + 回调/协程，与 wloc_proxy.py 的并发模型统一：
  * UDP → asyncio.DatagramProtocol（回调式，零额外线程）
  * TCP → asyncio.start_server（协程式，readexactly 处理 2 字节长度前缀）
  * 上游转发 → 异步 datagram 端点，并用 call_later 兜底超时
    （asyncio 的 datagram 没有 settimeout，必须自己实现，否则上游丢包时请求永远挂起）

⚠️ 协议逻辑段（is_target / parse_question / build_response / handle_query 的
   调度部分）与重构前**逐字节一致**，只替换 IO 层。
"""

import os
import sys
import socket
import struct
import asyncio
import datetime

LISTEN_HOST = os.environ.get('WLOC_DNS_HOST', '10.10.1.1')
LISTEN_PORT = int(os.environ.get('WLOC_DNS_PORT', '53'))
REDIRECT_TO = os.environ.get('WLOC_DNS_REDIRECT', '10.10.1.1')
UPSTREAM = os.environ.get('WLOC_DNS_UPSTREAM', '8.8.8.8')
LOG_FILE = os.environ.get('WLOC_DNS_LOG', '/var/log/wloc-dns.log')

TTL = 60
QTYPE_A = 1
QTYPE_AAAA = 28

UPSTREAM_TIMEOUT = 5.0             # 上游解析超时（秒），对齐原 settimeout(5)
TCP_IDLE_TIMEOUT = 10.0            # TCP 连接读超时（秒），对齐原 settimeout(10)
MAX_DNS_MSG = 4096                 # 与原来的 recvfrom(4096) 一致


def _upstream_addr():
    """解析上游地址，支持 'host' 或 'host:port' 两种写法（默认 53）。

    生产用 '8.8.8.8'；本地仿真测试用 '127.0.0.1:15354' 指定非特权端口。
    """
    raw = UPSTREAM.strip()
    if raw.count(':') == 1:
        host, _, port = raw.partition(':')
        try:
            return host, int(port)
        except ValueError:
            return raw, 53
    return raw, 53



def log(message):
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


def is_target(qname):
    """判断是否是 Apple 定位域名。"""
    name = qname.lower().rstrip('.')
    if not name.startswith('gs-loc'):
        return False
    return name.endswith('.apple.com') or name.endswith('.ls-apple.com')


def parse_question(data):
    """解析 DNS 查询，返回 (qname, qtype, qclass, question_bytes) 或 None。"""
    if len(data) < 12:
        return None
    qdcount = struct.unpack('!H', data[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    labels = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            return None
        pos += 1
        if pos + length > len(data):
            return None
        labels.append(data[pos:pos + length].decode('ascii', 'replace'))
        pos += length
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack('!HH', data[pos:pos + 4])
    return '.'.join(labels), qtype, qclass, data[12:pos + 4]


def build_response(query, qtype, question_bytes):
    """构造应答：A 记录指向 REDIRECT_TO；AAAA 返回空答案让设备走 IPv4。"""
    txid = query[:2]
    flags = b'\x81\x80'                      # QR=1, RD=1, RA=1, RCODE=0
    if qtype == QTYPE_A:
        answer = (b'\xc0\x0c'                # 指向 offset 12 的名字指针
                  + struct.pack('!HHIH', QTYPE_A, 1, TTL, 4)
                  + socket.inet_aton(REDIRECT_TO))
        ancount = 1
    else:
        answer = b''
        ancount = 0
    header = txid + flags + struct.pack('!HHHH', 1, ancount, 0, 0)
    return header + question_bytes + answer


# ============================== IO 层（重构部分）==============================

async def forward_async(data, loop):
    """异步把查询原样转发给上游解析器，返回响应字节或 None。

    asyncio 的 datagram 端点没有 settimeout，因此用 Future + call_later 自己实现
    超时兜底：无论成功、失败还是超时，都保证 Future 被解决一次且端点被关闭，
    避免句柄泄漏或请求永久挂起。
    """
    result = loop.create_future()

    def _resolve(value):
        if not result.done():
            result.set_result(value)

    class _Upstream(asyncio.DatagramProtocol):
        """临时上游端点：只关心"第一个回来的包"。

        ⚠️ 关键点（与同步版的语义对齐）：
          * 用**无连接** socket + 显式 sendto(data, (UPSTREAM, 53))，与原实现的
            socket.sendto 完全一致。若用 create_datagram_endpoint(remote_addr=...)，
            在部分平台会产生"已连接" UDP socket，上游的 ICMP 端口不可达会被
            直接投递成 error_received（WinError 10054），把正常请求误判为失败。
          * error_received 里的 ICMP 报错是**软错误**，不能当作最终结论 ——
            真实的同步版同样忽略它，靠 5s 超时兜底。因此这里只记日志，不 resolve。
        """

        def __init__(self):
            self.transport = None
            self.timer = None

        def connection_made(self, transport):
            self.transport = transport
            try:
                transport.sendto(data, _upstream_addr())
            except Exception as exc:
                log('上游发送失败：%s' % exc)
                _resolve(None)

        def datagram_received(self, resp, addr):
            _resolve(resp)

        def error_received(self, exc):
            # 软错误：记录即可，等超时或真实回包决定结果
            log('上游转发警告（忽略）：%s' % exc)

        def connection_lost(self, exc):
            # 端点被关闭而此前仍无结果 → 视为失败（安全兜底，不抛异常）
            if not result.done():
                _resolve(None)

        def shutdown(self):
            if self.timer is not None:
                try:
                    self.timer.cancel()
                except Exception:
                    pass
                self.timer = None
            if self.transport is not None:
                try:
                    self.transport.close()
                except Exception:
                    pass
                self.transport = None

    proto = _Upstream()
    try:
        # ⚠️ 必须给 local_addr —— Python 3.13 的 create_datagram_endpoint 在
        #    既无 local_addr 也无 remote_addr 时会抛 "unexpected address family"。
        #    绑 ('0.0.0.0', 0) = 随机端口 + 无连接语义，等价于原来的裸 UDP socket。
        await loop.create_datagram_endpoint(lambda: proto, local_addr=('0.0.0.0', 0))
    except Exception as exc:
        log('上游转发失败：%s' % exc)
        proto.shutdown()
        return None

    def _on_timeout():
        log('上游转发失败：timeout')
        _resolve(None)

    proto.timer = loop.call_later(UPSTREAM_TIMEOUT, _on_timeout)
    try:
        return await result
    finally:
        proto.shutdown()


async def handle_query_async(data, loop):
    """总调度：命中域名直接构造应答，否则异步转发上游。"""
    parsed = parse_question(data)
    if not parsed:
        return None
    qname, qtype, _qclass, question_bytes = parsed
    if is_target(qname):
        log('拦截 %s (type=%d) → %s' % (qname, qtype, REDIRECT_TO))
        return build_response(data, qtype, question_bytes)
    return await forward_async(data, loop)


class UdpDnsProtocol(asyncio.DatagramProtocol):
    """UDP DNS 协议：每个数据报触发一次 datagram_received 回调（无额外线程）。"""

    def __init__(self, loop):
        self.loop = loop
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # 回调里不能直接 await，用 create_task 派生协程
        self.loop.create_task(self._serve(data, addr))

    async def _serve(self, data, addr):
        try:
            response = await handle_query_async(data, self.loop)
            if response and self.transport is not None:
                self.transport.sendto(response, addr)
        except Exception as exc:
            log('UDP 处理异常（来自 %s）：%s' % (addr[0], exc))

    def error_received(self, exc):
        log('UDP 错误：%s' % exc)


async def handle_tcp(reader, writer, loop):
    """TCP DNS：2 字节大端长度前缀 + 报文体，与 RFC 1035 的 TCP 承载一致。"""
    peer = None
    try:
        peer = writer.get_extra_info('peername')
        header = await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_TIMEOUT)
        length = struct.unpack('!H', header)[0]
        body = await asyncio.wait_for(reader.readexactly(length), TCP_IDLE_TIMEOUT)
        response = await handle_query_async(body, loop)
        if response:
            writer.write(struct.pack('!H', len(response)) + response)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        pass
    except Exception as exc:
        who = peer[0] if peer else '?'
        log('TCP 处理异常（来自 %s）：%s' % (who, exc))
    finally:
        try:
            writer.close()
        except Exception:
            pass


class _UdpEndpoint(asyncio.DatagramProtocol):
    """UDP 监听端点的协议工厂载体（复用 UdpDnsProtocol 即可，此处仅作显式别名）。"""


async def main_async(port, host, loop):
    # UDP
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UdpDnsProtocol(loop), local_addr=(host, port))
    udp_sock = transport.get_extra_info('socket')
    if udp_sock is not None:
        try:
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass

    # TCP
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp(r, w, loop), host, port, reuse_address=True)

    log('wloc-dns 已监听 %s:%d（定位域名 → %s，其余转发 %s）[asyncio]'
        % (host, port, REDIRECT_TO, UPSTREAM))

    async with tcp_server:
        await tcp_server.serve_forever()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else LISTEN_PORT
    host = sys.argv[2] if len(sys.argv) > 2 else LISTEN_HOST

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main_async(port, host, loop))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            loop.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
