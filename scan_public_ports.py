#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从外部权威节点探测公网暴露的 TCP 端口。

用 check-host.net 公共 API（全球多国节点），从真正的外部视角判断
15.164.220.99 的哪些端口在公网上可达。

用法：
  python3 scan_public_ports.py [host] [port,port,...]
"""
import json
import sys
import time
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else '15.164.220.99'
PORTS = [int(x) for x in (sys.argv[2].split(',') if len(sys.argv) > 2
                          else '22,80,443,5000,8888,9999'.split(','))]

BASE = 'https://check-host.net'


def api(path):
    req = urllib.request.Request(BASE + path, headers={
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; portscan)',
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())


def main():
    print('目标: %s' % HOST)
    print('端口: %s' % PORTS)
    print('=' * 62)

    reqs = {}
    for p in PORTS:
        try:
            d = api('/check-tcp?host=%s:%d&max_nodes=6' % (HOST, p))
            reqs[p] = d.get('request_id')
            print('提交 %-6d request_id=%s' % (p, reqs[p]))
        except Exception as e:
            print('提交 %-6d 失败: %s' % (p, e))
        time.sleep(0.5)

    print()
    print('等待外部节点回传结果 ...')
    time.sleep(14)

    summary = {}
    for p in PORTS:
        rid = reqs.get(p)
        print()
        print('=== 端口 %d ===' % p)
        if not rid:
            print('  (无 request_id，跳过)')
            summary[p] = 'UNKNOWN'
            continue
        try:
            d = api('/check-result/%s' % rid)
        except Exception as e:
            print('  取结果失败: %s' % e)
            summary[p] = 'UNKNOWN'
            continue

        connected = 0
        total = 0
        for node, res in d.items():
            total += 1
            if res and isinstance(res, list) and res[0]:
                r = res[0]
                if isinstance(r, dict) and r.get('error'):
                    print('  %-26s %s' % (node, r['error']))
                else:
                    connected += 1
                    print('  %-26s ★ CONNECTED  %s' % (node, r))
            else:
                print('  %-26s (无数据)' % node)
        summary[p] = 'OPEN(%d/%d)' % (connected, total) if connected else 'CLOSED(0/%d)' % total

    print()
    print('=' * 62)
    print('汇总（外部视角）:')
    for p in PORTS:
        print('  %-6d %s' % (p, summary.get(p, '?')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
