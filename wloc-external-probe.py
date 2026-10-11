#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WLoc 外部可达性探针（通过 check-host.net 公共探测网络）

★★ 为什么需要这个：
   本机自探（wloc-ikev2-probe.sh）的流量在 [内网IP <-> 公网IP] 之间回环，
   根本不经过 GFW（tcpdump 已证实：源 172.16.0.10 → 目标 117.72.208.23，
   包未离开本机）。所以要判断「是否被墙」，必须从**真实外部节点**发起。

★ 局限（必读）：
   check-host.net **不支持 UDP 探测**，只支持 TCP / ICMP / HTTP。
   而 IKEv2 是 UDP。所以本脚本**测不了 4500 本身**。
   它能测的是「同一个 IP 的非 UDP 面是否活着」，用来分离两类故障：
     - ICMP/TCP 全通  → IP 活着，若 4500 不通则是 UDP 被针对性阻断
     - ICMP/TCP 全不通 → IP 级封锁（或京东云安全组变更）

   真正的 4500 外部验证，只能用「境外机器跑 ike-scan」这一条路。

用法：
   wloc-external-probe.py                执行一次探测并记录
   wloc-external-probe.py --json         只输出 JSON（不写日志）

依赖：curl（系统自带），无需 pip 包
"""

import json
import socket
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

TARGET = os.environ.get('WLOC_PROBE_TARGET') or socket.gethostbyname((open('/etc/wloc-web/vpn-address').read().strip() or 'ios.819263.xyz'))
LOG = '/var/log/wloc-external-probe.log'
ALERTLOG = '/var/log/wloc-external-alert.log'
STATE = '/var/log/wloc-external-probe.state'
API_BASE = 'https://check-host.net'


def _curl(url, timeout=15):
    """用系统 curl 发请求（避免依赖 requests）"""
    try:
        out = subprocess.run(
            ['curl', '-s', '-m', str(timeout), '-H', 'Accept: application/json', url],
            capture_output=True, timeout=timeout + 5,
        )
        return out.stdout.decode('utf-8', 'replace')
    except Exception as e:
        return json.dumps({'error': str(e)})


def submit_check(kind, host, max_nodes):
    """提交探测请求，返回 request_id"""
    url = f'{API_BASE}/check-{kind}?host={host}&max_nodes={max_nodes}'
    raw = _curl(url)
    try:
        data = json.loads(raw)
    except Exception:
        return None, {'error': 'bad json', 'raw': raw[:200]}
    if data.get('ok') != 1:
        return None, data
    return data.get('request_id'), data


def fetch_result(request_id, retries=6, delay=5):
    """轮询结果"""
    for _ in range(retries):
        time.sleep(delay)
        raw = _curl(f'{API_BASE}/check-result/{request_id}')
        try:
            data = json.loads(raw)
        except Exception:
            continue
        # 所有节点都有结果才算完成（值为 None 表示还在跑）
        if isinstance(data, dict) and data and all(v is not None for v in data.values()):
            return data
    return data if 'data' in dir() else {}


def summarize(result, kind):
    """把结果压成 ok/total 计数"""
    ok = 0
    total = 0
    detail = []
    if not isinstance(result, dict):
        return 0, 0, ['no result']
    for node, res in result.items():
        total += 1
        if not res:
            detail.append(f'{node}:pending')
            continue
        if kind == 'ping':
            # ping 结果形如 [[["TIMEOUT",...]],...]
            try:
                entry = res[0][0] if isinstance(res[0], list) else res[0]
                if isinstance(entry, list) and entry and entry[0] != 'TIMEOUT':
                    ok += 1
                    detail.append(f'{node}:ok')
                else:
                    detail.append(f'{node}:timeout')
            except Exception:
                detail.append(f'{node}:?')
        else:
            # tcp 结果形如 [{"time":...,"address":...}] 或 [{"error":...}]
            try:
                entry = res[0] if isinstance(res, list) else res
                if isinstance(entry, dict) and 'time' in entry:
                    ok += 1
                    detail.append(f'{node}:ok({entry["time"]*1000:.0f}ms)')
                else:
                    detail.append(f'{node}:{entry.get("error","?") if isinstance(entry,dict) else "?"}')
            except Exception:
                detail.append(f'{node}:?')
    return ok, total, detail


def main():
    as_json = '--json' in sys.argv
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    results = {}
    for kind, host, nodes in (
        ('ping', TARGET, 4),
        ('tcp', f'{TARGET}:443', 3),
    ):
        rid, meta = submit_check(kind, host, nodes)
        if not rid:
            results[kind] = {'ok': 0, 'total': 0, 'detail': [f'submit_fail:{meta}']}
            continue
        res = fetch_result(rid)
        ok, total, detail = summarize(res, kind)
        results[kind] = {'ok': ok, 'total': total, 'detail': detail}

    ping = results.get('ping', {})
    tcp = results.get('tcp', {})

    # 判定：只要有一类探通，说明 IP 活着
    if ping.get('ok', 0) > 0 or tcp.get('ok', 0) > 0:
        status = 'IP_ALIVE'
    elif ping.get('total', 0) > 0 or tcp.get('total', 0) > 0:
        status = 'IP_BLOCKED'
    else:
        status = 'UNKNOWN'

    line = (f'{ts} status={status} '
            f'ping={ping.get("ok",0)}/{ping.get("total",0)} '
            f'tcp443={tcp.get("ok",0)}/{tcp.get("total",0)}')

    if as_json:
        print(json.dumps({'line': line, 'results': results}, ensure_ascii=False))
        return 0

    with open(LOG, 'a') as f:
        f.write(line + '  ' + ' | '.join(ping.get('detail', []) + tcp.get('detail', [])) + '\n')

    prev = ''
    if os.path.exists(STATE):
        try:
            prev = open(STATE).read().strip()
        except Exception:
            pass

    if status != prev:
        with open(STATE, 'w') as f:
            f.write(status)
        msg = f'[WLoc 外部探测] {line}'
        subprocess.run(['logger', '-t', 'wloc-external-probe', '-p', 'daemon.warning', msg])
        with open(ALERTLOG, 'a') as f:
            f.write(msg + '\n')
        print(msg)

    # 轮转
    try:
        if os.path.getsize(LOG) > 2_000_000:
            with open(LOG) as f:
                lines = f.readlines()[-3000:]
            with open(LOG, 'w') as f:
                f.writelines(lines)
    except Exception:
        pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
