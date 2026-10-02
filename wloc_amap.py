#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""高德地图 Key 管理 —— 服务端持有，登录后下发

★ 为什么要有这个模块

  高德 Key 和 securityJsCode 如果**写在前端 HTML 里**，任何人查看网页源码
  就能拿到，直接盗用你的配额（甚至冒用账号）。
  正确做法是**登录后由服务端下发**（学 astrace 的 `/api/user/map-bootstrap`）。

★ 为什么需要多账号轮换

  高德**个人开发者「搜索类」配额只有 100 次/日**（企业 1000，商用 10000）。
  一个 key 对几十人的服务根本不够，所以要注册多个账号、用完自动切。
  本模块按「连续失败到阈值就切下一个」的简单策略轮换。

配置文件 /etc/wloc-web/amap.json（chmod 600，不要提交到代码库）：

    {
      "keys": [
        {"key": "高德Key", "securityJsCode": "安全密钥", "accountId": "账号备注"},
        {"key": "……", "securityJsCode": "……", "accountId": "备用账号"}
      ],
      "failThreshold": 3
    }

也支持环境变量（单 key 场景）：
    AMAP_KEY / AMAP_SECURITY_JS_CODE / AMAP_ACCOUNT_ID

状态文件 /etc/wloc-web/amap-state.json（自动生成）：
    {"date": "2026-10-02", "activeIndex": 0, "failures": {"0": 2}}
"""
import os
import json
import time
import threading

CONFIG_PATH = os.environ.get('WLOC_AMAP_CONFIG', '/etc/wloc-web/amap.json')
STATE_PATH = os.environ.get('WLOC_AMAP_STATE', '/etc/wloc-web/amap-state.json')
DEFAULT_FAIL_THRESHOLD = 3

_lock = threading.Lock()


# ---------------------------------------------------------------- 配置
def load_config():
    """读配置。返回 {'keys': [...], 'failThreshold': n}；无配置时 keys 为空。"""
    cfg = {'keys': [], 'failThreshold': DEFAULT_FAIL_THRESHOLD}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            if isinstance(data.get('keys'), list):
                cfg['keys'] = [k for k in data['keys'] if isinstance(k, dict) and k.get('key')]
            if isinstance(data.get('failThreshold'), int) and data['failThreshold'] > 0:
                cfg['failThreshold'] = data['failThreshold']
    except Exception:
        pass

    # 环境变量兜底（单 key）
    env_key = os.environ.get('AMAP_KEY')
    if env_key and not cfg['keys']:
        cfg['keys'] = [{
            'key': env_key,
            'securityJsCode': os.environ.get('AMAP_SECURITY_JS_CODE', ''),
            'accountId': os.environ.get('AMAP_ACCOUNT_ID', 'env'),
        }]
    return cfg


def is_configured():
    return len(load_config()['keys']) > 0


# ---------------------------------------------------------------- 状态
def _today():
    return time.strftime('%Y-%m-%d')


def _load_state():
    st = {'date': _today(), 'activeIndex': 0, 'failures': {}}
    try:
        with open(STATE_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            st.update({k: data[k] for k in ('date', 'activeIndex', 'failures') if k in data})
    except Exception:
        pass
    # 跨天重置
    if st.get('date') != _today():
        st = {'date': _today(), 'activeIndex': 0, 'failures': {}}
    if not isinstance(st.get('failures'), dict):
        st['failures'] = {}
    return st


def _save_state(st):
    try:
        tmp = STATE_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(st, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_PATH)
    except Exception:
        pass


# ---------------------------------------------------------------- 对外
def get_active():
    """返回当前应使用的那把 key（dict），没有可用 key 时返回 None。

    返回的 dict 一定含 key / securityJsCode / accountId / index 四个键。
    """
    cfg = load_config()
    keys = cfg['keys']
    if not keys:
        return None

    with _lock:
        st = _load_state()
        idx = st.get('activeIndex', 0)
        if not isinstance(idx, int) or idx < 0 or idx >= len(keys):
            idx = 0
        k = dict(keys[idx])
        k['index'] = idx
        k['securityJsCode'] = k.get('securityJsCode', '')
        k['accountId'] = k.get('accountId', 'key%d' % idx)
        return k


def report_failure(account_id=None, reason=''):
    """上报某个 key 失效。连续失败到阈值就切到下一个。

    返回 (switched: bool, new_index: int)
    """
    cfg = load_config()
    keys = cfg['keys']
    if not keys:
        return False, -1

    with _lock:
        st = _load_state()
        idx = st.get('activeIndex', 0)
        if not isinstance(idx, int) or idx < 0 or idx >= len(keys):
            idx = 0

        # 允许按 accountId 定位（前端上报时带的是 accountId）
        if account_id:
            for i, k in enumerate(keys):
                if k.get('accountId') == account_id:
                    idx = i
                    break

        fails = st['failures']
        cur = int(fails.get(str(idx), 0)) + 1
        fails[str(idx)] = cur

        switched = False
        if cur >= cfg['failThreshold'] and len(keys) > 1:
            st['activeIndex'] = (idx + 1) % len(keys)
            switched = True
        _save_state(st)

    return switched, st.get('activeIndex', idx)
