#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Keygen 授权对接层

用途：把 WLoc 的用户授权交给 Keygen 统一管理
      （与用户的安卓软件共用同一个 Keygen 账号）

配置：/etc/wloc-web/keygen.json
      {
        "api":     "https://api.keygen.sh",
        "account": "<你的 Account ID 或 slug>",
        "token":   "<API Token，最小权限>",
        "product": "<WLoc 的 Product ID>"
      }
      环境变量 KEYGEN_API / KEYGEN_ACCOUNT / KEYGEN_TOKEN / KEYGEN_PRODUCT 优先级更高

API 说明：
  - 校验授权码（validate-key）**不需要 token**
  - 激活设备（machines）**需要 token**（machine.create 权限）
"""

import json
import os

try:
    import requests
except ImportError:                      # 便于在无 requests 环境做静态检查
    requests = None

CONFIG_PATH = '/etc/wloc-web/keygen.json'
DEFAULT_API = 'https://api.keygen.sh'
TIMEOUT = 12

# validate-key 返回的 code 含义
CODE_MESSAGES = {
    'VALID': '授权有效',
    'NOT_FOUND': '授权码不存在',
    'NO_MATCH': '授权码不存在',
    'NO_MACHINES': '该设备尚未绑定卡密',
    'NO_MACHINE': '该设备尚未绑定卡密',
    'NOT_ACTIVATED': '该设备尚未绑定卡密',
    'FINGERPRINT_SCOPE_MISMATCH': '该设备尚未绑定卡密',
    'TOO_MANY_MACHINES': '该卡密已绑定其他设备，如需换机请联系管理员解绑',
    'MACHINE_LIMIT_EXCEEDED': '该卡密已绑定其他设备，如需换机请联系管理员解绑',
    'FINGERPRINT_SCOPE_REQUIRED': '该卡密要求绑定设备（缺少设备标识）',
    'SUSPENDED': '该卡密已被暂停，请联系管理员',
    'EXPIRED': '该卡密已过期，请购买新卡密',
    'OVERDUE': '授权已逾期',
    'BANNED': '授权已被封禁',
    'RESET': '授权已重置',
}

# 这些 code 表示「卡密有效但设备未绑定」→ 应触发自动激活
NEEDS_ACTIVATION_CODES = {
    'NO_MACHINES', 'NO_MACHINE', 'NOT_ACTIVATED', 'FINGERPRINT_SCOPE_MISMATCH',
}


# ==================== 配置 ====================

def load_config():
    cfg = {'api': DEFAULT_API, 'account': '', 'token': '', 'product': ''}
    try:
        with open(CONFIG_PATH, 'r') as fh:
            cfg.update(json.load(fh))
    except Exception:
        pass
    for key, env in (('api', 'KEYGEN_API'), ('account', 'KEYGEN_ACCOUNT'),
                     ('token', 'KEYGEN_TOKEN'), ('product', 'KEYGEN_PRODUCT')):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    cfg['api'] = (cfg.get('api') or DEFAULT_API).rstrip('/')
    return cfg


def is_configured():
    cfg = load_config()
    return bool(cfg.get('account'))


def _headers(cfg, with_token=True):
    headers = {
        'Accept': 'application/vnd.api+json',
        'Content-Type': 'application/vnd.api+json',
    }
    if with_token and cfg.get('token'):
        headers['Authorization'] = 'Bearer ' + cfg['token']
    return headers


def _msg(code, detail=''):
    """把 Keygen 的 code 转成中文提示。**不直接把英文 detail 抛给用户。**"""
    base = CODE_MESSAGES.get(code)
    if base:
        return base
    if not code:
        return '授权校验失败'
    return '授权校验失败（%s）' % code


# 激活接口返回的英文原文 → 中文提示
_ACTIVATE_ERROR_MAP = (
    ('machine count',      '该卡密已绑定其他设备，如需换机请联系管理员解绑'),
    ('maximum allowed',    '该卡密已绑定其他设备，如需换机请联系管理员解绑'),
    ('too many machines',  '该卡密已绑定其他设备，如需换机请联系管理员解绑'),
    ('already exists',     '该设备已绑定过此卡密'),
    ('already activated',  '该设备已绑定过此卡密'),
    ('not found',          '授权码不存在'),
    ('expired',            '该卡密已过期，请购买新卡密'),
    ('suspended',          '该卡密已被暂停，请联系管理员'),
    ('banned',             '该卡密已被封禁，请联系管理员'),
)


def _translate_activate_error(detail, status_code=None):
    """把激活失败的英文 detail 翻成中文，避免英文原文漏到界面上。"""
    low = (detail or '').lower()
    for keyword, zh in _ACTIVATE_ERROR_MAP:
        if keyword in low:
            return zh
    if not detail:
        return '设备激活失败（HTTP %s）' % (status_code or '?')
    return '设备激活失败，请联系管理员'


# ==================== 校验授权码 ====================

def validate_key(key, fingerprint=None, product=None):
    """
    校验授权码。返回 (valid: bool, result: dict)

    result 含：valid / code / detail / message / license
    """
    # 先做本地校验（不依赖网络库）
    key = (key or '').strip()
    if not key:
        return False, {'error': '请输入授权码', 'code': 'EMPTY'}

    if requests is None:
        return False, {'error': '缺少 requests 库', 'code': 'NO_REQUESTS'}

    cfg = load_config()
    if not cfg.get('account'):
        return False, {'error': 'Keygen 未配置（缺少 account）', 'code': 'NOT_CONFIGURED'}

    meta = {'key': key}
    scope = {}
    if fingerprint:
        scope['fingerprint'] = fingerprint
    prod = product or cfg.get('product')
    if prod:
        scope['product'] = prod
    if scope:
        meta['scope'] = scope

    url = '%s/v1/accounts/%s/licenses/actions/validate-key' % (cfg['api'], cfg['account'])
    try:
        resp = requests.post(url, headers=_headers(cfg, with_token=False),
                             json={'meta': meta}, timeout=TIMEOUT)
    except Exception as exc:
        return False, {'error': '无法连接 Keygen：%s' % exc, 'code': 'NETWORK_ERROR'}

    if resp.status_code == 404:
        return False, {'error': CODE_MESSAGES['NOT_FOUND'], 'code': 'NOT_FOUND'}
    if resp.status_code >= 400:
        return False, {'error': 'Keygen 返回 %d' % resp.status_code,
                       'code': 'HTTP_%d' % resp.status_code,
                       'raw': resp.text[:300]}

    try:
        body = resp.json()
    except Exception:
        return False, {'error': 'Keygen 返回非 JSON', 'code': 'BAD_RESPONSE'}

    meta_out = body.get('meta') or {}
    valid = bool(meta_out.get('valid'))
    code = meta_out.get('code') or ''
    detail = meta_out.get('detail') or ''

    return valid, {
        'valid': valid,
        'code': code,
        'detail': detail,
        'message': _msg(code, detail),
        'license': body.get('data') or {},
    }


# ==================== 设备管理 ====================

def activate_machine(license_id, fingerprint, license_key=None, name=None, platform='iOS'):
    """
    为某个 license 激活一台设备。返回 (ok, result)

    认证方式（二选一，优先用 license_key）：
      - Authorization: License <授权卡密>   ← license-scoped，**不需要 admin token**
      - Authorization: Bearer <API Token>   ← 需要 token 且要有 machine.create 权限

    参考同类安卓客户端的做法：用卡密自身认证即可完成自绑定。
    """
    if requests is None:
        return False, {'error': '缺少 requests 库'}

    cfg = load_config()
    if not cfg.get('account'):
        return False, {'error': 'Keygen 未配置'}
    if not license_id or not fingerprint:
        return False, {'error': '缺少 license_id 或 fingerprint'}

    key = (license_key or '').strip()
    if key:
        headers = _headers(cfg, with_token=False)
        headers['Authorization'] = 'License ' + key
    elif cfg.get('token'):
        headers = _headers(cfg, with_token=True)
    else:
        return False, {'error': '激活设备需要授权码或 API Token'}

    attributes = {'fingerprint': fingerprint, 'platform': platform}
    if name:
        attributes['name'] = name

    payload = {
        'data': {
            'type': 'machines',
            'attributes': attributes,
            'relationships': {
                'license': {'data': {'type': 'licenses', 'id': license_id}},
            },
        }
    }

    url = '%s/v1/accounts/%s/machines' % (cfg['api'], cfg['account'])
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    except Exception as exc:
        return False, {'error': '无法连接 Keygen：%s' % exc}

    if resp.status_code >= 400:
        detail = ''
        try:
            errs = resp.json().get('errors') or []
            if errs:
                detail = errs[0].get('detail') or errs[0].get('title') or ''
        except Exception:
            pass
        # 英文原文翻成中文，不直接抛给用户
        return False, {'error': _translate_activate_error(detail, resp.status_code),
                       'detail': detail,
                       'code': 'ACTIVATE_%d' % resp.status_code}

    try:
        data = (resp.json() or {}).get('data') or {}
    except Exception:
        return False, {'error': '返回非 JSON'}

    return True, {
        'machine_id': data.get('id'),
        'fingerprint': (data.get('attributes') or {}).get('fingerprint'),
    }


def list_machines(license_id, license_key=None):
    """
    列出某 license 下的设备。返回 (ok, machines)

    同样优先用卡密自身认证（不需要 admin token）。
    """
    if requests is None:
        return False, []
    cfg = load_config()
    if not cfg.get('account') or not license_id:
        return False, []

    key = (license_key or '').strip()
    if key:
        headers = _headers(cfg, with_token=False)
        headers['Authorization'] = 'License ' + key
    elif cfg.get('token'):
        headers = _headers(cfg, with_token=True)
    else:
        return False, []

    url = '%s/v1/accounts/%s/licenses/%s/machines' % (cfg['api'], cfg['account'], license_id)
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code >= 400:
            return False, []
        return True, (resp.json() or {}).get('data') or []
    except Exception:
        return False, []


def deactivate_machine(machine_id, license_key=None):
    """
    解绑设备（换手机时用）。返回 (ok, result)

    同样优先用卡密自身认证（不需要 admin token）。
    """
    if requests is None:
        return False, {'error': '缺少 requests 库'}
    cfg = load_config()
    if not cfg.get('account'):
        return False, {'error': 'Keygen 未配置'}
    if not machine_id:
        return False, {'error': '缺少 machine_id'}

    key = (license_key or '').strip()
    if key:
        headers = _headers(cfg, with_token=False)
        headers['Authorization'] = 'License ' + key
    elif cfg.get('token'):
        headers = _headers(cfg, with_token=True)
    else:
        return False, {'error': '解绑需要授权码或 API Token'}

    url = '%s/v1/accounts/%s/machines/%s' % (cfg['api'], cfg['account'], machine_id)
    try:
        resp = requests.delete(url, headers=headers, timeout=TIMEOUT)
    except Exception as exc:
        return False, {'error': '无法连接 Keygen：%s' % exc}
    if resp.status_code >= 400:
        detail = ''
        try:
            errs = resp.json().get('errors') or []
            if errs:
                detail = errs[0].get('detail') or errs[0].get('title') or ''
        except Exception:
            pass
        return False, {'error': detail or ('解绑失败（HTTP %d）' % resp.status_code),
                       'code': 'DEACTIVATE_%d' % resp.status_code}
    return True, {'machine_id': machine_id}


# ==================== 一步到位：校验 + 自动激活 ====================

def validate_or_activate(key, fingerprint, machine_name=None, product=None):
    """
    完整流程：先校验；若设备未绑定（NO_MACHINES 等），自动激活后重新校验。

    激活用 Authorization: License <授权码>，**不需要 admin API Token**。

    返回 (ok, result)，result 含：
      valid / code / message / license_id / machine_id / activated
    """
    valid, result = validate_key(key, fingerprint=fingerprint, product=product)
    result.setdefault('activated', False)

    if valid:
        lic = result.get('license') or {}
        result['license_id'] = lic.get('id')
        result['expiry'] = (lic.get('attributes') or {}).get('expiry')
        return True, result

    # 卡密有效但设备未绑定 → 自动激活
    if result.get('code') in NEEDS_ACTIVATION_CODES:
        # 先识别「设备数已满」：这种情况不该再尝试激活，直接告知已绑定其他设备
        detail_low = (result.get('detail') or '').lower()
        if 'machine count' in detail_low or 'maximum allowed' in detail_low:
            result['message'] = CODE_MESSAGES['TOO_MANY_MACHINES']
            lic0 = result.get('license') or {}
            result['license_id'] = lic0.get('id')
            return False, result

        lic = result.get('license') or {}
        license_id = lic.get('id')
        if not license_id:
            result['message'] = '卡密有效，但无法获取 license 信息'
            return False, result

        ok, act = activate_machine(license_id, fingerprint,
                                   license_key=key,
                                   name=machine_name, platform='iOS')
        if not ok:
            result['message'] = act.get('error', '设备激活失败')
            result['activate_error'] = act
            return False, result

        # 激活后再校验一次确认
        valid2, result2 = validate_key(key, fingerprint=fingerprint, product=product)
        result2['activated'] = True
        result2['machine_id'] = act.get('machine_id')
        lic2 = result2.get('license') or {}
        result2['license_id'] = lic2.get('id') or license_id
        result2['expiry'] = (lic2.get('attributes') or {}).get('expiry')
        if not valid2 and not result2.get('message'):
            result2['message'] = '激活后校验仍未通过'
        return valid2, result2

    lic = result.get('license') or {}
    result['license_id'] = lic.get('id')
    result['expiry'] = (lic.get('attributes') or {}).get('expiry')
    return False, result


# ==================== 自检 ====================

if __name__ == '__main__':
    import sys

    if '--check-config' in sys.argv:
        cfg = load_config()
        print('配置文件: %s' % CONFIG_PATH)
        print('  api     = %s' % cfg.get('api'))
        print('  account = %s' % (cfg.get('account') or '(未配置)'))
        print('  token   = %s' % (('已配置，长度 %d' % len(cfg.get('token') or ''))
                                  if cfg.get('token') else '(未配置)'))
        print('  product = %s' % (cfg.get('product') or '(未配置)'))
        print()
        print('是否可校验授权码: %s' % ('是' if cfg.get('account') else '否（缺 account）'))
        print('是否可激活设备:   %s' % ('是（用卡密自身认证，不需要 Token）'
                                        if cfg.get('account') else '否（缺 account）'))
        print('是否可解绑设备:   %s' % ('是' if (cfg.get('account') and cfg.get('token'))
                                        else '否（缺 token；也可在 Keygen 后台手动解绑）'))
        sys.exit(0)

    if '--ping' in sys.argv:
        # 用一个不存在的卡密探测连通性（预期返回 NOT_FOUND，说明接口通）
        ok, res = validate_key('AAAA-BBBB-CCCC-DDDD')
        code = res.get('code')
        print('code    = %s' % code)
        print('message = %s' % res.get('message'))
        if code == 'NOT_FOUND':
            print('✅ Keygen 接口连通正常（返回 NOT_FOUND 说明请求被正确受理）')
            sys.exit(0)
        print('⚠️ 返回异常：%s' % (res.get('error') or res))
        sys.exit(1)

    if '--selftest' in sys.argv:
        # 不需要真实凭据的离线自检
        assert _msg('NOT_FOUND') == '授权码不存在', 'code 映射错误'
        assert _msg('NO_MACHINES') == '该设备尚未绑定卡密'
        assert _msg('MACHINE_LIMIT_EXCEEDED') == '该卡密已绑定其他设备，如需换机请联系管理员解绑'
        assert 'NO_MACHINES' in NEEDS_ACTIVATION_CODES, '激活触发码缺失'
        assert 'FINGERPRINT_SCOPE_MISMATCH' in NEEDS_ACTIVATION_CODES
        assert 'EXPIRED' not in NEEDS_ACTIVATION_CODES, '过期不应触发激活'
        assert _msg('') == '授权校验失败', '空 code 兜底错误'
        # 英文原文不能漏到界面上
        assert 'machine count' not in _msg('SOME_UNKNOWN_CODE', 'machine count exceeded')
        assert _translate_activate_error('machine count has exceeded maximum allowed for license (1)') \
            == '该卡密已绑定其他设备，如需换机请联系管理员解绑'
        assert _translate_activate_error('') == '设备激活失败（HTTP ?）'
        assert _translate_activate_error('some weird english') == '设备激活失败，请联系管理员'
        cfg = load_config()
        assert cfg['api'].startswith('http'), 'api 地址异常'
        ok, res = validate_key('')
        assert not ok and res['code'] == 'EMPTY', '空授权码应被拒绝'
        print('  配置读取: OK (api=%s)' % cfg['api'])
        print('  空授权码: 已拒绝')
        print('  code 映射: OK')
        print('SELFTEST PASS')
        sys.exit(0)

    if '--machines' in sys.argv:
        # 列出某卡密已绑定的设备
        idx = sys.argv.index('--machines')
        key = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ''
        ok, res = validate_key(key)
        lic = res.get('license') or {}
        lid = lic.get('id')
        print('license_id = %s' % lid)
        if not lid:
            print('无法获取 license（code=%s）' % res.get('code'))
            sys.exit(1)
        ok2, machines = list_machines(lid, license_key=key)
        print('设备数 = %d' % len(machines))
        for m in machines:
            a = m.get('attributes') or {}
            print('  - id=%s' % m.get('id'))
            print('    fingerprint=%s' % a.get('fingerprint'))
            print('    platform=%s  name=%s' % (a.get('platform'), a.get('name')))
        sys.exit(0 if ok2 else 1)

    if '--validate' in sys.argv:
        # 真实校验（需要凭据）
        idx = sys.argv.index('--validate')
        key = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ''
        fp = None
        if '--fingerprint' in sys.argv:
            fp = sys.argv[sys.argv.index('--fingerprint') + 1]
        ok, res = validate_key(key, fingerprint=fp)
        print('valid=%s' % ok)
        print('code=%s' % res.get('code'))
        print('message=%s' % res.get('message'))
        if res.get('error'):
            print('error=%s' % res['error'])
        sys.exit(0 if ok else 1)

    print('用法:')
    print('  wloc_keygen.py --check-config              检查配置')
    print('  wloc_keygen.py --selftest                  离线自检')
    print('  wloc_keygen.py --validate <授权码> [--fingerprint <机器码>]')
