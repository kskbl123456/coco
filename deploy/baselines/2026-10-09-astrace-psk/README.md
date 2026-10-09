# 基线备份说明：astrace 完全对齐 + 双端 PSK

> 备份时间：**2026-10-09 16:38 UTC**（北京时间 2026-10-10 00:38）
> 服务器：`18.179.53.219`（AWS 东京 ap-northeast-1d，内网 `172.31.31.195`）
> 用途：本次「astrace 全量对齐 + iOS 混合认证修复 + 隧道证书重签」改动后的**可回滚基线**

## 一、备份包

| 项 | 值 |
|---|---|
| 文件 | `wloc-baseline-astrace-psk-20261009-20261009-163827.tar.gz` |
| 大小 | 175,357 字节（172K） |
| SHA256 | `02ceb53424dffe878f1578828470d306093314fa1df5c83408f160fcc719c10f` |
| 文件数 | 101 |
| ⚠️ 敏感 | **含私钥 / PSK / 数据库，禁止入库、禁止外发** |

**存放位置（三处）**

1. 服务器：`/opt/wloc-backup/baseline-astrace-psk-20261009/`
2. 本地：`E:/dingwei2/backup/baseline-astrace-psk-20261009/`
3. GitHub：**不入库**（`.gitignore` 未拦 `.tar.gz`，靠人工纪律 + 本说明约束）

## 二、这份基线固化了什么

### ① 认证改为「双端 PSK」（本次最关键修复）

`/etc/ipsec.conf`：`leftauth=pubkey` → **`leftauth=psk`**（配合原有 `rightauth=psk`）

- 根因：iOS 拒绝混合认证模式的 `IKE_AUTH response`，表现为连上 1 秒内自拆、无限重连
- 详见 `E:/dingwei2/连VPN秒断开-根因与修复.md`
- ⚠️ 旧版 `ipsec.conf` 无 `send_cert` 关键字（swanctl 语法），对应写法是 `leftsendcert`

### ② 隧道内 API 证书 SAN 跟随地址变更

`/etc/nginx/ssl/tunnel.pem`：SAN `IP:10.10.1.1` → **`IP:10.10.0.1, IP:10.10.1.1, DNS:tunnel.wloc`**

- 同一 CA（`wloc-cn-poc-ca-cert.pem`）重签，**根证书未变 → 设备免重新信任**
- 修复面板「VPN 未连接」误判

### ③ PAC 改 `http://` + 隧道内补 80 端口站点

- `app.py`：`ProxyAutoConfigURLString` 由 `https://` → **`http://apple.819263.xyz/proxy.pac`**（对齐 astrace）
- `/etc/nginx/sites-available/wloc`：新增 `listen 10.10.0.1:80;` 的 PAC 站点
  （缺则客户端连 80 无人监听 → PAC 取不到 → `FallBackAllowed=0` → VPN 被拆）
- `app.py` 删除 `EnableCertificateRevocationCheck` 字段

### ④ 探针脚本目标由写死改动态

- `wloc-external-probe.py` / `wloc-ikev2-probe.sh`：目标从写死 `57.181.170.250`
  → **动态解析 `/etc/wloc-web/vpn-address` 的域名**
- 此前所有 `IP_BLOCKED` 结论均基于错误目标，需重新评估

### ⑤ strongSwan 提案去 `!`

`ike=aes256-sha256-modp2048` · `esp=aes256-sha256-modp2048-modpnone`

## 三、关键文件 MD5（基线校验值）

```
2a5585a999db1694523defacb1eb6945  /etc/ipsec.conf
e41170567be712a6c290e25b61e651f4  /opt/wloc-web/app.py
4731a7fc44c0e24d3713eb106f9f8cc1  /opt/wloc-web/wloc_proxy.py
1de1fc6ab530de232a3fcce865ca7a40  /opt/wloc-web/wloc_dns.py
74503d7541d4cc980f3da518163032a1  /opt/wloc-web/vpn_sync.py
029db3edfd163ec72632b1ded6e2eb80  /etc/nginx/sites-available/wloc
88f36fd67a59ba867aef9fe3e5fb95d3  /etc/nginx/ssl/tunnel.pem
406d71399b705659b1745af1052399ce  /usr/local/bin/wloc-external-probe.py
c88ed0ed5ab43e45411dcfd3fff24b68  /usr/local/bin/wloc-ikev2-probe.sh
29b61b73f45bffa03f7c6d33fe29dcda  /var/www/wloc-pac/proxy.pac
```

> 注意：`MEMORY.md` 里 `app.py` / `ipsec.conf` 的旧 MD5 是 astrace 对齐中途值，
> **以本文件的值为准**（这两项在 10-09 下午还改过 PAC `http://` 与隧道 80 站点）。

## 四、恢复方式

### 方式 A：单文件回滚（推荐，最小影响）

服务器上已有细粒度备份，比整包恢复更安全：

```bash
sudo cp /opt/wloc-backup/ipsec.conf.bak-before-pskboth-*   /etc/ipsec.conf      # 回退双端PSK
sudo cp /etc/nginx/ssl/tunnel.pem.bak-10.10.1.1            /etc/nginx/ssl/tunnel.pem
sudo cp /opt/wloc-backup/app.py.bak-astrace-full-*         /opt/wloc-web/app.py
sudo cp /opt/wloc-backup/nginx-wloc.conf.bak-before-tunnel80-* /etc/nginx/sites-available/wloc
```

回滚后按序重载（**注意不要用 `ipsec restart`**）：

```bash
sudo ipsec reload
sudo systemctl reload nginx
sudo systemctl restart wloc-web
```

### 方式 B：整包恢复

```bash
sudo tar xzf wloc-baseline-astrace-psk-20261009-*.tar.gz -C /tmp/restore
# 按目录结构对应回写；写前先备份现场
```

⚠️ 整包覆盖会同时回退数据库，**仅在严重故障时使用**。

### 方式 C：重新生成备份

```bash
scp -i "C:/Users/s1423/.ssh/wloc-keys/57.181.170.250.pem" \
    E:/dingwei2/deploy/astrace-align/backup_astrace_align.sh ubuntu@18.179.53.219:/tmp/
ssh -i ".../57.181.170.250.pem" ubuntu@18.179.53.219 'sudo bash /tmp/backup_astrace_align.sh'
```

## 五、恢复后必须验证

```bash
# 1. 全部 unit 是否 active（enabled ≠ active）
systemctl is-active wloc-loopback-ip wloc-dns wloc-proxy wloc-web \
  strongswan-starter nginx wloc-vpn-sync.timer wloc-ikev2-probe.timer wloc-external-probe.timer

# 2. charon 是否被 systemd 接管（cgroup 里应同时有 starter + charon）
systemctl status strongswan-starter | grep -E 'cgroup|Active'

# 3. 隧道与改写
sudo ipsec statusall | grep -E 'ESTABLISHED|bytes'
sudo journalctl -u wloc-dns | grep 拦截
tail -50 /var/log/wloc-proxy.log | grep -E '已改写为|改写未生效|透传'   # 透传必须为 0

# 4. PAC 可达
curl -sI https://apple.819263.xyz/proxy.pac
```

## 六、本次基线的已知限制（未解决项）

- ⚠️ **UDP 4500 出方向（服务端→中国）被阻断**——换 IP 仍复现，见
  `E:/dingwei2/换IP后UDP4500被阻断-诊断报告.md`。**本基线不含抗墙修复**。
- ⚠️ 换 IP 后需重签证书（同 CA），并同步 5 处身份配置
- ⚠️ 备份包内含 `wloc.db`（含用户数据与 token），**严禁推送到任何远端**
