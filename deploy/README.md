# deploy/ —— 部署产物

仓库根目录是**代码**，这里是**部署产物**：systemd 单元、环境变量模板、nginx 配置、部署脚本。

> ⚠️ 这些文件在原仓库里是缺失的（只存在于服务器上），2026-10-02 按接口契约重建。

---

## 文件

| 文件 | 作用 |
|---|---|
| `deploy.sh` | 一键部署：装依赖 → 建用户 → 铺代码 → 建 venv → 签证书 → 装单元 → 启动 |
| `vpn_sync.py` | **VPN 账户与会话同步器**（见下，这是最容易被漏掉的一环） |
| `env.example` | 环境变量模板（**不是**生产值，部署后按需改） |
| `nginx.conf` | nginx 站点配置（公网面板 + **隧道内敏感接口**） |
| `units/` | 6 个 systemd 单元 |

---

## 用法

```bash
# ① 把仓库内容传到服务器
scp -r . root@<服务器>:/tmp/wloc-src/

# ② 执行部署
ssh root@<服务器> 'bash /tmp/wloc-src/deploy/deploy.sh'
```

`deploy.sh` 会：

1. 备份现有 ipsec 配置到 `/opt/wloc-backup/pre-*`
2. 安装 `nginx` / `python3-venv` / `python3-pip` / `openssl`
3. 建 `wloc` 系统用户
4. 把代码铺到 `/opt/wloc-web`，建 venv 并装依赖（用清华源）
5. 用现有 CA 签发代理证书（`gs-loc.apple.com`）
6. 装环境变量 + systemd 单元 + nginx 站点
7. **检查并补上两个致命项**（见下）
8. 启动服务并自检

---

## ★★ 两个必查项（少了任何一个，功能都是坏的）

### ① `/etc/ipsec.conf` 必须有 `leftsubnet`

```conf
conn wloc-xxx
    leftsubnet=10.10.1.1/32
```

**不加的后果**：VPN 能连上，`ipsec statusall` 显示 `ESTABLISHED`，
但 **`bytes_i / bytes_o` 恒为 0**，定位完全不生效。

因为流量选择器会默认取服务器网卡 IP，只允许访问服务器自身，
而客户端的定位流量要发往 `10.10.1.1`（代理/DNS 地址），不在选择器里 → 包根本不进隧道。

`deploy.sh` 会自动检测并补上。

### ② `/etc/ipsec.secrets` 必须 `include` 账号文件

```
include /etc/ipsec.d/wloc-users.secrets
```

**不加的后果**：手机连 VPN 报 **`no EAP key found`** → `EAP-MS-CHAPv2 verification failed`
→ 表现为「连不上」。

strongSwan **只读 `/etc/ipsec.secrets`**，把账号写进别的文件但不 include，charon 根本不知道。
`deploy.sh` 会自动检测并补上；`vpn_sync.py` 每次运行也会自愈。

---

## `vpn_sync.py` 干什么

由 `wloc-vpn-sync.timer` **每 5 秒**跑一次，做两件事：

| 做什么 | 缺了会怎样 |
|---|---|
| 把 `vpn_identities` 表写成 strongSwan 的 EAP 凭据文件，并 `ipsec rereadsecrets` | **面板建的 VPN 账号登不进来** |
| 解析 `ipsec leases` 填 `vpn_active_sessions` 表 | **代理查不到用户 → 改写失效，设备显示真实位置** |

> `ipsec leases` 的格式：`IP   online|offline   '身份'`

---

## ⚠️ 环境变量文件不会被覆盖

`deploy.sh` 里 `env` **只在新装时写入**，已存在就保留。

原因：`env` 是**部署状态**不是代码 —— 上线后手工调过的东西
（比如把 `WLOC_REMOTE_ID` 从 IP 改成域名）不能被模板冲掉。

**2026-10-02 实际踩过**：用过期模板覆盖 → 描述文件 `RemoteIdentifier` 变回 IP
→ 与 `ipsec.conf` 的 `leftid` 不匹配 → 手机连 VPN **秒断**。

日志特征（一眼定位）：
```
[CFG] looking for peer configs matching <本地IP>[<客户端发的身份>]...
[CFG] no matching peer config found
[ENC] generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]
```
> 把方括号里的身份和 `leftid` 一对比就知道了。

---

## ⚠️ 面板要读的文件，权限都是 `root:wloc` + 640

面板进程以 **`wloc` 用户**运行（不是 root）。这些文件必须让 `wloc` 能读：

| 文件 | 权限 |
|---|---|
| `/etc/wloc-web/env` | `600 root:root`（只给 systemd 读，服务进程由 systemd 注入） |
| `/etc/wloc-web/vpn-identity.env` | `640 root:wloc` |
| `/etc/wloc-web/amap.json` | `640 root:wloc` |
| `/etc/wloc-web/brand.json` | `640 root:wloc` |

写成 `600 root:root` 的话接口会返回 `ok:false`，**而且日志里不一定有明显报错** —— 先查权限。
（这个坑在三个文件上各踩过一次）

---

## 隧道内 API

nginx 额外监听 `10.10.1.1:8443`，敏感接口（设点/状态/地图 Key）只在那个 origin 暴露。

```
公网 origin   https://<面板地址>       → 登录 / me / auth-status / 下载配置
隧道 origin   https://10.10.1.1:8443   → 设点 / 状态 / 地图 Key（敏感）
```

**为什么成立**：隧道流量选择器是 `10.10.1.1/32`，不连 VPN 根本路由不到这个地址
→ **「能访问到隧道地址」就等于「已连 VPN」**，不需要额外鉴权层。

⚠️ `proxy_set_header X-Real-IP $remote_addr` **不能少** —— 后端靠它判断来源 IP。
⚠️ nginx 只绑 `10.10.1.1`，所以公网和内网地址都连不上 8443（这是对的），
也**不需要在云安全组放行 8443**。
