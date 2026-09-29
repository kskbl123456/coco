# coco

iOS 虚拟定位系统的服务端实现。

## 这是什么

通过 iOS 描述文件（`.mobileconfig`）在设备上安装一条 IKEv2 VPN，
把 Apple 定位接口（`gs-loc.*.apple.com`）的请求劫持到自建服务端做 MITM 改写，
使设备及其依赖系统定位的 App 读到伪造的经纬度。

> 仅供本人自用与学习研究。

## 组件

| 文件 | 作用 | 监听 |
|---|---|---|
| `wloc_proxy.py` | 定位代理（TLS MITM + Apple WLoc protobuf 坐标改写） | `10.10.1.1:9999`（PAC）/ `:443`（直连） |
| `wloc_dns.py` | 定位 DNS，把 gs-loc 域名解析到隧道内网关 | `10.10.1.1:53` |
| `app.py` | Flask 用户面板：授权码登录 + 下发描述文件 | `:5000`（nginx 反代） |
| `wloc_users.py` | 用户体系（授权码 / Bearer token / 设备绑定） | — |
| `wloc_keygen.py` | Keygen.sh 授权集成 | — |
| `static/` | 前端单文件页面 | — |

## 两条拦截链路

- **A · PAC**：设备拉 `http://10.10.1.1:8888/network/route.pac` → `PROXY 10.10.1.1:9999`
- **B · DNS 直连**：分域 DNS 把 gs-loc 域名解析到 `10.10.1.1` → 设备直连 `:443`（TLS MITM）

隧道只承载内网段 + 定位接口流量，公网流量不走隧道（split-tunnel）。

## Apple WLoc 协议要点

- 接口 `POST https://gs-loc.apple.com/clls/wloc`
- 响应信封：`version(2)` + `0000` + `msgtype(2)` + `0000` + `len(u16BE)` + payload
  - **msgtype 会变**（`0001`/`0003`），不可写死
- 坐标是 **varint 定点 `round(x × 1e8)`**，不是 double
- 需改写的实体：
  - `f2` WifiDevice → 内部 `f2` Location
  - `f22` / `f24` 基站实体 → 内部 `f5` Location
  - 两类 Location 的 schema **不同**，只能替换经纬度子字段 1/2，其余原样保留

## 部署与回滚

各组件均配有 `deploy_*.sh` / `rollback-*.sh`，带 MD5 白名单校验。

## 注意

仓库**不含**任何凭据、私钥与用户数据库。部署所需的密钥文件需单独配置：

- `/etc/wloc-web/vpn-identity.env`（Fernet 凭据加密密钥）
- `/etc/wloc-web/keygen.json`（Keygen API 凭据）
- `/etc/ipsec.d/private/`（证书私钥）
- `/etc/ipsec.d/wloc-users.secrets`（EAP 凭据）
