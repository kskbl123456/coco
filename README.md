# coco — WLoc 虚拟定位服务端

自研**服务端集中式** iOS 虚拟定位系统。手机连上 VPN 后，由服务端中间人改写 Apple WLoc
定位请求，使设备地图显示为指定坐标。

> 端侧客户端参考上游 `github.com/OpenHRTT/wloc`；**服务端实现为本仓库自有代码**。

## 架构

```
iPhone ──IKEv2 VPN──▶ strongSwan（伪装 @gs-loc.apple.com）
                          │
        ┌─────────────────┴──────────────────┐
        │ 路径 A：手动代理 10.10.1.1:9999     │ 路径 B：DNS 直连 10.10.1.1:443
        │      wloc_proxy.py（TLS MITM）      │      wloc_dns.py 把 gs-loc 域名解析到本机
        └─────────────────┬──────────────────┘
                          ▼
              改写 AppleWLoc 响应中的坐标 → 上游 gs-loc.apple.com
```

## 文件

| 文件 | 说明 |
|---|---|
| `app.py` | Flask 面板：授权码登录 + 生成 iOS 描述文件（`_build_mobileconfig`） |
| `wloc_proxy.py` | 定位代理：TLS MITM + AppleWLoc protobuf 坐标改写（含基站实体 f22/f24） |
| `wloc_dns.py` | 定位 DNS：gs-loc 域名劫持 + 上游解析（asyncio） |
| `wloc_users.py` | 用户体系：卡密登录、Bearer token、审计 |
| `wloc_vpn.py` | VPN 身份：`wloc_xxx` 用户名生成、密码 Fernet 加密存储 |
| `wloc_keygen.py` | Keygen 授权服务对接 |
| `static/index.html` | 前端单页（登录 / 选点 / 下载描述文件） |
| `生产部署文档.md` | **最全文档**（13 章）：部署、迁移、协议规格、排错 |
| `deploy-*.sh` / `rollback-*.sh` | 带 MD5 白名单校验的上线 / 回滚脚本 |
| `test_*.py` / `probe_*.py` | 改写核心测试、并发压测、Apple 探测工具 |

## 关键协议要点

- 接口 `POST https://gs-loc.apple.com/clls/wloc`，**functionID 必须 = 1**
- 响应信封 `version(2) + 0000 + msgtype(2) + 0000 + len(u16BE) + payload`，
  **msgtype 会变（0001/0003），不可写死**
- **坐标是 varint 定点 `round(x × 1e8)`，不是 double**
- 改写对象：`f2` WifiDevice→内部 `f2` Location；`f22`/`f24` 基站实体→内部 `f5` Location
  （两类 Location schema 不同，只能替换子字段 1/2）

## 部署

见 `生产部署文档.md`。改动生产代码前先跑备份脚本建立基线。

## 安全说明

本仓库**不含**任何凭据、私钥或用户数据。生产密钥位于服务器
`/etc/wloc-web/`、`/etc/ipsec.d/`，数据库 `wloc.db` 亦不入库。
