#!/bin/bash
# WLoc 节点 IKEv2（UDP 500 / 4500）可用性探测
# 部署在 57.181.170.250 大陆机，每 10 分钟一次。
# 只做探测与记录，不修改任何配置。
#
# ── 2026-10-08 重写 ──
#   旧版探 45.202.245.247（日本机，WLoc 已删）→ 2026-10-05 停用
#   新版改为探本机公网 IP，并**分开判定 500 与 4500**，
#   因为已知故障签名是「500 通 / 4500 不通」（2026-10-07 实测）。
#
# ★ 为什么必须带 --sport：
#   京东云出口丢弃「源端口 500」的 UDP 包（反 UDP 放大攻击策略，
#   53/123 同样被丢）。不带 --sport 会假失败。
#
# ★★ 本探测的固有局限（必须知道）：
#   本机 → 本机公网 IP 的流量**不经过 GFW**，路径是本机网络栈直接回环。
#   所以它**只能证明服务端进程与防火墙配置正常**，
#   **无法证明外部客户端能否连上**。
#   要测「是否被墙」，必须从**境外/异地探针**发起（见 --remote 模式）。
#
# ★ 判定签名：
#   ike=OK  ike4500=OK             → 服务端两侧端口正常
#   ike=OK  ike4500=FAIL           → ★ 4500 本地异常（进程/防火墙）
#   ike=FAIL ike4500=FAIL tcp22=OK  → 服务端挂了但机器活着
#
# 用法：
#   wloc-ikev2-probe.sh              本机自探（默认）
#   wloc-ikev2-probe.sh --alert-test 强制输出一次判定（验证告警链路）

LOG=/var/log/wloc-ikev2-probe.log
ALERTLOG=/var/log/wloc-ikev2-alert.log
STATE=/var/log/wloc-ikev2-probe.state
PROBE_HOST="${WLOC_PROBE_HOST:-$(cat /etc/wloc-web/vpn-address 2>/dev/null)}"
PROBE_HOST="${PROBE_HOST:-ios.819263.xyz}"
TARGET="${WLOC_PROBE_TARGET:-$(getent hosts "$PROBE_HOST" | awk '{print $1; exit}')}"

ALERT_TEST=0
[ "$1" = "--alert-test" ] && ALERT_TEST=1

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SPORT=$(( (RANDOM % 20000) + 40000 ))
SPORT2=$(( SPORT + 1 ))

# ── 1. UDP 500 探测 ──
# 服务端 ike= 配置是 modp2048 + sha256 → 用 --dhgroup=14 才可能应答 Handshake
# 默认 modp1024 会得到 NO_PROPOSAL_CHOSEN，也算「服务端活着」，单独记 OK_NOTIFY
IKE=FAIL
OUT=$(timeout 20 ike-scan --ikev2 --sport="$SPORT" --dhgroup=14 --retry=2 --timeout=2000 "$TARGET" 2>&1)
if echo "$OUT" | grep -q 'Handshake returned'; then
    IKE=OK
elif echo "$OUT" | grep -q 'NO_PROPOSAL_CHOSEN'; then
    IKE=OK_NOTIFY
fi

# ── 2. UDP 4500 探测（★ 关键）──
# 注意：--nat-t 会把 sport/dport 都改成 4500，
# 必须在它【之后】再写 --sport 覆盖源端口，否则源端口 4500 会被京东云出口丢弃。
IKE4500=FAIL
OUT2=$(timeout 20 ike-scan --ikev2 --nat-t --sport="$SPORT2" --dhgroup=14 --retry=2 --timeout=2000 "$TARGET" 2>&1)
if echo "$OUT2" | grep -q 'Handshake returned'; then
    IKE4500=OK
elif echo "$OUT2" | grep -q 'NO_PROPOSAL_CHOSEN'; then
    IKE4500=OK_NOTIFY
fi

# ── 3. 对照项：TCP22 与 ICMP ──
TCP=FAIL
timeout 6 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null && TCP=OK

PING=FAIL
ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1 && PING=OK

# ── 4. 落日志 ──
LINE="$TS ike=$IKE ike4500=$IKE4500 tcp22=$TCP icmp=$PING sport=$SPORT"
echo "$LINE" >> "$LOG"

# ── 5. 判定 ──
STATUS=OK
case "$IKE:$IKE4500:$TCP" in
    OK*:OK*:*)       STATUS=OK ;;
    OK*:FAIL:*)      STATUS=ALERT_4500 ;;
    FAIL:FAIL:OK)    STATUS=ALERT_IKE ;;
    FAIL:FAIL:FAIL)  STATUS=ALERT_IP ;;
    *)               STATUS=UNKNOWN ;;
esac

PREV=""
[ -f "$STATE" ] && PREV=$(cat "$STATE")

if [ "$STATUS" != "$PREV" ] || [ "$ALERT_TEST" = "1" ]; then
    echo "$STATUS" > "$STATE"
    MSG="[WLoc 探测] $TS status=$STATUS ike=$IKE ike4500=$IKE4500 tcp22=$TCP icmp=$PING target=$TARGET"
    logger -t wloc-ikev2-probe -p daemon.warning "$MSG"
    echo "$MSG" >> "$ALERTLOG"
    echo "$MSG"
fi

# ── 6. 日志轮转：保留最近 5000 行 ──
if [ "$(wc -l < "$LOG" 2>/dev/null || echo 0)" -gt 5000 ]; then
    tail -3000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

exit 0
