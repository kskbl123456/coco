import os
import sqlite3

def run_cmd(env_vars):
    env_str = ' '.join([f"{k}='{v}'" for k, v in env_vars.items()])
    os.system(f"{env_str} /usr/local/sbin/wloc-vpn-updown-probe")

def query_sessions():
    conn = sqlite3.connect('/opt/wloc-web/wloc.db')
    cur = conn.cursor()
    cur.execute("SELECT vpn_username, vpn_ip, session_id FROM vpn_active_sessions")
    rows = cur.fetchall()
    conn.close()
    return rows

print("1. Testing UP event...")
run_cmd({"PLUTO_VERB": "up-client", "PLUTO_XAUTH_ID": "wloc_test_user", "PLUTO_PEER_SOURCEIP4_1": "10.10.0.5", "PLUTO_UNIQUEID": "101"})
print("Sessions after UP:", query_sessions())

print("2. Testing Stale DOWN event (session_id=99, should be ignored)...")
run_cmd({"PLUTO_VERB": "down-client", "PLUTO_XAUTH_ID": "wloc_test_user", "PLUTO_PEER_SOURCEIP4_1": "10.10.0.5", "PLUTO_UNIQUEID": "99"})
print("Sessions after Stale DOWN:", query_sessions())

print("3. Testing Matching DOWN event (session_id=101, should delete session)...")
run_cmd({"PLUTO_VERB": "down-client", "PLUTO_XAUTH_ID": "wloc_test_user", "PLUTO_PEER_SOURCEIP4_1": "10.10.0.5", "PLUTO_UNIQUEID": "101"})
print("Sessions after Matching DOWN:", query_sessions())
