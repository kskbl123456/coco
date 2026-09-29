import wloc_vpn

wloc_vpn.init_db()
row = wloc_vpn.get_or_create_identity(1001)
print("VPN Username:", row["vpn_username"])
print("Status:", row["status"])
print("Profile Scope:", row["profile_scope"])

pwd = wloc_vpn.decrypt_password(row["password_ciphertext"])
print("Decrypted Password Length:", len(pwd))

row_cached = wloc_vpn.get_or_create_identity(1001)
print("Idempotent Check:", row["vpn_username"] == row_cached["vpn_username"])
