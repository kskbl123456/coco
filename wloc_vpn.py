import os
import secrets
import uuid
import sqlite3
from datetime import datetime, timezone
from cryptography.fernet import Fernet

def get_fernet():
    key = os.environ.get('WLOC_VPN_CREDENTIAL_KEY')
    env_file = '/etc/wloc-web/vpn-identity.env'
    if not key and os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if line.startswith('WLOC_VPN_CREDENTIAL_KEY='):
                    key = line.strip().split('=', 1)[1]
    if not key:
        key = Fernet.generate_key().decode()
        os.makedirs('/etc/wloc-web', exist_ok=True)
        with open(env_file, 'w') as f:
            f.write(f'WLOC_VPN_CREDENTIAL_KEY={key}\n')
        os.chmod(env_file, 0o640)
    return Fernet(key.encode() if isinstance(key, str) else key)

def init_db(db_path='/opt/wloc-web/wloc.db'):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS vpn_identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            vpn_username TEXT NOT NULL UNIQUE,
            password_ciphertext TEXT NOT NULL,
            profile_scope TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','sync_failed','revoked')),
            secret_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            synced_at TEXT
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_vpn_identities_status ON vpn_identities(status)')
    conn.commit()
    conn.close()

def generate_opaque_username():
    return f'wloc_{secrets.token_hex(6)}'

def generate_password():
    return secrets.token_urlsafe(18)

def derive_profile_scope(user_id):
    namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
    return str(uuid.uuid5(namespace, f'wloc-user-{user_id}'))

def get_or_create_identity(user_id, db_path='/opt/wloc-web/wloc.db'):
    fernet = get_fernet()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute('SELECT * FROM vpn_identities WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    
    if row:
        conn.close()
        return dict(row)
    
    vpn_username = generate_opaque_username()
    plain_password = generate_password()
    password_ciphertext = fernet.encrypt(plain_password.encode()).decode()
    profile_scope = derive_profile_scope(user_id)
    now = datetime.now(timezone.utc).isoformat()
    
    cur.execute('''
        INSERT INTO vpn_identities (user_id, vpn_username, password_ciphertext, profile_scope, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?)
    ''', (user_id, vpn_username, password_ciphertext, profile_scope, now, now))
    
    conn.commit()
    cur.execute('SELECT * FROM vpn_identities WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row)

def decrypt_password(password_ciphertext):
    fernet = get_fernet()
    return fernet.decrypt(password_ciphertext.encode()).decode()
