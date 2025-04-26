import requests
import sqlite3

from usemldsa.ok import mldsakeygen, mldsasign
from usemlkem.mlkem import ML_KEM_KEYGEN
from x25519.main import x25519keygen
from hashlib import sha3_256

DB_NAME = 'bob_keys.db'


# === Database Setup ===
def create_table():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bob_keys (
                key_name TEXT PRIMARY KEY,
                public_key TEXT,
                private_key TEXT
            )
        ''')


def clear_table():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('DELETE FROM bob_keys')


def store_key(key_name, public_key, private_key):
    def to_hex(val):
        return ''.join(format(x, '02x') for x in val) if isinstance(val, (bytes, bytearray, list)) else val

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            REPLACE INTO bob_keys (key_name, public_key, private_key)
            VALUES (?, ?, ?)
        ''', (key_name, to_hex(public_key), to_hex(private_key)))
        
        
        
def KDF(input_key_material: bytes) -> bytes:
    """
    Simple KDF using SHA3-256
    Input : bytes
    Output: 32 bytes (256-bit derived key)
    """
    return sha3_256(input_key_material).digest()        


# === Key Generation Functions ===
def generate_mldsa_keys():
    pk, sk = mldsakeygen()
    return pk.hex(), sk


def generate_mlkem_keys():
    ek, dk = ML_KEM_KEYGEN()
    return bytes(ek).hex(), dk


def generate_x25519_keys():
    pub, priv = x25519keygen()
    return pub.hex(), priv.hex()


def sign_data(sk, data):
    signature = mldsasign(sk, data)
    return signature.hex()


# === Main Process ===
def main():
    print("[*] Initializing Bob's Database...")
    create_table()
    clear_table()

    print("[*] Generating Bob's Keys...")
    keys = {
        'IK_B': generate_x25519_keys(),   # Identity Key
        'SPK_B': generate_x25519_keys(),  # Signed PreKey
        'OPK_B': generate_x25519_keys(),  # One-time PreKey
        'mldsa': generate_mldsa_keys(),   # Signature Keys
        'mlkem': generate_mlkem_keys(),   # KEM Keys
    }

    # Store all keys (pub + priv) in database
    for key_name, (pub, priv) in keys.items():
        store_key(key_name, pub, priv)

    print("[*] Preparing Payload to Publish (only public keys)...")

    mldsa_pk, mldsa_sk = keys['mldsa']
    mlkem_pk, mlkem_sk = keys['mlkem']
    ik_pub, ik_priv = keys['IK_B']
    spk_pub, spk_priv = keys['SPK_B']
    opk_pub, opk_priv = keys['OPK_B']

    data = {
        "mldsaPK_B": mldsa_pk,
        "mlkemPK_B": mlkem_pk,
        "Sig_mlkem": sign_data(mldsa_sk, bytes.fromhex(mlkem_pk)),
        "IK_B": ik_pub,
        "SPK_B": spk_pub,
        "Sig_spk": sign_data(mldsa_sk, bytes.fromhex(spk_pub)),
        "OPK_B": opk_pub,
    }

    print("[*] Publishing Data to Server...")
    try:
        response = requests.post("http://127.0.0.1:5000/publish_bob", json=data)

        if response.status_code == 200:
            print("[+] Server Response:", response.json())
        else:
            print(f"[!] Failed to publish keys: {response.status_code}")
            print(response.text)

    except requests.exceptions.RequestException as e:
        print(f"[!] Network Error: {e}")

    print("[*] Done.")


if __name__ == "__main__":
    main()
