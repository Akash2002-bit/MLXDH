import sqlite3
import requests
from usemlkem.mlkem import ML_KEM_DECAPS
from x25519.main import x25519sharedkey

from hashlib import sha3_256

DB_NAME = 'bob_keys.db'



def KDF(input_key_material: bytes) -> bytes:
    """
    Simple KDF using SHA3-256
    Input : bytes
    Output: 32 bytes (256-bit derived key)
    """
    return sha3_256(input_key_material).digest()


# === DB Operations ===
def retrieve_private_key(key_name):
    """Fetch only the private key from Bob's local DB."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            'SELECT private_key FROM bob_keys WHERE key_name=?', (key_name,))
        row = cursor.fetchone()
        if row:
            return row[0]  # Only private key
        print(f"[!] No private key found for: {key_name}")
        return None


def display_private_keys():
    """Display and collect all private keys from Bob's local DB."""
    keys = ["mldsa", "mlkem", "IK_B", "SPK_B", "OPK_B"]
    key_dict = {}

    print("\n==============================")
    print(" Collect Bob's Private Keys from Local DB")
    print("==============================")

    for key_name in keys:
        priv = retrieve_private_key(key_name)
        if priv:
            # print(f"[{key_name}] Private Key: {priv}")
            key_dict[key_name] = priv
    return key_dict


# === Network Communication ===
def fetch_from_server(endpoint):
    """Generic GET request to fetch data from server."""
    try:
        response = requests.get(f"http://127.0.0.1:5000/{endpoint}")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[X] Error while fetching from {endpoint}: {e}")
        return None


# === Utilities ===
def scalar_from_hex(hex_str):
    """Convert hex string to 32-byte scalar (little endian)."""
    return int(hex_str, 16).to_bytes(32, 'little')

def hex_to_bytes(h):
    return bytes.fromhex(h)  # Proper conversion back to bytes


# === Main Process ===
def main():
    key_dict = display_private_keys()

    print("\n[+] Fetching IK_A and EK_A from server...")
    data_ik_ek = fetch_from_server("retrieve_ik")
    if not data_ik_ek:
        return

    IK_A = bytes.fromhex(data_ik_ek.get("IK_A"))
    EK_A = bytes.fromhex(data_ik_ek.get("EK_A"))

    # print(f"IK_A : {IK_A.hex()}")
    # print(f"EK_A : {EK_A.hex()}")

    print("\n[+] Fetching CT from server...")
    data_ct = fetch_from_server("retrieve_ct")
    if not data_ct:
        return

    CT = bytes.fromhex(data_ct.get("CT"))
    #print(f"CT : {CT.hex()}")

    print("\n==============================")
    print(" Decapsulate CT & Perform DH Operations")
    print("==============================")

    sk_mlkem_hex = key_dict.get("mlkem")
    if not sk_mlkem_hex:
        print("[X] No MLKEM Private Key Found!")
        return

    sk_mlkem = list(bytes.fromhex(sk_mlkem_hex))
    K = ML_KEM_DECAPS(sk_mlkem, list(CT))

    # Extract Bob's private keys
    ik_priv = key_dict.get("IK_B")
    spk_priv = key_dict.get("SPK_B")
    opk_priv = key_dict.get("OPK_B")

    if not (ik_priv and spk_priv and opk_priv):
        print("[X] Missing one or more of Bob's private keys!")
        return

    # Correct Explicit DH operations
    DH1 = x25519sharedkey(hex_to_bytes(spk_priv), (IK_A))
    DH2 = x25519sharedkey(hex_to_bytes(ik_priv), (EK_A))
    DH3 = x25519sharedkey(hex_to_bytes(spk_priv), (EK_A))
    DH4 = x25519sharedkey(hex_to_bytes(opk_priv), (EK_A))
    
    

    print("[*] DH1 Successful with SPK_B & IK_A")
    print("[*] DH2 Successful with IK_B & EK_A")
    print("[*] DH3 Successful with SPK_B & EK_A")
    print("[*] DH4 Successful with OPK_B & EK_A")


    SS_input = DH1 + DH2 + DH3 + DH4 + bytes(K)

    SS = KDF(SS_input)

    print("\n[+] Derived Shared Secret (SS):")
    print(SS.hex())
    
    
    # print("\n[*] DH Output Values:")
    # print("DH1:", DH1.hex())
    # print("DH2:", DH2.hex())
    # print("DH3:", DH3.hex())
    # print("DH4:", DH4.hex())
    # print("K from ML-KEM:", bytes(K).hex())
    # print("Final SS:", SS.hex())    


if __name__ == "__main__":
    main()
