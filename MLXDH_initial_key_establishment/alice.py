import requests
from usemldsa.ok import mldsaverify
from usemlkem.mlkem import ML_KEM_ENCAPS
from x25519.main import x25519keygen, x25519sharedkey


from hashlib import sha3_256


def generate_x25519_keys():
    pub, priv = x25519keygen()
    return pub.hex(), priv.hex()


def KDF(input_key_material: bytes) -> bytes:
    """
    Simple KDF using SHA3-256
    Input : bytes
    Output: 32 bytes (256-bit derived key)
    """
    return sha3_256(input_key_material).digest()


# === Generate Alice's Identity & Ephemeral Keys ===
ik_pub, ik_priv = generate_x25519_keys()
ek_pub, ek_priv = generate_x25519_keys()


print("\n==============================")
print(" Generating Alice's Keys")
print("==============================")

# === Retrieve Bob's Data from Server ===
print("\n[*] Fetching Bob's Data from Server...")
response = requests.get("http://127.0.0.1:5000/retrieve_bob")

if response.status_code != 200:
    print(f"[X] Failed to retrieve Bob's data: {response.status_code} - {response.text}")
    exit()

print("[+] Alice Retrieved Bob's Data Successfully ✅")

retrieved = response.json()

# === Convert Hex Strings to Bytes ===
def from_hex(data):
    return bytes.fromhex(data)

def hex_to_bytes(h):
    return bytes.fromhex(h)  # Proper conversion back to bytes

mldsaPK_B = from_hex(retrieved["mldsaPK_B"])
mlkemPK_B = from_hex(retrieved["mlkemPK_B"])
Sig_mlkem = from_hex(retrieved["Sig_mlkem"])
IK_B = from_hex(retrieved["IK_B"])
SPK_B = from_hex(retrieved["SPK_B"])
Sig_spk = from_hex(retrieved["Sig_spk"])
OPK_B = from_hex(retrieved["OPK_B"])


# === Verify Bob's Signatures ===
def verify_signature(pk, sig, msg, label):
    if mldsaverify(pk, msg, sig):
        print(f"[+] {label} Signature Verified ✅")
    else:
        print(f"[X] {label} Signature Verification Failed ❌")
        exit()


verify_signature(mldsaPK_B, Sig_mlkem, mlkemPK_B, "MLKEM")
verify_signature(mldsaPK_B, Sig_spk, SPK_B, "SPK")


print("\n==============================")
print(" Performing encapsulation and sending CT")
print("==============================")


# === Publish Alice's IK_A and EK_A to Server ===
data = {
    "IK_A": ik_pub,
    "EK_A": ek_pub
}

print("\n[*] Publishing Alice's IK_A & EK_A to Server...")
response = requests.post("http://127.0.0.1:5000/publish_ik", json=data)

if response.status_code == 200:
    print("[+] Alice Published IK_A & EK_A Successfully ✅")
else:
    print(f"[X] Failed to publish IK_A & EK_A: {response.status_code} - {response.text}")
    exit()


# === Derive Shared Secret (SS) ===
print("\n[*] Deriving Shared Secret...")

# Helper to convert hex scalar to 32 bytes (little-endian)
def scalar_from_hex(hex_str):
    return int(hex_str, 16).to_bytes(32, 'little')


K, CT = ML_KEM_ENCAPS(list(mlkemPK_B))


DH1 = x25519sharedkey(hex_to_bytes(ik_priv), (SPK_B))
DH2 = x25519sharedkey(hex_to_bytes(ek_priv), (IK_B))
DH3 = x25519sharedkey(hex_to_bytes(ek_priv), (SPK_B))
DH4 = x25519sharedkey(hex_to_bytes(ek_priv), (OPK_B))


print("[*] DH1 Successful with IK_A & SPK_B")
print("[*] DH2 Successful with EK_A & IK_B")
print("[*] DH3 Successful with EK_A & SPK_B")
print("[*] DH4 Successful with EK_A & OPK_B")



SS_input = DH1 + DH2 + DH3 + DH4 + bytes(K)

# Apply KDF on input to get final SS
SS = KDF(SS_input)

print("[+] Alice's Derived Shared Secret (SS):")
print(SS.hex())



# === Send Ciphertext (CT) to Server ===
print("\n[*] Sending Ciphertext (CT) to Server...")
data = {
    "CT": bytes(CT).hex()  # FIXED: Convert CT (list) to bytes before hex
}

response = requests.post("http://127.0.0.1:5000/publish_ct", json=data)

if response.status_code == 200:
    print("[+] CT Published Successfully ✅")
else:
    print(f"[X] Failed to publish CT: {response.status_code} - {response.text}")
    exit()
