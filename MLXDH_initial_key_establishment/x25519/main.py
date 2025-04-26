import os
import binascii
from x25519.x25519 import base_point_mult, multscalar, bytes_to_int


def x25519keygen():
    # Generate 32-byte private keys
    #a = os.urandom(32)
    b = os.urandom(32)

    # print("\n--- Private Keys (Hex) ---")
    # print("Bob Private Key (b):   ", binascii.hexlify(a).decode())
    # print("Alice Private Key (a): ", binascii.hexlify(b).decode())

    # Public Keys
    #a_pub = base_point_mult(a)
    b_pub = base_point_mult(b)

    # print("\n--- Public Keys (Hex) ---")
    # print("Bob Public Key (bG):   ", binascii.hexlify(b_pub).decode())
    # print("Alice Public Key (aG): ", binascii.hexlify(a_pub).decode())
    
    #return binascii.hexlify(b_pub).decode(), binascii.hexlify(b).decode()
    return b_pub, b

# def x25519sharedkey(a, b_pub):
    
#     # Shared Secrets
#     k_a = multscalar(a, b_pub)  # Alice computes (a * bG)  

#     return k_a

def x25519sharedkey(a, b_pub):
    return multscalar(a, b_pub)


# # Shared Secrets
# k_a = multscalar(a, b_pub)  # Alice computes (a * bG)
# k_b = multscalar(b, a_pub)  # Bob computes (b * aG)

# print("\n--- Shared Secrets (Hex) ---")
# print("Bob Shared Secret (b * aG):    ", binascii.hexlify(k_b).decode())
# print("Alice Shared Secret (a * bG):  ", binascii.hexlify(k_a).decode())

# # Check if Shared Secrets Match
# print("\n--- Key Agreement Status ---")
# if k_a == k_b:
#     print("SUCCESS: Shared secrets match!")
# else:
#     print("ERROR: Shared secrets do NOT match!")

