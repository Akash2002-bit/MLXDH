# ML-DSA Parameters
DEFAULT_PARAMETERS = {
    "ML_DSA_44": {
        "d": 13, "tau": 39, "gamma_1": 131072, "gamma_2": 95232,
        "k": 4, "l": 4, "eta": 2, "omega": 80, "c_tilde_bytes": 32,
    },
    "ML_DSA_65": {
        "d": 13, "tau": 49, "gamma_1": 524288, "gamma_2": 261888,
        "k": 6, "l": 5, "eta": 4, "omega": 55, "c_tilde_bytes": 48,
    },
    "ML_DSA_87": {
        "d": 13, "tau": 60, "gamma_1": 524288, "gamma_2": 261888,
        "k": 8, "l": 7, "eta": 2, "omega": 75, "c_tilde_bytes": 64,
    },
}

def get_ml_dsa_instance(choice):
    from usemldsa.ml_dsa import ML_DSA  # Local import for clean dependency handling

    param_map = {
        "44": ML_DSA(DEFAULT_PARAMETERS["ML_DSA_44"]),
        "65": ML_DSA(DEFAULT_PARAMETERS["ML_DSA_65"]),
        "87": ML_DSA(DEFAULT_PARAMETERS["ML_DSA_87"]),
    }

    return param_map.get(choice, None)

def prompt_choice():
    print("\nChoose ML-DSA Variant:")
    print("1 -> ML_DSA_44")
    print("2 -> ML_DSA_65")
    print("3 -> ML_DSA_87")
    return input("Enter your choice (44 / 65 / 87): ").strip()

# === Key Generation ===
def mldsakeygen():
    # choice = prompt_choice()
    # ml_dsa = get_ml_dsa_instance(choice)
    ml_dsa = get_ml_dsa_instance("65".strip())

    if not ml_dsa:
        raise ValueError("Invalid ML-DSA Choice!")

    pk, sk = ml_dsa.keygen()
    return pk, sk

# === Signing ===
def mldsasign(sk, message):
    # choice = prompt_choice()
    # ml_dsa = get_ml_dsa_instance(choice)
    ml_dsa = get_ml_dsa_instance("65".strip())

    if not ml_dsa:
        raise ValueError("Invalid ML-DSA Choice!")

    if isinstance(message, str):
        message = message.encode()

    return ml_dsa.sign(sk, message)

# === Verification ===
def mldsaverify(pk, message, signature):
    # choice = prompt_choice()
    
    # ml_dsa = get_ml_dsa_instance(choice)
    ml_dsa = get_ml_dsa_instance("65".strip())
    

    if not ml_dsa:
        raise ValueError("Invalid ML-DSA Choice!")

    verified = ml_dsa.verify(pk, message, signature)

    print("\nVerification Result:", "✅ Successful" if verified else "❌ Failed")

    return verified
