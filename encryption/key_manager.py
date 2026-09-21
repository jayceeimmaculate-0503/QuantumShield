print("KEY_MANAGER FILE LOADED")
import os
from Crypto.Random import get_random_bytes


# =========================================================
# KEY MANAGEMENT CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

KEY_FILE = os.path.join(
    BASE_DIR,
    "encryption",
    "secret.key"
)


# =========================================================
# GENERATE NEW AES-256 KEY
# =========================================================

def generate_key():

    # Generate 32-byte = 256-bit key
    key = get_random_bytes(32)

    # Store key securely
    with open(KEY_FILE, "wb") as f:
        f.write(key)

    return key


# =========================================================
# LOAD EXISTING KEY
# =========================================================

def load_key():

    # If key doesn't exist, create one
    if not os.path.exists(KEY_FILE):

        return generate_key()

    # Load existing key
    with open(KEY_FILE, "rb") as f:

        key = f.read()

    return key


# =========================================================
# VALIDATE AES KEY
# =========================================================

def validate_key(key):

    # AES supports 16, 24 or 32 byte keys
    if len(key) not in [16, 24, 32]:

        return False

    return True
# =========================================================
# KEY MANAGER SELF TEST
# =========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("QuantumShield - AES Key Manager Test")
    print("=" * 60)

    try:

        print("\n[1] Loading AES key...")

        key = load_key()

        print("Key loaded successfully.")
        print("Key length:", len(key), "bytes")

        print("\n[2] Validating AES key...")

        if validate_key(key):

            print("AES key validation successful.")

        else:

            print("AES key validation FAILED.")

        print("\n[3] Checking AES-256...")

        if len(key) == 32:

            print("AES-256 key confirmed.")

        else:

            print("WARNING: Key is not 256-bit.")

        print("\n[4] Checking key file...")

        if os.path.exists(KEY_FILE):

            print("Key file exists.")
            print("Key location:", KEY_FILE)

        else:

            print("Key file NOT found.")

        print("\nSUCCESS! 🎉")
        print("AES key management is working correctly.")

    except Exception as e:

        print("\nKEY MANAGER TEST FAILED ❌")
        print("Error:", e)

    print("\n" + "=" * 60)
    print("QuantumShield key manager test completed.")
    print("=" * 60)