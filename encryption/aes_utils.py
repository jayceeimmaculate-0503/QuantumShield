print("AES_UTILS FILE LOADED")
from Crypto.Cipher import AES

from encryption.key_manager import (
    load_key,
    validate_key
)


# =========================================================
# AES FILE ENCRYPTION
# =========================================================

def encrypt_file(filepath):

    # Load AES key
    key = load_key()

    # Validate key
    if not validate_key(key):

        raise ValueError(
            "Invalid AES encryption key."
        )

    # Create AES cipher
    cipher = AES.new(
        key,
        AES.MODE_EAX
    )


    # Read original file
    with open(filepath, "rb") as f:

        data = f.read()


    # Encrypt + generate authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(
        data
    )


    # Create encrypted filename
    encrypted_path = filepath + ".enc"


    # Save encrypted file
    with open(encrypted_path, "wb") as f:

        # Store nonce
        f.write(cipher.nonce)

        # Store authentication tag
        f.write(tag)

        # Store encrypted data
        f.write(ciphertext)


    return encrypted_path


# =========================================================
# AES FILE DECRYPTION
# =========================================================

def decrypt_file(
    filepath,
    output_path
):

    # Load AES key
    key = load_key()

    # Validate key
    if not validate_key(key):

        raise ValueError(
            "Invalid AES decryption key."
        )


    # Read encrypted file
    with open(filepath, "rb") as f:

        # EAX nonce
        nonce = f.read(16)

        # Authentication tag
        tag = f.read(16)

        # Remaining encrypted data
        ciphertext = f.read()


    # Recreate AES cipher
    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=nonce
    )


    # Decrypt and verify integrity
    data = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )


    # Restore original file
    with open(output_path, "wb") as f:

        f.write(data)


    return output_path
# =========================================================
# AES SELF TEST
# =========================================================

if __name__ == "__main__":

    import os

    print("=" * 60)
    print("QuantumShield - AES Encryption Test")
    print("=" * 60)

    base_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    test_file = os.path.join(
        base_dir,
        "aes_test.txt"
    )

    decrypted_file = os.path.join(
        base_dir,
        "aes_test_decrypted.txt"
    )

    original_data = (
        b"QuantumShield AES test file. "
        b"Testing encryption and decryption."
    )

    try:

        print("\n[1] Creating test file...")

        with open(test_file, "wb") as f:
            f.write(original_data)

        print("Test file created.")

        print("\n[2] Encrypting file...")

        encrypted_file = encrypt_file(test_file)

        print("Encryption successful.")
        print("Encrypted:", encrypted_file)

        print("\n[3] Decrypting file...")

        decrypt_file(
            encrypted_file,
            decrypted_file
        )

        print("Decryption successful.")

        print("\n[4] Verifying file integrity...")

        with open(decrypted_file, "rb") as f:
            decrypted_data = f.read()

        if original_data == decrypted_data:

            print("\nSUCCESS! 🎉")
            print("Original and decrypted files MATCH.")
            print("AES file encryption is working correctly.")

        else:

            print("\nFAILED! ❌")
            print("Original and decrypted files DO NOT MATCH.")

    except Exception as e:

        print("\nAES TEST FAILED ❌")
        print("Error:", e)

    finally:

        for file in [
            test_file,
            test_file + ".enc",
            decrypted_file
        ]:

            if os.path.exists(file):
                os.remove(file)

    print("\n" + "=" * 60)
    print("QuantumShield AES test completed.")
    print("=" * 60)