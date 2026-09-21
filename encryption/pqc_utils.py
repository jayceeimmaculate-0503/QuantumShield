import oqs


# ============================================================
# ML-KEM-768 - Post-Quantum Key Encapsulation
# ============================================================

ALGORITHM = "ML-KEM-768"


def generate_keypair():
    """
    Generate ML-KEM-768 public and secret keys.
    """

    kem = oqs.KeyEncapsulation(ALGORITHM)

    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()

    return public_key, secret_key


def encapsulate(public_key):
    """
    Encapsulate a shared secret using the recipient's public key.

    Returns:
        ciphertext
        shared_secret
    """

    kem = oqs.KeyEncapsulation(ALGORITHM)

    ciphertext, shared_secret = kem.encap_secret(public_key)

    return ciphertext, shared_secret


def decapsulate(secret_key, ciphertext):
    """
    Decapsulate the ciphertext using the secret key.

    Returns:
        shared_secret
    """

    kem = oqs.KeyEncapsulation(
        ALGORITHM,
        secret_key
    )

    shared_secret = kem.decap_secret(ciphertext)

    return shared_secret


def test_pqc():
    """
    Complete ML-KEM-768 test:
    Key Generation → Encapsulation → Decapsulation
    """

    print("=" * 60)
    print("QuantumShield - Post-Quantum Cryptography Test")
    print("=" * 60)

    print("\nAlgorithm:", ALGORITHM)

    # 1. Generate keys
    print("\n[1] Generating ML-KEM-768 key pair...")

    public_key, secret_key = generate_keypair()

    print("Public Key generated")
    print("Secret Key generated")

    print("Public Key Size:", len(public_key), "bytes")
    print("Secret Key Size:", len(secret_key), "bytes")

    # 2. Encapsulation
    print("\n[2] Performing key encapsulation...")

    ciphertext, shared_secret_sender = encapsulate(public_key)

    print("Ciphertext generated")
    print("Ciphertext Size:", len(ciphertext), "bytes")

    # 3. Decapsulation
    print("\n[3] Performing key decapsulation...")

    shared_secret_receiver = decapsulate(
        secret_key,
        ciphertext
    )

    print("Shared secret recovered")

    print(
        "Shared Secret Size:",
        len(shared_secret_sender),
        "bytes"
    )

    # 4. Verify
    print("\n[4] Verifying shared secrets...")

    if shared_secret_sender == shared_secret_receiver:

        print("SUCCESS!")
        print("Sender and Receiver shared secrets MATCH.")

    else:

        print("FAILED!")
        print("Shared secrets DO NOT MATCH.")

    print("\n" + "=" * 60)
    print("ML-KEM-768 Test Completed")
    print("=" * 60)


if __name__ == "__main__":
    test_pqc()