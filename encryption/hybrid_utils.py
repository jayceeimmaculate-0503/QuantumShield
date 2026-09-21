import os
import struct
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from encryption.pqc_utils import (
    generate_keypair,
    encapsulate,
    decapsulate
)


# ============================================================
# QUANTUMSHIELD HYBRID ENCRYPTION
# AES-256 + ML-KEM-768
# ============================================================

ALGORITHM = "ML-KEM-768"

# File identification
MAGIC = b"QSHIELD"
VERSION = 1

# AES-GCM parameters
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

# ML-KEM-768 ciphertext size
KEM_CIPHERTEXT_SIZE = 1088

# Header format:
# MAGIC       -> 7 bytes
# VERSION     -> 1 byte
# KEM CT LEN  -> 4 bytes
# NONCE       -> 12 bytes
# TAG         -> 16 bytes
#
# Then:
# KEM ciphertext
# encrypted AES key
# encrypted file data


# ============================================================
# KEY DERIVATION
# ============================================================

def derive_aes_key(shared_secret):
    """
    Derive a 256-bit AES key from the ML-KEM shared secret.

    ML-KEM produces a 32-byte shared secret.
    SHA-256 converts it into a deterministic 32-byte AES key.
    """

    if not isinstance(shared_secret, bytes):
        raise TypeError("ML-KEM shared secret must be bytes.")

    if len(shared_secret) != 32:
        raise ValueError(
            "Invalid ML-KEM shared secret size."
        )

    return hashlib.sha256(
        b"QuantumShield-AES-256" + shared_secret
    ).digest()


# ============================================================
# HYBRID ENCRYPTION
# ============================================================

def hybrid_encrypt_file(
    filepath,
    public_key=None
):
    """
    Encrypt a file using:

        ML-KEM-768
              +
        AES-256-GCM

    ML-KEM protects the AES session key.
    AES-GCM encrypts the actual file.
    """

    # --------------------------------------------------------
    # Validate input file
    # --------------------------------------------------------

    if not os.path.isfile(filepath):
        raise FileNotFoundError(
            f"Input file not found: {filepath}"
        )

    if os.path.getsize(filepath) == 0:
        raise ValueError(
            "Cannot encrypt an empty file."
        )

    # --------------------------------------------------------
    # Generate ML-KEM key pair if public key is not supplied
    # --------------------------------------------------------

    if public_key is None:
        public_key, secret_key = generate_keypair()
    else:
        secret_key = None

    if not isinstance(public_key, bytes):
        raise TypeError(
            "ML-KEM public key must be bytes."
        )

    # --------------------------------------------------------
    # Generate AES-256 session key
    # --------------------------------------------------------

    aes_key = get_random_bytes(
        AES_KEY_SIZE
    )

    # --------------------------------------------------------
    # Generate ML-KEM shared secret
    # --------------------------------------------------------

    kem_ciphertext, shared_secret = encapsulate(
        public_key
    )

    # --------------------------------------------------------
    # Derive a KEK from ML-KEM shared secret
    # --------------------------------------------------------

    kek = derive_aes_key(
        shared_secret
    )

    # --------------------------------------------------------
    # Encrypt AES session key using AES-GCM
    # --------------------------------------------------------

    key_nonce = get_random_bytes(
        NONCE_SIZE
    )

    key_cipher = AES.new(
        kek,
        AES.MODE_GCM,
        nonce=key_nonce
    )

    encrypted_aes_key, key_tag = (
        key_cipher.encrypt_and_digest(
            aes_key
        )
    )

    # --------------------------------------------------------
    # Read original file
    # --------------------------------------------------------

    with open(filepath, "rb") as f:
        data = f.read()

    # --------------------------------------------------------
    # Encrypt actual file using AES-256-GCM
    # --------------------------------------------------------

    file_nonce = get_random_bytes(
        NONCE_SIZE
    )

    file_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=file_nonce
    )

    ciphertext, file_tag = (
        file_cipher.encrypt_and_digest(
            data
        )
    )

    # --------------------------------------------------------
    # Create output path
    # --------------------------------------------------------

    encrypted_path = filepath + ".hybrid.enc"

    # --------------------------------------------------------
    # QuantumShield file format
    # --------------------------------------------------------
    #
    # MAGIC
    # VERSION
    # KEM ciphertext length
    # KEM ciphertext
    #
    # KEY nonce
    # KEY authentication tag
    # encrypted AES key
    #
    # FILE nonce
    # FILE authentication tag
    # encrypted file data
    #
    # --------------------------------------------------------

    with open(
        encrypted_path,
        "wb"
    ) as f:

        # Magic
        f.write(MAGIC)

        # Version
        f.write(
            struct.pack(
                ">B",
                VERSION
            )
        )

        # KEM ciphertext length
        f.write(
            struct.pack(
                ">I",
                len(kem_ciphertext)
            )
        )

        # ML-KEM ciphertext
        f.write(
            kem_ciphertext
        )

        # Key nonce
        f.write(
            key_nonce
        )

        # Key authentication tag
        f.write(
            key_tag
        )

        # Encrypted AES key
        f.write(
            encrypted_aes_key
        )

        # File nonce
        f.write(
            file_nonce
        )

        # File authentication tag
        f.write(
            file_tag
        )

        # Encrypted file
        f.write(
            ciphertext
        )

    return encrypted_path


# ============================================================
# HYBRID DECRYPTION
# ============================================================

def hybrid_decrypt_file(
    filepath,
    output_path,
    secret_key
):
    """
    Decrypt a QuantumShield hybrid file.

    Requires the ML-KEM-768 secret key that corresponds
    to the public key used during encryption.
    """

    # --------------------------------------------------------
    # Validate encrypted file
    # --------------------------------------------------------

    if not os.path.isfile(filepath):
        raise FileNotFoundError(
            f"Encrypted file not found: {filepath}"
        )

    if not filepath.endswith(
        ".hybrid.enc"
    ):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    # --------------------------------------------------------
    # Read complete encrypted file
    # --------------------------------------------------------

    with open(filepath, "rb") as f:
        data = f.read()

    # Minimum header size:
    #
    # MAGIC = 7
    # VERSION = 1
    # KEM LENGTH = 4
    #
    minimum_size = 12

    if len(data) < minimum_size:
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    offset = 0

    # --------------------------------------------------------
    # Check MAGIC
    # --------------------------------------------------------

    magic = data[
        offset:
        offset + len(MAGIC)
    ]

    offset += len(MAGIC)

    if magic != MAGIC:
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    # --------------------------------------------------------
    # Check VERSION
    # --------------------------------------------------------

    version = data[offset]

    offset += 1

    if version != VERSION:
        raise ValueError(
            "Unsupported QuantumShield hybrid file version."
        )

    # --------------------------------------------------------
    # Read KEM ciphertext length
    # --------------------------------------------------------

    if offset + 4 > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    kem_length = struct.unpack(
        ">I",
        data[offset:offset + 4]
    )[0]

    offset += 4

    # ML-KEM-768 must use 1088-byte ciphertext
    if kem_length != KEM_CIPHERTEXT_SIZE:
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    # --------------------------------------------------------
    # Read ML-KEM ciphertext
    # --------------------------------------------------------

    if offset + kem_length > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    kem_ciphertext = data[
        offset:
        offset + kem_length
    ]

    offset += kem_length

    # --------------------------------------------------------
    # Read key nonce
    # --------------------------------------------------------

    if offset + NONCE_SIZE > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    key_nonce = data[
        offset:
        offset + NONCE_SIZE
    ]

    offset += NONCE_SIZE

    # --------------------------------------------------------
    # Read key authentication tag
    # --------------------------------------------------------

    if offset + TAG_SIZE > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    key_tag = data[
        offset:
        offset + TAG_SIZE
    ]

    offset += TAG_SIZE

    # --------------------------------------------------------
    # Read encrypted AES key
    # --------------------------------------------------------

    encrypted_key_size = AES_KEY_SIZE

    if offset + encrypted_key_size > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    encrypted_aes_key = data[
        offset:
        offset + encrypted_key_size
    ]

    offset += encrypted_key_size

    # --------------------------------------------------------
    # Read file nonce
    # --------------------------------------------------------

    if offset + NONCE_SIZE > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    file_nonce = data[
        offset:
        offset + NONCE_SIZE
    ]

    offset += NONCE_SIZE

    # --------------------------------------------------------
    # Read file authentication tag
    # --------------------------------------------------------

    if offset + TAG_SIZE > len(data):
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    file_tag = data[
        offset:
        offset + TAG_SIZE
    ]

    offset += TAG_SIZE

    # --------------------------------------------------------
    # Remaining data = encrypted file
    # --------------------------------------------------------

    ciphertext = data[offset:]

    if len(ciphertext) == 0:
        raise ValueError(
            "Invalid QuantumShield hybrid file."
        )

    # --------------------------------------------------------
    # Validate secret key
    # --------------------------------------------------------

    if not isinstance(secret_key, bytes):
        raise TypeError(
            "ML-KEM secret key must be bytes."
        )

    if len(secret_key) != 2400:
        raise ValueError(
            "Invalid ML-KEM-768 secret key."
        )

    # --------------------------------------------------------
    # ML-KEM decapsulation
    # --------------------------------------------------------

    shared_secret = decapsulate(
        secret_key,
        kem_ciphertext
    )

    # --------------------------------------------------------
    # Derive KEK
    # --------------------------------------------------------

    kek = derive_aes_key(
        shared_secret
    )

    # --------------------------------------------------------
    # Recover AES session key
    # --------------------------------------------------------

    key_cipher = AES.new(
        kek,
        AES.MODE_GCM,
        nonce=key_nonce
    )

    try:

        aes_key = key_cipher.decrypt_and_verify(
            encrypted_aes_key,
            key_tag
        )

    except ValueError:

        raise ValueError(
            "QuantumShield key authentication failed."
        )

    # --------------------------------------------------------
    # Validate recovered AES key
    # --------------------------------------------------------

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(
            "Invalid AES-256 session key."
        )

    # --------------------------------------------------------
    # Decrypt actual file
    # --------------------------------------------------------

    file_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=file_nonce
    )

    try:

        plaintext = file_cipher.decrypt_and_verify(
            ciphertext,
            file_tag
        )

    except ValueError:

        raise ValueError(
            "QuantumShield file authentication failed."
        )

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    output_directory = os.path.dirname(
        os.path.abspath(output_path)
    )

    if output_directory:
        os.makedirs(
            output_directory,
            exist_ok=True
        )

    # --------------------------------------------------------
    # Restore original file
    # --------------------------------------------------------

    with open(
        output_path,
        "wb"
    ) as f:

        f.write(plaintext)

    return output_path


# ============================================================
# SIMPLE TEST
# ============================================================

def test_hybrid():
    """
    Complete QuantumShield hybrid encryption test.

    ML-KEM-768
        ↓
    AES-256-GCM
        ↓
    Encrypt
        ↓
    Decrypt
        ↓
    Compare original and restored file
    """

    print("=" * 65)
    print("QuantumShield - Hybrid PQC Encryption Test")
    print("=" * 65)

    test_file = "quantumshield_test.txt"
    decrypted_file = "quantumshield_restored.txt"

    original_data = (
        b"QuantumShield Hybrid PQC Test - "
        b"ML-KEM-768 + AES-256-GCM"
    )

    # --------------------------------------------------------
    # Create test file
    # --------------------------------------------------------

    with open(
        test_file,
        "wb"
    ) as f:

        f.write(original_data)

    print("\n[1] Generating ML-KEM-768 key pair...")

    public_key, secret_key = generate_keypair()

    print(
        "Public Key Size:",
        len(public_key),
        "bytes"
    )

    print(
        "Secret Key Size:",
        len(secret_key),
        "bytes"
    )

    # --------------------------------------------------------
    # Encryption
    # --------------------------------------------------------

    print("\n[2] Encrypting file...")

    encrypted_file = hybrid_encrypt_file(
        test_file,
        public_key
    )

    print(
        "Encrypted File:",
        encrypted_file
    )

    # --------------------------------------------------------
    # Decryption
    # --------------------------------------------------------

    print("\n[3] Decrypting file...")

    hybrid_decrypt_file(
        encrypted_file,
        decrypted_file,
        secret_key
    )

    print(
        "Restored File:",
        decrypted_file
    )

    # --------------------------------------------------------
    # Compare
    # --------------------------------------------------------

    print("\n[4] Verifying original and restored files...")

    with open(
        test_file,
        "rb"
    ) as f:

        original = f.read()

    with open(
        decrypted_file,
        "rb"
    ) as f:

        restored = f.read()

    if original == restored:

        print("\nSUCCESS!")
        print(
            "Original and restored files MATCH."
        )
        print(
            "QuantumShield Hybrid Encryption is working."
        )

    else:

        print("\nFAILED!")
        print(
            "Original and restored files DO NOT MATCH."
        )

    print("\n" + "=" * 65)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    test_hybrid()
