import os
import hashlib
import oqs

from Crypto.Cipher import AES


# =========================================================
# QUANTUMSHIELD - HYBRID PQC CONFIGURATION
# =========================================================

ALGORITHM = "ML-KEM-768"

# QuantumShield encrypted-file format
MAGIC = b"QSHIELD1"
FORMAT_VERSION = 1

# AES-GCM configuration
AES_KEY_SIZE = 32          # 256 bits
AES_NONCE_SIZE = 12        # Recommended GCM nonce size
AES_TAG_SIZE = 16          # 128-bit authentication tag

# Maximum reasonable KEM ciphertext size.
# ML-KEM-768 ciphertext is normally 1088 bytes.
MAX_KEM_CIPHERTEXT_SIZE = 4096

# Maximum nonce size accepted by parser.
MAX_NONCE_SIZE = 32

# Maximum tag size accepted by parser.
MAX_TAG_SIZE = 32


# =========================================================
# DIRECTORY CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

KEY_DIR = os.path.join(
    BASE_DIR,
    "keys"
)

PRIVATE_KEY_FILE = os.path.join(
    KEY_DIR,
    "mlkem_private.key"
)

PUBLIC_KEY_FILE = os.path.join(
    KEY_DIR,
    "mlkem_public.key"
)


# =========================================================
# DIRECTORY
# =========================================================

def ensure_key_directory():
    """
    Create the QuantumShield key directory if it does not exist.
    """

    os.makedirs(
        KEY_DIR,
        exist_ok=True
    )


# =========================================================
# FILE HELPERS
# =========================================================

def _read_exact(file_object, size, field_name):
    """
    Read exactly 'size' bytes.

    Raises ValueError if the encrypted file is truncated.
    """

    data = file_object.read(size)

    if len(data) != size:
        raise ValueError(
            f"QuantumShield file is corrupted or truncated "
            f"while reading {field_name}."
        )

    return data


# =========================================================
# ML-KEM KEY PAIR GENERATION
# =========================================================

def generate_mlkem_keypair():
    """
    Generate and permanently store one ML-KEM-768 key pair.

    Returns:
        public_key
    """

    ensure_key_directory()

    print("[QuantumShield] Generating ML-KEM-768 key pair...")

    with oqs.KeyEncapsulation(ALGORITHM) as kem:

        public_key = kem.generate_keypair()

        secret_key = kem.export_secret_key()

    # Store private/secret key
    with open(
        PRIVATE_KEY_FILE,
        "wb"
    ) as f:

        f.write(secret_key)

    # Store public key
    with open(
        PUBLIC_KEY_FILE,
        "wb"
    ) as f:

        f.write(public_key)

    print(
        "[QuantumShield] ML-KEM-768 key pair generated successfully."
    )

    return public_key


# =========================================================
# LOAD EXISTING KEY PAIR
# =========================================================

def load_mlkem_keys():
    """
    Load the existing ML-KEM public and private keys.

    If the keys do not exist, generate them.

    Returns:
        (public_key, secret_key)
    """

    ensure_key_directory()

    private_exists = os.path.exists(
        PRIVATE_KEY_FILE
    )

    public_exists = os.path.exists(
        PUBLIC_KEY_FILE
    )

    # -----------------------------------------------------
    # No keys -> create a new key pair
    # -----------------------------------------------------

    if not private_exists and not public_exists:

        public_key = generate_mlkem_keypair()

        with open(
            PRIVATE_KEY_FILE,
            "rb"
        ) as f:

            secret_key = f.read()

        return public_key, secret_key

    # -----------------------------------------------------
    # Only one key exists -> inconsistent key storage
    # -----------------------------------------------------

    if private_exists != public_exists:

        raise ValueError(
            "QuantumShield ML-KEM key storage is inconsistent. "
            "Both mlkem_private.key and mlkem_public.key "
            "must exist together."
        )

    # -----------------------------------------------------
    # Load public key
    # -----------------------------------------------------

    with open(
        PUBLIC_KEY_FILE,
        "rb"
    ) as f:

        public_key = f.read()

    # -----------------------------------------------------
    # Load private key
    # -----------------------------------------------------

    with open(
        PRIVATE_KEY_FILE,
        "rb"
    ) as f:

        secret_key = f.read()

    if not public_key:

        raise ValueError(
            "QuantumShield ML-KEM public key is empty."
        )

    if not secret_key:

        raise ValueError(
            "QuantumShield ML-KEM private key is empty."
        )

    return public_key, secret_key


# =========================================================
# PUBLIC KEY
# =========================================================

def get_public_key():
    """
    Return the existing ML-KEM-768 public key.

    This function NEVER generates a new key pair if
    an existing key pair is already present.
    """

    public_key, _ = load_mlkem_keys()

    return public_key


# =========================================================
# PRIVATE KEY
# =========================================================

def get_private_key():
    """
    Return the existing ML-KEM-768 private key.
    """

    _, secret_key = load_mlkem_keys()

    return secret_key


# =========================================================
# AES KEY DERIVATION
# =========================================================

def derive_aes_key(shared_secret):
    """
    Derive a 256-bit AES key from the ML-KEM shared secret.

    Architecture:

        ML-KEM shared secret
                |
                v
             SHA-256
                |
                v
          AES-256 key
    """

    if not shared_secret:

        raise ValueError(
            "ML-KEM shared secret is empty."
        )

    aes_key = hashlib.sha256(
        shared_secret
    ).digest()

    if len(aes_key) != AES_KEY_SIZE:

        raise ValueError(
            "Invalid AES-256 key length."
        )

    return aes_key


# =========================================================
# HYBRID FILE HEADER
# =========================================================

def _write_header(
    file_object,
    kem_ciphertext,
    nonce,
    tag
):
    """
    Write the QuantumShield hybrid encryption header.

    Format:

        MAGIC
        VERSION
        KEM ciphertext size
        KEM ciphertext
        nonce size
        nonce
        tag size
        tag
        encrypted data
    """

    # -----------------------------------------------------
    # MAGIC
    # -----------------------------------------------------

    file_object.write(
        MAGIC
    )

    # -----------------------------------------------------
    # FORMAT VERSION
    # -----------------------------------------------------

    file_object.write(
        bytes([FORMAT_VERSION])
    )

    # -----------------------------------------------------
    # KEM ciphertext size
    # -----------------------------------------------------

    file_object.write(
        len(kem_ciphertext).to_bytes(
            4,
            "big"
        )
    )

    # -----------------------------------------------------
    # KEM ciphertext
    # -----------------------------------------------------

    file_object.write(
        kem_ciphertext
    )

    # -----------------------------------------------------
    # Nonce size
    # -----------------------------------------------------

    file_object.write(
        bytes([len(nonce)])
    )

    # -----------------------------------------------------
    # Nonce
    # -----------------------------------------------------

    file_object.write(
        nonce
    )

    # -----------------------------------------------------
    # Authentication tag size
    # -----------------------------------------------------

    file_object.write(
        bytes([len(tag)])
    )

    # -----------------------------------------------------
    # Authentication tag
    # -----------------------------------------------------

    file_object.write(
        tag
    )


# =========================================================
# HYBRID FILE HEADER READER
# =========================================================

def _read_header(file_object):
    """
    Safely read and validate the QuantumShield file header.

    Returns:

        kem_ciphertext
        nonce
        tag
    """

    # -----------------------------------------------------
    # MAGIC
    # -----------------------------------------------------

    magic = _read_exact(
        file_object,
        len(MAGIC),
        "file magic"
    )

    if magic != MAGIC:

        # Show useful debugging information.
        try:
            detected = magic.decode(
                "ascii",
                errors="replace"
            )
        except Exception:
            detected = repr(magic)

        raise ValueError(
            "Invalid QuantumShield hybrid file: "
            f"expected magic {MAGIC!r}, "
            f"but found {detected!r}. "
            "This file was probably created by an older "
            "encryption format, is corrupted, or is not "
            "a QuantumShield .pqc file."
        )

    # -----------------------------------------------------
    # FORMAT VERSION
    # -----------------------------------------------------

    version_byte = _read_exact(
        file_object,
        1,
        "format version"
    )

    version = version_byte[0]

    if version != FORMAT_VERSION:

        raise ValueError(
            "Unsupported QuantumShield file version: "
            f"{version}. Expected version "
            f"{FORMAT_VERSION}."
        )

    # -----------------------------------------------------
    # KEM CIPHERTEXT SIZE
    # -----------------------------------------------------

    ciphertext_size_bytes = _read_exact(
        file_object,
        4,
        "KEM ciphertext size"
    )

    ciphertext_size = int.from_bytes(
        ciphertext_size_bytes,
        "big"
    )

    if ciphertext_size <= 0:

        raise ValueError(
            "Invalid QuantumShield KEM ciphertext size."
        )

    if ciphertext_size > MAX_KEM_CIPHERTEXT_SIZE:

        raise ValueError(
            "QuantumShield KEM ciphertext size is "
            "unreasonably large."
        )

    # -----------------------------------------------------
    # KEM CIPHERTEXT
    # -----------------------------------------------------

    kem_ciphertext = _read_exact(
        file_object,
        ciphertext_size,
        "KEM ciphertext"
    )

    # -----------------------------------------------------
    # NONCE SIZE
    # -----------------------------------------------------

    nonce_size_bytes = _read_exact(
        file_object,
        1,
        "AES-GCM nonce size"
    )

    nonce_size = nonce_size_bytes[0]

    if nonce_size <= 0:

        raise ValueError(
            "Invalid AES-GCM nonce size."
        )

    if nonce_size > MAX_NONCE_SIZE:

        raise ValueError(
            "AES-GCM nonce size is invalid."
        )

    # -----------------------------------------------------
    # NONCE
    # -----------------------------------------------------

    nonce = _read_exact(
        file_object,
        nonce_size,
        "AES-GCM nonce"
    )

    # -----------------------------------------------------
    # TAG SIZE
    # -----------------------------------------------------

    tag_size_bytes = _read_exact(
        file_object,
        1,
        "AES-GCM authentication tag size"
    )

    tag_size = tag_size_bytes[0]

    if tag_size <= 0:

        raise ValueError(
            "Invalid AES-GCM authentication tag size."
        )

    if tag_size > MAX_TAG_SIZE:

        raise ValueError(
            "AES-GCM authentication tag size is invalid."
        )

    # -----------------------------------------------------
    # TAG
    # -----------------------------------------------------

    tag = _read_exact(
        file_object,
        tag_size,
        "AES-GCM authentication tag"
    )

    return (
        kem_ciphertext,
        nonce,
        tag
    )


# =========================================================
# HYBRID FILE ENCRYPTION
# =========================================================

def hybrid_encrypt_file(
    input_path,
    output_path=None
):
    """
    Encrypt a file using:

        ML-KEM-768
             |
             v
        Shared Secret
             |
             v
          SHA-256
             |
             v
        AES-256-GCM
    """

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not os.path.isfile(input_path):

        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    # -----------------------------------------------------
    # Output path
    # -----------------------------------------------------

    if output_path is None:

        output_path = (
            input_path
            + ".pqc"
        )

    # -----------------------------------------------------
    # Load stable ML-KEM key pair
    # -----------------------------------------------------

    public_key, _ = load_mlkem_keys()

    # -----------------------------------------------------
    # Read plaintext
    # -----------------------------------------------------

    with open(
        input_path,
        "rb"
    ) as f:

        plaintext = f.read()

    # -----------------------------------------------------
    # ML-KEM encapsulation
    # -----------------------------------------------------

    print(
        "[QuantumShield] Performing ML-KEM-768 encapsulation..."
    )

    with oqs.KeyEncapsulation(
        ALGORITHM
    ) as kem:

        kem_ciphertext, shared_secret = (
            kem.encap_secret(
                public_key
            )
        )

    if not kem_ciphertext:

        raise ValueError(
            "ML-KEM encapsulation produced empty ciphertext."
        )

    if not shared_secret:

        raise ValueError(
            "ML-KEM encapsulation produced empty shared secret."
        )

    # -----------------------------------------------------
    # Derive AES-256 key
    # -----------------------------------------------------

    aes_key = derive_aes_key(
        shared_secret
    )

    # -----------------------------------------------------
    # AES-256-GCM encryption
    # -----------------------------------------------------

    print(
        "[QuantumShield] Encrypting using AES-256-GCM..."
    )

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=os.urandom(
            AES_NONCE_SIZE
        )
    )

    encrypted_data, tag = (
        cipher.encrypt_and_digest(
            plaintext
        )
    )

    nonce = cipher.nonce

    # -----------------------------------------------------
    # Validate generated values
    # -----------------------------------------------------

    if len(nonce) != AES_NONCE_SIZE:

        raise ValueError(
            "Invalid AES-GCM nonce generated."
        )

    if len(tag) != AES_TAG_SIZE:

        raise ValueError(
            "Invalid AES-GCM authentication tag generated."
        )

    # -----------------------------------------------------
    # Write encrypted QuantumShield file
    # -----------------------------------------------------

    with open(
        output_path,
        "wb"
    ) as f:

        _write_header(
            f,
            kem_ciphertext,
            nonce,
            tag
        )

        f.write(
            encrypted_data
        )

    print(
        "[QuantumShield] Encryption completed successfully."
    )

    print(
        "[QuantumShield] Output:",
        output_path
    )

    return output_path


# =========================================================
# HYBRID FILE DECRYPTION
# =========================================================

def hybrid_decrypt_file(
    encrypted_path,
    output_path=None
):
    """
    Decrypt a QuantumShield .pqc file.

    Steps:

        .pqc file
           |
           v
        Parse header
           |
           v
        ML-KEM decapsulation
           |
           v
        Shared Secret
           |
           v
        SHA-256
           |
           v
        AES-256-GCM
           |
           v
        Original file
    """

    # -----------------------------------------------------
    # Validate encrypted file
    # -----------------------------------------------------

    if not os.path.isfile(
        encrypted_path
    ):

        raise FileNotFoundError(
            f"Encrypted file not found: "
            f"{encrypted_path}"
        )

    # -----------------------------------------------------
    # Load private key
    # -----------------------------------------------------

    _, secret_key = load_mlkem_keys()

    # -----------------------------------------------------
    # Read QuantumShield encrypted file
    # -----------------------------------------------------

    with open(
        encrypted_path,
        "rb"
    ) as f:

        (
            kem_ciphertext,
            nonce,
            tag
        ) = _read_header(f)

        # Everything remaining is AES-GCM ciphertext
        encrypted_data = f.read()

    # -----------------------------------------------------
    # Validate encrypted data
    # -----------------------------------------------------

    if len(encrypted_data) == 0:

        raise ValueError(
            "QuantumShield encrypted file contains "
            "no encrypted data."
        )

    # -----------------------------------------------------
    # ML-KEM decapsulation
    # -----------------------------------------------------

    print(
        "[QuantumShield] Performing ML-KEM-768 decapsulation..."
    )

    try:

        with oqs.KeyEncapsulation(
            ALGORITHM,
            secret_key
        ) as kem:

            shared_secret = kem.decap_secret(
                kem_ciphertext
            )

    except Exception as e:

        raise ValueError(
            "ML-KEM decapsulation failed. "
            "The encrypted file may have been created "
            "with a different ML-KEM private key or "
            "may be corrupted."
        ) from e

    if not shared_secret:

        raise ValueError(
            "ML-KEM decapsulation returned an empty "
            "shared secret."
        )

    # -----------------------------------------------------
    # Derive AES-256 key
    # -----------------------------------------------------

    aes_key = derive_aes_key(
        shared_secret
    )

    # -----------------------------------------------------
    # AES-256-GCM decryption
    # -----------------------------------------------------

    print(
        "[QuantumShield] Decrypting using AES-256-GCM..."
    )

    try:

        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce
        )

        plaintext = cipher.decrypt_and_verify(
            encrypted_data,
            tag
        )

    except ValueError as e:

        raise ValueError(
            "AES-GCM authentication failed. "
            "The file may be corrupted, modified, "
            "or encrypted using a different ML-KEM key pair."
        ) from e

    # -----------------------------------------------------
    # Determine output filename
    # -----------------------------------------------------

    if output_path is None:

        if encrypted_path.lower().endswith(
            ".pqc"
        ):

            original_name = encrypted_path[
                :-4
            ]

        else:

            original_name = encrypted_path

        output_directory = (
            os.path.dirname(
                encrypted_path
            )
            or "."
        )

        output_path = os.path.join(
            output_directory,
            "decrypted_"
            + os.path.basename(
                original_name
            )
        )

    # -----------------------------------------------------
    # Write restored file
    # -----------------------------------------------------

    with open(
        output_path,
        "wb"
    ) as f:

        f.write(plaintext)

    print(
        "[QuantumShield] Decryption completed successfully."
    )

    print(
        "[QuantumShield] Restored file:",
        output_path
    )

    return output_path


# =========================================================
# TEST / SELF TEST
# =========================================================

def run_self_test():
    """
    Complete QuantumShield hybrid encryption test.

    Creates a test file, encrypts it, decrypts it,
    and compares the original and restored files.
    """

    print()
    print("=" * 70)
    print(
        "QuantumShield - ML-KEM-768 + AES-256-GCM"
    )
    print(
        "Hybrid PQC Encryption Self-Test"
    )
    print("=" * 70)

    test_file = os.path.join(
        BASE_DIR,
        "hybrid_pqc_test.txt"
    )

    # -----------------------------------------------------
    # Test content
    # -----------------------------------------------------

    test_content = (
        "QuantumShield ML-KEM-768 + "
        "AES-256-GCM Hybrid Test\n"
        "Post-Quantum Secure File Encryption"
    )

    # -----------------------------------------------------
    # Create test file
    # -----------------------------------------------------

    print()
    print("[1] Creating test file...")

    with open(
        test_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            test_content
        )

    print(
        "    Test file:",
        test_file
    )

    # -----------------------------------------------------
    # Encrypt
    # -----------------------------------------------------

    print()
    print("[2] Encrypting test file...")

    encrypted = hybrid_encrypt_file(
        test_file
    )

    print(
        "    Encrypted:",
        encrypted
    )

    # -----------------------------------------------------
    # Decrypt
    # -----------------------------------------------------

    print()
    print("[3] Decrypting test file...")

    decrypted = hybrid_decrypt_file(
        encrypted
    )

    print(
        "    Decrypted:",
        decrypted
    )

    # -----------------------------------------------------
    # Read original
    # -----------------------------------------------------

    print()
    print("[4] Verifying file integrity...")

    with open(
        test_file,
        "rb"
    ) as f:

        original_data = f.read()

    # -----------------------------------------------------
    # Read decrypted
    # -----------------------------------------------------

    with open(
        decrypted,
        "rb"
    ) as f:

        decrypted_data = f.read()

    # -----------------------------------------------------
    # Compare
    # -----------------------------------------------------

    if original_data == decrypted_data:

        print()
        print("SUCCESS! 🎉")
        print(
            "Original and decrypted files MATCH."
        )
        print(
            "ML-KEM-768 + SHA-256 + AES-256-GCM "
            "hybrid encryption is working correctly."
        )

    else:

        print()
        print("FAILED ❌")
        print(
            "Original and decrypted files "
            "DO NOT MATCH."
        )

        raise RuntimeError(
            "QuantumShield self-test failed."
        )

    print()
    print("=" * 70)
    print(
        "QuantumShield self-test completed successfully."
    )
    print("=" * 70)


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    try:

        run_self_test()

    except Exception as e:

        print()
        print("=" * 70)
        print("QuantumShield SELF-TEST FAILED ❌")
        print("=" * 70)
        print(
            "Error:",
            str(e)
        )
        print("=" * 70)

        raise
