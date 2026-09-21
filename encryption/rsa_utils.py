from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os


# =========================================================
# RSA KEY CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

RSA_FOLDER = os.path.join(
    BASE_DIR,
    "encryption",
    "rsa_keys"
)

PUBLIC_KEY_FILE = os.path.join(
    RSA_FOLDER,
    "public.pem"
)

PRIVATE_KEY_FILE = os.path.join(
    RSA_FOLDER,
    "private.pem"
)


# =========================================================
# CREATE RSA KEY PAIR
# =========================================================

def generate_rsa_keys():

    # Create rsa_keys folder if it doesn't exist
    os.makedirs(
        RSA_FOLDER,
        exist_ok=True
    )

    # Generate 2048-bit RSA key pair
    key = RSA.generate(2048)

    # Export private key
    private_key = key.export_key()

    with open(
        PRIVATE_KEY_FILE,
        "wb"
    ) as f:

        f.write(private_key)


    # Export public key
    public_key = key.publickey().export_key()

    with open(
        PUBLIC_KEY_FILE,
        "wb"
    ) as f:

        f.write(public_key)


    return True


# =========================================================
# LOAD PUBLIC KEY
# =========================================================

def load_public_key():

    if not os.path.exists(
        PUBLIC_KEY_FILE
    ):

        generate_rsa_keys()

    with open(
        PUBLIC_KEY_FILE,
        "rb"
    ) as f:

        return RSA.import_key(
            f.read()
        )


# =========================================================
# LOAD PRIVATE KEY
# =========================================================

def load_private_key():

    if not os.path.exists(
        PRIVATE_KEY_FILE
    ):

        generate_rsa_keys()

    with open(
        PRIVATE_KEY_FILE,
        "rb"
    ) as f:

        return RSA.import_key(
            f.read()
        )


# =========================================================
# RSA ENCRYPT DATA
# =========================================================

def rsa_encrypt(data):

    public_key = load_public_key()

    cipher = PKCS1_OAEP.new(
        public_key
    )

    encrypted_data = cipher.encrypt(
        data
    )

    return encrypted_data


# =========================================================
# RSA DECRYPT DATA
# =========================================================

def rsa_decrypt(encrypted_data):

    private_key = load_private_key()

    cipher = PKCS1_OAEP.new(
        private_key
    )

    decrypted_data = cipher.decrypt(
        encrypted_data
    )

    return decrypted_data