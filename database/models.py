import sqlite3
import hashlib
import os


# =========================================================
# DATABASE PATH
# =========================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATABASE = os.path.join(
    BASE_DIR,
    "database",
    "quantumshield.db"
)


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # -----------------------------------------------------
    # USERS TABLE (Added otp_code and otp_expiry columns)
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_code TEXT,
            otp_expiry TIMESTAMP
        )
    """)

    # -----------------------------------------------------
    # ACTIVITY LOG TABLE
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            filename TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )
    """)

    conn.commit()
    conn.close()

    print("Database initialized successfully!")


# =========================================================
# ADD USER
# =========================================================

def add_user(username, email, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # SHA-256 password hashing
    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    try:
        cursor.execute("""
            INSERT INTO users
            (username, email, password_hash)
            VALUES (?, ?, ?)
        """, (
            username,
            email,
            password_hash
        ))

        conn.commit()
        print("User added successfully!")
        success = True

    except sqlite3.IntegrityError:
        print("Username or email already exists!")
        success = False

    conn.close()
    return success


# =========================================================
# CHECK LOGIN
# =========================================================

def check_login(username, email, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Hash entered password
    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    cursor.execute("""
        SELECT *
        FROM users
        WHERE username = ?
        AND email = ?
        AND password_hash = ?
    """, (
        username,
        email,
        password_hash
    ))

    user = cursor.fetchone()
    conn.close()

    if user:
        return True

    return False


# =========================================================
# OTP FUNCTIONS (Updated for Email & 10 Mins Expiry)
# =========================================================

def save_otp(email, otp_code):
    """Save or update OTP and set 10 minutes expiry for a specific email."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET otp_code = ?, otp_expiry = datetime('now', '+10 minutes')
        WHERE email = ?
    """, (otp_code, email))

    conn.commit()
    conn.close()


def verify_otp(email, otp_code):
    """Verify if the OTP matches and has not expired (within 10 mins)."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM users
        WHERE email = ?
        AND otp_code = ?
        AND otp_expiry >= datetime('now')
    """, (email, otp_code))

    user = cursor.fetchone()
    conn.close()

    if user:
        return True
    return False


def clear_otp(email):
    """Clear or reset the OTP and expiry after successful verification."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET otp_code = NULL, otp_expiry = NULL
        WHERE email = ?
    """, (email,))

    conn.commit()
    conn.close()


# =========================================================
# DELETE ACCOUNT (Danger Zone Feature)
# =========================================================

def delete_user(username, password):
    """Verify password and delete user from database (keeping logs for security audit if needed)."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Check if user & password match first
    cursor.execute("""
        SELECT * FROM users
        WHERE username = ? AND password_hash = ?
    """, (username, password_hash))

    user = cursor.fetchone()

    if user:
        # NOTICE: Antha activity_logs delete panra line-ah ingrunthu eduthutom! 
        # So logs safe-ah irukkum.
        
        # Delete user account only
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

# =========================================================
# ADD SECURITY ACTIVITY LOG
# =========================================================

def add_activity(
    username,
    action,
    filename="",
    status="SUCCESS"
):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO activity_logs
        (username, action, filename, status)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        action,
        filename,
        status
    ))

    conn.commit()
    conn.close()


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    init_db()