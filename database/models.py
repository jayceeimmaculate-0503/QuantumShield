import os
import hashlib
import psycopg2


def get_db_connection():
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )

    return psycopg2.connect(database_url)


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                otp_code TEXT,
                otp_expiry TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                log_id SERIAL PRIMARY KEY,
                username TEXT,
                action TEXT NOT NULL,
                filename TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT
            )
        """)

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    print("Database initialized successfully!")


def add_user(username, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    try:
        cursor.execute("""
            INSERT INTO users
            (username, email, password_hash)
            VALUES (%s, %s, %s)
        """, (username, email, password_hash))

        conn.commit()

        print("User added successfully!")
        success = True

    except psycopg2.IntegrityError:
        conn.rollback()

        print("Username or email already exists!")
        success = False

    finally:
        cursor.close()
        conn.close()

    return success


def check_login(username, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    try:
        cursor.execute("""
            SELECT *
            FROM users
            WHERE username = %s
            AND email = %s
            AND password_hash = %s
        """, (username, email, password_hash))

        user = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if user:
        return True

    return False


def save_otp(email, otp_code):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE users
            SET otp_code = %s,
                otp_expiry = CURRENT_TIMESTAMP
                              + INTERVAL '10 minutes'
            WHERE email = %s
        """, (otp_code, email))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def verify_otp(email, otp_code):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT *
            FROM users
            WHERE email = %s
            AND otp_code = %s
            AND otp_expiry >= CURRENT_TIMESTAMP
        """, (email, otp_code))

        user = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if user:
        return True

    return False


def clear_otp(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE users
            SET otp_code = NULL,
                otp_expiry = NULL
            WHERE email = %s
        """, (email,))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def delete_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    try:
        cursor.execute("""
            SELECT *
            FROM users
            WHERE username = %s
            AND password_hash = %s
        """, (username, password_hash))

        user = cursor.fetchone()

        if user:
            cursor.execute("""
                DELETE FROM users
                WHERE username = %s
            """, (username,))

            conn.commit()

            return True

        return False

    finally:
        cursor.close()
        conn.close()


def add_activity(
    username,
    action,
    filename="",
    status="SUCCESS"
):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO activity_logs
            (username, action, filename, status)
            VALUES (%s, %s, %s, %s)
        """, (
            username,
            action,
            filename,
            status
        ))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


init_db()