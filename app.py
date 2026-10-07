from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    send_from_directory
)

from werkzeug.utils import secure_filename
import random
import resend
import os
import psycopg2
from encryption.phishing_utils import predict_url

from encryption.pqc_utils import (
    generate_keypair,
    encapsulate,
    decapsulate
)

from encryption.aes_utils import (
    encrypt_file,
    decrypt_file
)

from encryption.hybrid_pqc_utils import (
    hybrid_encrypt_file,
    hybrid_decrypt_file
)

from database.models import (
    init_db,
    add_user,
    check_login,
    add_activity,
    save_otp,
    verify_otp,
    clear_otp,
    delete_user
)
init_db()

# =========================================================
# APPLICATION SETUP
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "static",
    "uploads"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# # =========================================================
# EMAIL SENDER UTILITY
# =========================================================

def send_otp_email(receiver_email, otp_code):
    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        print("[ERROR] RESEND_API_KEY is not configured.")
        return False

    try:
        resend.api_key = api_key

        params = {
            "from": "QuantumShield <onboarding@resend.dev>",
            "to": [receiver_email],
            "subject": "QuantumShield Security OTP",
            "html": f"""
                <html>
                    <body>
                        <h2>QuantumShield Security Verification</h2>

                        <p>Your QuantumShield verification OTP is:</p>

                        <h1>{otp_code}</h1>

                        <p>This OTP is valid for 5 minutes.</p>

                        <p>Please do not share this OTP with anyone.</p>

                        <p>
                            Regards,<br>
                            QuantumShield Security Team
                        </p>
                    </body>
                </html>
            """
        }

        email = resend.Emails.send(params)

        print(
            f"[SUCCESS] OTP email sent to {receiver_email}. "
            f"Email ID: {email}"
        )

        return True

    except Exception as e:
        print(f"[ERROR] Email sending failed: {e}")
        return False


# =========================================================
# DASHBOARD OPERATION RESULT HELPER
# =========================================================

def set_operation_result(
    operation,
    status,
    title,
    message,
    filename="",
    output_file="",
    algorithm="",
    integrity="",
    download_file=""
):

    session["operation_result"] = {
        "operation": operation,
        "status": status,
        "title": title,
        "message": message,
        "filename": filename,
        "output_file": output_file,
        "algorithm": algorithm,
        "integrity": integrity,
        "download_file": download_file
    }


# =========================================================
# LOGIN WITH OTP
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def home():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()
        email = request.form.get("email", "").strip()
        password = request.form.get(
            "password",
            ""
        )


        if check_login(
            username,
            email,
            password
        ):
            otp = str(random.randint(100000, 999999))
            save_otp(email, otp)
            send_otp_email(email, otp)

            session["temp_username"] = username
            session["temp_email"] = email
            session["flow"] = "login"

            return redirect("/verify-otp")


        return """
        <h3>Invalid username, email or password.</h3>
        <a href="/">Try Again</a>
        """


    return render_template(
        "login.html"
    )


# =========================================================
# SIGNUP WITH OTP
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        success = add_user(
            username,
            email,
            password
        )

        if success:
            otp = str(random.randint(100000, 999999))
            save_otp(email, otp)
            send_otp_email(email, otp)

            session["temp_username"] = username
            session["temp_email"] = email
            session["flow"] = "signup"

            return redirect("/verify-otp")
        else:
            return """
            <h3>Username or Email already exists!</h3>
            <a href="/signup">Try Again</a>
            """


    return render_template(
        "signup.html"
    )


# =========================================================
# OTP VERIFICATION ROUTE
# =========================================================

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_route():
    if "temp_email" not in session:
        return redirect("/")

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        email = session["temp_email"]
        username = session["temp_username"]
        flow = session.get("flow", "login")

        # Inga verify_otp function database-oda pesum
        if verify_otp(email, entered_otp):
            clear_otp(email)
            session["username"] = username
            session["email"] = email

            session.pop("temp_username", None)
            session.pop("temp_email", None)
            session.pop("flow", None)

            add_activity(username, "LOGIN_OTP_SUCCESS" if flow == "login" else "SIGNUP_VERIFIED", "", "SUCCESS")
            return redirect("/dashboard")
        else:
            return render_template("otp.html", error="Invalid or Expired OTP. Please try again.")

    # GET request vanthalum 405 error varathu, page normal-ah load agum
    return render_template("otp.html", error=None)

# =========================================================
# RESEND OTP ROUTE
# =========================================================

@app.route("/resend-otp")
def resend_otp():
    if "temp_email" not in session:
        return redirect("/")

    email = session["temp_email"]
    
    # Puthiya OTP generate panni save panrathu
    otp = str(random.randint(100000, 999999))
    save_otp(email, otp)
    send_otp_email(email, otp)

    return render_template("otp.html", error=None, message="New OTP has been sent successfully!")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/")

    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            username,
            action,
            filename,
            timestamp,
            status
        FROM activity_logs
        ORDER BY log_id DESC
        LIMIT 10
    """)

    logs = cursor.fetchall()
    conn.close()

    operation_result = session.pop(
        "operation_result",
        None
    )

    return render_template(
        "dashboard.html",
        logs=logs,
        username=session["username"],
        operation_result=operation_result
    )


# =========================================================
# DELETE ACCOUNT ROUTE
# =========================================================

@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "username" not in session:
        return redirect("/")

    username = session["username"]
    password = request.form.get("password", "")

    if delete_user(username, password):
        session.clear()
        return redirect("/")
    else:
        set_operation_result(
            operation="DELETE_ACCOUNT",
            status="ERROR",
            title="Deletion Failed",
            message="Incorrect password. Account could not be deleted.",
            algorithm="User Management"
        )
        return redirect("/dashboard")


# =========================================================
# AES FILE ENCRYPTION
# =========================================================

@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    if "username" not in session:
        return redirect("/")

    file = request.files.get("file")

    if not file or file.filename == "":
        set_operation_result(
            operation="AES_ENCRYPT",
            status="ERROR",
            title="Encryption Failed",
            message="No file was selected.",
            algorithm="AES File Encryption"
        )
        return redirect("/dashboard")

    filename = secure_filename(file.filename)

    if not filename:
        set_operation_result(
            operation="AES_ENCRYPT",
            status="ERROR",
            title="Invalid File",
            message="The selected filename is invalid.",
            algorithm="AES File Encryption"
        )
        return redirect("/dashboard")

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    file.save(filepath)
    username = session["username"]

    try:
        encrypted_path = encrypt_file(filepath)
        encrypted_filename = os.path.basename(encrypted_path)

        add_activity(
            username,
            "FILE_ENCRYPTED",
            filename,
            "SUCCESS"
        )

        set_operation_result(
            operation="AES_ENCRYPT",
            status="SUCCESS",
            title="File Encrypted Successfully",
            message="Your file has been securely encrypted.",
            filename=filename,
            output_file=encrypted_filename,
            algorithm="AES File Encryption",
            integrity="Encryption completed successfully",
            download_file=encrypted_filename
        )

        return redirect("/dashboard")

    except Exception as e:
        add_activity(
            username,
            "FILE_ENCRYPTED",
            filename,
            "FAILED"
        )

        set_operation_result(
            operation="AES_ENCRYPT",
            status="ERROR",
            title="Encryption Failed",
            message=str(e),
            filename=filename,
            algorithm="AES File Encryption"
        )

        return redirect("/dashboard")


# =========================================================
# AES FILE DECRYPTION
# =========================================================

@app.route(
    "/decrypt",
    methods=["POST"]
)
def decrypt():

    if "username" not in session:
        return redirect("/")

    file = request.files.get("file")

    if not file or file.filename == "":
        set_operation_result(
            operation="AES_DECRYPT",
            status="ERROR",
            title="Decryption Failed",
            message="No encrypted file was selected.",
            algorithm="AES File Decryption"
        )
        return redirect("/dashboard")

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(".enc"):
        set_operation_result(
            operation="AES_DECRYPT",
            status="ERROR",
            title="Invalid Encrypted File",
            message="Please select a valid .enc file.",
            filename=filename,
            algorithm="AES File Decryption"
        )
        return redirect("/dashboard")

    encrypted_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    file.save(encrypted_path)

    original_filename = filename[:-4]
    decrypted_filename = "decrypted_" + original_filename
    decrypted_path = os.path.join(
        UPLOAD_FOLDER,
        decrypted_filename
    )

    username = session["username"]

    try:
        decrypt_file(
            encrypted_path,
            decrypted_path
        )

        add_activity(
            username,
            "FILE_DECRYPTED",
            filename,
            "SUCCESS"
        )

        set_operation_result(
            operation="AES_DECRYPT",
            status="SUCCESS",
            title="File Decrypted Successfully",
            message="Your original file has been restored successfully.",
            filename=filename,
            output_file=decrypted_filename,
            algorithm="AES File Decryption",
            integrity="Decryption completed successfully",
            download_file=decrypted_filename
        )

        return redirect("/dashboard")

    except Exception as e:
        add_activity(
            username,
            "FILE_DECRYPTED",
            filename,
            "FAILED"
        )

        set_operation_result(
            operation="AES_DECRYPT",
            status="ERROR",
            title="Decryption Failed",
            message=str(e),
            filename=filename,
            algorithm="AES File Decryption"
        )

        return redirect("/dashboard")


# =========================================================
# ML-KEM-768 SECURITY TEST
# =========================================================

@app.route(
    "/pqc-test",
    methods=["POST"]
)
def pqc_test():

    if "username" not in session:
        return redirect("/")

    username = session["username"]

    try:
        public_key, secret_key = generate_keypair()
        ciphertext, shared_secret_sender = encapsulate(public_key)
        shared_secret_receiver = decapsulate(
            secret_key,
            ciphertext
        )

        if shared_secret_sender == shared_secret_receiver:
            add_activity(
                username,
                "PQC_TEST",
                "ML-KEM-768",
                "SUCCESS"
            )

            set_operation_result(
                operation="PQC_TEST",
                status="SUCCESS",
                title="Post-Quantum Security Test Passed",
                message="Sender and receiver shared secrets MATCH.",
                filename="ML-KEM-768",
                output_file="Security Verification",
                algorithm="ML-KEM-768",
                integrity="Shared secret verification successful"
            )

            return redirect("/dashboard")

        add_activity(
            username,
            "PQC_TEST",
            "ML-KEM-768",
            "FAILED"
        )

        set_operation_result(
            operation="PQC_TEST",
            status="ERROR",
            title="Post-Quantum Security Test Failed",
            message="Sender and receiver shared secrets do not match.",
            filename="ML-KEM-768",
            algorithm="ML-KEM-768",
            integrity="Verification failed"
        )

        return redirect("/dashboard")

    except Exception as e:
        add_activity(
            username,
            "PQC_TEST",
            "ML-KEM-768",
            "FAILED"
        )

        set_operation_result(
            operation="PQC_TEST",
            status="ERROR",
            title="PQC Security Test Error",
            message=str(e),
            filename="ML-KEM-768",
            algorithm="ML-KEM-768"
        )

        return redirect("/dashboard")


# =========================================================
# QUANTUMSHIELD HYBRID PQC ENCRYPTION
# =========================================================

@app.route(
    "/hybrid-encrypt",
    methods=["POST"]
)
def hybrid_encrypt():

    if "username" not in session:
        return redirect("/")

    file = request.files.get("file")

    if not file or file.filename == "":
        set_operation_result(
            operation="HYBRID_ENCRYPT",
            status="ERROR",
            title="Hybrid Encryption Failed",
            message="No file was selected.",
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )
        return redirect("/dashboard")

    filename = secure_filename(file.filename)

    if not filename:
        set_operation_result(
            operation="HYBRID_ENCRYPT",
            status="ERROR",
            title="Invalid File",
            message="The selected filename is invalid.",
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )
        return redirect("/dashboard")

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )
    file.save(filepath)
    username = session["username"]

    try:
        encrypted_path = hybrid_encrypt_file(filepath)
        encrypted_filename = os.path.basename(encrypted_path)

        add_activity(
            username,
            "HYBRID_PQC_ENCRYPTED",
            filename,
            "SUCCESS"
        )

        set_operation_result(
            operation="HYBRID_ENCRYPT",
            status="SUCCESS",
            title="Hybrid PQC Encryption Successful",
            message="Your file is protected using QuantumShield hybrid post-quantum encryption.",
            filename=filename,
            output_file=encrypted_filename,
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM",
            integrity="Authenticated encryption completed successfully",
            download_file=encrypted_filename
        )

        return redirect("/dashboard")

    except Exception as e:
        add_activity(
            username,
            "HYBRID_PQC_ENCRYPTED",
            filename,
            "FAILED"
        )

        set_operation_result(
            operation="HYBRID_ENCRYPT",
            status="ERROR",
            title="Hybrid PQC Encryption Failed",
            message=str(e),
            filename=filename,
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )

        return redirect("/dashboard")


# =========================================================
# QUANTUMSHIELD HYBRID PQC DECRYPTION
# =========================================================

@app.route(
    "/hybrid-decrypt",
    methods=["POST"]
)
def hybrid_decrypt():

    if "username" not in session:
        return redirect("/")

    file = request.files.get("file")

    if not file or file.filename == "":
        set_operation_result(
            operation="HYBRID_DECRYPT",
            status="ERROR",
            title="Hybrid Decryption Failed",
            message="No QuantumShield file was selected.",
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )
        return redirect("/dashboard")

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(".pqc"):
        set_operation_result(
            operation="HYBRID_DECRYPT",
            status="ERROR",
            title="Invalid QuantumShield File",
            message="Please select a genuine .pqc file created by QuantumShield.",
            filename=filename,
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )
        return redirect("/dashboard")

    encrypted_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )
    file.save(encrypted_path)

    original_filename = filename[:-4]
    decrypted_filename = "decrypted_" + original_filename
    decrypted_path = os.path.join(
        UPLOAD_FOLDER,
        decrypted_filename
    )

    username = session["username"]

    try:
        hybrid_decrypt_file(
            encrypted_path,
            decrypted_path
        )

        add_activity(
            username,
            "HYBRID_PQC_DECRYPTED",
            filename,
            "SUCCESS"
        )

        set_operation_result(
            operation="HYBRID_DECRYPT",
            status="SUCCESS",
            title="Hybrid PQC Decryption Successful",
            message="The original file has been successfully restored.",
            filename=filename,
            output_file=decrypted_filename,
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM",
            integrity="GCM authentication verified successfully",
            download_file=decrypted_filename
        )

        return redirect("/dashboard")

    except Exception as e:
        add_activity(
            username,
            "HYBRID_PQC_DECRYPTED",
            filename,
            "FAILED"
        )

        set_operation_result(
            operation="HYBRID_DECRYPT",
            status="ERROR",
            title="Hybrid PQC Decryption Failed",
            message=str(e),
            filename=filename,
            algorithm="ML-KEM-768 + SHA-256 + AES-256-GCM"
        )

        return redirect("/dashboard")


# =========================================================
# PHISHING URL CHECKER
# =========================================================

@app.route(
    "/check-phishing",
    methods=["POST"]
)
def check_phishing():

    if "username" not in session:
        return redirect("/")

    username = session["username"]
    url = request.form.get("url", "").strip()

    if not url:
        add_activity(
            username,
            "PHISHING_URL_CHECK",
            "",
            "FAILED"
        )
        return jsonify({
            "success": False,
            "message": "Please enter a URL."
        }), 400

    # --- INGA THAAN CHANGE: www. mattum irunthalum https:// add aagira madri panna podhum ---
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        # Ithu unga palaya function-aye call pannum, ellam values-um kidaikkum!
        result = predict_url(url)
        detected_result = result.get("result")

        if detected_result == "PHISHING":
            add_activity(
                username,
                "PHISHING_URL_DETECTED",
                result.get("url"),
                "DANGER"
            )
        else:
            add_activity(
                username,
                "PHISHING_URL_CHECKED",
                result.get("url"),
                "SAFE"
            )

        return jsonify({
            "success": True,
            "url": result.get("url"),
            "result": result.get("result"),
            "message": result.get("message"),
            "risk_level": result.get("risk_level", "LOW RISK"),
            "risk_score": result.get("risk_score", 0),
            "ml_probability": result.get("ml_probability", 0),
            "rule_score": result.get("rule_score", 0),
            "reasons": result.get("reasons", []),
            "trusted_domain": result.get("trusted_domain", False),
            "brand_impersonation": result.get("brand_impersonation", [])
        })

    except Exception as e:
        add_activity(
            username,
            "PHISHING_URL_CHECK",
            url,
            "FAILED"
        )
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# =========================================================
# SECURE FILE DOWNLOAD
# =========================================================

@app.route(
    "/download/<filename>"
)
def download_file(filename):

    if "username" not in session:
        return redirect("/")

    filename = secure_filename(filename)

    if not filename:
        return redirect("/dashboard")

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    if not os.path.isfile(filepath):
        set_operation_result(
            operation="DOWNLOAD",
            status="ERROR",
            title="Download Failed",
            message="Requested file was not found.",
            output_file=filename
        )
        return redirect("/dashboard")

    return send_from_directory(
        UPLOAD_FOLDER,
        filename,
        as_attachment=True
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
def logout():

    username = session.get("username")

    if username:
        add_activity(
            username,
            "LOGOUT",
            "",
            "SUCCESS"
        )

    session.clear()
    return redirect("/")


# =========================================================
# START QUANTUMSHIELD
# =========================================================

if __name__ == "__main__":
    init_db()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )