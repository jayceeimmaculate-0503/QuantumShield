import re
import math
import os
import ipaddress
import joblib

import pandas as pd
from urllib.parse import urlparse


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "phishing_rf_model.pkl"
)


# =========================================================
# TRUSTED DOMAINS
# =========================================================
# These are used only as a trust signal.
# They are NOT an unconditional safety guarantee.

TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "github.com",
    "python.org",
    "linkedin.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "paypal.com",
    "ebay.com",
    "adobe.com",
    "oracle.com",
    "ibm.com",
    "cloudflare.com",
    "nasa.gov",
    "tesla.com",
    "stackoverflow.com",
    "reddit.com",
    "mozilla.org",
    "ubuntu.com",
    "mit.edu",
    "stanford.edu",
}


# =========================================================
# BRANDS
# =========================================================

KNOWN_BRANDS = {
    "paypal",
    "google",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "github",
    "adobe",
    "oracle",
    "cloudflare",
    "tesla",
}


# =========================================================
# SUSPICIOUS WORDS
# =========================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "bank",
    "password",
    "confirm",
    "credential",
    "wallet",
    "payment",
    "payments",
    "free",
    "bonus",
    "gift",
    "claim",
    "urgent",
    "alert",
    "suspended",
    "unlock",
    "recover",
    "validate",
    "authentication",
]


# =========================================================
# SUSPICIOUS TLDs
# =========================================================

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
}


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(text):

    if not text:
        return 0.0

    entropy = 0.0

    for char in set(text):

        probability = (
            text.count(char) / len(text)
        )

        entropy -= (
            probability *
            math.log2(probability)
        )

    return entropy


# =========================================================
# URL NORMALIZATION
# =========================================================

def normalize_url(url):

    if not url or not str(url).strip():
        raise ValueError("URL cannot be empty.")

    url = str(url).strip()

    # Remove surrounding spaces
    url = url.strip()

    # Add scheme if missing
    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        url = "http://" + url

    return url


# =========================================================
# IP ADDRESS CHECK
# =========================================================

def is_ip_address(hostname):

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


# =========================================================
# REGISTERED DOMAIN
# =========================================================

def get_registered_domain(hostname):

    hostname = (
        hostname
        .lower()
        .strip()
        .rstrip(".")
    )

    if hostname.startswith("www."):
        hostname = hostname[4:]

    if is_ip_address(hostname):
        return hostname

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


# =========================================================
# TRUSTED DOMAIN CHECK
# =========================================================

def is_trusted_domain(hostname):

    registered_domain = get_registered_domain(
        hostname
    )

    return registered_domain in TRUSTED_DOMAINS


# =========================================================
# BRAND IMPERSONATION CHECK
# =========================================================

def detect_brand_impersonation(hostname):

    registered_domain = get_registered_domain(
        hostname
    )

    domain_without_tld = (
        registered_domain
        .rsplit(".", 1)[0]
        .lower()
    )

    found_brands = []

    for brand in KNOWN_BRANDS:

        if brand in domain_without_tld:

            # Exact brand domain is legitimate
            if domain_without_tld == brand:
                continue

            found_brands.append(brand)

    return found_brands


# =========================================================
# URL FEATURE EXTRACTION
# =========================================================

def extract_url_features(url):

    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    path = parsed.path or ""
    query = parsed.query or ""

    url_lower = url.lower()

    features = {}

    # -----------------------------------------------------
    # Basic length features
    # -----------------------------------------------------

    features["url_length"] = len(url)

    features["hostname_length"] = len(
        hostname
    )

    features["path_length"] = len(
        path
    )

    features["query_length"] = len(
        query
    )

    # -----------------------------------------------------
    # Character features
    # -----------------------------------------------------

    features["num_dots"] = url.count(".")

    features["num_hyphens"] = url.count("-")

    features["num_underscores"] = url.count("_")

    features["num_slashes"] = url.count("/")

    features["num_question_marks"] = url.count("?")

    features["num_equal"] = url.count("=")

    features["num_at"] = url.count("@")

    features["num_ampersand"] = url.count("&")

    features["num_percent"] = url.count("%")

    features["num_digits"] = sum(
        c.isdigit()
        for c in url
    )

    # -----------------------------------------------------
    # Digit ratio
    # -----------------------------------------------------

    if len(hostname) > 0:

        features["digit_ratio"] = round(
            sum(c.isdigit() for c in hostname)
            / len(hostname),
            4
        )

    else:

        features["digit_ratio"] = 0.0

    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    features["has_ip"] = int(
        is_ip_address(hostname)
    )

    # -----------------------------------------------------
    # HTTP / HTTPS
    # -----------------------------------------------------

    features["has_https"] = int(
        parsed.scheme.lower() == "https"
    )

    features["has_http"] = int(
        parsed.scheme.lower() == "http"
    )

    # -----------------------------------------------------
    # @ symbol
    # -----------------------------------------------------

    features["has_at_symbol"] = int(
        "@" in url
    )

    # -----------------------------------------------------
    # Double slash inside path
    # -----------------------------------------------------

    features["has_double_slash"] = int(
        "//" in path
    )

    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    suspicious_found = [

        word

        for word in SUSPICIOUS_WORDS

        if word in url_lower
    ]

    features["suspicious_word_count"] = len(
        suspicious_found
    )

    # -----------------------------------------------------
    # Subdomain count
    # -----------------------------------------------------

    if hostname:

        hostname_parts = hostname.split(".")

        if len(hostname_parts) >= 3:

            features["subdomain_count"] = (
                len(hostname_parts) - 2
            )

        else:

            features["subdomain_count"] = 0

    else:

        features["subdomain_count"] = 0

    # -----------------------------------------------------
    # Hostname hyphens
    # -----------------------------------------------------

    features["hostname_hyphen_count"] = (
        hostname.count("-")
    )

    # -----------------------------------------------------
    # Hostname dots
    # -----------------------------------------------------

    features["hostname_dot_count"] = (
        hostname.count(".")
    )

    # -----------------------------------------------------
    # Entropy
    # -----------------------------------------------------

    features["url_entropy"] = calculate_entropy(
        url
    )

    # -----------------------------------------------------
    # Encoded characters
    # -----------------------------------------------------

    features["encoded_character_count"] = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    # -----------------------------------------------------
    # Punycode
    # -----------------------------------------------------

    features["has_punycode"] = int(
        "xn--" in hostname
    )

    # -----------------------------------------------------
    # Port
    # -----------------------------------------------------

    try:

        features["has_port"] = int(
            parsed.port is not None
        )

    except ValueError:

        features["has_port"] = 1

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    features["has_suspicious_tld"] = int(
        any(
            hostname.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    impersonated_brands = (
        detect_brand_impersonation(hostname)
    )

    features["brand_impersonation"] = int(
        len(impersonated_brands) > 0
    )

    # -----------------------------------------------------
    # Hyphen ratio
    # -----------------------------------------------------

    if len(hostname) > 0:

        features["hyphen_ratio"] = round(
            hostname.count("-")
            / len(hostname),
            4
        )

    else:

        features["hyphen_ratio"] = 0.0

    return features


# =========================================================
# SECURITY RULE ENGINE
# =========================================================

def security_rule_score(url):

    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    full_url = url.lower()

    score = 0

    reasons = []

    # -----------------------------------------------------
    # Rule 1: IP address
    # -----------------------------------------------------

    if is_ip_address(hostname):

        score += 35

        reasons.append(
            "URL uses an IP address instead of a domain"
        )

    # -----------------------------------------------------
    # Rule 2: @ symbol
    # -----------------------------------------------------

    if "@" in url:

        score += 40

        reasons.append(
            "URL contains an @ symbol"
        )

    # -----------------------------------------------------
    # Rule 3: Punycode
    # -----------------------------------------------------

    if "xn--" in hostname:

        score += 35

        reasons.append(
            "URL contains punycode"
        )

    # -----------------------------------------------------
    # Rule 4: Excessive hyphens
    # -----------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 4:

        score += 25

        reasons.append(
            "Domain contains excessive hyphens"
        )

    elif hyphen_count >= 3:

        score += 15

        reasons.append(
            "Domain contains multiple hyphens"
        )

    # -----------------------------------------------------
    # Rule 5: Excessive subdomains
    # -----------------------------------------------------

    subdomain_count = max(
        len(hostname.split(".")) - 2,
        0
    )

    if subdomain_count >= 4:

        score += 25

        reasons.append(
            "URL contains excessive subdomains"
        )

    elif subdomain_count >= 3:

        score += 15

        reasons.append(
            "URL contains multiple subdomains"
        )

    # -----------------------------------------------------
    # Rule 6: Suspicious keywords
    # -----------------------------------------------------

    suspicious_found = [

        word

        for word in SUSPICIOUS_WORDS

        if word in full_url
    ]

    keyword_count = len(
        suspicious_found
    )

    if keyword_count >= 4:

        score += 30

        reasons.append(
            "URL contains several phishing-related keywords"
        )

    elif keyword_count >= 3:

        score += 20

        reasons.append(
            "URL contains multiple suspicious keywords"
        )

    elif keyword_count == 2:

        score += 10

        reasons.append(
            "URL contains suspicious keywords"
        )

    # -----------------------------------------------------
    # Rule 7: Suspicious TLD
    # -----------------------------------------------------

    if any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        score += 20

        reasons.append(
            "Domain uses a commonly abused TLD"
        )

    # -----------------------------------------------------
    # Rule 8: Very long URL
    # -----------------------------------------------------

    if len(url) > 200:

        score += 20

        reasons.append(
            "URL is unusually long"
        )

    elif len(url) > 150:

        score += 10

        reasons.append(
            "URL is relatively long"
        )

    # -----------------------------------------------------
    # Rule 9: Excessive encoding
    # -----------------------------------------------------

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    if encoded_count >= 8:

        score += 20

        reasons.append(
            "URL contains excessive encoded characters"
        )

    elif encoded_count >= 5:

        score += 10

        reasons.append(
            "URL contains several encoded characters"
        )

    # -----------------------------------------------------
    # Rule 10: Brand impersonation
    # -----------------------------------------------------

    impersonated_brands = (
        detect_brand_impersonation(hostname)
    )

    if impersonated_brands:

        score += 35

        reasons.append(
            "Possible brand impersonation detected"
        )

    # -----------------------------------------------------
    # Rule 11: Many digits in hostname
    # -----------------------------------------------------

    if len(hostname) > 0:

        digit_count = sum(
            c.isdigit()
            for c in hostname
        )

        if digit_count >= 5:

            score += 15

            reasons.append(
                "Domain contains an unusually high number of digits"
            )

    # -----------------------------------------------------
    # Rule 12: HTTP
    # -----------------------------------------------------

    if parsed.scheme.lower() == "http":

        score += 5

        reasons.append(
            "Connection does not use HTTPS"
        )

    return min(score, 100), reasons


# =========================================================
# MODEL LOADING
# =========================================================

def load_phishing_model():

    if not os.path.exists(
        MODEL_FILE
    ):

        raise FileNotFoundError(
            "Phishing detection model not found. "
            "Please train the Random Forest model first."
        )

    return joblib.load(
        MODEL_FILE
    )


# =========================================================
# FINAL RISK LEVEL
# =========================================================

def get_risk_level(score):

    if score >= 70:

        return "HIGH RISK"

    elif score >= 40:

        return "MEDIUM RISK"

    else:

        return "LOW RISK"


# =========================================================
# PHISHING PREDICTION
# =========================================================

def predict_url(url):

    # -----------------------------------------------------
    # Normalize
    # -----------------------------------------------------

    url = normalize_url(url)

    # -----------------------------------------------------
    # Parse
    # -----------------------------------------------------

    parsed = urlparse(url)

    if not parsed.netloc:

        raise ValueError(
            "Invalid URL format."
        )

    hostname = (
        parsed.hostname or ""
    ).lower()

    if not hostname:

        raise ValueError(
            "Invalid hostname."
        )

    # -----------------------------------------------------
    # Extract features
    # -----------------------------------------------------

    features = extract_url_features(
        url
    )

    feature_df = pd.DataFrame(
        [features]
    )

    # -----------------------------------------------------
    # Load model
    # -----------------------------------------------------

    model = load_phishing_model()

    # -----------------------------------------------------
    # ML prediction
    # -----------------------------------------------------

    prediction = model.predict(
        feature_df
    )[0]

    # -----------------------------------------------------
    # ML probability
    # -----------------------------------------------------

    phishing_probability = 0.0

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = (
            model.predict_proba(
                feature_df
            )[0]
        )

        classes = list(
            model.classes_
        )

        if 1 in classes:

            phishing_index = (
                classes.index(1)
            )

            phishing_probability = (
                float(
                    probabilities[
                        phishing_index
                    ]
                ) * 100
            )

    # -----------------------------------------------------
    # Security rules
    # -----------------------------------------------------

    rule_score, rule_reasons = (
        security_rule_score(url)
    )

    # -----------------------------------------------------
    # Trusted domain
    # -----------------------------------------------------

    trusted = is_trusted_domain(
        hostname
    )

    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    impersonated_brands = (
        detect_brand_impersonation(
            hostname
        )
    )

    # -----------------------------------------------------
    # Combine ML + Rules
    # -----------------------------------------------------

    final_score = (
        phishing_probability * 0.70
        + rule_score * 0.30
    )

    # -----------------------------------------------------
    # Trusted domain adjustment
    # -----------------------------------------------------
    # Trusted domains receive a confidence reduction,
    # but are not blindly declared safe.

    if trusted:

        final_score = min(
            final_score,
            15.0
        )

    # -----------------------------------------------------
    # Strong indicators
    # -----------------------------------------------------

    strong_indicator = (

        features["has_ip"] == 1

        or features["has_at_symbol"] == 1

        or features["has_punycode"] == 1
    )

    if strong_indicator:

        final_score = max(
            final_score,
            75.0
        )

    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    if impersonated_brands:

        final_score = max(
            final_score,
            70.0
        )

    # -----------------------------------------------------
    # Limit score
    # -----------------------------------------------------

    final_score = min(
        100.0,
        max(
            0.0,
            final_score
        )
    )

    # -----------------------------------------------------
    # Risk level
    # -----------------------------------------------------

    risk_level = get_risk_level(
        final_score
    )

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    if final_score >= 70:

        final_result = "PHISHING"

    else:

        final_result = "LEGITIMATE"

    # -----------------------------------------------------
    # Reasons
    # -----------------------------------------------------

    final_reasons = []

    if trusted:

        final_reasons.append(
            "Recognized domain with a known trusted-domain suffix"
        )

    final_reasons.extend(
        rule_reasons
    )

    # Remove duplicate reasons
    final_reasons = list(
        dict.fromkeys(
            final_reasons
        )
    )

    # -----------------------------------------------------
    # Default explanation
    # -----------------------------------------------------

    if not final_reasons:

        final_reasons.append(
            "No major suspicious indicators were detected"
        )

    # -----------------------------------------------------
    # Message
    # -----------------------------------------------------

    if final_result == "PHISHING":

        message = (
            "⚠️ This URL shows characteristics "
            "associated with phishing or malicious activity."
        )

    elif risk_level == "MEDIUM RISK":

        message = (
            "⚠️ This URL has some suspicious characteristics. "
            "Use caution before entering sensitive information."
        )

    else:

        message = (
            "✅ This URL appears to have a low phishing risk. "
            "Low risk does not guarantee that the website is authentic."
        )

    # -----------------------------------------------------
    # Return
    # -----------------------------------------------------

    return {

        "url": url,

        "result": final_result,

        "risk_level": risk_level,

        "message": message,

        "risk_score": round(
            final_score,
            2
        ),

        # Kept for compatibility with your
        # existing dashboard code.
        "confidence": round(
            final_score,
            2
        ),

        "features": features,

        "reasons": final_reasons,

        "ml_probability": round(
            phishing_probability,
            2
        ),

        "rule_score": rule_score,

        "trusted_domain": trusted,

        "brand_impersonation": (
            impersonated_brands
        ),
    }