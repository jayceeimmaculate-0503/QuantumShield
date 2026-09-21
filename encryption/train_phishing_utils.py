import os
import random

import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from phishing_utils import extract_url_features


# =========================================================
# PATHS
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

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# =========================================================
# RANDOM SEED
# =========================================================

random.seed(42)


# =========================================================
# SAFE DOMAINS
# =========================================================

safe_domains = [

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

    # Additional legitimate domains
    "docker.com",
    "kubernetes.io",
    "pypi.org",
    "npmjs.com",
    "wordpress.org",
    "apache.org",
    "mozilla.com",
    "intel.com",
    "amd.com",
    "samsung.com",
    "sony.com",
    "dell.com",
    "hp.com",
    "lenovo.com",
]


# =========================================================
# PHISHING BRANDS
# =========================================================

brands = [

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
    "bank",
    "wallet",
]


# =========================================================
# PHISHING WORDS
# =========================================================

phishing_words = [

    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "payment",
    "wallet",
    "urgent",
    "alert",
    "claim",
    "bonus",
    "suspended",
    "unlock",
    "recover",
    "validate",
]


# =========================================================
# SAFE PATHS
# =========================================================

safe_paths = [

    "",
    "/",
    "/about",
    "/contact",
    "/products",
    "/services",
    "/blog",
    "/help",
    "/support",
    "/docs",
    "/news",
    "/privacy",
    "/terms",

    # Authentication
    "/login",
    "/signin",
    "/account",
    "/account/login",
    "/account/settings",

    # Security
    "/security",
    "/security-center",

    # Password
    "/password",
    "/password/reset",

    # Payment
    "/checkout",
    "/payment",
    "/payments",

    # Verification
    "/verify",
    "/verification",

    # Other
    "/notifications",
    "/profile",
    "/settings",
    "/search",
]


# =========================================================
# SAFE SUBDOMAINS
# =========================================================

safe_subdomains = [

    "",
    "www",
    "docs",
    "support",
    "blog",
    "help",
    "developer",
    "community",
    "status",
]


# =========================================================
# SAFE URL GENERATOR
# =========================================================

def generate_safe_urls(count=3000):

    urls = []

    for _ in range(count):

        domain = random.choice(
            safe_domains
        )

        subdomain = random.choice(
            safe_subdomains
        )

        path = random.choice(
            safe_paths
        )

        # -------------------------------------------------
        # Create host
        # -------------------------------------------------

        if subdomain:

            host = (
                f"{subdomain}."
                f"{domain}"
            )

        else:

            host = domain

        # -------------------------------------------------
        # URL patterns
        # -------------------------------------------------

        pattern = random.randint(
            1,
            8
        )

        if pattern == 1:

            url = (
                f"https://{host}"
                f"{path}"
            )

        elif pattern == 2:

            url = (
                f"https://{host}"
                f"{path}?page="
                f"{random.randint(1, 50)}"
            )

        elif pattern == 3:

            url = (
                f"https://{host}"
                f"{path}?id="
                f"{random.randint(1, 99999)}"
            )

        elif pattern == 4:

            url = (
                f"https://{host}"
                f"{path}?ref="
                f"{random.choice([
                    'home',
                    'menu',
                    'search',
                    'profile',
                    'dashboard'
                ])}"
            )

        elif pattern == 5:

            url = (
                f"https://{host}"
                f"{path}?lang="
                f"{random.choice([
                    'en',
                    'ta',
                    'fr',
                    'de'
                ])}"
            )

        elif pattern == 6:

            url = (
                f"https://{host}"
                f"{path}?sort="
                f"{random.choice([
                    'new',
                    'old',
                    'popular'
                ])}"
            )

        elif pattern == 7:

            url = (
                f"https://{host}"
                f"{path}?category="
                f"{random.choice([
                    'technology',
                    'news',
                    'science',
                    'books'
                ])}"
            )

        else:

            url = (
                f"https://{host}"
                f"{path}?page="
                f"{random.randint(1, 20)}"
                f"&lang=en"
            )

        urls.append(url)

    return urls


# =========================================================
# PHISHING URL GENERATOR
# =========================================================

def generate_phishing_urls(count=3000):

    urls = []

    for _ in range(count):

        brand = random.choice(
            brands
        )

        word1 = random.choice(
            phishing_words
        )

        word2 = random.choice(
            phishing_words
        )

        number = random.randint(
            10,
            99999
        )

        pattern = random.randint(
            1,
            14
        )

        # -------------------------------------------------
        # Pattern 1
        # -------------------------------------------------

        if pattern == 1:

            url = (
                f"http://{brand}-"
                f"{word1}-{word2}.com"
            )

        # -------------------------------------------------
        # Pattern 2
        # -------------------------------------------------

        elif pattern == 2:

            url = (
                f"http://secure-"
                f"{brand}-{word1}.com"
            )

        # -------------------------------------------------
        # Pattern 3
        # -------------------------------------------------

        elif pattern == 3:

            url = (
                f"http://{brand}."
                f"{word1}-{word2}.com"
            )

        # -------------------------------------------------
        # Pattern 4
        # -------------------------------------------------

        elif pattern == 4:

            url = (
                f"http://{brand}-account-"
                f"{word1}.net"
            )

        # -------------------------------------------------
        # Pattern 5
        # -------------------------------------------------

        elif pattern == 5:

            url = (
                f"http://{word1}-"
                f"{brand}-security.org"
            )

        # -------------------------------------------------
        # Pattern 6
        # -------------------------------------------------

        elif pattern == 6:

            url = (
                f"http://{brand}-"
                f"{word1}-"
                f"{number}.com"
            )

        # -------------------------------------------------
        # Pattern 7
        # -------------------------------------------------

        elif pattern == 7:

            url = (
                f"http://{brand}.com."
                f"{word1}-{word2}.example.com"
            )

        # -------------------------------------------------
        # Pattern 8
        # -------------------------------------------------

        elif pattern == 8:

            url = (
                f"http://{brand}-"
                f"{word1}-{word2}-"
                f"account.com/login"
            )

        # -------------------------------------------------
        # Pattern 9
        # -------------------------------------------------

        elif pattern == 9:

            url = (
                f"http://{brand}-"
                f"{word1}-{word2}.xyz"
            )

        # -------------------------------------------------
        # Pattern 10
        # -------------------------------------------------

        elif pattern == 10:

            url = (
                f"http://{word1}-"
                f"{brand}-verify-"
                f"{number}.top"
            )

        # -------------------------------------------------
        # Pattern 11
        # -------------------------------------------------

        elif pattern == 11:

            url = (
                f"http://{brand}-"
                f"{word1}-"
                f"{word2}-"
                f"{number}.click"
            )

        # -------------------------------------------------
        # Pattern 12
        # -------------------------------------------------

        elif pattern == 12:

            url = (
                f"http://{brand}-"
                f"secure-login-"
                f"{number}.zip"
            )

        # -------------------------------------------------
        # Pattern 13
        # -------------------------------------------------

        elif pattern == 13:

            url = (
                f"http://verify-"
                f"{brand}-"
                f"{word1}-"
                f"{word2}.tk"
            )

        # -------------------------------------------------
        # Pattern 14
        # -------------------------------------------------

        else:

            url = (
                f"http://{brand}-"
                f"{word1}-"
                f"{word2}-"
                f"account-"
                f"{number}.xyz/login"
            )

        urls.append(url)

    return urls


# =========================================================
# CREATE DATASET
# =========================================================

print()
print("==============================================")
print(" QUANTUMSHIELD PHISHING DATASET GENERATION")
print("==============================================")


safe_urls = generate_safe_urls(
    3000
)

phishing_urls = generate_phishing_urls(
    3000
)


data = []


# =========================================================
# SAFE = 0
# =========================================================

for url in safe_urls:

    features = extract_url_features(
        url
    )

    features["label"] = 0

    data.append(
        features
    )


# =========================================================
# PHISHING = 1
# =========================================================

for url in phishing_urls:

    features = extract_url_features(
        url
    )

    features["label"] = 1

    data.append(
        features
    )


# =========================================================
# DATAFRAME
# =========================================================

df = pd.DataFrame(
    data
)


print(
    "\nTotal samples       :",
    len(df)
)

print(
    "Legitimate samples  :",
    len(safe_urls)
)

print(
    "Phishing samples    :",
    len(phishing_urls)
)


print(
    "\nFeature columns:"
)

print(
    list(
        df.drop(
            columns=["label"]
        ).columns
    )
)


# =========================================================
# DATA PREPARATION
# =========================================================

X = df.drop(
    columns=["label"]
)

y = df["label"]


X_train, X_test, y_train, y_test = (
    train_test_split(

        X,
        y,

        test_size=0.20,

        random_state=42,

        stratify=y
    )
)


print(
    "\nTraining samples    :",
    len(X_train)
)

print(
    "Testing samples     :",
    len(X_test)
)


# =========================================================
# RANDOM FOREST
# =========================================================

model = RandomForestClassifier(

    n_estimators=400,

    max_depth=20,

    min_samples_leaf=2,

    max_features="sqrt",

    random_state=42,

    class_weight="balanced",

    n_jobs=-1
)


print(
    "\nTraining Random Forest..."
)


# =========================================================
# TRAIN
# =========================================================

model.fit(
    X_train,
    y_train
)


# =========================================================
# EVALUATION
# =========================================================

y_pred = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    y_pred
)


print()
print("==============================================")
print(" MODEL TRAINING COMPLETED")
print("==============================================")


print(
    f"Accuracy : {accuracy * 100:.2f}%"
)


print(
    "\nClassification Report:"
)


print(
    classification_report(

        y_test,

        y_pred,

        target_names=[
            "LEGITIMATE",
            "PHISHING"
        ]
    )
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

matrix = confusion_matrix(
    y_test,
    y_pred
)


print(
    "\nConfusion Matrix:"
)

print(
    matrix
)


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

importance = pd.DataFrame({

    "feature": X.columns,

    "importance":
        model.feature_importances_

})


importance = importance.sort_values(

    by="importance",

    ascending=False
)


print(
    "\nTop Important Features:"
)

print(
    importance
    .head(15)
    .to_string(
        index=False
    )
)


# =========================================================
# SAVE MODEL
# =========================================================

joblib.dump(
    model,
    MODEL_FILE
)


print()
print("==============================================")
print(" MODEL SAVED SUCCESSFULLY")
print("==============================================")


print(
    "Model path:"
)

print(
    MODEL_FILE
)


print()
print(
    "🛡️ QuantumShield phishing model is ready!"
)