from phishing_utils import predict_url

url = input("Enter URL: ")

result = predict_url(url)

print("\n================================")
print("URL:", result["url"])
print("RESULT:", result["result"])
print("RISK LEVEL:", result["risk_level"])
print("RISK SCORE:", result["risk_score"])
print("ML PROBABILITY:", result["ml_probability"])
print("RULE SCORE:", result["rule_score"])
print("TRUSTED DOMAIN:", result["trusted_domain"])
print("BRAND IMPERSONATION:", result["brand_impersonation"])
print("REASONS:", result["reasons"])
print("================================")