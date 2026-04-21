import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# ---------------- LOAD DATA ----------------
data = pd.read_csv("../data/emails.csv")

# ---------------- CLEAN DATA ----------------
data = data.drop(columns=["Unnamed: 0"])
data = data.dropna()

data["Email Type"] = data["Email Type"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

# ---------------- SPLIT DATA ----------------
X = data["Email Text"]
y = data["Email Type"]

# ---------------- VECTORIZATION ----------------
vectorizer = TfidfVectorizer(stop_words="english")
X_vectorized = vectorizer.fit_transform(X)

# ---------------- TRAIN TEST SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized, y, test_size=0.2, random_state=42
)

# ---------------- MODEL TRAINING ----------------
model = LogisticRegression(max_iter=200)
model.fit(X_train, y_train)

# ---------------- MODEL EVALUATION ----------------
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("\n🔹 Model Accuracy:", round(accuracy * 100, 2), "%")

# ---------------- USER INPUT ----------------
print("\n📩 Enter an email to test:")
user_input = input()

text = user_input.lower()

# ---------------- ML PREDICTION ----------------
input_vector = vectorizer.transform([user_input])
prediction = model.predict(input_vector)
probability = model.predict_proba(input_vector)[0][1]

# ---------------- RESULT ----------------
if prediction[0] == 1:
    print("\n⚠️ PHISHING EMAIL DETECTED")
else:
    print("\n✅ SAFE EMAIL")

print(f"🤖 ML Confidence: {round(probability*100,2)}%")

# ================= ADVANCED RISK ENGINE =================

risk_score = 0
reasons = []

# -------- ML Contribution --------
risk_score += probability * 40
reasons.append(f"ML Risk Contribution: {round(probability*40,2)}")

# -------- URL Detection --------
urls = re.findall(r'(https?://\S+)', user_input)
if urls:
    risk_score += 10
    reasons.append("Contains URL")

# -------- CATEGORY 1: CREDENTIAL ATTACK --------
credential_patterns = [
    "password reset", "login attempt", "verify account",
    "account verification", "unauthorized login", "confirm password"
]

for pattern in credential_patterns:
    if pattern in text:
        risk_score += 12
        reasons.append(f"Credential attack: {pattern}")

# -------- CATEGORY 2: FINANCIAL FRAUD --------
financial_patterns = [
    "payment failed", "invoice attached", "refund initiated",
    "bank alert", "transaction declined", "update payment"
]

for pattern in financial_patterns:
    if pattern in text:
        risk_score += 10
        reasons.append(f"Financial fraud: {pattern}")

# -------- CATEGORY 3: SOCIAL ENGINEERING --------
social_patterns = [
    "urgent action required", "act now", "limited time",
    "account suspended", "immediate response needed"
]

for pattern in social_patterns:
    if pattern in text:
        risk_score += 8
        reasons.append(f"Social engineering: {pattern}")

# -------- CATEGORY 4: PSYCHOLOGICAL ATTACK --------
psychological_patterns = [
    "you have won", "lottery", "reward", "prize",
    "security alert", "your account is blocked"
]

for pattern in psychological_patterns:
    if pattern in text:
        risk_score += 9
        reasons.append(f"Psychological trigger: {pattern}")

# -------- CATEGORY 5: URL MANIPULATION --------
url_patterns = [
    "secure-login", "verify-now", "update-account",
    "login-secure", "account-update"
]

for pattern in url_patterns:
    if pattern in text:
        risk_score += 7
        reasons.append(f"Suspicious URL pattern: {pattern}")

# -------- BEHAVIOR ANALYSIS --------
if "urgent" in text:
    risk_score += 5
    reasons.append("Urgency detected")

if text.count("!") > 2:
    risk_score += 3
    reasons.append("Multiple exclamation marks")

# -------- SAFE SIGNALS --------
safe_patterns = [
    "meeting scheduled", "thank you", "regards",
    "team update", "attached file"
]

for pattern in safe_patterns:
    if pattern in text:
        risk_score -= 6

# -------- NORMALIZE --------
risk_score = max(0, min(risk_score, 100))

# -------- RISK LEVEL --------
if risk_score >= 75:
    risk_level = "HIGH"
elif risk_score >= 40:
    risk_level = "MEDIUM"
else:
    risk_level = "LOW"

# ---------------- OUTPUT ----------------
print("\n📊 --- Risk Analysis ---")
print("Risk Score:", round(risk_score, 2))
print("Risk Level:", risk_level)

print("\n🧠 Reasons:")
for r in reasons:
    print("-", r)

# ================= ADVANCED COMPLIANCE ENGINE =================

compliance_issues = []
recommendations = []

# -------- DYNAMIC MAPPING --------
if "password" in text or "login" in text:
    compliance_issues.append("ISO 27001: Access Control Risk")
    recommendations.append("Enable MFA & strengthen authentication")

if "bank" in text or "payment" in text:
    compliance_issues.append("DPDP: Financial Data Risk")
    recommendations.append("Encrypt sensitive financial data")

if "urgent" in text:
    compliance_issues.append("Social Engineering Risk")
    recommendations.append("Conduct phishing awareness training")

# -------- LEVEL BASED ACTION --------
if risk_level == "HIGH":
    recommendations.append("Block sender immediately")
    recommendations.append("Trigger incident response")

elif risk_level == "MEDIUM":
    recommendations.append("Monitor activity")

# ---------------- PRINT ----------------
print("\n📜 --- Compliance Impact ---")

if compliance_issues:
    for issue in compliance_issues:
        print("-", issue)
else:
    print("No major compliance issues")

print("\n🛡️ --- Recommended Actions ---")
for rec in recommendations:
    print("-", rec)