import streamlit as st
import pandas as pd
import re
import datetime
import matplotlib.pyplot as plt
import numpy as np
import time
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Cyber SOC Platform", layout="wide")

# ---------------- LOGIN SYSTEM ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

def login():
    st.title("🔐 Admin Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.logged_in = True
        else:
            st.error("Invalid credentials")

if not st.session_state.logged_in:
    login()
    st.stop()

# ---------------- MAIN APP ----------------
st.title("🔐 Cyber SOC & Real-Time Monitoring Platform")
st.caption("AI + Threat Intelligence + SOC + Analytics + GRC")

st.markdown("---")

# ---------------- SESSION ----------------
if "history" not in st.session_state:
    st.session_state.history = []

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "user_risk" not in st.session_state:
    st.session_state.user_risk = 0

# ---------------- MODEL ----------------
data = pd.read_csv("../data/emails.csv")
data = data.drop(columns=["Unnamed: 0"]).dropna()

data["Email Type"] = data["Email Type"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

X = data["Email Text"]
y = data["Email Type"]

vectorizer = TfidfVectorizer(stop_words="english")
X_vectorized = vectorizer.fit_transform(X)

model = LogisticRegression(max_iter=200)
model.fit(X_vectorized, y)

# ---------------- SIDEBAR ----------------
st.sidebar.header("⚙️ Settings")

auto_refresh = st.sidebar.checkbox("Enable Real-Time Monitoring")
show_logs = st.sidebar.checkbox("Show Logs", True)
show_alerts = st.sidebar.checkbox("Show Alerts", True)

st.sidebar.markdown("---")
st.sidebar.write("System Status: 🟢 Active")

# ---------------- INPUT ----------------
user_input = st.text_area("📩 Enter Email Text", height=120)

# ================= MAIN =================
if st.button("Analyze") or auto_refresh:

    if user_input.strip() == "":
        st.warning("Enter email text")
    else:
        text = user_input.lower()
        input_vector = vectorizer.transform([user_input])
        probability = model.predict_proba(input_vector)[0][1]

        # ================= RULE ENGINE =================
        urls = re.findall(r'(https?://\S+)', user_input)

        risk_score = probability * 40
        reasons = []

        if urls:
            risk_score += 15
            reasons.append("Contains external link")

        for url in urls:
            if "@" in url:
                risk_score += 20
                reasons.append("URL contains '@'")
            if url.count("-") >= 2:
                risk_score += 10
                reasons.append("Suspicious domain structure")
            if any(short in url for short in ["bit.ly","tinyurl","goo.gl"]):
                risk_score += 20
                reasons.append("Shortened URL")
            for term in ["login","verify","update","secure","account"]:
                if term in url:
                    risk_score += 8
                    reasons.append(f"Suspicious URL keyword: {term}")
            if len(url) > 50:
                risk_score += 5
                reasons.append("Long URL detected")
            if url.count(".") > 3:
                risk_score += 10
                reasons.append("Too many subdomains")

        credential_patterns = [
            "password reset","verify account","login attempt",
            "confirm password","reset your password","account verification"
        ]

        for p in credential_patterns:
            if p in text:
                risk_score += 12
                reasons.append(f"Credential attack: {p}")

        financial_patterns = [
            "payment failed","invoice","refund","transaction",
            "bank alert","update payment","billing issue"
        ]

        for p in financial_patterns:
            if p in text:
                risk_score += 10
                reasons.append(f"Financial fraud: {p}")

        social_patterns = [
            "urgent","act now","limited time","immediate action",
            "account suspended","respond immediately"
        ]

        for p in social_patterns:
            if p in text:
                risk_score += 8
                reasons.append(f"Social engineering: {p}")

        psychological_patterns = [
            "you won","lottery","reward","prize",
            "free gift","exclusive offer"
        ]

        for p in psychological_patterns:
            if p in text:
                risk_score += 9
                reasons.append(f"Psychological trigger: {p}")

        risk_score = max(0, min(risk_score, 100))
        trust_score = 100 - risk_score

        if probability > 0.7 or risk_score > 65:
            prediction = 1
        else:
            prediction = 0

        if risk_score > 70:
            level = "HIGH"
        elif risk_score > 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        entry = {
            "Time": datetime.datetime.now(),
            "Email": user_input[:60],
            "Risk": risk_score,
            "Level": level
        }

        st.session_state.history.append(entry)

        if level == "HIGH":
            st.session_state.alerts.append(entry)

        st.session_state.user_risk += risk_score * 0.1

        # ================= KPI =================
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Risk Score", round(risk_score,2))
        col2.metric("Trust Score", round(trust_score,2))
        col3.metric("AI Confidence", round(probability*100,2))
        col4.metric("User Risk", round(st.session_state.user_risk,2))

        st.markdown("---")

        # ================= STATUS =================
        if prediction:
            st.error("🚨 PHISHING DETECTED")
        else:
            st.success("✅ SAFE EMAIL")

        st.progress(int(risk_score))

        # ================= BREAKDOWN =================
        st.subheader("📊 Risk Breakdown")

        breakdown_df = pd.DataFrame({
            "Component": ["ML","URL","Rules"],
            "Score": [probability*40, len(urls)*10, risk_score-(probability*40)]
        })

        st.dataframe(breakdown_df)

        fig = plt.figure()
        plt.bar(breakdown_df["Component"], breakdown_df["Score"])
        st.pyplot(fig)

        # ================= REASONS =================
        st.subheader("🧠 Detection Reasons")

        if reasons:
            for r in reasons:
                st.write("-", r)
        else:
            st.write("No major threats detected")

        # ================= ALERTS =================
        if show_alerts:
            st.subheader("🚨 Live Alerts")
            if st.session_state.alerts:
                for a in st.session_state.alerts[-5:]:
                    st.error(f"{a['Time']} - HIGH RISK")
            else:
                st.success("No alerts")

        # ================= HISTORY =================
        if show_logs:
            st.subheader("📁 Email Logs")
            df = pd.DataFrame(st.session_state.history)
            st.dataframe(df)

# ================= COMPLIANCE ENGINE =================
        st.subheader("📜 Compliance Impact (Advanced)")

        compliance_issues = []
        compliance_score = 0

        # OWASP
        if "password" in text or "login" in text:
            compliance_issues.append("OWASP A2: Authentication Failure")
            compliance_score += 20

        if "http" in text or "link" in text:
            compliance_issues.append("OWASP A10: SSRF / Phishing Link Abuse")
            compliance_score += 15

        if "urgent" in text:
            compliance_issues.append("OWASP A8: Social Engineering Risk")
            compliance_score += 10

        if "payment" in text:
            compliance_issues.append("OWASP A5: Security Misconfiguration")
            compliance_score += 15

        # ISO
        if "login" in text:
            compliance_issues.append("ISO 27001 A.9: Access Control")
            compliance_score += 15

        if "link" in text:
            compliance_issues.append("ISO 27001 A.13: Network Security")
            compliance_score += 10

        if "urgent" in text:
            compliance_issues.append("ISO 27001 A.7: Human Risk")
            compliance_score += 10

        # DPDP
        if any(k in text for k in ["password","otp","bank"]):
            compliance_issues.append("DPDP: Personal Data Breach Risk")
            compliance_score += 20

        if any(k in text for k in ["email","phone"]):
            compliance_issues.append("DPDP: PII Exposure Risk")
            compliance_score += 10

        compliance_issues = list(set(compliance_issues))

        for issue in compliance_issues:
            st.write("•", issue)

        if compliance_score > 60:
            comp_level = "HIGH"
        elif compliance_score > 30:
            comp_level = "MEDIUM"
        else:
            comp_level = "LOW"

        st.metric("Compliance Risk Level", comp_level)

        # ================= ACTION =================
        st.subheader("🛡️ Recommended Actions")

        if level == "HIGH":
            st.write("- Block sender")
            st.write("- Trigger incident response")
            st.write("- Enable MFA")
        elif level == "MEDIUM":
            st.write("- Monitor activity")
        else:
            st.write("No action needed")

# ================= REAL-TIME =================
if auto_refresh:
    st.info("🔄 Real-time monitoring active")
    time.sleep(3)
    st.stop()

# ---------------- FOOTER ----------------
st.markdown("---")
st.caption("Developed by Harsh Mehta | Enterprise Cyber SOC Platform")
