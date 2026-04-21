# 🔐 AI-Powered Cyber Threat Intelligence & Phishing Detection Platform

A real-time cybersecurity system designed to detect phishing emails using a hybrid approach combining intelligent analysis, rule-based detection, and threat intelligence. The platform simulates a Security Operations Center (SOC) environment with risk scoring, alerting, and compliance mapping.

---

## 🚀 Features

* 🔍 Advanced phishing detection system
* 🌐 URL intelligence and suspicious link analysis
* ⚠️ Risk scoring and trust evaluation
* 🚨 Real-time alert monitoring
* 📊 SOC-style dashboard for threat visibility
* 📁 Email logging and activity tracking
* 🧠 Explainable detection (reason-based analysis)
* 📜 Compliance mapping (ISO 27001, OWASP Top 10, DPDP)

---

## 🧠 How It Works

1. User inputs email content into the system
2. The system analyzes the email using intelligent processing
3. A rule-based engine evaluates:

   * URL patterns and link behavior
   * Social engineering signals
   * Credential and financial fraud indicators
4. A combined risk score is calculated
5. The system classifies the email as **Safe** or **Phishing**
6. Results are displayed on a dashboard with alerts, logs, and insights

---

## 📊 Dashboard Capabilities

* Risk Score & Trust Score visualization
* AI Confidence indicator
* Detection reasons (Explainable AI)
* Risk breakdown (URL, behavior, content, threat)
* Live alert system for high-risk emails
* Email logs and historical trend analysis

---

## 🛠️ Project Structure

app/
│── app.py              # Main SOC dashboard

data/
│── emails.csv         # Dataset

src/
│── model.py           # ML model logic
│── load_data.py       # Data preprocessing

requirements.txt       # Dependencies

---

## ▶️ Run Locally

1. Install dependencies:
   pip install -r requirements.txt

2. Run the application:
   streamlit run app/app.py

---

## 📌 Use Case

This project simulates a real-world cybersecurity system used in organizations for:

* Detecting phishing attacks
* Monitoring email-based threats
* Supporting SOC operations
* Enhancing risk management and compliance

---

## 🎯 Key Concepts Covered

* Cybersecurity & Threat Intelligence
* Phishing Detection Techniques
* SOC (Security Operations Center)
* Risk Scoring Models
* Social Engineering Detection
* Governance, Risk & Compliance (GRC)

---

## 👨‍💻 Author

**Harsh Mehta**
MBA (SCIT) | Cybersecurity & AI Enthusiast

---

