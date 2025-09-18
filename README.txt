# 🔐 CrackTime Analyzer

[![Tests](https://github.com/<your-username>/<your-repo>/actions/workflows/python-tests.yml/badge.svg)](https://github.com/<your-username>/<your-repo>/actions/workflows/python-tests.yml)

A **password strength auditing tool** that estimates password entropy and crack time.  
It works both from the **command line** and via a **Streamlit web GUI**, and can export results to **JSON/CSV reports**.  
⚠️ *For educational/demo purposes only. Do not use real passwords.*

---

## ✨ Features
- CLI tool and Streamlit GUI.
- Password entropy & crack-time estimation (using `zxcvbn`).
- Multiple attacker speed presets (CPU, GPU, clusters).
- Strength meter with visual feedback (0–4).
- Crack-time gauge with human-readable estimates.
- Export analysis reports to **JSON/CSV**.
- Includes automated tests (Pytest + GitHub Actions CI).

---

## 📸 Screenshots
### Weak password
![Weak Password](screenshots/weak_password.png)

### Strong password
![Strong Password](screenshots/strong_password.png)

---

## 📥 Installation
Clone and install:
```bash
git clone https://github.com/<JDhat2002>/<CrackTime-Analyzer>.git
cd CrackTime-Analyzer
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
