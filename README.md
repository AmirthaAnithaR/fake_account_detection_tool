# 🛡️ Fake Account Detection Tool

An AI-assisted cybersecurity tool designed to identify and analyze potentially fake, suspicious, and impersonating social media accounts using **forensic risk scoring, fuzzy name matching, profile-image analysis, account behavior indicators, and automated reporting**.

Built as part of a **Cybersecurity Hackathon** focused on combating fake social media accounts and online impersonation.

---

## 🚨 Problem Statement

Fake social media accounts are increasingly used for:

* Identity impersonation
* Online fraud and scams
* Cyberbullying
* Spreading misinformation
* Social engineering attacks
* Malicious activities

Manually investigating large numbers of social media profiles can be time-consuming.

The **Fake Account Detection Tool** provides investigators with a centralized interface to analyze suspicious profiles and generate forensic-style reports.

---

## 💡 Solution

The application analyzes multiple account-level indicators and combines them into a **forensic risk score**.

The system can identify:

* Suspicious account characteristics
* Potential impersonation
* Duplicate profile images
* Unusual follower/following patterns
* Low account activity
* Default profile usage
* Suspicious username/name patterns

The result is presented through an interactive **Streamlit dashboard**.

---

## ✨ Key Features

### 🔐 Officer Authentication

Provides an authentication layer for authorized investigators before accessing the analysis dashboard.

### 🎯 Forensic Risk Scoring

Accounts are evaluated using multiple indicators such as:

* Account age
* Followers
* Following count
* Post/activity count
* Default profile status
* Username/name characteristics
* Dataset classification

The application categorizes accounts into:

| Risk Level     | Description                           |
| -------------- | ------------------------------------- |
| 🟢 Low Risk    | Fewer suspicious indicators           |
| 🟡 Medium Risk | Several suspicious indicators         |
| 🔴 High Risk   | Multiple strong suspicious indicators |

---

### 🕵️ Impersonation Detection

The tool compares account information to identify possible impersonation.

It uses:

* Fuzzy name similarity
* Profile-image hash comparison
* Account age
* Following patterns
* Activity indicators
* Risk score

This helps investigators identify accounts that may be pretending to be another person.

---

### 🖼️ Duplicate Profile Image Detection

The system compares profile-image hashes and identifies accounts that use the same image.

This can help detect:

* Duplicate accounts
* Impersonation profiles
* Coordinated fake accounts
* Reused profile images

---

### 🚩 Account Reporting

Investigators can report suspicious accounts through the dashboard.

The system maintains report information and can flag accounts after reaching the configured reporting threshold.

---

### 📄 Automated Forensic PDF Reports

The application can generate PDF reports containing important investigation information such as:

* Flagged accounts
* Risk scores
* Risk status
* Investigation details
* Officer information
* Report date

This provides a downloadable investigation summary.

---

## 🧠 Detection Workflow

```text
                 Social Media Account Data
                           │
                           ▼
                  Data Preprocessing
                           │
                           ▼
                ┌─────────────────────┐
                │ Account Analysis    │
                └─────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Account Data    Name Similarity   Image Hash
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                   Risk Score Calculation
                           │
                           ▼
              ┌─────────────────────────┐
              │ Risk Classification     │
              └─────────────────────────┘
                    │       │       │
                    ▼       ▼       ▼
                  Low    Medium    High
                           │
                           ▼
                 Investigator Review
                           │
                           ▼
                    PDF Report
```

---

## 🛠️ Tech Stack

### Frontend / Interface

* **Streamlit**

### Programming Language

* **Python**

### Data Processing

* **Pandas**
* **NumPy**

### Detection & Analysis

* **FuzzyWuzzy**
* String similarity analysis
* Image hashing
* Rule-based forensic scoring

### Reporting

* **ReportLab**

### Image Processing

* **Pillow (PIL)**

---

## 📂 Project Structure

```text
fake_account_detection_tool/
│
├── fake_account_detection_tool.py
├── fusers_with_images.csv
├── requirements.txt
├── README.md
└── assets/
```

> The exact files may vary depending on the dataset and deployment configuration.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/AmirthaAnithaR/fake_account_detection_tool.git
```

### 2. Navigate to the project

```bash
cd fake_account_detection_tool
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / macOS

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
streamlit run fake_account_detection_tool.py
```

The application will open in your browser.

---

## 📊 Example Investigation

The system can analyze an account using multiple signals:

```text
Account
   │
   ├── Account Age
   ├── Followers / Following
   ├── Post Activity
   ├── Default Profile
   ├── Username Characteristics
   ├── Name Similarity
   └── Profile Image Hash
             │
             ▼
       Risk Score
             │
      ┌──────┼──────┐
      ▼      ▼      ▼
     LOW   MEDIUM   HIGH
```

Investigators can then review suspicious accounts and generate a forensic report.

---

## 🔍 Detection Techniques

### 1. Rule-Based Risk Scoring

The system assigns scores based on suspicious account characteristics.

Multiple indicators are combined to produce an overall risk score.

### 2. Fuzzy Name Matching

Fuzzy string matching is used to identify accounts whose names are highly similar.

This is particularly useful for detecting potential impersonation.

### 3. Image Hash Comparison

Profile images are represented using hashes.

Matching hashes can indicate that multiple accounts are using the same profile image.

### 4. Behavioral Indicators

Account activity and follower/following relationships are considered as additional signals.

---

## 🔐 Security Considerations

This project is intended as a **cybersecurity investigation prototype**.

For production deployment:

* Store credentials securely.
* Never commit passwords or API keys to GitHub.
* Use environment variables or secret-management systems.
* Implement proper password hashing.
* Add role-based access control.
* Maintain secure audit logs.
* Encrypt sensitive investigation data.
* Apply appropriate data-retention policies.
* Follow applicable privacy and data-protection regulations.

---

## ⚠️ Disclaimer

This tool is intended for **research, educational, and cybersecurity investigation purposes**.

A high-risk score does **not** conclusively prove that an account is fake or malicious. The result should be treated as an investigative indicator and verified using additional evidence.

---

## 🚀 Future Enhancements

Potential improvements include:

* 🤖 Machine-learning based fake-account classification
* 📱 Integration with social-media APIs
* 🔎 Real-time account analysis
* 🧠 Advanced behavioral analysis
* 🖼️ AI-based face/profile-image similarity
* 🌐 Network/graph-based account relationship analysis
* 📈 Investigation analytics dashboard
* 🔔 Automated suspicious-account alerts
* 🗃️ Secure investigator database
* 📑 Advanced evidence management
* 👥 Multi-investigator support

---

## 🎯 Hackathon Impact

The project aims to support cybersecurity investigators by reducing the time required to manually analyze suspicious social media accounts.

By combining **multiple forensic indicators into a single investigation workflow**, the system can help investigators prioritize potentially suspicious accounts for further examination.

---

## ⭐ Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.

**Built for Cybersecurity • Fake Account Detection • Digital Investigation • Social Media Security**
