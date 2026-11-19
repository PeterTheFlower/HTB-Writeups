# Hack The Box — Penetration Testing Writeups & Reports

Collection of structured, production-grade penetration testing writeups and vulnerability reports from retired Hack The Box machines.

Each writeup follows a consistent, report-style format including **Summaries**, **Technical Step-by-Step Methodology**, **Theoretical Deep Dives**, **MITRE ATT&CK Mapping**, and **Actionable Hardening Recommendations**.

---

## 🗂️ Machines Index

### 🪟 Windows

| Machine | Difficulty | Primary Attack Vectors | Key Technologies / CVEs | Report |
| :--- | :---: | :--- | :--- | :---: |
| **[Driver](machines/windows/driver)** | Easy | Default Credentials, Forced NTLM Coercion (SCF), LPE via Printer Driver | Responder, WinRM, CVE-2019-19363 (Ricoh Driver) | [Read](machines/windows/driver) |
| **[Puppy](machines/windows/puppy)** | Medium | AD ACL Abuse (GenericWrite/GenericAll), KeePass Cracking, Targeted Kerberoasting, DPAPI Decryption | BloodHound, bloodyAD, KeePassXC, DPAPI | [Read](machines/windows/puppy) |
| **[Administrator](machines/windows/administrator)** | Medium | Chained ForceChangePassword, FTP Credential Leak, Password Safe Cracking, Targeted Kerberoasting, DCSync | BloodHound, Password Safe, DCSync, Pass-the-Hash | [Read](machines/windows/administrator) |

### 🐧 Linux

| Machine | Difficulty | Primary Attack Vectors | Key Technologies / CVEs | Report |
| :--- | :---: | :--- | :--- | :---: |
| **[Union](machines/linux/union)** | Medium | Union SQLi (WAF Bypass), MySQL `FILE` Priv LFI, HTTP Header Command Injection, Sudo Abuse | MySQL `LOAD_FILE()`, `X-Forwarded-For` RCE, `sudo NOPASSWD` | [Read](machines/linux/union) |

---

## 🏗️ Repository Structure

```text
.
└── machines/
    ├── linux/
    │   └── union/
    │       ├── README.md               # Full report with theory & recommendations
    │       └── images_writeup/         # Screenshots (web interface, SQLi, challenge)
    └── windows/
        ├── driver/
        │   ├── README.md               # Full report with theory & recommendations
        │   └── images_writeup/         # Screenshots (web login, uploads)
        ├── puppy/
        │   ├── README.md               # AD attack chain report
        │   └── images_writeup/         # BloodHound path graphs
        └── administrator/
            ├── README.md               # Full AD compromise & DCSync report
            └── images_writeup/         # BloodHound graphs & attack paths
```

---

## 🎯 Report Standards

Every writeup in this repository adheres to the following structure:
1. **Summary**: High-level overview of the machine and exploitation chain.
2. **Reconnaissance & Enumeration**: Initial scanning (Nmap), port analysis, and reasoning.
3. **Initial Access**: Deep dive with underlying theoretical mechanics and execution commands.
4. **Privilege Escalation**: Root/SYSTEM path analysis, dead-end explanations, and technical post-exploitation.
5. **Attack Path Summary**: Visual/diagrammatic breakdown of the entire attack chain.
6. **Findings & Recommendations**: Formal vulnerability disclosures with **MITRE ATT&CK** tags, severities, and defensive remediation advice.
7. **Lessons Learned**: Retrospective takeaways and operational insights.

---

## ⚠️ Disclaimer
All assessments and testing documented in this repository were conducted strictly in authorized, isolated lab environments provided by [Hack The Box](https://www.hackthebox.com/). These writeups are published strictly for educational and defensive purposes.
