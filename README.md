# Hack The Box — Penetration Testing Writeups & Reports

A curated collection of production-grade penetration testing writeups and vulnerability reports from completed Hack The Box machines.

Each report is structured as a professional engagement deliverable featuring **Executive & Technical Summaries**, **Theoretical Vulnerability Mechanics**, **Step-by-Step Proof-of-Concepts**, **Dead-End Analysis**, **MITRE ATT&CK Mapping**, and **Actionable Remediation Guidelines**.

---

## 📊 Overview & Metrics

<div align="center">

| Total Machines | 🐧 Linux | 🪟 Windows | 🟢 Easy | 🟡 Medium | 🔴 Hard |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **7** | **4** | **3** | **4** | **3** | **0** |

</div>

### ⚡ Quick Navigation
- [🐧 Linux Machines](#-linux) (4)
- [🪟 Windows Machines](#-windows) (3)
- [🏷️ Categorized Attack Index](#️-categorized-attack-index)
- [🎯 Report Standards](#-report-standards)

---

## 🗂️ Machines Directory

### 🐧 Linux

<details open>
<summary><b>Click to expand / collapse Linux machines (4)</b></summary>
<br>

| Machine | Difficulty | Attack Vector Summary | Key Tech / CVEs | Report |
| :--- | :---: | :--- | :--- | :---: |
| **[Trick](machines/linux/trick)** | `Easy` 🟢 | DNS Zone Transfer (AXFR) ➔ SQLi Auth Bypass ➔ VHost Fuzzing ➔ Filter-Bypass LFI ➔ Fail2Ban Sudo Action Hijacking | BIND9, Nginx, PHP-FPM, SQLMap, Fail2Ban | [📄 Read](machines/linux/trick) |
| **[Shoppy](machines/linux/shoppy)** | `Easy` 🟢 | NoSQL Injection (Auth Bypass & Blind Exfil) ➔ MD5 Cracking ➔ Targeted VHost Fuzzing ➔ Chat Credential Leak ➔ C++ Reversing ➔ Docker Group Abuse | Node.js, MongoDB, NoSQLi, Mattermost, Ghidra, Docker LPE | [📄 Read](machines/linux/shoppy) |
| **[Union](machines/linux/union)** | `Medium` 🟡 | In-band UNION SQLi (WAF Bypass) ➔ MySQL `FILE` Priv LFI ➔ Credential Reuse ➔ `X-Forwarded-For` Command Injection ➔ Sudo NOPASSWD | MySQL `LOAD_FILE()`, `iptables` RCE, `sudo ALL` | [📄 Read](machines/linux/union) |
| **[MetaTwo](machines/linux/metatwo)** | `Easy` 🟢 | BookingPress SQLi ➔ Media Metadata XXE ➔ ProFTPD Credential Leak ➔ Passpie GPG Cracking | WordPress, CVE-2022-0739, CVE-2021-29447, Passpie | [📄 Read](machines/linux/metatwo) |

</details>

---

### 🪟 Windows

<details open>
<summary><b>Click to expand / collapse Windows machines (3)</b></summary>
<br>

| Machine | Difficulty | Attack Vector Summary | Key Tech / CVEs | Report |
| :--- | :---: | :--- | :--- | :---: |
| **[Driver](machines/windows/driver)** | `Easy` 🟢 | Web Default Creds ➔ Forced NTLM Coercion (SCF File Drop) ➔ Hashcat NetNTLMv2 Cracking ➔ LPE via Ricoh Driver Vulnerability | Responder, WinRM, CVE-2019-19363 | [📄 Read](machines/windows/driver) |
| **[Puppy](machines/windows/puppy)** | `Medium` 🟡 | AD ACL Abuse (`GenericWrite`/`GenericAll`) ➔ KeePass Database Memory/File Cracking ➔ Targeted Kerberoasting ➔ DPAPI Decryption | BloodHound, bloodyAD, KeePassXC, DPAPI | [📄 Read](machines/windows/puppy) |
| **[Administrator](machines/windows/administrator)** | `Medium` 🟡 | Active Directory Chained `ForceChangePassword` ➔ FTP Cleartext Cred Leak ➔ Password Safe Cracking ➔ Targeted Kerberoasting ➔ DCSync | BloodHound, Password Safe, DCSync, Impacket | [📄 Read](machines/windows/administrator) |

</details>

---

## 🏷️ Categorized Attack Index

Quickly locate writeups by specific offensive techniques and attack families:

<details>
<summary><b>Active Directory & Windows Exploitation</b></summary>

- **Active Directory ACL Abuse**: [Puppy](machines/windows/puppy), [Administrator](machines/windows/administrator)
- **Kerberoasting (Targeted)**: [Puppy](machines/windows/puppy), [Administrator](machines/windows/administrator)
- **NTLM Relay / Forced Authentication**: [Driver](machines/windows/driver)
- **DCSync & Domain Compromise**: [Administrator](machines/windows/administrator)
- **DPAPI Credential Extraction**: [Puppy](machines/windows/puppy)

</details>

<details>
<summary><b>Web Application Security & Injection</b></summary>

- **NoSQL Injection**: [Shoppy](machines/linux/shoppy) *(Authentication bypass & Blind data extraction in MongoDB)*
- **SQL Injection**: [Trick](machines/linux/trick) *(Auth Bypass & SQLMap file-read)*, [Union](machines/linux/union) *(Union-based WAF bypass)*, [MetaTwo](machines/linux/metatwo) *(BookingPress plugin CVE)*
- **Local File Inclusion (LFI) & Path Traversal**: [Trick](machines/linux/trick) *(Nested `....//` filter bypass)*, [Union](machines/linux/union) *(via MySQL `LOAD_FILE()`)*
- **XML External Entity (XXE)**: [MetaTwo](machines/linux/metatwo) *(WAV audio metadata XXE)*
- **Command Injection (RCE)**: [Union](machines/linux/union) *(HTTP `X-Forwarded-For` injection)*

</details>

<details>
<summary><b>Linux Privilege Escalation & Misconfigurations</b></summary>

- **Docker Socket / Group Abuse**: [Shoppy](machines/linux/shoppy) *(Host filesystem root mount via Docker daemon)*
- **Binary Reverse Engineering & Sudo**: [Shoppy](machines/linux/shoppy) *(Ghidra decompilation of C++ password manager)*
- **Service / Daemon Config Hijacking**: [Trick](machines/linux/trick) *(Fail2Ban `action.d` writable directory + sudo restart)*
- **Sudo Misconfigurations**: [Union](machines/linux/union) *(`NOPASSWD: ALL`)*, [Trick](machines/linux/trick) *(`NOPASSWD: /etc/init.d/fail2ban restart`)*, [Shoppy](machines/linux/shoppy) *(`(deploy) /home/deploy/password-manager`)*
- **Network / DNS Misconfigurations**: [Trick](machines/linux/trick) *(DNS AXFR zone transfer on ISC BIND)*

</details>

<details>
<summary><b>Credential Harvesting & Vault Cracking</b></summary>

- **MD5 Hash Cracking**: [Shoppy](machines/linux/shoppy) *(Hashcat mode 0 on MongoDB exfiltrated user hash)*
- **Chat Intelligence & Credential Leaks**: [Shoppy](machines/linux/shoppy) *(Disclosing SSH credentials in Mattermost)*
- **KeePass Master Password Recovery**: [Puppy](machines/windows/puppy)
- **Password Safe Cracking**: [Administrator](machines/windows/administrator)
- **GPG / Passpie Key Recovery**: [MetaTwo](machines/linux/metatwo)
- **NetNTLMv2 Hash Cracking**: [Driver](machines/windows/driver)

</details>

---

## 🎯 Report Standards

Every writeup in this repository adheres to a strict 10-point technical standard:

1. **Metadata & Executive Summary**: Target context, attack chain overview, and business impact.
2. **Reconnaissance & Service Enumeration**: Port matrix, Nmap outputs, and architectural theory blockquotes.
3. **Initial Access**: Deep dive into the vulnerability mechanics, payload crafting, and step-by-step execution.
4. **Privilege Escalation**: Root/SYSTEM vector analysis, permission enumeration, and **comprehensive dead-end documentation**.
5. **Attack Path Flow**: Clean ASCII / Mermaid diagram visualizing the full exploitation sequence.
6. **Tools Used**: Comprehensive matrix of tooling utilized across the engagement.
7. **Lessons Learned**: Senior-level operational reflections, defensive takeaways, and methodology improvements.

---

## ⚠️ Disclaimer
All assessments, scans, and exploitation documented in this repository were conducted strictly in authorized, isolated lab environments provided by [Hack The Box](https://www.hackthebox.com/). These writeups are authored and published strictly for defensive hardening, research, and educational purposes.
