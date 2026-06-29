<img width="1048" height="690" alt="Screenshot 2026-06-29 125625" src="https://github.com/user-attachments/assets/05ce5c47-3f48-41b9-a9f2-cfb5b64ed82f" />
# 🐕 HashHound

**Password Hash Analyzer, Identifier & Cracker**

HashHound is a Python-based cryptography tool that identifies unknown hash types, generates hashes from plaintext, performs dictionary-based hash cracking, and analyzes password strength — all from the terminal.

> Built for CTF challenges, security research, and cryptography education.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 Hash Identifier | Detect MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM |
| ⚡ Hash Generator | Generate all hashes from any plaintext instantly |
| 🔓 Dictionary Cracker | Wordlist-based attack with speed stats |
| 🛡️ Password Analyzer | Score passwords 0–6 with actionable feedback |
| 🎨 Color Output | Strength-coded terminal display |
| 🖥️ Demo Mode | Run built-in demo without any input |

---

## 📁 Project Structure

```
HashHound/
├── hashhound.py      # Main script
├── wordlist.txt      # Sample wordlist (add rockyou.txt for real cracking)
├── requirements.txt  # Dependencies
└── README.md
```

---

## ⚙️ Setup

```bash
pip install -r requirements.txt
```

---

## 🧠 Usage

```bash
# Demo mode
python hashhound.py --demo

# Identify a hash
python hashhound.py --identify 5f4dcc3b5aa765d61d8327deb882cf99

# Generate all hashes from plaintext
python hashhound.py --generate "MyPassword123"

# Crack a hash with dictionary attack
python hashhound.py --crack 5f4dcc3b5aa765d61d8327deb882cf99 --type MD5 --wordlist wordlist.txt

# Analyze password strength
python hashhound.py --strength "Admin@123"

# Interactive mode
python hashhound.py
```

---

## 📊 Hash Strength Reference

| Algorithm | Strength | Status |
|---|---|---|
| MD5 | ⚠️ WEAK | Broken — collision attacks exist |
| NTLM | ⚠️ WEAK | Broken — easily cracked |
| SHA1 | ⚠️ WEAK | Deprecated — SHAttered attack |
| SHA224 | 🟡 MODERATE | Acceptable, SHA256+ preferred |
| SHA256 | ✅ STRONG | Widely used, no known attacks |
| SHA384 | ✅ STRONG | Truncated SHA512 variant |
| SHA512 | ✅ VERY STRONG | Recommended |

---

## 💡 Tips for Real Cracking

Download **rockyou.txt** wordlist (14M passwords):
```bash
# Kali Linux
gunzip /usr/share/wordlists/rockyou.txt.gz
python hashhound.py --crack <hash> --type MD5 --wordlist /usr/share/wordlists/rockyou.txt
```

---

## ⚠️ Disclaimer

HashHound is for **educational and authorized security research only**. Only crack hashes you own or have explicit permission to test.

---

## 🛠️ Built With

- Python standard library (hashlib, re, argparse)
- [colorama](https://pypi.org/project/colorama/) — terminal colors

---

## 👤 Author

**Aqsa** — Cybersecurity Researcher | ICE Student @ IUB  
[GitHub](https://github.com/Aqsa819) · [LinkedIn](https://linkedin.com/in/aqsa)

---

## 📄 License

MIT License
