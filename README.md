# 🐺 MailFox – Advanced Email Breach Scanner  
### Made by **sid7.py | ProxyNation Cyber Labs**

MailFox is a cybersecurity auditing tool that checks whether email credentials appear in public breach databases or local leak dumps. It is designed for cybersecurity students, bug bounty hunters, SOC analysts, and red teams (with authorization).

> Ethical Usage: You must **only** scan emails/domains you own or have explicit written permission to test.  
> Unauthorized scanning is illegal and punishable by cybercrime laws.

---

## 🚀 Features

- Scan by:
  - Email address
  - Domain (example: @company.com)
  - Username
  - Plain password string
- Online breach data fetching via ProxyNova Combo API
- Local breach dump scanning (TXT / JSON)
- Multi-threaded high-speed scanning
- Rich UI experience:
  - Animated progress bars
  - Beautiful tables
  - Colored scan statistics
- Export results:
  - JSON, TXT, CSV
- Password hash tri-encoding:
  - MD5 / SHA1 / SHA256
- Interactive mode for beginners

---

## 📦 Installation

### Requirements
- Python **3.8+**

### Install dependencies:

```bash
pip install requests rich colorama pyfiglet
