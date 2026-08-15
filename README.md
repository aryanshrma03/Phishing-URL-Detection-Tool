# 🛡️ Phishing URL Detection Tool

A modular cybersecurity desktop application built with **Python** and **CustomTkinter** for analyzing URLs and identifying characteristics commonly associated with phishing and malicious links.

## 📌 Project Overview

The tool performs local URL inspection and produces:

- Risk score from 0–100
- Risk classification
- Detailed security checks
- Suspicious URL indicators
- Extracted URL components
- Security recommendations
- Optional VirusTotal URL reputation lookup

The local analyzer does not require an API key or internet connection.

> **Important:** This is a defensive heuristic analyzer. A URL being classified as safe does not guarantee that it is safe.

## 🚀 Features

- 🔗 URL validation and normalization
- 🎯 0–100 risk score
- 🚦 Low / Medium / High / Critical classification
- 🌐 Domain and hostname analysis
- 🔢 IP-address URL detection
- 🔐 HTTPS/TLS detection
- 🧩 Suspicious subdomain detection
- `@` symbol detection
- URL shortening service detection
- Excessive subdomain detection
- Long URL detection
- Suspicious TLD detection
- Punycode / IDN detection
- Percent-encoding detection
- Suspicious keyword detection
- Hyphen and digit analysis
- Port analysis
- Query-parameter inspection
- Redirect-like parameter detection
- Extracted URL information
- Recommendations
- Optional VirusTotal reputation lookup
- Modular architecture
- Unit tests

## 🛡️ Privacy

Local analysis is performed entirely on your machine.

The optional VirusTotal lookup sends the URL to VirusTotal's API. It is **disabled unless you configure an API key**.

Set the key as an environment variable:

### Windows PowerShell

```powershell
$env:VT_API_KEY="your_api_key"
```

### Linux/macOS

```bash
export VT_API_KEY="your_api_key"
```

Never commit an API key to GitHub.

## 🛠 Technologies

| Technology | Purpose |
|---|---|
| Python | Core application |
| CustomTkinter | GUI |
| urllib.parse | URL parsing |
| ipaddress | IP detection |
| re | Pattern analysis |
| hashlib | URL hashing |
| urllib | VirusTotal API communication |
| unittest | Testing |

## 📂 Project Structure

```text
Phishing-URL-Detection-Tool/
│
├── src/
│   ├── main.py
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   └── gui.py
│   │
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── url_parser.py
│   │   ├── heuristics.py
│   │   ├── scoring.py
│   │   └── virustotal.py
│   │
│   ├── components/
│   │   ├── __init__.py
│   │   ├── header.py
│   │   ├── url_input.py
│   │   ├── risk_meter.py
│   │   └── results.py
│   │
│   └── config/
│       ├── __init__.py
│       └── theme.py
│
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py
│
├── .gitignore
├── requirements.txt
└── README.md
```

## 📦 Installation

```bash
git clone https://github.com/aryanshrma03/Phishing-URL-Detection-Tool.git
cd Phishing-URL-Detection-Tool
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## ▶️ Run

```bash
python src/main.py
```

## 🧪 Run Tests

```bash
python -m unittest discover -s tests -v
```

## 🔍 Detection Methodology

The analyzer uses multiple independent indicators rather than relying on one rule.

Examples include:

### Domain Indicators
- Raw IP address instead of a domain
- Suspicious TLD
- Punycode
- Excessive subdomains
- Suspicious brand-like terms

### URL Structure
- Very long URLs
- Excessive URL encoding
- `@` symbol
- Suspicious ports
- Long query strings
- Redirect parameters

### Infrastructure
- URL shorteners
- Missing HTTPS
- Numeric-heavy hostnames

Each finding contributes a weighted number of risk points. The final score is capped at 100.

## ⚠️ Limitations

Heuristic detection cannot guarantee whether a URL is malicious.

Attackers can:
- Use legitimate HTTPS certificates
- Compromise legitimate websites
- Use newly registered domains
- Hide malicious content behind redirects
- Create URLs that look completely normal

For higher-confidence analysis, combine this tool with reputation services, DNS intelligence, sandboxing, browser protections, and endpoint security.

## 🔮 Future Improvements

- [ ] Machine-learning classification
- [ ] WHOIS/domain-age lookup
- [ ] DNS analysis
- [ ] Google Safe Browsing integration
- [ ] URLhaus integration
- [ ] PhishTank integration
- [ ] Screenshot-based website analysis
- [ ] HTML/JavaScript inspection
- [ ] Browser extension
- [ ] Batch URL scanning
- [ ] CSV/JSON report export
- [ ] SQLite scan history
- [ ] Async reputation checks

## 👨‍💻 Author

**Aryan Sharma**

Cybersecurity-focused Python project demonstrating defensive URL analysis and modular security-tool development.
