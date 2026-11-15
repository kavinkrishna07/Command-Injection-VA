# Command-Injection-VA
# Command Injection Vulnerability Assessment (Ubuntu / Linux)

A lightweight cybersecurity laboratory and vulnerability assessment interface built with Python Flask for Ubuntu / Linux environments. This project demonstrates how command injection vulnerabilities arise in web applications, how raw inputs interact with the system shell (`/bin/bash`), and how to implement robust defenses using input validation, parameterized command execution with `subprocess.run(shell=False)`, and strict execution timeouts.

---

## Overview

Command injection occurs when an application concatenates untrusted user-supplied data directly into a system shell command (`/bin/sh` or `/bin/bash`). In a vulnerable application, attackers can append shell metacharacters (such as `;`, `&&`, or `|`) to execute unauthorized secondary operating system commands (e.g. `; id`, `; uname -a`, `; whoami`).

This lab provides two operational modes:
- **Safe Mode (Defensive Pattern)**:
  - Input Validation: Enforces strict allow-lists and regex patterns on hostnames and IP addresses.
  - Interception: Detects shell chaining operators (`;&|\`$()<>^\r\n`) and halts execution before any command reaches the OS.
  - Secure Execution: Demonstrates parameterized execution using `subprocess.run(['ping', '-c', '1', host], shell=False, timeout=6)`.
- **Unsafe Mode (Real-World Vulnerable Pattern)**:
  - Demonstrates direct shell concatenation: `os.system("ping -c 1 " + user_input)` via `/bin/bash`.
  - Prompts with an interactive **"Are you sure?" confirmation dialog** before triggering raw system execution.
  - Allows observation of real command injection behavior directly in the Ubuntu terminal console.

---

## Architecture & Security Principles

```
  User Browser (http://127.0.0.1:5001)
               │
               ▼
   [ Flask Web Interface ] ────> Custom Input Box OR Predefined Diagnostics
               │
       ┌───────┴───────┐
       ▼               ▼
  [ Safe Mode ]   [ Unsafe Mode ]
       │               │
  Allow-List &    Confirmation
  Regex Check     Dialog ("Are you sure?")
       │               │
  ┌────┴────┐          ▼
  ▼         ▼     [ /bin/bash (shell=True) ]
Blocked   Secure       │
(Trap)    Subprocess   ▼
          (shell=False) Direct OS Output
```

---

## Test Cases Matrix

| Case ID | Test Label | Tool | Target Input | Expected Outcome | Security Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ping-loopback` | Ping 127.0.0.1 | `ping` | `127.0.0.1` | Real ping statistics | **PASS** (Safe diagnostic) |
| `ping-localhost`| Ping localhost | `ping` | `localhost` | Real ping statistics | **PASS** (Safe diagnostic) |
| `show-hostname` | Show system info | `uname`| `-a` | Kernel & OS information | **PASS** (Safe diagnostic) |
| `lookup-example`| Hostname lookup | `nslookup`| `example.com`| DNS resolution output | **PASS** (Safe diagnostic) |
| `inject-semicolon`| Semicolon chaining | `ping` | `127.0.0.1; id` | User ID & group output | **VULNERABLE** in Unsafe / **BLOCKED** in Safe |
| `inject-and` | AND operator chaining | `ping` | `127.0.0.1 && uname -a` | System architecture details | **VULNERABLE** in Unsafe / **BLOCKED** in Safe |
| `inject-pipe` | Pipe chaining | `ping` | `127.0.0.1 \| whoami` | Current username output | **VULNERABLE** in Unsafe / **BLOCKED** in Safe |

---

## Getting Started (Ubuntu / Linux)

### Prerequisites
- Python 3.10+ installed:
  ```bash
  sudo apt update
  sudo apt install -y python3 python3-venv python3-pip
  ```

### Installation & Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kavinkrishna07/Command-Injection-VA.git
   cd Command-Injection-VA
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the application:**
   ```bash
   python3 app.py
   ```

5. **Open in browser:**
   Navigate to [http://127.0.0.1:5001](http://127.0.0.1:5001).

---

## Code Comparison: Vulnerable vs. Secure

### Vulnerable Implementation (Anti-Pattern on Ubuntu)
```python
import os
# Flaw: String concatenation passed directly to /bin/bash allows command chaining
user_input = request.form['host']          # e.g., '127.0.0.1; id'
os.system('ping -c 1 ' + user_input)       # Executes both ping AND id!
```

### Secure Implementation (Defensive Pattern on Ubuntu)
```python
import subprocess, re
# 1. Strict regex allow-list validation
SAFE = re.compile(r'^(localhost|\d{1,3}(\.\d{1,3}){3})$')
host = request.form['host'].strip()
if not SAFE.match(host):
    abort(400) # Reject invalid or suspicious inputs

# 2. Parameterized argument list with shell=False and execution timeout
subprocess.run(['ping', '-c', '1', '-W', '3', host],
               shell=False,
               timeout=6)
```

---

## Ethical Disclaimer

This project is developed strictly for educational and academic purposes as part of cybersecurity coursework. It demonstrates defensive secure coding practices and safe vulnerability assessment methodologies.
