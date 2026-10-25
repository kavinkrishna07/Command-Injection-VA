# Command-Injection-VA
# Command Injection Vulnerability Assessment

A lightweight, beginner-friendly cybersecurity laboratory and vulnerability assessment tool built with Python Flask. This project demonstrates how command injection vulnerabilities arise in web applications, how suspicious input patterns are detected safely, and how to implement robust defenses using input validation, parameterized command execution with `subprocess.run(shell=False)`, and strict execution timeouts on Windows.

---

## Overview

Command injection occurs when an application passes unsanitized user-supplied data to a system shell (`cmd.exe`, PowerShell, or Bash). In a vulnerable application, attackers can append shell metacharacters (such as `;`, `&&`, or `|`) to execute unauthorized secondary operating system commands.

This lab provides a safe, controlled environment to study this vulnerability:
- **Harmless Diagnostics**: Executes only approved diagnostic operations (`ping`, `hostname`, `nslookup`).
- **Input Validation**: Enforces strict allow-lists and regex patterns on hostnames and IP addresses.
- **Simulated Detection**: Detects command injection patterns and displays what a vulnerable application would have constructed—**without executing injected commands**.
- **Secure Implementation**: Demonstrates secure execution using `subprocess.run(cmd, shell=False, timeout=6)`.
- **Educational Code Comparison**: Provides side-by-side comparisons of vulnerable patterns vs. secure implementations.
- **Actionable Remediation**: Generates a test summary and structured remediation checklist based on assessment findings.

---

## Architecture & Security Principles

```
  User Browser (127.0.0.1:5001)
               │
               ▼
   [ Flask Web Interface ] ────> Predefined Diagnostic Selection (No Free Typing)
               │
               ▼
   [ Input Validation Engine ]
        ├── Pattern Analyzer: Detects shell chaining operators (;&|`$()<>^\r\n)
        └── Allow-List Validator: Validates against SAFE_HOST_PATTERN
               │
       ┌───────┴───────┐
       ▼               ▼
[ Malicious Pattern ]  [ Valid Diagnostic ]
       │               │
  (BLOCKED)            ▼
  Explains risk,   [ Secure Subprocess Invocation ]
  Never executes   ├── Argument Array: ['ping', '-n', '1', host]
                   ├── shell=False (No shell interpretation)
                   └── timeout=6s (Prevents Denial of Service)
                       │
                       ▼
               [ Windows OS Result ]
```

### Defense-in-Depth Measures
1. **No Arbitrary Input Execution**: Free-text command entry is disabled; users select from curated diagnostic test cases.
2. **Pattern Analysis**: Identifies injection syntax and immediately halts execution with educational feedback.
3. **Array-Based Argument Passing**: Arguments are passed as individual elements in a list, preventing the OS from interpreting arguments as command separators.
4. **Localhost Binding**: Runs strictly on `127.0.0.1` to prevent unauthorized network access.

---

## Repository Structure

```
Command-Injection-VA/
│
├── app.py                 # Core Flask application, validation logic, and subprocess execution
├── requirements.txt       # Python dependencies (Flask)
├── .gitignore             # Git ignore patterns (.venv, __pycache__)
├── README.md              # Project documentation and setup guide
│
├── templates/
│   └── index.html         # Responsive, two-column web interface with code comparison tabs
│
├── screenshots/           # Evidence screenshots captured during assessment
│   ├── 01_application_interface.png
│   ├── 02_normal_diagnostic_test.png
│   ├── 04_command_injection_detection.png
│   └── 06_assessment_findings.png
│
└── docs/                  # Formal academic report and documentation
    └── project_report.md
```

---

## Test Cases Matrix

| Case ID | Test Label | Tool | Target Input | Expected Outcome | Security Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ping-loopback` | Ping 127.0.0.1 | `ping` | `127.0.0.1` | Real ping statistics | **PASS** (Safe diagnostic) |
| `ping-localhost`| Ping localhost | `ping` | `localhost` | Real ping statistics | **PASS** (Safe diagnostic) |
| `show-hostname` | Show PC hostname | `hostname`| *(none)* | Current machine hostname | **PASS** (Safe diagnostic) |
| `lookup-example`| Hostname lookup | `nslookup`| `example.com`| DNS resolution output | **PASS** (Safe diagnostic) |
| `inject-semicolon`| Semicolon chaining | `ping` | `127.0.0.1; whoami` | Blocked by pattern engine | **BLOCKED** (Injection risk) |
| `inject-and` | AND operator chaining | `ping` | `127.0.0.1 && whoami` | Blocked by pattern engine | **BLOCKED** (Injection risk) |
| `inject-pipe` | Pipe chaining | `ping` | `127.0.0.1 \| whoami` | Blocked by pattern engine | **BLOCKED** (Injection risk) |

---

## Getting Started (Windows PowerShell)

### Prerequisites
- Python 3.10+ installed and added to `PATH`.

### Installation & Run

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/kavinkrishna07/Command-Injection-VA.git
   cd Command-Injection-VA
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(If execution policies block scripts, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Start the application:**
   ```powershell
   python app.py
   ```

5. **Open in browser:**
   Navigate to [http://127.0.0.1:5001](http://127.0.0.1:5001).

---

## Code Comparison: Vulnerable vs. Secure

### Vulnerable Implementation (Anti-Pattern)
```python
import os
# Flaw: String concatenation passed to a shell allows command chaining
user_input = request.form['host']          # e.g., '127.0.0.1; whoami'
os.system('ping -n 1 ' + user_input)       # Executes both ping AND whoami!
```

### Secure Implementation (Defensive Pattern)
```python
import subprocess, re
# 1. Strict regex allow-list validation
SAFE = re.compile(r'^(localhost|\d{1,3}(\.\d{1,3}){3})$')
host = request.form['host'].strip()
if not SAFE.match(host):
    abort(400) # Reject invalid or suspicious inputs

# 2. Parameterized argument list with shell=False and execution timeout
subprocess.run(['ping', '-n', '1', '-w', '3000', host],
               shell=False,
               timeout=6)
```

---

## Ethical Disclaimer

This project is developed strictly for educational and academic purposes as part of cybersecurity coursework. It demonstrates defensive secure coding practices and safe vulnerability assessment methodologies. The simulator enforces strict input controls and does not execute arbitrary or malicious commands. The author does not endorse unauthorized testing against systems without explicit permission.
