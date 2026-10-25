# COMMAND INJECTION VULNERABILITY ASSESSMENT

**ETHICAL HACKING - PROJECT REPORT**  
*Submitted in partial fulfillment of the requirements for the award of the degree of*  
**BACHELOR OF ENGINEERING IN COMPUTER SCIENCE AND ENGINEERING (CYBER SECURITY)**  
**ANNA UNIVERSITY, CHENNAI**

---

### PROJECT WORK
**Academic Year: 2026–2027**  
**Department of Computer Science and Engineering (Cyber Security)**  
**Sri Eshwar College of Engineering**  
*(An Autonomous Institution, Approved by AICTE, Affiliated to Anna University, Chennai)*  
*Kinathukadavu (Tk), Coimbatore – 641 202, Tamil Nadu*

---

## BONAFIDE CERTIFICATE

Certified that this Report titled **"Command Injection Vulnerability Assessment"** is the bonafide work of:

| Student Name | Register Number |
| :--- | :--- |
| **Kavin Krishna** | *(Register Number)* |

who carried out the project work under the supervision of the faculty coordinator.

<br><br>

```
-----------------------------------------               -----------------------------------------
               SIGNATURE                                               SIGNATURE
Dr. S. Sampath Kumar, M.Tech., Ph.D.,                   Supervisor / Faculty Guide,
Professor and Head of the Department,                   Department of Computer Science and Engineering,
Department of CSE (Cyber Security),                     Sri Eshwar College of Engineering,
Sri Eshwar College of Engineering,                      Coimbatore – 641 202.
Coimbatore – 641 202.
```

<br>

Submitted for the Autonomous Semester End Ethical Hacking Essentials Project Viva-Voce held on `..........................`

<br>

```
_________________________                               _________________________
   INTERNAL EXAMINER                                       EXTERNAL EXAMINER
```

---

## TABLE OF CONTENTS

- **CHAPTER 1: INTRODUCTION & OBJECTIVES**
  - 1.1 Introduction
  - 1.2 Project Objectives
- **CHAPTER 2: ETHICAL GUIDELINES & LAB SETUP**
  - 2.1 Project Guidelines
  - 2.2 Lab Setup & System Configuration
- **CHAPTER 3: SYSTEM ARCHITECTURE & IMPLEMENTATION**
  - 3.1 Problem Statement
  - 3.2 Technical Background
  - 3.3 Implementation Objectives
  - 3.4 Tools and Technologies Required
  - 3.5 Implementation Tasks and Test Results
    - Task 1 — Application Environment & Server Configuration
    - Task 2 — Diagnostic Command Selection (Figure 1: Application Interface)
    - Task 3 — Harmless Command Execution & Output (Figure 2: Normal Diagnostic Test)
    - Task 4 — Input Validation and Allow-Listing (Figure 3: Input Validation)
    - Task 5 — Suspicious Input & Injection Detection (Figure 4: Command Injection Detection)
    - Task 6 — Defensive Secure Implementation (Figure 5: Secure Implementation)
    - Task 7 — Assessment Findings & Remediation (Figure 6: Final Assessment Results)
  - 3.6 Expected Outputs
  - 3.7 Mapping to Syllabus Units
- **CHAPTER 4: EVIDENCE, REPOSITORY & CONCLUSION**
  - 4.1 Screenshot Guidelines and Verification
  - 4.2 GitHub Repository Structure
  - 4.3 Ethical Disclaimer and Conclusion

---

## CHAPTER 1

### 1.1 Introduction
In the domain of web application security and ethical hacking, Command Injection (CWE-78) consistently ranks among the most severe vulnerability classes. It arises when an application constructs operating system commands using untrusted, user-supplied data without adequate sanitization, validation, or escaping, and subsequently passes that concatenated string to a system shell interpreter (such as Windows `cmd.exe`, PowerShell, or Unix `/bin/sh`). 

When an operating system shell processes input containing metacharacters (e.g., `;`, `&&`, `|`, `||`, `` ` ``, `$()`), it interprets them as command delimiters or control operators. Consequently, an attacker can append arbitrary secondary commands that execute under the privileges of the web application server. This can lead to complete server takeover, unauthorized system enumeration, data exfiltration, lateral network pivoting, and denial of service.

Traditional diagnostic web utilities—such as router administrative panels, network monitoring consoles, and troubleshooting interfaces—frequently expose diagnostic functions like `ping`, `nslookup`, and `traceroute`. Historically, junior developers implemented these features by directly interpolating inputs into commands using functions like `os.system()` or `subprocess.Popen(..., shell=True)`. While functional under normal circumstances, such designs fail catastrophically when presented with adversarial inputs.

This project, titled **Command Injection Vulnerability Assessment**, delivers a dedicated, lightweight, and beginner-friendly local vulnerability laboratory implemented in Python Flask. The platform demonstrates:
1. The mechanics of operating system command execution.
2. The exact syntax and behavior of command chaining operators.
3. Safe detection and simulation of injection risks without executing harmful commands.
4. Robust defensive remediation using strict allow-listing, parameterized array execution with `subprocess.run(shell=False)`, and execution timeouts.

All demonstrations are strictly bound to `127.0.0.1` on Windows, ensuring a completely safe, controlled, and educational testing environment.

### 1.2 Project Objectives
The primary objectives of this project are:
1. **Develop a Lightweight Diagnostic Interface**: Create an intuitive, web-based diagnostic console using Python Flask, HTML5, and CSS that runs locally on Windows.
2. **Execute Controlled, Harmless Diagnostics**: Provide safe diagnostic utilities (`ping`, `hostname`, `nslookup`) that execute against validated local targets and return real command output.
3. **Simulate Command Injection Risks Safely**: Demonstrate command injection attack patterns (semicolon, AND chaining, piping) using pattern detection without ever executing malicious commands.
4. **Implement Defensive Secure Coding Controls**: Enforce defensive mechanisms including regex-based allow-lists, parameterized argument arrays, `shell=False`, and process timeouts.
5. **Present Educational Comparative Analysis**: Compare vulnerable string-concatenation anti-patterns with secure implementations side-by-side.
6. **Provide Actionable Vulnerability Assessment Findings**: Automatically generate structured test summaries, detected risks, pass/fail statuses, and industry-standard remediation guidance.

---

## CHAPTER 2

### 2.1 Project Guidelines
This laboratory assessment has been designed and implemented in strict compliance with ethical hacking standards, academic integrity guidelines, and the principle of least privilege. The following ethical principles governed the development and execution of the lab:

- **Authorized and Localhost Testing Only**: All network diagnostics and executions are restricted strictly to loopback addresses (`127.0.0.1`, `localhost`) and approved public targets (`example.com`). The application binds exclusively to the local loopback interface and is not exposed to external networks.
- **Simulation Without Harmful Execution**: When a test case simulating command injection is evaluated (e.g., `127.0.0.1 && whoami`), the application identifies the metacharacters, explains the exploit mechanism, and intentionally halts execution. Secondary injected commands are **never** executed.
- **No Arbitrary Command Invocation**: Free-form text fields that permit arbitrary command entry are disallowed. All interactions are driven by curated, predefined test cases, ensuring that unintended OS commands cannot be triggered.
- **Controlled Process Execution**: All active operating system commands are invoked through strict timeouts (6 seconds) to prevent Denial of Service (DoS) conditions or hanging background threads.
- **Responsible Information Presentation**: The web interface avoids security-through-obscurity; it transparently displays the exact command invoked, the execution parameters, and defensive recommendations.

### 2.2 Lab Setup & System Configuration
The lab environment was configured on a local Windows host utilizing a standard Python virtual environment.

#### Table 2.1: Lab Environment Configuration
| Parameter | Value |
| :--- | :--- |
| **Host Operating System** | Windows 11 (64-bit) |
| **Python Version** | Python 3.13.x / Python 3.10+ |
| **Web Framework** | Flask 3.0.3 |
| **Interface Binding** | `127.0.0.1:5001` (Localhost only) |
| **Execution Shell** | None (`shell=False`, direct process invocation) |
| **Process Management Module**| Python `subprocess` standard library |
| **Pattern Detection Engine** | Python `re` (Regular Expressions) |
| **Diagnostic Utilities** | Windows native `ping.exe`, `hostname.exe`, `nslookup.exe` |

#### Table 2.2: Software and Tools Used
| Software / Module | Purpose in the Project |
| :--- | :--- |
| **Python Flask** | Provides the backend web server, request routing, and Jinja2 template rendering. |
| **Python `subprocess`** | Executes approved system diagnostic binaries securely using argument lists with `shell=False`. |
| **Python `re`** | Implements the pattern detection engine for identifying shell metacharacters and validating hostnames. |
| **Jinja2 / HTML5 / CSS3** | Delivers a clean, responsive, two-column interface featuring terminal views, tabbed code comparisons, and status cards. |
| **PowerShell / Git** | Used for environment setup, process management, version control, and GitHub synchronization. |

---

## CHAPTER 3

### 3.1 Problem Statement
Many web applications need to perform system diagnostics or query system states. Developers often achieve this by invoking operating system shell utilities. However, concatenating raw user input directly into shell execution strings exposes the host system to Remote Command Execution (RCE). 

A classic vulnerable implementation resembles:
```python
# VULNERABLE SNIPPET
host = request.form['host']
os.system("ping -n 1 " + host)
```
If an adversary submits `127.0.0.1 && whoami`, the shell treats the input as two distinct commands:
1. `ping -n 1 127.0.0.1`
2. `whoami`

Both commands execute sequentially, allowing the attacker to discover the web server's service account name. 

There is an acute need for an educational vulnerability assessment platform that clearly illustrates this vulnerability, demonstrates how shell metacharacters operate, and presents the exact secure implementation required to neutralize the threat.

### 3.2 Technical Background

#### The Role of Shell Metacharacters
Operating system shells parse input strings according to specific grammar rules. Certain characters act as control instructions rather than literal strings:
- `;` (Command Separator): Executes commands sequentially regardless of success.
- `&&` (Logical AND): Executes the following command only if the preceding command returns exit code 0.
- `|` (Pipe): Routes the standard output of the first command as the standard input of the second.
- `||` (Logical OR): Executes the subsequent command only if the preceding command fails.
- `` `command` `` or `$(command)` (Command Substitution): Evaluates the enclosed command and replaces it with its output.

#### Process Invocation Mechanics: `shell=True` vs. `shell=False`
- **When `shell=True` is enabled**: Python passes the command string directly to the shell (`cmd.exe /c` on Windows or `/bin/sh -c` on Linux). The shell tokenizes the string, detects metacharacters, and executes multiple commands.
- **When `shell=False` is used**: Python invokes the target binary directly via the operating system's native process creation API (e.g., `CreateProcessW` on Windows). The command and its arguments are passed as an explicit array of strings: `['ping', '-n', '1', host]`. Even if `host` contains `;` or `&&`, the OS passes the entire token literally as a single command-line argument to `ping.exe`. The ping utility simply reports an unknown host error; no secondary process is ever spawned.

#### Input Validation Strategies
- **Blacklisting**: Attempting to block known malicious characters often fails due to bypasses (e.g., whitespace manipulation, alternate delimiters, variable expansion).
- **Allow-Listing (Whitelisting)**: The definitive defense. The application only permits inputs that match strict, expected patterns (e.g., only alphanumeric characters and valid IPv4 dot-decimal formats).

### 3.3 Implementation Objectives
1. Provide predefined diagnostic test cases representing both benign commands and common injection vectors.
2. Intercept and evaluate inputs before process creation.
3. If an input contains shell operators, log the risk, display the dangerous construction for learning, and halt execution.
4. If an input is verified safe, execute it using parameterized arguments and capture stdout/stderr.
5. Display live output inside a formatted terminal interface.
6. Display a comparative code snippet viewer (Vulnerable vs. Secure) customized to the active diagnostic tool.
7. Output an assessment finding report with risk classification and actionable remediation steps.

### 3.4 Tools Required
The laboratory requires only standard, lightweight tools:
- **Operating System**: Windows 10/11
- **Python**: Version 3.10 or higher
- **Dependencies**: Listed in `requirements.txt`:
  ```
  Flask==3.0.3
  ```
- **Git**: For version control and repository management.

---

### 3.5 Implementation Tasks and Test Results

#### Task 1 — Application Environment & Server Configuration
The Flask application is initialized in `app.py`. The server binds exclusively to `127.0.0.1` on port `5001`. Security headers and local execution configurations are established. The execution timeout is configured to 6 seconds (`TIMEOUT_SECONDS = 6`).

#### Task 2 — Diagnostic Command Selection
The web application provides an intuitive two-column dashboard. The sidebar presents a curated dropdown divided into two distinct groups:
1. **Safe diagnostic commands** (benign ping, localhost ping, hostname inspection, nslookup).
2. **Injection-pattern demos** (semicolon chaining, AND chaining, pipe chaining).

A status key explains the color-coded outcome badges (PASS, BLOCKED, ERROR, TIMEOUT).

```
================================================================================
FIGURE 1: APPLICATION INTERFACE
================================================================================
```
![Figure 1: Application Interface](screenshots/01_application_interface.png)  
*Figure 1: Application Interface showing project title, sidebar diagnostic selector, status key, and reference cards.*

---

#### Task 3 — Harmless Command Execution & Output
When a user selects a safe diagnostic test (e.g., `Ping localhost (safe)`), the backend executes:
```python
['ping', '-n', '1', '-w', '3000', 'localhost']
```
The command is invoked via `subprocess.run()` with `shell=False`. The application captures standard output and standard error, returning the actual execution statistics.

```
================================================================================
FIGURE 2: NORMAL DIAGNOSTIC TEST
================================================================================
```
![Figure 2: Normal Diagnostic Test](screenshots/02_normal_diagnostic_test.png)  
*Figure 2: Normal Diagnostic Test showing successful ping execution against localhost with real round-trip times and security notes.*

---

#### Task 4 — Input Validation and Allow-Listing
Input validation is enforced using a dual-stage verification system:
1. **Pattern Inspection**: The input string is scanned for forbidden shell operators via regex:
   ```python
   INJECTION_PATTERN = re.compile(r"[;&|`$()\<\>^\r\n]")
   ```
2. **Allow-List Matching**: Safe hostnames and IP addresses are validated against an exact regex:
   ```python
   SAFE_HOST_PATTERN = re.compile(r"^(localhost|example\.com|\d{1,3}(?:\.\d{1,3}){3})$")
   ```
If an input fails validation or contains unapproved targets, execution is rejected before process instantiation, returning a `BLOCKED (invalid host)` status.

---

#### Task 5 — Suspicious Input & Injection Detection
When a user selects an injection test case such as `127.0.0.1 | whoami`, the regex engine detects the pipe (`|`) metacharacter. The application halts immediately:
- The command status transitions to `BLOCKED (injection pattern)`.
- The actual command field shows `not executed`.
- The interface displays an educational alert: **"WHAT A VULNERABLE APP WOULD HAVE RUN — NOT EXECUTED HERE"**, exposing the concatenated string `ping -n 1 127.0.0.1 | whoami`.
- The terminal output explicitly reports: `C:\> Blocked - injected text was never sent to Windows.`

```
================================================================================
FIGURE 4: COMMAND INJECTION DETECTION
================================================================================
```
![Figure 4: Command Injection Detection](screenshots/04_command_injection_detection.png)  
*Figure 4: Command Injection Detection displaying blocked metacharacter status, simulated vulnerable string, and safe rejection message.*

---

#### Task 6 — Defensive Secure Implementation
To provide direct educational value, the application features a tabbed **Code Comparison** card directly beneath the command output. The student can toggle between:
- **Vulnerable Pattern**: Demonstrates the dangerous `os.system('ping -n 1 ' + user_input)` pattern.
- **Secure Pattern**: Demonstrates input allow-listing and parameterized execution using `subprocess.run(['ping', '-n', '1', host], shell=False, timeout=6)`.

The implementation code is clean, readable, and structured as follows in `app.py`:
```python
def run_safe_command(cmd):
    """Execute an approved command with shell=False and a timeout."""
    completed = subprocess.run(
        cmd,
        shell=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip() or "(no output)"
```

---

#### Task 7 — Assessment Findings & Remediation
Following every execution, the application automatically aggregates and displays:
1. **Test Summary**:
   - Result status (`PASS`, `BLOCKED`, `ERROR`, `TIMEOUT`)
   - Command executed confirmation (`Yes` / `No`)
   - Injection detection alert (`Yes` / `No`)
   - Shell invocation verification (`No - shell=False enforced`)
   - Timeout parameter verification (`Yes - 6s`)
2. **Remediation Recommendations**:
   - Enforce strict allow-list validation before calling system binaries.
   - Build commands as argument arrays, never as concatenated strings.
   - Always specify `shell=False` when using `subprocess.run`.
   - Enforce execution timeouts to eliminate process hanging and denial of service.

```
================================================================================
FIGURE 6: FINAL ASSESSMENT RESULTS & REMEDIATION
================================================================================
```
![Figure 6: Final Assessment Results](screenshots/06_assessment_findings.png)  
*Figure 6: Assessment Findings & Remediation showing test summary attributes, defensive checklist, and tabbed code comparison.*

---

### 3.6 Expected Outputs
Execution of the Command Injection Vulnerability Assessment laboratory yields clear, deterministic, and verifiable outputs across all test cases:

#### Table 3.1: Expected Execution Outcomes
| Test Case Identifier | Input Target | Invoked Command | Expected Status | Behavioral Explanation |
| :--- | :--- | :--- | :--- | :--- |
| `ping-localhost` | `localhost` | `ping -n 1 -w 3000 localhost` | **PASS** | Valid target; runs via subprocess; returns real packet statistics. |
| `show-hostname` | *(empty)* | `hostname` | **PASS** | Approved parameterless command; returns Windows computer name. |
| `lookup-example` | `example.com` | `nslookup example.com` | **PASS** | Valid domain; queries DNS server; returns resolution records. |
| `inject-semicolon`| `127.0.0.1; whoami` | *None (Blocked)* | **BLOCKED** | Metacharacter `;` detected; execution aborted; risk explained. |
| `inject-and` | `127.0.0.1 && whoami`| *None (Blocked)* | **BLOCKED** | Metacharacters `&&` detected; execution aborted; risk explained. |
| `inject-pipe` | `127.0.0.1 \| whoami`| *None (Blocked)* | **BLOCKED** | Metacharacter `\|` detected; execution aborted; risk explained. |

---

### 3.7 Mapping to Syllabus Units
This project aligns directly with standard university curriculum topics in Ethical Hacking, Secure Coding, and Web Application Security:

#### Table 3.2: Mapping to Syllabus Topics
| Syllabus Topic | Practical Implementation in Project | Academic Unit |
| :--- | :--- | :---: |
| **Web Application Vulnerabilities** | Demonstrates the syntax, causes, and impacts of OS Command Injection (OWASP Top 10 A03:2021 - Injection). | Unit 3 |
| **Input Validation & Sanitization** | Implements allow-listing via regular expressions and rejection of shell metacharacters. | Unit 2 |
| **Secure Process Execution** | Implements parameterized process creation using `subprocess.run()` with `shell=False` and strict timeouts. | Unit 4 |
| **Reconnaissance & Diagnostics** | Utilizes network diagnostic commands (`ping`, `nslookup`, `hostname`) in a controlled security context. | Unit 1 |
| **Vulnerability Assessment & Reporting** | Generates assessment summaries, risk classifications, and defensive remediation checklists. | Unit 5 |

---

## CHAPTER 4

### 4.1 Screenshot Guidelines and Verification
The screenshots captured and cataloged in the `screenshots/` directory serve as empirical verification of the system's operational and defensive capabilities:
- **Figure 1 (`01_application_interface.png`)**: Captures the main application dashboard, demonstrating clean UI design, sidebar navigation, diagnostic test selection, and reference documentation.
- **Figure 2 (`02_normal_diagnostic_test.png`)**: Demonstrates functional execution of a legitimate diagnostic ping command against `localhost`, confirming real command execution and terminal output parsing.
- **Figure 4 (`04_command_injection_detection.png`)**: Confirms the security engine's capability to detect command injection patterns (`| whoami`), safely block execution, and present the educational anti-pattern without endangering the system.
- **Figure 6 (`06_assessment_findings.png`)**: Illustrates the final assessment report, presenting status metrics, automated remediation recommendations, and side-by-side code comparisons.

All screenshots were taken directly from the running web application on Windows 11 with no simulated mockups or fake graphics.

---

### 4.2 GitHub Repository Structure
To ensure full academic transparency, reproducibility, and professional engineering standards, the project is structured in a dedicated Git repository:

```
Command-Injection-VA/
│
├── app.py                 # Core Flask application, validation logic, and subprocess execution
├── requirements.txt       # Python dependencies (Flask 3.0.3)
├── .gitignore             # Virtual environment and cache ignore rules
├── README.md              # Comprehensive project documentation and execution guide
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

#### Table 4.1: Repository Component Descriptions
| File / Directory | Description |
| :--- | :--- |
| `app.py` | Python application script containing routing, validation regexes, diagnostic command maps, execution logic, and assessment reporting. |
| `templates/index.html` | Front-end HTML/CSS/JS template featuring a responsive layout, terminal emulator styling, and interactive comparison tabs. |
| `screenshots/` | Storage repository for numbered figures demonstrating each test case outcome. |
| `docs/project_report.md` | Complete academic project report in markdown format ready for documentation or PDF rendering. |
| `README.md` | Public GitHub documentation providing installation instructions, architecture diagrams, and security principles. |

---

### 4.3 Ethical Disclaimer and Conclusion
This project, **Command Injection Vulnerability Assessment**, was developed strictly for educational and academic purposes as part of the Ethical Hacking curriculum. All diagnostic executions were conducted solely within an authorized localhost environment on the author's personal workstation. The software explicitly disallows arbitrary command submission and never executes malicious payloads.

In conclusion, the project successfully achieves all stated objectives:
1. It demystifies the mechanics of command injection by exposing the behavior of shell metacharacters in a safe, controlled manner.
2. It proves that simple string concatenation is fundamentally insecure for operating system invocations.
3. It demonstrates the definitive industry remediation: **strict input allow-listing combined with parameterized argument passing using `subprocess.run(..., shell=False, timeout=...)`**.

By integrating vulnerability assessment, live diagnostics, interactive code comparisons, and actionable remediation checklists into a single lightweight platform, this project provides a comprehensive, professional, and accessible educational tool for understanding and eliminating command injection vulnerabilities in modern software systems.
