# COMMAND INJECTION VULNERABILITY ASSESSMENT

**ETHICAL HACKING - PROJECT REPORT**  
SUBMITTED IN PARTIAL FULFILLMENT OF THE REQUIREMENTS FOR THE AWARD OF THE DEGREE OF  
**BACHELOR OF ENGINEERING IN COMPUTER SCIENCE AND ENGINEERING (CYBERSECURITY)**  
**OF THE ANNA UNIVERSITY**

**OCT/NOV 2026**

---

### PROJECT WORK
**BATCH: 2024 – 2028**

**Submitted by:**  
Kavin Krishna - *(Register Number)*

**Under the Guidance of:**  
Dr. A. Sarfaraz Ahmed, Ph.D.  
Assistant Professor CSE

<br>

**Sri Eshwar College of Engineering**  
*(An Autonomous Institution)*  
Kinathukadavu (Tk), Coimbatore – 641 202, Tamil Nadu  
Approved by AICTE, New Delhi and Affiliated to Anna University, Chennai  
Accredited by NAAC with 'A' Grade | NBA | NIRF

---

## BONAFIDE CERTIFICATE

Certified that this Report titled **“COMMAND INJECTION VULNERABILITY ASSESSMENT”** is the bonafide work of

**Kavin Krishna** &nbsp;&nbsp;&nbsp;&nbsp; *(Register Number)*

who carried out the project work under the supervision of Dr. A. Sarfaraz Ahmed.

<br>

```
SIGNATURE                                               SIGNATURE
Dr. S. Sampath Kumar, M.Tech., PhD,                     Dr. A. Sarfaraz Ahmed., Ph.D.
ASSOCIATE PROFESSOR &                                   SUPERVISOR,
HEAD OF THE DEPARTMENT,                                 ASSISTANT PROFESSOR,
Department of Computer Science and                      Department of Computer Science and 
Engineering (Cybersecurity),                            Engineering,
Sri Eshwar College of Engineering,                      Sri Eshwar College of Engineering, 
Coimbatore – 641 202.                                   Coimbatore – 641 202.
```

<br>

Submitted for the Autonomous Semester End Ethical Hacking Essentials Project Viva-Voce held on ……………………..

<br>

```
INTERNAL EXAMINER                                       EXTERNAL EXAMINER
```

---

## INSTITUTIONAL VISION, MISSION & QUALITY POLICY

### QUALITY POLICY
To establish a system of Quality Enhancement, which would on a continuous basis evaluate and enhance the quality of teaching – learning, research and extension activities of the institution, leading to improvements in all processes, enabling the institution to attain excellence.

### INSTITUTE VISION
To be recognized as a premier institution, grooming students into globally acknowledged engineering professionals.

### INSTITUTE MISSION
- Providing outcome and value-based engineering education
- Nurturing research and entrepreneurial culture
- Enabling students to be industry ready and fulfill their career aspirations
- Grooming students through behavioral and leadership training programs
- Making students socially responsible

### DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING (CYBERSECURITY)

#### DEPARTMENT VISION
To produce globally competitive cybersecurity professionals capable of addressing evolving cyber threats through innovation, research, and ethical practices.

#### DEPARTMENT MISSION
- Establishing a world-class academic environment with cutting-edge cybersecurity infrastructure and industry-driven faculty expertise.
- Encouraging research and innovation in cybersecurity, fostering lifelong learning among students and faculty.
- Developing leadership and entrepreneurial skills to drive cybersecurity advancements.
- Creating opportunities for students to evolve as ethical cybersecurity professionals with a strong societal impact.

### PROGRAM EDUCATIONAL OBJECTIVES (PEOs)
- **PEO1**: To prepare graduates for careers in cybersecurity, ensuring they can secure digital ecosystems effectively.
- **PEO2**: To equip students with the ability to pursue higher studies, research, entrepreneurship, and leadership roles in cybersecurity.
- **PEO3**: To enable students to develop innovative solutions for real-world cybersecurity challenges.

---

## PROGRAM OUTCOMES & PROGRAM SPECIFIC OUTCOMES

### PROGRAM OUTCOMES (POs)
- **PO1: Engineering Knowledge**: Apply knowledge of mathematics, natural science, computing, engineering fundamentals and an engineering specialization to solve complex engineering problems.
- **PO2: Problem Analysis**: Identify, formulate, review research literature and analyze complex engineering problems reaching substantiated conclusions.
- **PO3: Design/Development of Solutions**: Design creative solutions for complex engineering problems and design systems/components/processes to meet identified security needs.
- **PO4: Conduct Investigations of Complex Problems**: Conduct investigations using research-based knowledge including design of experiments, analysis, and interpretation of data.
- **PO5: Engineering Tool Usage**: Create, select and apply appropriate techniques, resources, and modern IT tools recognizing their limitations.
- **PO6: The Engineer and The World**: Analyze and evaluate societal, environmental, safety, legal, and cultural aspects relevant to professional engineering practice.
- **PO7: Ethics**: Apply ethical principles and commit to professional ethics, human values, and adhere to national and international cyber laws.
- **PO8: Individual and Collaborative Teamwork**: Function effectively as an individual, and as a member or leader in diverse and multidisciplinary teams.
- **PO9: Communication**: Communicate effectively and inclusively within the engineering community, writing effective reports and technical design documentation.
- **PO10: Project Management and Finance**: Apply knowledge of engineering management principles and economic decision-making to one's own work.
- **PO11: Life-Long Learning**: Recognize the need for independent and life-long learning in the context of emerging technological advancements.

### PROGRAM SPECIFIC OUTCOMES (PSOs)
- **PSO1**: Demonstrate expertise in open-source cybersecurity tools and vulnerability assessment frameworks.
- **PSO2**: Develop innovative security solutions by integrating defensive technologies.
- **PSO3**: Implement Secure Software Development Lifecycle (SSDLC) principles for robust cybersecurity solutions.

---

## DECLARATION

I, **Kavin Krishna**, *(Register Number)*, declare that the project entitled **“COMMAND INJECTION VULNERABILITY ASSESSMENT”**, submitted in partial fulfilment to Anna University as the project work of Bachelor of Engineering CSE (CyberSecurity) Degree, is a record of original work done by me under the supervision and guidance of **Dr. A. Sarfaraz Ahmed, Ph.D., Assistant Professor**, Department of Computer Science and Engineering, Sri Eshwar College of Engineering, Coimbatore.

**Place:** Coimbatore  
**Date:**  

<br>
**Kavin Krishna**

**Project Guided by:**  
[Dr. A. Sarfaraz Ahmed, Ph.D.]

---

## ACKNOWLEDGEMENT

The success of a work depends on a team and cooperation. We take this opportunity to express our gratitude and thanks to everyone who helped us in our project. We would like to thank the management for the constant support provided by them to complete this project.

It is indeed our great honor bounded duty to thank our beloved Chairman **Mr. R. Mohanram**, for his academic interest towards the students. We are indebted to our Director **Mr. R. Rajaram**, for motivating and providing us with all facilities.

We wish to express our sincere regards and deep sense of gratitude to **Dr. Sudha Mohanram M.E, Ph.D.**, Principal, for the excellent facilities and encouragement provided during the course of the study and project.

We are indebted to **Dr. S. Sampath Kumar, M.Tech., PhD.**, Associate Professor & Head of Computer Science and Engineering (CyberSecurity) Department for having permitted us to carry out this project and giving the complete freedom to utilize the resources of the department.

We also extend our heartfelt thanks to our Project Guide **Dr. A. Sarfaraz Ahmed, Ph.D.**, Assistant Professor, Department of Computer Science and Engineering for providing us support and guidance which really helped us.

We solemnly express our thanks to all the teaching and non-teaching staff of the CSE Department, family and friends for their valuable support which inspired us to work on this project.

---

## TABLE OF CONTENTS

```
TABLE OF CONTENTS .................................................................... 3
CHAPTER 1 ............................................................................ 4
  1.1 Introduction .................................................................... 4
  1.2 Project Objectives ............................................................. 5
CHAPTER 2 ............................................................................ 6
  2.1 Project Guidelines ............................................................. 6
  2.2 Lab Setup ...................................................................... 7
CHAPTER 3 ............................................................................ 9
  3.1 Problem Statement .............................................................. 9
  3.2 Background ..................................................................... 9
      Operating System Command Execution ............................................ 9
      Shell Metacharacters and Chaining Operators ................................... 9
      Subprocess Process Invocation Mechanics ...................................... 10
      Allow-List Input Validation .................................................. 10
      Automated Threat Remediation Frameworks ....................................... 10
  3.3 Objectives .................................................................... 11
  3.4 Tools Required ................................................................ 11
  3.5 Implementation Tasks .......................................................... 12
      Task 1 — Environment & Application Server Configuration ....................... 12
      Task 2 — Predefined Diagnostic Target Selection ............................... 13
      Task 3 — Harmless Command Execution & Output Capture .......................... 14
      Task 4 — Dual-Stage Input Validation & Allow-Listing .......................... 15
      Task 5 — Semicolon (;) Command Separation Detection ........................... 16
      Task 6 — Logical AND (&&) Chaining Metacharacter Mitigation ................... 17
      Task 7 — Pipe (|) Redirection Metacharacter Analysis .......................... 18
      Task 8 — Secure Parameterized Implementation (shell=False & Timeout) .......... 19
      Task 9 — Assessment Findings and Remediation Reporting ........................ 20
  3.6 Expected Outputs .............................................................. 21
  3.7 Mapping to Syllabus Units ..................................................... 22
CHAPTER 4 ........................................................................... 23
  4.1 Screenshot Guidelines ......................................................... 23
  4.2 GitHub Repository Structure ................................................... 24
  4.3 Ethical Disclaimer and Conclusion ............................................. 25
ANNEXURE — SDG MAPPING & EXPENDITURE STATEMENT ...................................... 26
```

---

## CHAPTER 1

### 1.1 Introduction
In ethical hacking and application security, ensuring software resilience against arbitrary code execution is paramount. Web applications frequently interact with the underlying operating system to perform essential tasks such as network health checks, DNS queries, and service verification. However, when user-supplied input is directly concatenated into an operating system command string and passed to a system command interpreter (`cmd.exe`, PowerShell, or Bash), a critical vulnerability known as **Command Injection (CWE-78)** is introduced.

Command injection allows an adversary to append unauthorized operating system commands using shell metacharacters such as semicolons (`;`), logical operators (`&&`, `||`), or pipes (`|`). Because the command interpreter runs under the security context of the parent application server, an injected command can compromise the server, read or delete confidential files, modify configuration settings, and pivot across the internal network.

Assessing and eliminating command injection requires a multi-layered defense. Traditional blacklisting approaches often fail because attackers can bypass naive keyword filters using alternative encodings, whitespace variations, and string manipulations. A robust security implementation requires:
1. Strict input validation based on allow-lists (whitelisting).
2. Parameterized command execution using explicit argument arrays where `shell=False` is enforced.
3. Execution timeouts to prevent denial-of-service conditions.

Performing these vulnerability assessments manually across varied input vectors can be prone to human error. This project addresses this challenge by developing a lightweight, beginner-friendly web application—**Command Injection Vulnerability Assessment**—built using Python Flask. The application demonstrates real diagnostic executions (`ping`, `hostname`, `nslookup`), safely detects and intercepts injection attempts without executing harmful secondary payloads, compares vulnerable anti-patterns with secure alternatives, and generates real-time assessment summaries and remediation recommendations on Windows.

### 1.2 Project Objectives
1. To develop a modular Python Flask web application restricted to localhost (`127.0.0.1:5001`) on Windows.
2. To implement harmless network diagnostic operations (`ping`, `hostname`, `nslookup`) that return actual, real-time command output.
3. To construct a dual-stage input validation engine utilizing regular expressions for shell metacharacter detection and strict hostname allow-listing.
4. To safely demonstrate the risk of command injection using controlled test cases (semicolon, AND chaining, pipe redirection) without executing injected payloads.
5. To implement secure command execution using Python’s `subprocess.run()` with `shell=False`, argument list passing, and execution timeouts.
6. To provide an educational side-by-side code comparison between insecure string concatenation and secure parameterized implementations.
7. To generate real-time assessment summaries detailing execution status, injection risk detection, and prioritized remediation recommendations.

---

## CHAPTER 2

### 2.1 Project Guidelines
This project has been designed and executed in strict accordance with ethical hacking principles and academic guidelines:
- **Authorized Testing Only**: The application operates solely on localhost (`127.0.0.1`) on the student’s workstation. No external or unauthorized network systems are targeted.
- **Simulated Safe Detection**: When injection test cases are selected, the security engine detects suspicious characters, halts command execution, and displays educational warnings. Injected commands are **never executed**.
- **No Arbitrary Input Execution**: Free-text command entry is restricted. Interactions are handled through curated predefined test cases to prevent unintended system actions.
- **Resource Protection**: Subprocess execution is strictly capped at a 6-second timeout to mitigate denial-of-service risks.

### 2.2 Lab Setup
The lab was developed and verified on a single Windows 11 host using Python Flask and native diagnostic binaries.

#### Table 2.1: Lab Environment Configuration
| Parameter | Value |
| :--- | :--- |
| Operating System | Windows 11 (64-bit) |
| Python Version | Python 3.13.x / Python 3.10+ |
| Web Framework | Flask 3.0.3 |
| Local Binding | `127.0.0.1:5001` (Localhost) |
| Execution Mode | Native Process Execution (`shell=False`) |
| Diagnostic Utilities | `ping.exe`, `hostname.exe`, `nslookup.exe` |
| Project Directory | `d:\Extrass\ETH_Project\` |

#### Table 2.2: Software and Tools Used
| Software / Tool | Purpose in the Project |
| :--- | :--- |
| **Python Flask** | Provides web backend, routing, and Jinja2 rendering. |
| **Python `subprocess`** | Manages direct, parameterized process invocation with timeout controls. |
| **Python `re`** | Implements regex patterns for metacharacter filtering and allow-listing. |
| **HTML5 / CSS3 / JS** | Renders the two-column dashboard, terminal output, and interactive comparison tabs. |
| **Git / GitHub** | Provides version control and repository synchronization. |

---

## CHAPTER 3

### 3.1 Problem Statement
Many web applications invoke system-level utilities for network troubleshooting. When developers use insecure string concatenation (e.g., `os.system("ping -n 1 " + user_input)`), adversaries can exploit shell parsing mechanics to execute arbitrary commands. A dedicated platform is needed to safely demonstrate this vulnerability, explain the mechanics of shell metacharacters, and showcase effective defensive programming techniques.

### 3.2 Background
- **Operating System Command Execution**: Invoking system binaries via shells versus direct process APIs.
- **Shell Metacharacters and Chaining Operators**: Mechanics of `;`, `&&`, `|`, and how shells interpret them as control directives.
- **Subprocess Invocation Mechanics**: The critical difference between `shell=True` (string parsing by shell) and `shell=False` (direct kernel process creation via array arguments).
- **Allow-List Input Validation**: Why regex whitelisting is superior to blacklisting.
- **Automated Threat Remediation**: Practical steps for neutralizing injection risks.

### 3.3 Objectives
1. Configure Flask application environment and local binding.
2. Provide curated diagnostic test selections.
3. Execute approved commands and capture standard output/error.
4. Enforce dual-stage input validation.
5. Intercept and block semicolon, AND, and pipe injection patterns.
6. Provide side-by-side code comparisons.
7. Deliver automated findings and remediation reports.

### 3.4 Tools Required
- Windows 11 operating system
- Python 3.10+ with Flask 3.0.3
- Git version control

---

### 3.5 Implementation Tasks

#### Task 1 — Environment & Application Server Configuration
**What it does**: Initializes the Flask server on `127.0.0.1:5001` with execution timeouts and security settings.  
**How it is implemented**: Configured in `app.py` with `TIMEOUT_SECONDS = 6` and localhost binding.  
**Why it is required**: Restricts exposure to the local development environment and protects against infinite loops.  
**Output produced**: A running Flask server listening locally on port 5001.

---

#### Task 2 — Predefined Diagnostic Target Selection
**What it does**: Provides a user interface with curated safe diagnostics and injection demos.  
**How it is implemented**: Rendered via `templates/index.html` featuring a sidebar selector and status guide.  
**Why it is required**: Eliminates arbitrary text entry, preventing unintended command execution.  
**Output produced**: Clean, professional two-column web dashboard.

[ Insert Image: 01_application_interface.png ]  
*Figure 1: Application Interface showing diagnostic dropdown, status key, and reference cards.*

---

#### Task 3 — Harmless Command Execution & Output Capture
**What it does**: Executes approved diagnostic operations (`ping`, `hostname`, `nslookup`) and returns real output.  
**How it is implemented**: Invoked using `subprocess.run(['ping', '-n', '1', '-w', '3000', 'localhost'], shell=False)`.  
**Why it is required**: Demonstrates legitimate system diagnostic functionality.  
**Output produced**: Real terminal output displaying ping statistics and round-trip times.

[ Insert Image: 02_normal_diagnostic_test.png ]  
*Figure 2: Normal Diagnostic Test showing successful ping execution against localhost.*

---

#### Task 4 — Dual-Stage Input Validation & Allow-Listing
**What it does**: Validates target inputs against strict regex patterns before any process execution.  
**How it is implemented**: Implemented via `INJECTION_PATTERN = re.compile(r"[;&|`$()\<\>^\r\n]")` and `SAFE_HOST_PATTERN = re.compile(r"^(localhost|example\.com|\d{1,3}(?:\.\d{1,3}){3})$")`.  
**Why it is required**: Ensures that only recognized, harmless hostnames can proceed to execution.  
**Output produced**: Automatic rejection of non-whitelisted or malformed host targets.

[ Insert Image: 03_input_validation.png ]  
*Figure 3: Input Validation code showing regex patterns, timeout limits, and allow-list checking.*

---

#### Task 5 — Semicolon (;) Command Separation Detection
**What it does**: Intercepts input containing semicolons (e.g., `127.0.0.1; whoami`) and halts execution.  
**How it is implemented**: Detected by `injection_hits()`, returning `BLOCKED (injection pattern)` status.  
**Why it is required**: Semicolons allow sequential command execution in shells.  
**Output produced**: Blocked status, risk explanation, and zero secondary command execution.

---

#### Task 6 — Logical AND (&&) Chaining Metacharacter Mitigation
**What it does**: Intercepts logical AND operators (e.g., `127.0.0.1 && whoami`) and demonstrates risk mitigation.  
**How it is implemented**: The pattern engine flags `&&`, logs the simulated vulnerable string, and refuses execution.  
**Why it is required**: Demonstrates how command chaining attacks are neutralized before reaching the OS.  
**Output produced**: Warning callout displaying the vulnerable string with full execution suppression.

[ Insert Image: 05_secure_implementation.png ]  
*Figure 4: Command Chaining Mitigation showing blocked status for 127.0.0.1 && whoami.*

---

#### Task 7 — Pipe (|) Redirection Metacharacter Analysis
**What it does**: Detects pipe operators (e.g., `127.0.0.1 | whoami`) used to redirect output streams.  
**How it is implemented**: Scanned by regex; returns educational callout showing what vulnerable apps would build.  
**Why it is required**: Pipe operators allow chaining command inputs and outputs together.  
**Output produced**: Visual warning and educational security analysis.

[ Insert Image: 04_command_injection_detection.png ]  
*Figure 5: Command Injection Detection showing blocked pipe redirection and simulated command.*

---

#### Task 8 — Secure Parameterized Implementation (shell=False & Timeout)
**What it does**: Demonstrates direct process invocation using parameter arrays, avoiding shell interpretation.  
**How it is implemented**: Implemented with `subprocess.run(cmd, shell=False, timeout=TIMEOUT_SECONDS)`.  
**Why it is required**: Passing arguments as an array ensures that even metacharacters are treated as literal arguments by the executable.  
**Output produced**: Interactive tabbed code comparison showing vulnerable vs. secure implementations.

---

#### Task 9 — Assessment Findings and Remediation Reporting
**What it does**: Generates a real-time assessment report summarizing execution metrics and defense guidelines.  
**How it is implemented**: Aggregates status, command facts, shell invocation checks, and remediation lists.  
**Why it is required**: Provides actionable, industry-standard remediation guidance for developers.  
**Output produced**: Two-column findings card with test summary and remediation checklist.

[ Insert Image: 06_assessment_findings.png ]  
*Figure 6: Assessment Findings & Remediation showing test summary metrics and defense checklist.*

---

### 3.6 Expected Outputs
- Safe commands execute and display real terminal output.
- Injected inputs are detected, blocked, and explained without executing secondary commands.
- Code comparisons illustrate the exact technical differences between vulnerable and secure coding patterns.
- Comprehensive remediation checklists are dynamically displayed for every test case.

### 3.7 Mapping to Syllabus Units
- **Unit 1**: Ethical Hacking Basics & Network Diagnostics (`ping`, `nslookup`, `hostname`).
- **Unit 2**: Input Validation and Sanitization (Regex Whitelisting).
- **Unit 3**: Web Application Vulnerability Assessment (OWASP A03: Injection).
- **Unit 4**: Secure Process Execution & Defensive Programming (`shell=False`, argument arrays).
- **Unit 5**: Vulnerability Assessment Reporting & Remediation.

---

## CHAPTER 4

### 4.1 Screenshot Guidelines
- **Figure 1**: Application Interface (`01_application_interface.png`)
- **Figure 2**: Normal Diagnostic Test (`02_normal_diagnostic_test.png`)
- **Figure 3**: Input Validation Source Code (`03_input_validation.png`)
- **Figure 4**: Command Chaining Mitigation (`05_secure_implementation.png`)
- **Figure 5**: Command Injection Detection (`04_command_injection_detection.png`)
- **Figure 6**: Assessment Findings & Remediation (`06_assessment_findings.png`)

### 4.2 GitHub Repository Structure
```
Command-Injection-VA/
│
├── app.py                 # Core application and secure execution engine
├── requirements.txt       # Flask dependencies
├── .gitignore             # Environment and cache rules
├── README.md              # Project documentation and guide
│
├── templates/
│   └── index.html         # Front-end dashboard and code comparison tabs
│
├── screenshots/           # Evidence screenshots (Figures 1 to 6)
│   ├── 01_application_interface.png
│   ├── 02_normal_diagnostic_test.png
│   ├── 03_input_validation.png
│   ├── 04_command_injection_detection.png
│   ├── 05_secure_implementation.png
│   └── 06_assessment_findings.png
│
└── docs/                  # Formal documentation and academic report
    └── project_report.md
```

### 4.3 Ethical Disclaimer and Conclusion
This project was conducted strictly within an authorized local environment for educational purposes. It successfully demonstrates the risks of command injection and proves that strict input allow-listing combined with `subprocess.run(shell=False)` provides robust defense against injection attacks.

---

## ANNEXURE

### POs & PSOs Mapping
| PO1 | PO2 | PO3 | PO4 | PO5 | PO6 | PO7 | PO8 | PO9 | PO10 | PO11 | PSO1 | PSO2 | PSO3 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

- **Project Title**: Command Injection Vulnerability Assessment
- **Program**: B.E CSE (CYBERSECURITY)
- **Batch**: 2024 – 2028
- **Student Name**: Kavin Krishna
- **Supervisor**: Dr. A. Sarfaraz Ahmed, Ph.D.
- **SDG Goals Mapped**: Industry, Innovation and Infrastructure (SDG 9)
- **TRL Level**: 3 (Analytical and Experimental Critical Function and /or characteristic proof of concept)

### VENUE AND EXPENDITURE STATEMENT FOR THE PROJECT WORK
- **Laboratory details**: Cybersecurity Lab, CSE(Cybersecurity)
- **Software Requirements**: Windows 11, Python 3.10+, Flask 3.0.3, subprocess, re, PowerShell, Web Browser
- **Hardware Requirements**: Personal computer with sufficient RAM and storage.

```
Signature of the student                               Signature of the Supervisor
Kavin Krishna                                          (Dr. A. Sarfaraz Ahmed, Ph.D.)
```
