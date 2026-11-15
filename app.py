"""
Command Injection Vulnerability Assessment (Ubuntu / Linux)
Interactive Cybersecurity Laboratory.

Demonstrates:
- Safe Mode (Defensive): Strict regex allow-list validation, array-based argument passing with shell=False, and execution timeouts on Ubuntu/Linux.
- Unsafe Mode (Vulnerable): Direct concatenation into system shell (shell=True via /bin/bash), demonstrating how command injection occurs in real-world web applications.
"""

import os
import platform
import re
import shutil
import subprocess

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Determine operating environment
IS_WIN = platform.system().lower() == "windows"
BASH_PATH = r"C:\Program Files\Git\bin\bash.exe" if IS_WIN and os.path.exists(r"C:\Program Files\Git\bin\bash.exe") else shutil.which("bash") or "/bin/bash"

# ---------------------------------------------------------------------------
# Predefined test cases — Ubuntu / Linux diagnostic tools & injection patterns
# ---------------------------------------------------------------------------
TEST_CASES = [
    {
        "id": "ping-loopback",
        "label": "Ping 127.0.0.1 (safe diagnostic)",
        "tool": "ping",
        "target": "127.0.0.1",
    },
    {
        "id": "ping-localhost",
        "label": "Ping localhost (safe diagnostic)",
        "tool": "ping",
        "target": "localhost",
    },
    {
        "id": "show-hostname",
        "label": "Show system info: uname -a (safe diagnostic)",
        "tool": "uname",
        "target": "-a",
    },
    {
        "id": "lookup-example",
        "label": "Hostname lookup: example.com (safe, needs internet)",
        "tool": "lookup",
        "target": "example.com",
    },
    {
        "id": "inject-semicolon",
        "label": "Unsafe pattern: semicolon  (127.0.0.1; id)",
        "tool": "ping",
        "target": "127.0.0.1; id",
    },
    {
        "id": "inject-and",
        "label": "Unsafe pattern: && chaining  (127.0.0.1 && uname -a)",
        "tool": "ping",
        "target": "127.0.0.1 && uname -a",
    },
    {
        "id": "inject-pipe",
        "label": "Unsafe pattern: pipe  (127.0.0.1 | whoami)",
        "tool": "ping",
        "target": "127.0.0.1 | whoami",
    },
]

# ---------------------------------------------------------------------------
# Code snippets shown in the comparison panel (Ubuntu / Linux focused)
# ---------------------------------------------------------------------------
CODE_SNIPPETS = {
    "ping": {
        "unsafe": (
            "# UNSAFE — string concatenation executed directly in /bin/bash\n"
            "import os\n"
            "user_input = request.form['host']   # e.g. '127.0.0.1; id'\n"
            "os.system('ping -c 1 ' + user_input) # executes BOTH ping AND id on Ubuntu!"
        ),
        "safe": (
            "# SECURE — shell=False, regex allow-list, argument array on Ubuntu\n"
            "import subprocess, re\n"
            "SAFE = re.compile(r'^(localhost|example\\.com|\\d{1,3}(\\.\\d{1,3}){3})$')\n"
            "host = request.form['host'].strip().lower()\n"
            "if not SAFE.match(host):\n"
            "    abort(400)           # reject invalid input before execution\n"
            "subprocess.run(['ping', '-c', '1', '-W', '3', host],\n"
            "               shell=False, timeout=6)  # host is ONE literal argument"
        ),
    },
    "lookup": {
        "unsafe": (
            "# UNSAFE — user input goes straight into a Linux shell string\n"
            "import os\n"
            "host = request.form['host']   # e.g. 'example.com; id'\n"
            "os.system('nslookup ' + host) # secondary Linux command executes!"
        ),
        "safe": (
            "# SECURE — validated host passed as argument array, no shell\n"
            "import subprocess, re\n"
            "SAFE = re.compile(r'^[a-z0-9.-]{1,253}$')\n"
            "host = request.form['host'].strip().lower()\n"
            "if not SAFE.match(host):\n"
            "    abort(400)\n"
            "subprocess.run(['nslookup', host], shell=False, timeout=6)"
        ),
    },
    "uname": {
        "unsafe": (
            "# UNSAFE — even diagnostic utilities are vulnerable if shell=True\n"
            "import subprocess\n"
            "subprocess.run('uname ' + user_arg, shell=True) # shell risk"
        ),
        "safe": (
            "# SECURE — static argument array, shell=False is always correct\n"
            "import subprocess\n"
            "subprocess.run(['uname', '-a'], shell=False, timeout=6)"
        ),
    },
}

# ---------------------------------------------------------------------------
# Remediation recommendations
# ---------------------------------------------------------------------------
REMEDIATIONS = {
    "PASS": [
        "Input was validated against an allow-list before use.",
        "Command was built as an argument list — shell=False prevents shell operator interpretation.",
        "A timeout was applied so the process cannot hang the Ubuntu server.",
        "No user-supplied data was concatenated into a shell string.",
    ],
    "BLOCKED": [
        "Implement input validation using an allow-list or strict regex before any command call.",
        "Never pass raw user input to os.system(), subprocess.run(shell=True), or similar.",
        "Build commands as Python lists (['ping', '-c', '1', host]) instead of strings ('ping ' + host).",
        "Always set shell=False and a timeout when using subprocess on Ubuntu.",
        "Log and alert on blocked injection attempts for security monitoring.",
    ],
    "VULNERABLE": [
        "CRITICAL: User input was directly concatenated and executed via the system shell (/bin/bash).",
        "Refactor immediately: disable shell=True and pass command arguments as a Python list.",
        "Implement strict allow-list regex validation to reject shell metacharacters (; & | ` $ < > ^).",
        "Run the web service under an unprivileged user (e.g. www-data) with least privilege.",
        "Toggle back to Safe Mode to verify how strict validation mitigates this vulnerability.",
    ],
    "TIMEOUT": [
        "Always set a timeout on subprocess calls to prevent denial-of-service.",
        "Consider reducing the timeout value for interactive tools.",
        "Log timeouts — repeated timeouts may indicate network issues or misuse.",
    ],
    "ERROR": [
        "Verify that approved diagnostic tools (ping, nslookup, uname) exist on system PATH.",
        "Restrict tool execution to a pre-approved allow-list.",
        "Handle OSError and subprocess failures gracefully with clear user feedback.",
    ],
}

# ---------------------------------------------------------------------------
# Validation patterns & safety limits
# ---------------------------------------------------------------------------
INJECTION_PATTERN = re.compile(r"[;&|`$()\<\>^\r\n]")
SAFE_HOST_PATTERN = re.compile(r"^(localhost|example\.com|\d{1,3}(?:\.\d{1,3}){3})$")

TIMEOUT_SECONDS = 6


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_case(case_id):
    for case in TEST_CASES:
        if case["id"] == case_id:
            return case
    return None


def injection_hits(text):
    """Return sorted list of unsafe characters found."""
    return sorted(set(INJECTION_PATTERN.findall(text)))


def is_safe_host(host):
    """Allow only known-safe hostnames / IPs."""
    host = host.strip().lower()
    if injection_hits(host) or " " in host:
        return False
    return bool(SAFE_HOST_PATTERN.match(host))


def build_safe_command(tool, host):
    """Return an argument list for safe subprocess execution on Ubuntu/Linux."""
    if tool == "ping":
        if IS_WIN:
            return ["ping", "-n", "1", "-w", "3000", host]
        return ["ping", "-c", "1", "-W", "3", host]
    if tool == "lookup":
        return ["nslookup", host]
    if tool == "uname" or tool == "hostname":
        if IS_WIN:
            return ["hostname"]
        return ["uname", "-a"]
    return None


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


def run_raw_system_shell(cmd_str):
    """Directly execute command in the OS bash shell (real vulnerable application behavior)."""
    exec_cmd = cmd_str
    # If running on Windows host, translate ping -c to ping -n so ping functions smoothly in git bash
    if IS_WIN:
        exec_cmd = re.sub(r"\bping\s+-c\s+(\d+)", r"ping -n \1", exec_cmd)

    if IS_WIN and os.path.exists(BASH_PATH):
        completed = subprocess.run(
            [BASH_PATH, "-c", exec_cmd],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    else:
        completed = subprocess.run(
            exec_cmd,
            shell=True,
            executable="/bin/bash" if os.path.exists("/bin/bash") else None,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip() or "(command executed with no output)"


def status_theme(status):
    """Map a status string to (CSS class, icon character)."""
    if "VULNERABLE" in status or "EXPLOITED" in status:
        return "theme-unsafe", "&#9888;"
    if "PASS" in status or "RAN" in status:
        return "theme-pass", "&#10003;"
    if "BLOCKED" in status:
        return "theme-blocked", "&#128683;"
    if "TIMEOUT" in status:
        return "theme-timeout", "&#9203;"
    return "theme-error", "&#10007;"


def remediation_for(status):
    """Pick the right remediation list from the status string."""
    for key in ("VULNERABLE", "PASS", "BLOCKED", "TIMEOUT", "ERROR"):
        if key in status:
            return REMEDIATIONS[key]
    return REMEDIATIONS["ERROR"]


def snippets_for(tool):
    """Return unsafe/safe code snippet pair for a tool."""
    return CODE_SNIPPETS.get(tool, CODE_SNIPPETS["ping"])


# ---------------------------------------------------------------------------
# Assessment logic
# ---------------------------------------------------------------------------

def assess(case, unsafe_mode=False):
    target = case.get("target", "").strip()
    tool = case.get("tool", "ping")
    hits = injection_hits(target)

    print(f"\n--- Assessment: {case.get('label', target)} ---")
    print(f"Target : {target!r}")
    print(f"Mode   : {'UNSAFE (Direct OS Execution)' if unsafe_mode else 'SAFE (Defensive)'}")

    # =========================================================================
    # UNSAFE MODE (Real Vulnerability: Direct System Shell Execution)
    # =========================================================================
    if unsafe_mode:
        # Build direct shell command as a real-world vulnerable web app would
        if any(op in target for op in [";", "&", "|", "`", "$", "(", ")"]):
            shell_cmd = f"ping -c 1 {target}"
        elif is_safe_host(target):
            shell_cmd = f"ping -c 1 {target}"
        elif target == "":
            shell_cmd = "uname -a" if not IS_WIN else "hostname"
        else:
            # Direct command or custom parameter passed directly into shell
            shell_cmd = f"ping -c 1 ; {target}"

        try:
            code, output = run_raw_system_shell(shell_cmd)
            status = "VULNERABLE (Command Executed)"
            result = {
                "command": shell_cmd,
                "unsafe_example": shell_cmd,
                "output": output,
                "status": status,
                "explanation": (
                    f"REAL VULNERABILITY EXECUTED: Unsafe Mode passed the unvalidated input directly "
                    f"to the system shell ({shell_cmd!r}) using shell=True (/bin/bash). "
                    "The shell parsed the command line and executed secondary commands with the privileges "
                    "of the running system process."
                ),
                "remediation": REMEDIATIONS["VULNERABLE"],
                "snippets": snippets_for(tool),
                "command_executed": "Yes",
                "injection_detected": "Yes (Filter Bypassed in Unsafe Mode)" if (hits or not is_safe_host(target)) else "No",
                "shell_invoked": "Yes (/bin/bash via shell=True)",
                "is_vulnerable": True,
            }
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            result = {
                "command": shell_cmd,
                "unsafe_example": shell_cmd,
                "output": f"Command exceeded {TIMEOUT_SECONDS}s timeout.",
                "status": status,
                "explanation": "The injected command timed out after 6 seconds.",
                "remediation": REMEDIATIONS["TIMEOUT"],
                "snippets": snippets_for(tool),
                "command_executed": "Yes",
                "injection_detected": "Yes" if hits else "No",
                "shell_invoked": "Yes (/bin/bash)",
                "is_vulnerable": True,
            }
        except OSError as err:
            status = "ERROR"
            result = {
                "command": shell_cmd,
                "unsafe_example": shell_cmd,
                "output": f"Shell error: {err}",
                "status": status,
                "explanation": f"Could not execute command via shell: {err}",
                "remediation": REMEDIATIONS["ERROR"],
                "snippets": snippets_for(tool),
                "command_executed": "No",
                "injection_detected": "Yes" if hits else "No",
                "shell_invoked": "Yes",
                "is_vulnerable": True,
            }

        print("Command:", result["command"])
        print("Status :", result["status"])
        print("Output :\n", result["output"])
        return result

    # =========================================================================
    # SAFE MODE (Defensive Pattern: Input Validation & shell=False)
    # =========================================================================
    if hits:
        status = "BLOCKED (injection pattern)"
        result = {
            "command": "not executed",
            "unsafe_example": f"ping -c 1 {target}",
            "output": "Blocked — shell metacharacters were intercepted by the input validation engine and never executed.",
            "status": status,
            "explanation": (
                f"Shell operators {hits} were detected in the input. "
                "In Safe Mode, the application validates input against strict patterns. "
                "The suspicious characters were caught and execution was blocked before reaching the system shell."
            ),
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "No",
            "injection_detected": "Yes",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }
        print("Status :", result["status"])
        return result

    if tool != "hostname" and tool != "uname" and not is_safe_host(target):
        status = "BLOCKED (invalid host)"
        result = {
            "command": "not executed",
            "unsafe_example": f"{tool} {target}",
            "output": "Blocked — input does not match allow-list (only localhost, example.com, or IPv4 permitted in Safe Mode).",
            "status": status,
            "explanation": "In Safe Mode, only predefined safe host patterns are allowed. Custom inputs not matching the allow-list are rejected.",
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "No",
            "injection_detected": "Yes (Allow-list violation)",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }
        print("Status :", result["status"])
        return result

    cmd = build_safe_command(tool, target)
    if cmd is None:
        status = "BLOCKED (invalid tool)"
        result = {
            "command": "not executed",
            "unsafe_example": f"{tool} {target}",
            "output": "Blocked — tool is not on the approved diagnostic list.",
            "status": status,
            "explanation": "Only ping, nslookup, and uname/hostname are allowed.",
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "No",
            "injection_detected": "No",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }
        print("Status :", result["status"])
        return result

    try:
        code, output = run_safe_command(cmd)
        status = "PASS" if code == 0 else "RAN (non-zero exit)"
        result = {
            "command": " ".join(cmd),
            "unsafe_example": None,
            "output": output,
            "status": status,
            "explanation": (
                f"Secure execution: input was validated, then subprocess executed "
                f"{cmd} with shell=False and a {TIMEOUT_SECONDS}s timeout. "
                "The host is passed as a separate argument in an array — shell operators cannot chain commands."
            ),
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "Yes",
            "injection_detected": "No",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
        result = {
            "command": " ".join(cmd),
            "unsafe_example": None,
            "output": f"Stopped after {TIMEOUT_SECONDS} s (timeout).",
            "status": status,
            "explanation": "The command exceeded the time limit and was stopped automatically.",
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "Yes",
            "injection_detected": "No",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }
    except OSError as err:
        status = "ERROR"
        result = {
            "command": " ".join(cmd),
            "unsafe_example": None,
            "output": f"Could not start command: {err}",
            "status": status,
            "explanation": "Could not find diagnostic tool on system PATH.",
            "remediation": remediation_for(status),
            "snippets": snippets_for(tool),
            "command_executed": "No",
            "injection_detected": "No",
            "shell_invoked": "No",
            "is_vulnerable": False,
        }

    print("Command:", result["command"])
    print("Status :", result["status"])
    print("Output :\n", result["output"])
    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    selected = TEST_CASES[0]["id"]
    custom_input = ""
    unsafe_mode = False

    if request.method == "POST":
        selected = request.form.get("case_id", "")
        custom_input = request.form.get("custom_input", "").strip()
        unsafe_mode = request.form.get("unsafe_mode") == "1"

        if custom_input:
            case = {
                "id": "custom",
                "label": f"Custom Input: {custom_input}",
                "tool": "ping",
                "target": custom_input,
            }
            result = assess(case, unsafe_mode=unsafe_mode)
        else:
            case = find_case(selected)
            if case:
                result = assess(case, unsafe_mode=unsafe_mode)
            else:
                result = {
                    "command": "not executed",
                    "unsafe_example": None,
                    "output": "Unknown test case.",
                    "status": "ERROR",
                    "explanation": "Pick a test from the list or enter a custom input.",
                    "remediation": REMEDIATIONS["ERROR"],
                    "snippets": CODE_SNIPPETS["ping"],
                    "command_executed": "No",
                    "injection_detected": "No",
                    "shell_invoked": "No",
                    "is_vulnerable": False,
                }

    theme, icon = status_theme(result["status"]) if result else ("", "")
    return render_template(
        "index.html",
        cases=TEST_CASES,
        selected=selected,
        custom_input=custom_input,
        unsafe_mode=unsafe_mode,
        result=result,
        theme=theme,
        icon=icon,
    )


if __name__ == "__main__":
    print("Command Injection Vulnerability Assessment (Ubuntu / Linux)")
    print("Open http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
