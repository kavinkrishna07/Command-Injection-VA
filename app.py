"""
Command Injection Vulnerability Assessment
Simple local lab for Windows.

Safe tests actually run ping or nslookup with subprocess (shell=False).
Injection-pattern tests are detected and never executed.
"""

import re
import subprocess

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Predefined test cases — users pick from this list; free typing is rejected.
# ---------------------------------------------------------------------------
TEST_CASES = [
    {
        "id": "ping-loopback",
        "label": "Ping 127.0.0.1 (safe)",
        "tool": "ping",
        "target": "127.0.0.1",
    },
    {
        "id": "ping-localhost",
        "label": "Ping localhost (safe)",
        "tool": "ping",
        "target": "localhost",
    },
    {
        "id": "show-hostname",
        "label": "Show this PC hostname (safe)",
        "tool": "hostname",
        "target": "",
    },
    {
        "id": "lookup-example",
        "label": "Hostname lookup: example.com (safe, needs internet)",
        "tool": "lookup",
        "target": "example.com",
    },
    {
        "id": "inject-semicolon",
        "label": "Unsafe pattern: semicolon  (127.0.0.1; whoami)",
        "tool": "ping",
        "target": "127.0.0.1; whoami",
    },
    {
        "id": "inject-and",
        "label": "Unsafe pattern: && chaining  (127.0.0.1 && whoami)",
        "tool": "ping",
        "target": "127.0.0.1 && whoami",
    },
    {
        "id": "inject-pipe",
        "label": "Unsafe pattern: pipe  (127.0.0.1 | whoami)",
        "tool": "ping",
        "target": "127.0.0.1 | whoami",
    },
]

# ---------------------------------------------------------------------------
# Unsafe-vs-secure code snippets shown in the comparison panel.
# Keyed by tool name so the right snippet appears for each result.
# ---------------------------------------------------------------------------
CODE_SNIPPETS = {
    "ping": {
        "unsafe": (
            "# UNSAFE — shell=True lets operators chain commands\n"
            "import os\n"
            "user_input = request.form['host']   # e.g. '127.0.0.1; whoami'\n"
            "os.system('ping -n 1 ' + user_input) # runs BOTH ping AND whoami!"
        ),
        "safe": (
            "# SECURE — shell=False, allow-list, argument list\n"
            "import subprocess, re\n"
            "SAFE = re.compile(r'^(localhost|\\d{1,3}(\\.\\d{1,3}){3})$')\n"
            "host = request.form['host'].strip()\n"
            "if not SAFE.match(host):\n"
            "    abort(400)           # reject anything not on the list\n"
            "subprocess.run(['ping', '-n', '1', host],\n"
            "               shell=False, timeout=6)  # host is ONE argument"
        ),
    },
    "lookup": {
        "unsafe": (
            "# UNSAFE — user input goes straight into a shell string\n"
            "import os\n"
            "host = request.form['host']   # e.g. 'example.com && del C:\\\\*'\n"
            "os.system('nslookup ' + host) # second command also runs!"
        ),
        "safe": (
            "# SECURE — validated host passed as argument, no shell\n"
            "import subprocess, re\n"
            "SAFE = re.compile(r'^[a-z0-9.-]{1,253}$')\n"
            "host = request.form['host'].strip().lower()\n"
            "if not SAFE.match(host):\n"
            "    abort(400)\n"
            "subprocess.run(['nslookup', host], shell=False, timeout=6)"
        ),
    },
    "hostname": {
        "unsafe": (
            "# UNSAFE — even a static command can be misused if shell=True\n"
            "import subprocess\n"
            "subprocess.run('hostname', shell=True) # unnecessary shell risk"
        ),
        "safe": (
            "# SECURE — no user input needed; shell=False is always correct\n"
            "import subprocess\n"
            "subprocess.run(['hostname'], shell=False, timeout=6)"
        ),
    },
}

# ---------------------------------------------------------------------------
# Remediation recommendations keyed by status category.
# ---------------------------------------------------------------------------
REMEDIATIONS = {
    "PASS": [
        "Input was validated against an allow-list before use.",
        "Command was built as an argument list — shell=False prevents operator abuse.",
        "A timeout was applied so the process cannot hang the server.",
        "No user-supplied data was concatenated into a shell string.",
    ],
    "BLOCKED": [
        "Implement input validation using an allow-list or strict regex before any command call.",
        "Never pass raw user input to os.system(), subprocess.run(shell=True), or similar.",
        "Build commands as Python lists (['ping', host]) instead of strings ('ping ' + host).",
        "Always set shell=False and a timeout when using subprocess.",
        "Log and alert on blocked injection attempts for monitoring.",
    ],
    "TIMEOUT": [
        "Always set a timeout on subprocess calls to prevent denial-of-service.",
        "Consider reducing the timeout value for interactive tools.",
        "Log timeouts — repeated timeouts may indicate network issues or misuse.",
    ],
    "ERROR": [
        "Verify that approved diagnostic tools (ping, nslookup, hostname) exist on PATH.",
        "Restrict tool execution to a pre-approved allow-list.",
        "Handle OSError and subprocess failures gracefully with clear user feedback.",
    ],
}

# ---------------------------------------------------------------------------
# Validation patterns
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
    """Return sorted list of unsafe characters found — never executes anything."""
    return sorted(set(INJECTION_PATTERN.findall(text)))


def is_safe_host(host):
    """Allow only known-safe hostnames / IPs."""
    host = host.strip().lower()
    if injection_hits(host) or " " in host:
        return False
    return bool(SAFE_HOST_PATTERN.match(host))


def build_safe_command(tool, host):
    """Return an argument list (never a shell string)."""
    if tool == "ping":
        return ["ping", "-n", "1", "-w", "3000", host]
    if tool == "lookup":
        return ["nslookup", host]
    if tool == "hostname":
        return ["hostname"]
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


def status_theme(status):
    """Map a status string to (CSS class, icon character)."""
    if "PASS" in status or "RAN" in status:
        return "theme-pass", "&#10003;"
    if "BLOCKED" in status:
        return "theme-blocked", "&#128683;"
    if "TIMEOUT" in status:
        return "theme-timeout", "&#9203;"
    return "theme-error", "&#10007;"


def remediation_for(status):
    """Pick the right remediation list from the status string."""
    for key in ("PASS", "BLOCKED", "TIMEOUT", "ERROR"):
        if key in status:
            return REMEDIATIONS[key]
    return REMEDIATIONS["ERROR"]


def snippets_for(tool):
    """Return unsafe/safe code snippet pair for a tool."""
    return CODE_SNIPPETS.get(tool, CODE_SNIPPETS["ping"])


# ---------------------------------------------------------------------------
# Assessment logic
# ---------------------------------------------------------------------------

def assess(case):
    target = case["target"]
    tool   = case["tool"]
    hits   = injection_hits(target)

    print(f"\n--- Test: {case['label']} ---")
    print(f"Target : {target!r}")

    # ── Injection pattern detected ──────────────────────────────────────────
    if hits:
        status = "BLOCKED (injection pattern)"
        result = {
            "command":        "not executed",
            "unsafe_example": f"ping -n 1 {target}",
            "output":         "Blocked — injected text was never sent to Windows.",
            "status":         status,
            "explanation": (
                f"Shell operators {hits} were detected in the input. "
                "A vulnerable app using os.system('ping -n 1 ' + user_input) would run "
                "the extra text as a second OS command. "
                "This lab detects the pattern and stops here — nothing is executed."
            ),
            "remediation": remediation_for(status),
            "snippets":    snippets_for(tool),
        }
        print("Status :", result["status"])
        return result

    # ── Host not on allow-list ──────────────────────────────────────────────
    if tool != "hostname" and not is_safe_host(target):
        status = "BLOCKED (invalid host)"
        result = {
            "command":        "not executed",
            "unsafe_example": f"{tool} {target}",
            "output":         "Blocked — host is not on the allow-list.",
            "status":         status,
            "explanation":    "Only localhost, example.com, or a plain IPv4 address is allowed.",
            "remediation":    remediation_for(status),
            "snippets":       snippets_for(tool),
        }
        print("Status :", result["status"])
        return result

    # ── Tool not approved ───────────────────────────────────────────────────
    cmd = build_safe_command(tool, target)
    if cmd is None:
        status = "BLOCKED (invalid tool)"
        result = {
            "command":        "not executed",
            "unsafe_example": f"{tool} {target}",
            "output":         "Blocked — tool is not on the approved list.",
            "status":         status,
            "explanation":    "Only ping, nslookup, and hostname are allowed.",
            "remediation":    remediation_for(status),
            "snippets":       snippets_for(tool),
        }
        print("Status :", result["status"])
        return result

    # ── Run the approved command ────────────────────────────────────────────
    try:
        code, output = run_safe_command(cmd)
        status = "PASS" if code == 0 else "RAN (non-zero exit)"
        result = {
            "command":        " ".join(cmd),
            "unsafe_example": None,
            "output":         output,
            "status":         status,
            "explanation": (
                f"Secure execution: input was validated, then subprocess ran "
                f"{cmd} with shell=False and a {TIMEOUT_SECONDS}s timeout. "
                "The host is a separate argument — shell operators cannot chain a second command."
            ),
            "remediation": remediation_for(status),
            "snippets":    snippets_for(tool),
        }

    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
        result = {
            "command":        " ".join(cmd),
            "unsafe_example": None,
            "output":         f"Stopped after {TIMEOUT_SECONDS} s (timeout).",
            "status":         status,
            "explanation":    "The command exceeded the time limit and was stopped automatically.",
            "remediation":    remediation_for(status),
            "snippets":       snippets_for(tool),
        }

    except OSError as err:
        status = "ERROR"
        result = {
            "command":        " ".join(cmd),
            "unsafe_example": None,
            "output":         f"Could not start command: {err}",
            "status":         status,
            "explanation":    "Windows could not find ping or nslookup. Check that the tool exists on PATH.",
            "remediation":    remediation_for(status),
            "snippets":       snippets_for(tool),
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
    result   = None
    selected = TEST_CASES[0]["id"]

    if request.method == "POST":
        selected = request.form.get("case_id", "")
        case     = find_case(selected)
        if case:
            result = assess(case)
        else:
            result = {
                "command":        "not executed",
                "unsafe_example": None,
                "output":         "Unknown test case.",
                "status":         "ERROR",
                "explanation":    "Pick a test from the list. Free-typed commands are not accepted.",
                "remediation":    REMEDIATIONS["ERROR"],
                "snippets":       CODE_SNIPPETS["ping"],
            }

    theme, icon = status_theme(result["status"]) if result else ("", "")
    return render_template(
        "index.html",
        cases    = TEST_CASES,
        selected = selected,
        result   = result,
        theme    = theme,
        icon     = icon,
    )


if __name__ == "__main__":
    print("Command Injection Vulnerability Assessment")
    print("Open http://127.0.0.1:5000")
    print("Safe tests run ping / nslookup. Injection patterns are not executed.")
    app.run(host="127.0.0.1", port=5001, debug=False)
