"""agent_guard.py: keep an AI agent's actions under control.

Wrap any function an agent can call (send an email, update a record, delete a
file) with @guard. Every call then passes through five checks:

  1. Kill switch: if the STOP file exists, nothing runs.
  2. Allow-list: tools not listed in POLICY are refused.
  3. Budget: an agent can take at most N actions per run.
  4. Approval: risky actions wait for a human yes/no.
  5. Audit log: every attempt, allowed or not, is written to a
     tamper-evident log (each line carries a hash of the line before).

It also checks Meta's "Agents Rule of Two" at startup: an agent that reads
untrusted input, touches private data AND can act externally is forced into
human approval for every write, external or destructive action.

Works with any agent framework, because it wraps the tool functions
themselves. Standard library only, Python 3.9+.

Run the demo:     python agent_guard.py demo
Verify the log:   python agent_guard.py verify agent_audit.jsonl
Stop all agents:  python agent_guard.py stop      (resume: python agent_guard.py resume)
"""
import contextlib
import functools
import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 1. Policy: edit this for each agent. Risk levels, lowest to highest:
#    read        looks at data, changes nothing
#    write       changes your own systems (update a record, create a draft)
#    external    leaves your company (send email, post, call an outside API)
#    destructive cannot be undone (delete, pay, change permissions)
# ---------------------------------------------------------------------------
POLICY = {
    "agent_name": "inbox-triage-agent",
    "owner": "ops-lead@example.com",
    "run_id": None,  # auto-generated per run; set explicitly to correlate
    # Rule of Two: answer honestly for this agent
    "reads_untrusted_input": True,    # inbound email, web pages, uploads
    "touches_private_data": True,     # CRM, finance, HR, source code
    "can_act_externally": True,       # sends, posts, pays, edits records
    "max_actions_per_run": 25,
    "require_approval_for": ["external", "destructive"],
    "tools": {
        "search_crm": "read",
        "draft_reply": "write",
        "send_email": "external",
        "delete_record": "destructive",
    },
}

AUDIT_LOG = os.environ.get("AGENT_AUDIT_LOG", "agent_audit.jsonl")
STOP_FILE = os.environ.get("AGENT_STOP_FILE", "AGENT_STOP")

# Values that should never be written to the audit log in clear text.
# Uses (?!\d) instead of \b to catch numbers glued to word characters.
SECRET_PATTERNS = [
    (re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,})\b"), "[KEY]"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}\d(?!\d)"), "[NUMBER]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
]

VALID_RISKS = {"read", "write", "external", "destructive"}

# ---------------------------------------------------------------------------
# Run-scoped state (thread-safe via lock)
# ---------------------------------------------------------------------------
_run_lock = threading.Lock()
_action_count = 0
_run_id = None


def reset_run(run_id=None):
    """Reset the action counter for a new agent run. Call before each invocation."""
    global _action_count, _run_id
    with _run_lock:
        _action_count = 0
        _run_id = run_id or POLICY.get("run_id") or _generate_run_id()


def _generate_run_id():
    import uuid
    return uuid.uuid4().hex[:8]


def _current_run_id():
    global _run_id
    if _run_id is None:
        reset_run()
    return _run_id


# ---------------------------------------------------------------------------
# Policy validation (fail fast at startup)
# ---------------------------------------------------------------------------
def validate_policy(policy=POLICY):
    """Validate POLICY. Raises ValueError on misconfiguration."""
    if not isinstance(policy.get("max_actions_per_run"), int) or policy["max_actions_per_run"] <= 0:
        raise ValueError("max_actions_per_run must be a positive integer")
    for tool, risk in policy.get("tools", {}).items():
        if risk not in VALID_RISKS:
            raise ValueError(f"Invalid risk level '{risk}' for tool '{tool}'. "
                             f"Must be one of: {sorted(VALID_RISKS)}")
    for r in policy.get("require_approval_for", []):
        if r not in VALID_RISKS:
            raise ValueError(f"Invalid risk level in require_approval_for: '{r}'")
    for key in ("reads_untrusted_input", "touches_private_data", "can_act_externally"):
        if not isinstance(policy.get(key), bool):
            raise ValueError(f"{key} must be a boolean")


# ---------------------------------------------------------------------------
# Audit log with a hash chain: editing or deleting any line breaks the chain
# ---------------------------------------------------------------------------
def _last_hash(path):
    if not os.path.exists(path):
        return "0" * 64
    last = None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
    except (OSError, IOError):
        return "0" * 64
    if last is None:
        return "0" * 64
    try:
        return json.loads(last)["hash"]
    except (json.JSONDecodeError, KeyError):
        return "0" * 64


def _mask(value):
    text = json.dumps(value, ensure_ascii=False, default=str)
    for pattern, label in SECRET_PATTERNS:
        text = pattern.sub(label, text)
    if len(text) > 500:
        text = text[:500] + "...[truncated]"
    return text


def _write_audit_locked(entry, path):
    """Write an audit entry with file locking (Unix) or best-effort (Windows)."""
    # Acquire lock
    lock_path = path + ".lock"
    lock_fd = None
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        if sys.platform != "win32":
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # Write entry
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    finally:
        if lock_fd is not None:
            if sys.platform != "win32":
                import fcntl
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def write_audit(entry, path=AUDIT_LOG):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "run_id": _current_run_id(),
        **entry,
        "prev_hash": _last_hash(path),
    }
    body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    _write_audit_locked(entry, path)


def verify_audit(path=AUDIT_LOG):
    """Return (ok, message). Detects edited, inserted or deleted lines."""
    if not os.path.exists(path):
        return False, "Audit log not found."
    prev = "0" * 64
    line_count = 0
    try:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                line_count += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"Line {n} is not valid JSON."
                if "hash" not in entry:
                    return False, f"Line {n} is missing a hash."
                claimed = entry.pop("hash")
                if entry.get("prev_hash") != prev:
                    return False, f"Chain broken at line {n}: a line before it was changed or removed."
                body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                if hashlib.sha256(body.encode("utf-8")).hexdigest() != claimed:
                    return False, f"Line {n} was edited after it was written."
                prev = claimed
    except (OSError, IOError) as e:
        return False, f"Cannot read audit log: {e}"
    if line_count == 0:
        return True, "Audit log is empty."
    return True, f"Audit log intact ({line_count} entries)."


# ---------------------------------------------------------------------------
# Approval: console by default. Swap in Slack, Teams or email for real use.
# ---------------------------------------------------------------------------
def console_approval(agent, tool, risk, args, timeout=300):
    print(f"\n[APPROVAL NEEDED] {agent} wants to run '{tool}' (risk: {risk})")
    print(f"  with: {_mask(args)}")
    try:
        import select
        # Unix: use select for timeout
        if sys.platform != "win32":
            print(f"  Allow? [y/N] (timeout: {timeout}s) ", end="", flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                print("\n  Timed out — denied.")
                return False
            answer = sys.stdin.readline().strip().lower()
            return answer == "y"
        else:
            # Windows: no select on stdin; block with no timeout
            print(f"  Allow? [y/N] ")
            answer = input().strip().lower()
            return answer == "y"
    except (KeyboardInterrupt, EOFError):
        print("\n  Interrupted — denied.")
        return False


APPROVER = console_approval


# ---------------------------------------------------------------------------
# Rule of Two check
# ---------------------------------------------------------------------------
def rule_of_two_status(policy=POLICY):
    flags = [policy["reads_untrusted_input"], policy["touches_private_data"],
             policy["can_act_externally"]]
    violated = all(flags)
    if violated:
        return (True, "This agent breaks the Rule of Two. Every write, external "
                "or destructive action will need human approval.")
    return (False, f"{sum(flags)} of 3 risk properties. Within the Rule of Two.")


def _needs_approval(risk, policy=POLICY):
    if risk in policy["require_approval_for"]:
        return True
    violated, _ = rule_of_two_status(policy)
    return violated and risk in ("write", "external", "destructive")


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------
def guard(func):
    """Decorate every tool function the agent is allowed to call."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        global _action_count
        agent, tool = POLICY["agent_name"], func.__name__
        risk = POLICY["tools"].get(tool)
        call = {"args": list(args), "kwargs": kwargs}
        base = {"agent": agent, "tool": tool, "risk": risk, "input": _mask(call)}

        def refuse(reason):
            # Best-effort audit on block path
            try:
                write_audit({**base, "decision": "blocked", "reason": reason})
            except Exception:
                pass
            raise ActionBlocked(f"{tool}: {reason}")

        if os.path.exists(STOP_FILE):
            refuse("kill switch is on")
        if risk is None:
            refuse("tool is not on the allow-list")

        with _run_lock:
            if _action_count >= POLICY["max_actions_per_run"]:
                refuse(f"action budget of {POLICY['max_actions_per_run']} used up")

        approved_by = None
        if _needs_approval(risk):
            try:
                if not APPROVER(agent, tool, risk, call):
                    refuse("human approver said no")
            except (KeyboardInterrupt, EOFError):
                refuse("approval interrupted")
            approved_by = POLICY["owner"]

        # Pre-execution audit entry (fail-closed: if we can't log, don't run)
        try:
            write_audit({**base, "decision": "allowed", "approved_by": approved_by,
                         "outcome": "pending"})
        except Exception as e:
            raise ActionBlocked(f"{tool}: audit log unavailable: {e}")

        with _run_lock:
            _action_count += 1

        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            write_audit({**base, "decision": "allowed", "approved_by": approved_by,
                         "outcome": f"error: {exc}"})
            raise
        write_audit({**base, "decision": "allowed", "approved_by": approved_by,
                     "outcome": "ok", "output": _mask(result)})
        return result
    return wrapper


# ---------------------------------------------------------------------------
# Demo: fake tools standing in for real integrations
# ---------------------------------------------------------------------------
@guard
def search_crm(query):
    return [{"client": "Acme MX", "status": "renewal due"}]


@guard
def draft_reply(to, body):
    return {"draft_id": "d-101", "to": to}


@guard
def send_email(to, body):
    return {"sent": True, "to": to}


@guard
def delete_record(record_id):
    return {"deleted": record_id}


@guard
def export_all_contacts():  # deliberately NOT in the allow-list
    return "all contacts"


def demo():
    reset_run()
    print("Rule of Two:", *rule_of_two_status())
    steps = [
        ("search_crm", lambda: search_crm("renewals this month")),
        ("draft_reply", lambda: draft_reply("client@acme.mx", "Hi, your renewal...")),
        ("send_email", lambda: send_email("client@acme.mx", "Hi, your renewal...")),
        ("export_all_contacts", lambda: export_all_contacts()),
        ("delete_record", lambda: delete_record("crm-889")),
    ]
    for name, step in steps:
        try:
            print(f"{name}: allowed ->", step())
        except ActionBlocked as e:
            print(f"{name}: BLOCKED ->", e)
    print("\n" + verify_audit()[1], f"See {AUDIT_LOG}.")


if __name__ == "__main__":
    # Validate policy before doing anything
    try:
        validate_policy()
    except ValueError as e:
        print(f"Policy error: {e}", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "demo":
        demo()
    elif cmd == "verify":
        ok, msg = verify_audit(sys.argv[2] if len(sys.argv) > 2 else AUDIT_LOG)
        print(msg)
        sys.exit(0 if ok else 1)
    elif cmd == "stop":
        open(STOP_FILE, "w").close()
        print(f"Kill switch ON. Remove '{STOP_FILE}' or run 'resume' to allow actions again.")
    elif cmd == "resume":
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)
        print("Kill switch OFF.")
    else:
        print(__doc__)
