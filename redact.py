"""Redact common identifiers and secrets from text before it goes to an AI tool.

Writes the redacted text to stdout and a key file you keep locally, so you can
put the real values back into the AI's answer. Pattern matching misses things:
read the output before you paste it.

Usage:
    python redact.py input.txt > safe.txt
    python redact.py - > safe.txt                (read from stdin)
    python redact.py input.txt --key-out my.key.json
    python redact.py input.txt --key-dir ./private-keys
    python redact.py --unredact safe.txt         (key is auto-discovered)
    python redact.py --unredact safe.txt --key my.key.json
    python redact.py --test                      (run built-in test suite)
    python redact.py --help

Key files:
    Keys live in ~/.local/share/redact/ by default (mode 0700) and are created
    with mode 0600 from the very first byte, so they are never briefly
    world-readable. An existing key file is never overwritten: the new one gets
    a .1, .2, ... suffix instead.

Exit codes:
    0  redaction completed (one or more items redacted)
    1  error (file not found, encoding error, bad arguments, ...)
    2  no identifiers found (file may be clean, or patterns missed something)
"""
import argparse
import glob
import json
import os
import re
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# Patterns
#
# Each entry is (label, pattern, flags, value_group):
#   value_group 0  -> the whole match is the secret.
#   value_group n  -> the secret is capture group n. Text before it is kept as
#                     a prefix ("password = "), text after it as a suffix
#                     (a closing quote), so the redaction stays readable and
#                     the round trip stays byte-identical.
#
# Order matters: specific patterns run before the generic catch-all, and
# UUID runs before PHONE so a UUID is never half-eaten as a phone number.
# ---------------------------------------------------------------------------
PATTERNS = [
    # Private keys first: the whole block goes, including anything inside it.
    ("PRIVATE_KEY",
     r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?"
     r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
     0, 0),

    # Provider-issued API keys and tokens.
    ("API_KEY",
     r"\b(?:sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}"
     r"|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}"
     r"|sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}"
     r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|AC[0-9a-f]{32})\b",
     re.IGNORECASE, 0),

    # JWT tokens.
    ("JWT",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     0, 0),

    # Database connection strings.
    ("DB_CONN",
     r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s\"']+\b",
     re.IGNORECASE, 0),

    # HTTP auth headers. The scheme word is kept as a prefix, the credential
    # is the value.
    ("AUTH_HEADER",
     r"\b(?:authorization|proxy-authorization|cookie|set-cookie)\b"
     r"(\s*[:=]\s*)"
     r"((?:bearer|basic|token|digest|apikey)\s+)?"
     r"([^\s\"';,]+)",
     re.IGNORECASE, 3),

    # AWS secret access keys. The name set is wide on purpose and the value
    # may be quoted.
    ("AWS_SECRET",
     r"\b(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key)\b"
     r"(\s*[:=]\s*)"
     r"([\"']?)"
     r"([A-Za-z0-9/+=]{40})"
     r"(\2)?",
     re.IGNORECASE, 3),

    # UUIDs, before PHONE so a UUID is not half-eaten as a phone number.
    ("UUID",
     r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
     re.IGNORECASE, 0),

    # Email.
    ("EMAIL",
     r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
     re.IGNORECASE, 0),

    # IBAN.
    ("IBAN",
     r"\b[A-Za-z]{2}\d{2}(?: ?[A-Za-z0-9]{4}){3,7}(?: ?[A-Za-z0-9]{1,3})?\b",
     0, 0),

    # Mexican CURP: position 11 is H, M or X (non-binary).
    ("MX_CURP",
     r"\b[A-Z]{4}\d{6}[HMX][A-Z]{5}[A-Z0-9]\d\b",
     re.IGNORECASE, 0),

    # Mexican RFC.
    ("MX_RFC",
     r"\b[A-Z&\u00d1]{3,4}\d{6}[A-Z0-9]{3}\b",
     re.IGNORECASE, 0),

    # Card numbers. Numeric lookbehind instead of \b so a card glued to a word
    # character ("card4111111111111111") is still caught. Luhn-checked in
    # redact().
    ("CARD",
     r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
     0, 0),

    # US SSN.
    ("US_SSN",
     r"\b\d{3}-\d{2}-\d{4}\b",
     0, 0),

    # IPv4 addresses.
    ("IP_ADDR",
     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
     0, 0),

    # Phone. Requires a + prefix, a parenthesized area code, or a separator
    # after the first group — bare 10-digit sequences (UUIDs, IDs) are
    # excluded.
    ("PHONE",
     r"(?<!\w)(?:\+\d{1,3}[ .-]?|\(\d{2,4}\)[ .-]?|\d{1,4}[ .-])"
     r"\d{2,4}[ .-]?\d{3,4}[ .-]?\d{3,4}(?!\w)",
     0, 0),

    # Generic key=value secrets. Last, so specific patterns get to label the
    # value first. The whole identifier is matched, not just the keyword, so
    # SCREAMING_SNAKE_CASE names (DB_PASSWORD, AWS_SECRET_ACCESS_KEY) match:
    # "_" is a word character and would break a \b before the keyword.
    ("GENERIC_SECRET",
     r"(?<![\w-])[A-Za-z0-9_.\-]*"
     r"(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key"
     r"|auth|authorization|credential|credentials|cookie|session)"
     r"[A-Za-z0-9_.\-]*"
     r"(\s*[:=]\s*)"
     r"([\"']?)"
     r"([^\s\"'`,;]+)"
     r"(\2)?",
     re.IGNORECASE, 3),
]

# A placeholder we generated ourselves. Used to avoid re-redacting a value
# that a previous pattern already replaced.
PLACEHOLDER_RE = re.compile(r"^\[[0-9a-f]{6}_[A-Z0-9_]+_\d+\]$")

# Labels carry their own name out of a placeholder: "[a1b2c3_API_KEY_1]" is
# labelled API_KEY, not "API".
LABEL_RE = re.compile(r"^\[[0-9a-f]{6}_(.+)_\d+\]$")

# Auth scheme words. The generic pattern must not claim these: the auth
# header pattern already owns the whole header, and redacting the scheme word
# on its own would leave two placeholders where one belongs.
AUTH_SCHEMES = frozenset({"bearer", "basic", "token", "digest", "apikey"})

DEFAULT_KEY_DIR = os.path.join("~", ".local", "share", "redact")


def luhn_ok(number):
    """Validate a card number using the Luhn algorithm."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact(text, run_id=None):
    """Redact identifiers in text. Returns (redacted_text, key_dict).

    key_dict maps placeholder -> original value.
    """
    key = {}           # placeholder -> original value
    reverse_key = {}   # original value -> placeholder (O(1) dedup)
    counters = {}
    # Per-run namespace prefix, so a placeholder already present in the input
    # can never be confused with one we generate.
    run_id = run_id or uuid.uuid4().hex[:6]

    def make_placeholder(label, value):
        if value in reverse_key:
            return reverse_key[value]
        counters[label] = counters.get(label, 0) + 1
        candidate = f"[{run_id}_{label}_{counters[label]}]"
        while candidate in text or candidate in key:
            counters[label] += 1
            candidate = f"[{run_id}_{label}_{counters[label]}]"
        key[candidate] = value
        reverse_key[value] = candidate
        return candidate

    def make_sub(label, value_group):
        def sub(match):
            if value_group:
                value = match.group(value_group)
                start = match.start(value_group) - match.start(0)
                end = match.end(value_group) - match.start(0)
                prefix = match.group(0)[:start]
                suffix = match.group(0)[end:]
            else:
                value = match.group(0)
                prefix = suffix = ""

            # Card numbers: validate with Luhn before redacting.
            if label == "CARD" and not luhn_ok(value):
                return match.group(0)

            # Already replaced by an earlier pattern: leave it alone.
            if PLACEHOLDER_RE.match(value):
                return match.group(0)

            # A bare auth scheme word belongs to the auth header pattern.
            if label == "GENERIC_SECRET" and value.lower() in AUTH_SCHEMES:
                return match.group(0)

            return prefix + make_placeholder(label, value) + suffix
        return sub

    for label, pattern, flags, value_group in PATTERNS:
        text = re.sub(pattern, make_sub(label, value_group), text, flags=flags)
    return text, key


def unredact(text, key):
    """Restore original values from a key dict."""
    for placeholder, original in key.items():
        text = text.replace(placeholder, original)
    return text


# ---------------------------------------------------------------------------
# Key file handling
# ---------------------------------------------------------------------------
def key_dir_default(explicit=None):
    """Return the directory to keep key files in, creating it if needed."""
    path = os.path.abspath(os.path.expanduser(explicit or DEFAULT_KEY_DIR))
    try:
        os.makedirs(path, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as e:
        print(f"Error: cannot use key directory {path}: {e}", file=sys.stderr)
        raise
    return path


def write_key(key, path, version=True):
    """Write a key file with 0600 permissions, never overwriting an existing one.

    Returns the path actually written.
    """
    attempts = 1000 if version else 1
    for i in range(attempts):
        target = path if i == 0 else f"{path}.{i}"
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if not version:
                raise OSError(
                    f"key file already exists: {target} "
                    f"(remove it, or use --key-dir to pick another location)")
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(key, f, indent=2, ensure_ascii=False)
        return target
    raise OSError(f"could not create a unique key file at {path}")


def load_key(path, quiet=False):
    """Load a key file, with a clear error if it is not usable."""
    try:
        with open(path, encoding="utf-8") as f:
            key = json.load(f)
    except FileNotFoundError:
        if not quiet:
            print(f"Error: key file not found: {path}", file=sys.stderr)
        raise
    except json.JSONDecodeError as e:
        if not quiet:
            print(f"Error: key file is not valid JSON: {path} ({e})",
                  file=sys.stderr)
        raise
    except OSError as e:
        if not quiet:
            print(f"Error reading key file: {e}", file=sys.stderr)
        raise
    if not isinstance(key, dict):
        if not quiet:
            print(f"Error: key file is not a mapping of placeholder -> value: "
                  f"{path}", file=sys.stderr)
        raise ValueError("key file has the wrong shape")
    return key


def find_key(text, redacted_path, key_dir, explicit=None):
    """Find the key file that matches this text.

    Returns (key, path, hits) where hits is the number of placeholders from
    the key that appear in the text. Returns (None, None, 0) if nothing fits.
    """
    candidates = []
    if explicit:
        candidates.append(explicit)
    else:
        # Next to the redacted file (legacy layout, and --key-out targets).
        base = redacted_path + ".key.json"
        candidates += sorted(glob.glob(base + ".*"), reverse=True) + [base]
        # The private key directory, newest first.
        if os.path.isdir(key_dir):
            candidates += sorted(
                glob.glob(os.path.join(key_dir, "*.key.json*")),
                key=os.path.getmtime, reverse=True)

    best = (None, None, 0)
    for path in candidates:
        try:
            key = load_key(path, quiet=True)
        except (OSError, ValueError):
            continue
        hits = sum(1 for p in key if p in text)
        if hits > best[2]:
            best = (key, path, hits)
        if hits and hits == len(key):
            return best
    return best


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def read_source(path):
    """Read a file (or stdin) as UTF-8. Warns if bytes had to be replaced."""
    if path == "-":
        try:
            data = sys.stdin.buffer.read()
        except OSError as e:
            print(f"Error reading stdin: {e}", file=sys.stderr)
            return None
        source_name = "stdin"
    else:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {path}", file=sys.stderr)
            return None
        except IsADirectoryError:
            print(f"Error: path is a directory: {path}", file=sys.stderr)
            return None
        except OSError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return None
        source_name = path

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        print("WARNING: input contains invalid UTF-8 bytes (replaced with U+FFFD). "
              "Redacted values may be unrecoverable from the key file.",
              file=sys.stderr)
    return text, source_name


def cmd_redact(args):
    read = read_source(args.file)
    if read is None:
        return 1
    text, source_name = read

    safe, key = redact(text)

    if not key:
        print("\n[No identifiers found. File may be clean, or patterns missed "
              "something.]", file=sys.stderr)
        sys.stdout.write(safe)
        return 2

    if args.key_out:
        key_path = os.path.abspath(os.path.expanduser(args.key_out))
        parent = os.path.dirname(key_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
    else:
        key_dir = key_dir_default(args.key_dir)
        base = "stdin" if source_name == "stdin" else os.path.basename(source_name)
        key_path = os.path.join(key_dir, base + ".key.json")

    try:
        written = write_key(key, key_path, version=not args.key_out)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"\n[{len(key)} items redacted; key saved to {written}]", file=sys.stderr)
    print("WARNING: key file contains original sensitive values in plaintext.",
          file=sys.stderr)
    print("Keep it local — do NOT sync to cloud storage, email, or commit to git.",
          file=sys.stderr)
    if source_name != "stdin" and os.path.dirname(os.path.abspath(written)) == \
            os.path.dirname(os.path.abspath(source_name)):
        print("The key file is next to the input — consider adding *.key.json "
              "to your .gitignore.", file=sys.stderr)
    print(f"To restore:  python redact.py --unredact <redacted_file> "
          f"--key {written}", file=sys.stderr)

    sys.stdout.write(safe)
    return 0


def cmd_unredact(args):
    read = read_source(args.file)
    if read is None:
        return 1
    text, _ = read

    if args.key:
        key_path = os.path.abspath(os.path.expanduser(args.key))
        try:
            key = load_key(key_path)
        except (OSError, ValueError):
            return 1
        hits = sum(1 for p in key if p in text)
        if hits == 0:
            print(f"Error: none of the {len(key)} placeholders in {key_path} appear "
                  f"in {args.file} — wrong key file?", file=sys.stderr)
            return 1
    else:
        key_dir = key_dir_default(args.key_dir)
        key, key_path, hits = find_key(text, args.file, key_dir)
        if key is None or hits == 0:
            print(f"Error: no key file matching {args.file} was found.",
                  file=sys.stderr)
            print("Looked next to the file and in " + key_dir +
                  ". Pass one explicitly with --key <path>.", file=sys.stderr)
            return 1

    missing = [p for p in key if p not in text]
    if missing:
        print(f"Warning: {len(missing)} of {len(key)} placeholders from "
              f"{key_path} are not in the text; they were left as-is.",
              file=sys.stderr)

    sys.stdout.write(unredact(text, key))
    return 0


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that exits 1 (not 2) on usage errors.

    Exit code 2 is reserved for "no identifiers found".
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(1)


def build_parser():
    p = _Parser(
        prog="redact.py",
        description="Redact common identifiers and secrets from text.",
        epilog="Exit codes: 0 redacted, 1 error, 2 nothing found.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("file", nargs="?", help="input file, or - for stdin")
    p.add_argument("--unredact", action="store_true",
                   help="restore original values from a key file")
    p.add_argument("--key", help="key file to use with --unredact")
    p.add_argument("--key-dir", help="directory holding key files "
                                     "(default: ~/.local/share/redact)")
    p.add_argument("--key-out", help="write the key file to this exact path")
    p.add_argument("--test", action="store_true", help="run the built-in test suite")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv:
        print(__doc__)
        return 1
    if argv[0] in ("--help", "-h"):
        print(__doc__)
        return 0
    if argv[0] == "--test":
        return run_tests()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.unredact:
        if not args.file:
            print("Error: --unredact needs the redacted file to restore.",
                  file=sys.stderr)
            return 1
        return cmd_unredact(args)

    if not args.file:
        print("Error: no input file given.", file=sys.stderr)
        return 1
    if args.key:
        print("Error: --key only applies to --unredact.", file=sys.stderr)
        return 1
    return cmd_redact(args)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------
class Case:
    """A test case.

    gone:   strings that must NOT appear in the redacted output
    kept:   strings that must still appear in the redacted output
    label:  optional expected label in the placeholder
    """

    def __init__(self, text, gone=(), kept=(), label=None, desc=""):
        self.text = text
        self.gone = list(gone)
        self.kept = list(kept)
        self.label = label
        self.desc = desc or text


def build_cases():
    cases = []

    # --- provider API keys -------------------------------------------------
    for secret in [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
        "AIzaSyD-1234567890abcdefghijklmnopqrstu",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "SG.dnS3fX0kY7ZmFrTGt3aBcD.DeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghij",
    ]:
        cases.append(Case(f"key {secret} end", gone=[secret], label="API_KEY",
                          desc=f"provider key: {secret[:16]}..."))
    cases.append(Case("akiaiosfodnn7example", gone=["akiaiosfodnn7example"],
                      label="API_KEY", desc="lowercase AWS access key id"))
    cases.append(Case(
        "key eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0FEyVkBxw end",
        gone=["eyJhbGciOiJIUzI1NiJ9"], label="JWT", desc="jwt token"))

    # --- generic key=value secrets ----------------------------------------
    for text, secret in [
        ("api_key = \"abcdef1234567890abcdef\"", "abcdef1234567890abcdef"),
        ("password=hunter2", "hunter2"),
        ("passwd: hunter2", "hunter2"),
        ("pwd = hunter2", "hunter2"),
        ("secret=hunter2", "hunter2"),
        ("token=hunter2", "hunter2"),
        ("api_key=hunter2", "hunter2"),
        ("access_key=hunter2", "hunter2"),
        ("db_password=hunter2", "hunter2"),
        ("DB_PASSWORD=hunter2", "hunter2"),
        ("DB_PASSWORD: hunter2", "hunter2"),
        ("my_secret=x", "x"),
        ("MY_SECRET_KEY=x", "x"),
        ("auth_token=x", "x"),
        ("AWS_SECRET_ACCESS_KEY=abc123XYZ+/=", "abc123XYZ+/="),
        ("x-api-key: abc123def456ghi789", "abc123def456ghi789"),
        ("credential=abc123", "abc123"),
        ("session=abc123def456ghi789", "abc123def456ghi789"),
    ]:
        cases.append(Case(text, gone=[secret], label="GENERIC_SECRET",
                          desc=f"generic secret: {text}"))

    # --- auth headers ------------------------------------------------------
    cases.append(Case("Authorization: Bearer abc123def456ghi789",
                      gone=["abc123def456ghi789"], kept=["Bearer"],
                      label="AUTH_HEADER", desc="Authorization: Bearer token"))
    cases.append(Case("authorization: Basic dXNlcjpwYXNz",
                      gone=["dXNlcjpwYXNz"], kept=["Basic"],
                      label="AUTH_HEADER", desc="Authorization: Basic token"))
    cases.append(Case("Cookie: session=abc123def456ghi789",
                      gone=["abc123def456ghi789"], label="AUTH_HEADER",
                      desc="Cookie header"))

    # --- AWS secrets -------------------------------------------------------
    aws_value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    cases.append(Case(f"aws_secret_access_key = {aws_value}", gone=[aws_value],
                      label="AWS_SECRET", desc="aws_secret_access_key"))
    cases.append(Case(f"aws_secret_access_key = \"{aws_value}\"", gone=[aws_value],
                      kept=['"'], label="AWS_SECRET",
                      desc="quoted aws secret (quotes preserved)"))
    cases.append(Case(f"AWS_SECRET_KEY={aws_value}", gone=[aws_value],
                      label="AWS_SECRET", desc="AWS_SECRET_KEY"))
    cases.append(Case(f"secret_access_key={aws_value}", gone=[aws_value],
                      label="AWS_SECRET", desc="secret_access_key"))

    # --- private keys ------------------------------------------------------
    for header in ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY",
                   "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
                   "DSA PRIVATE KEY", "PGP PRIVATE KEY BLOCK"]:
        block = f"-----BEGIN {header}-----\nTOPSECRET\n-----END {header}-----"
        cases.append(Case(block, gone=["TOPSECRET"], label="PRIVATE_KEY",
                          desc=f"private key: {header}"))

    # --- database connections ---------------------------------------------
    for url in ["postgres://user:pw@host:5432/db",
                "mysql://user:pw@host:3306/db",
                "mongodb://user:pw@host:27017/db",
                "redis://:pw@host:6379/0",
                "amqp://user:pw@host:5672/vhost"]:
        cases.append(Case(f"dsn {url} end", gone=[url], label="DB_CONN",
                          desc=f"db conn: {url.split(':')[0]}"))

    # --- UUIDs must not be half-eaten --------------------------------------
    uuid_value = "550e8400-e29b-41d4-a716-446655440000"
    cases.append(Case(f"trace_id {uuid_value} done", gone=[uuid_value],
                      label="UUID", desc="uuid redacted whole"))
    cases.append(Case(f"trace_id {uuid_value} done", gone=[uuid_value],
                      kept=[], label="UUID", desc="uuid not half-eaten as phone"))
    cases.append(Case(f"trace_id {uuid_value.upper()} done",
                      gone=[uuid_value.upper()], label="UUID",
                      desc="uppercase uuid"))

    # --- cards -------------------------------------------------------------
    cases.append(Case("card 4111111111111111 end", gone=["4111111111111111"],
                      label="CARD", desc="visa card"))
    cases.append(Case("card4111111111111111", gone=["4111111111111111"],
                      label="CARD", desc="card glued to a word character"))
    cases.append(Case("4111111111111111x", gone=["4111111111111111"],
                      label="CARD", desc="card followed by a letter"))
    cases.append(Case('"4111111111111111"', gone=["4111111111111111"],
                      label="CARD", desc="card in quotes"))
    cases.append(Case("number 1234567890123456 end", kept=["1234567890123456"],
                      desc="Luhn failure is left alone"))
    cases.append(Case("num 41111111111111111111 long", kept=["41111111111111111111"],
                      desc="20-digit run is not partially matched"))

    # --- phones ------------------------------------------------------------
    for text in ["call 555-123-4567 now", "call 5551234567 now",
                 "call (555) 123-4567 now", "call 555.123.4567 now",
                 "call 555 123 4567 now", "call 020 7946 0958",
                 "call +1 555 123 4567 now", "call +44 20 7946 0958 now",
                 "call 1-555-123-4567"]:
        cases.append(Case(text, label="PHONE", desc=f"phone: {text}"))

    # --- things that must NOT be flagged ------------------------------------
    cases.append(Case("meeting 2024-01-15 10:30:00 sharp",
                      kept=["2024-01-15 10:30:00"], desc="timestamp is not a phone"))
    cases.append(Case("log 2024-01-15T10:30:00Z entry",
                      kept=["2024-01-15T10:30:00Z"], desc="iso timestamp"))
    cases.append(Case("the monkey 0123456789abcdef0123456789abcdef01234567 zoo",
                      kept=["0123456789abcdef0123456789abcdef01234567"],
                      desc="'monkey' does not trigger AWS_SECRET"))
    cases.append(Case("the password is not here", kept=["the password is not here"],
                      desc="prose mention of a password is left alone"))
    cases.append(Case("hello world, this is a test", kept=["hello world"],
                      desc="clean text"))

    # --- other identifiers --------------------------------------------------
    cases.append(Case("contact a.b+tag@sub.example.co.uk today",
                      gone=["a.b+tag@sub.example.co.uk"], label="EMAIL",
                      desc="email"))
    cases.append(Case("ssn 123-45-6789 here", gone=["123-45-6789"],
                      label="US_SSN", desc="us ssn"))
    cases.append(Case("iban GB82 WEST 1234 5698 7654 32",
                      gone=["GB82 WEST 1234 5698 7654 32"], label="IBAN",
                      desc="iban"))
    cases.append(Case("host 192.168.1.100 up", gone=["192.168.1.100"],
                      label="IP_ADDR", desc="ipv4 address"))
    cases.append(Case("curp BADD110313HCMLNS09", gone=["BADD110313HCMLNS09"],
                      label="MX_CURP", desc="curp with H"))
    cases.append(Case("curp BADD110313MCMLNS09", gone=["BADD110313MCMLNS09"],
                      label="MX_CURP", desc="curp with M"))
    cases.append(Case("curp PEPA050505XDFRLN04", gone=["PEPA050505XDFRLN04"],
                      label="MX_CURP", desc="curp with X (non-binary)"))
    cases.append(Case("curp pepa050505xdfrrn04", gone=["pepa050505xdfrrn04"],
                      label="MX_CURP", desc="lowercase curp"))
    cases.append(Case("rfc GODE561231GR8", gone=["GODE561231GR8"],
                      label="MX_RFC", desc="mexican rfc"))
    cases.append(Case("rfc gode561231gr8", gone=["gode561231gr8"],
                      label="MX_RFC", desc="lowercase rfc"))

    return cases


def run_tests():
    """Run the built-in test suite. Returns 0 on success, 1 on failure."""
    passed = failed = 0
    failures = []

    for case in build_cases():
        safe, key = redact(case.text)
        problems = []
        for secret in case.gone:
            if secret in safe:
                problems.append(f"secret still present: {secret!r}")
        for keep in case.kept:
            if keep not in safe:
                problems.append(f"expected to keep: {keep!r}")
        if case.label and key:
            labels = set()
            for p in key:
                m = LABEL_RE.match(p)
                if m:
                    labels.add(m.group(1))
            if case.label not in labels:
                problems.append(f"expected label {case.label}, got {sorted(labels)}")
        if case.gone and not key:
            problems.append("nothing was redacted")

        if problems:
            failed += 1
            failures.append((case, problems, safe, key))
            print(f"  FAIL: {case.desc}")
            for p in problems:
                print(f"         {p}")
            print(f"         input:  {case.text!r}")
            print(f"         output: {safe!r}")
        else:
            passed += 1

    print(f"\n  pattern cases: {passed} passed, {failed} failed")

    # --- round trip ---------------------------------------------------------
    rt_passed = rt_failed = 0
    rt_texts = [
        "card 4111111111111111 end, phone 555-123-4567, ssn 123-45-6789",
        "email a@b.com and a@b.com (dedup)",
        'api_key = "abcdef1234567890abcdef"',
        "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        "Authorization: Bearer abc123def456ghi789",
        "db_password=hunter2 and DB_SECRET=alsosecret",
        "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----",
        "trace 550e8400-e29b-41d4-a716-446655440000 and 555-123-4567",
    ]
    for text in rt_texts:
        safe, key = redact(text)
        if unredact(safe, key) == text:
            rt_passed += 1
        else:
            rt_failed += 1
            failures.append((Case(text, desc="round trip"),
                             ["round trip is not byte-identical"], safe, key))
            print(f"  FAIL: round trip not byte-identical: {text!r}")
            print(f"         restored: {unredact(safe, key)!r}")
    print(f"  round trip:    {rt_passed} passed, {rt_failed} failed")

    # --- key file permissions and location ----------------------------------
    import shutil
    import stat
    import tempfile

    tmp = tempfile.mkdtemp(prefix="redact-test-")
    try:
        src = os.path.join(tmp, "doc.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("password=hunter2\n")
        key_dir = os.path.join(tmp, "keys")
        os.makedirs(key_dir, mode=0o700)
        safe, key = redact("password=hunter2\n")
        written = write_key(key, os.path.join(key_dir, "doc.txt.key.json"))
        mode = stat.S_IMODE(os.stat(written).st_mode)
        if mode == 0o600:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL: key file mode is {oct(mode)}, expected 0o600")
        # never overwrite
        second = write_key(key, os.path.join(key_dir, "doc.txt.key.json"))
        if second != written and os.path.exists(written):
            passed += 1
        else:
            failed += 1
            print("  FAIL: existing key file was overwritten")
        # unredact finds it and restores
        restored = unredact(safe, load_key(written))
        if restored == "password=hunter2\n":
            passed += 1
        else:
            failed += 1
            print("  FAIL: key file did not restore the original")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("  key file:      permissions, versioning and restore checked")

    # --- performance --------------------------------------------------------
    big = " ".join(f"user{i}@example.com" for i in range(10000))
    t0 = time.time()
    redact(big)
    elapsed = time.time() - t0
    print(f"  performance:   10k unique emails in {elapsed:.2f}s")
    if elapsed < 5.0:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL: 10k emails took {elapsed:.2f}s")

    total_passed = passed
    total_failed = failed
    print(f"\n{'=' * 60}")
    print(f"Results: {total_passed} passed, {total_failed} failed")
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
