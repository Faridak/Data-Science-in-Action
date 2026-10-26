"""Pre-screen a document for signs of hidden prompt injection before giving it to an AI tool.

This is a tripwire, not a shield: a clean result does NOT mean the file is safe.

Supported input: plain text, HTML, Markdown. PDFs, DOCX, and images must be
extracted to text first (e.g., pdftotext, python-docx, or an OCR tool).

Usage:
    python injection_check.py suspicious_file.html
    python injection_check.py --help

Exit codes:
    0  no CRITICAL findings
    2  one or more CRITICAL findings (gate-able in CI)
"""
import base64
import binascii
import html as html_mod
import re
import sys
import unicodedata

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# ---------------------------------------------------------------------------
# Invisible characters often used to hide text from human readers
# ---------------------------------------------------------------------------
# Severity: HIGH for truly invisible chars, LOW for typographic ones
HIDDEN_CHARS = {
    "\u200b": ("zero-width space", HIGH),
    "\u200c": ("zero-width non-joiner", MEDIUM),
    "\u200d": ("zero-width joiner", MEDIUM),
    "\u2060": ("word joiner", MEDIUM),
    "\ufeff": ("zero-width no-break space (BOM)", MEDIUM),
    "\u202e": ("right-to-left override", HIGH),
    "\u202d": ("left-to-right override", HIGH),
    "\u202a": ("left-to-right embedding", HIGH),
    "\u202b": ("right-to-left embedding", HIGH),
    "\u202c": ("pop directional formatting", HIGH),
    "\u00ad": ("soft hyphen", LOW),
    "\u00a0": ("non-breaking space", LOW),
    "\u202f": ("narrow no-break space", LOW),
    "\u200e": ("left-to-right mark", MEDIUM),
    "\u200f": ("right-to-left mark", MEDIUM),
    "\u2061": ("function application", MEDIUM),
    "\u2062": ("invisible times", MEDIUM),
    "\u2063": ("invisible separator", MEDIUM),
    "\u2064": ("invisible plus", MEDIUM),
}

# Unicode tag characters (U+E0000–U+E007F) — invisible letters
TAG_BLOCK = re.compile("[\U000E0000-\U000E007F]")

# Common homoglyphs: characters that look like ASCII but aren't.
# Each maps to (ascii_equiv, script). Severity is HIGH only when the
# surrounding text contains >= 20 ASCII letters (Latin-script context).
HOMOGLYPHS = {
    "\u0430": ("a", "Cyrillic"),   # а
    "\u0435": ("e", "Cyrillic"),   # е
    "\u043e": ("o", "Cyrillic"),   # о
    "\u0440": ("p", "Cyrillic"),   # р
    "\u0441": ("c", "Cyrillic"),   # с
    "\u0445": ("x", "Cyrillic"),   # х
    "\u0456": ("i", "Cyrillic"),   # і
    "\u03b1": ("a", "Greek"),      # α
    "\u03bf": ("o", "Greek"),      # ο
    "\u03c1": ("p", "Greek"),      # ρ
    "\u03b5": ("e", "Greek"),      # ε
    "\u0501": ("d", "Cyrillic"),   # ԁ
    "\u0261": ("g", "Latin"),      # ɡ
    "\uff41": ("a", "fullwidth"),  # ａ
    "\uff45": ("e", "fullwidth"),  # ｅ
    "\uff4f": ("o", "fullwidth"),  # ｏ
    "\uff50": ("p", "fullwidth"),  # ｐ
    "\u0251": ("a", "script"),     # ɑ
    "\u0391": ("A", "Greek"),      # Α
    "\u0392": ("B", "Greek"),      # Β
    "\u0395": ("E", "Greek"),      # Ε
    "\u0396": ("Z", "Greek"),      # Ζ
    "\u0397": ("H", "Greek"),      # Η
    "\u0399": ("I", "Greek"),      # Ι
    "\u039a": ("K", "Greek"),      # Κ
    "\u039c": ("M", "Greek"),      # Μ
    "\u039d": ("N", "Greek"),      # Ν
    "\u039f": ("O", "Greek"),      # Ο
    "\u03a1": ("P", "Greek"),      # Ρ
    "\u03a4": ("T", "Greek"),      # Τ
    "\u03a7": ("X", "Greek"),      # Χ
}

# Phrases that address the AI instead of the human reader
INSTRUCTION_PHRASES = re.compile(
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions"
    r"|disregard\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)"
    r"|forget\s+(everything|all|your)\s+(above|previous|prior)"
    r"|new\s+instructions?\s*:"
    r"|override\s+(your|all|previous)\s+(instructions|rules|guidelines)"
    r"|you\s+are\s+now\b"
    r"|from\s+now\s+on\b"
    r"|act\s+as\s+(if|a|an)\b"
    r"|pretend\s+(you|to\s+be)\b"
    r"|system\s*prompt\b"
    r"|do\s+not\s+tell\s+the\s+user\b"
    r"|assistant\s*[:,]"
    r"|send\s+(this|the|all|these)\s+.{0,40}\s+to\b"
    r"|forward\s+.{0,40}\s+to\b"
    r"|include\s+.{0,30}(link|url|image|attachment)\b"
    r"|reveal\s+(your|the)\s+(system|hidden|secret)\s+(prompt|instructions)\b",
    re.IGNORECASE | re.DOTALL,
)

# Styling tricks that hide text in HTML or exported documents
# Note: opacity: 0.5 and font-size: 0.9rem are NOT hiding (zero only counts
# when it is not the start of a larger number like 0.5 or 0.9).
HIDING_STYLES = re.compile(
    r"display\s*:\s*none\b"
    r"|visibility\s*:\s*hidden\b"
    r"|font-size\s*:\s*0(?![\d.])(px|pt|em|rem|%|vh|vw)?\b"
    r"|color\s*:\s*(#fff(f{3})?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)"
    r"|opacity\s*:\s*0(?![\d.])(px|pt|%)?\b"
    r"|position\s*:\s*absolute\b.{0,60}(left|top)\s*:\s*-\d{3,}"
    r"|text-indent\s*:\s*-\d{3,}"
    r"|transform\s*:\s*scale\(\s*0(\.\d+)?\s*\)"
    r"|height\s*:\s*0(px)?\b.{0,40}overflow\s*:\s*hidden"
    r"|width\s*:\s*0(px)?\b.{0,40}overflow\s*:\s*hidden"
    r"|clip\s*:\s*rect\(\s*0"
    r"|overflow\s*:\s*hidden\b.{0,40}(height|width)\s*:\s*0",
    re.IGNORECASE | re.DOTALL,
)

# HTML comments and attribute-based hiding
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
HIDDEN_ATTRS = re.compile(
    r"(title|alt|data-[a-z-]+)\s*=\s*[\"'][^\"']{20,}[\"']",
    re.IGNORECASE,
)

# The regex threshold is deliberately lower than the real minimum because
# the quantifier counts only non-padding characters. A 40-char token with
# == padding has only 38 matching chars. The len() guard below is the
# real minimum (including padding).
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{28,}={0,2}")


# ---------------------------------------------------------------------------
# Normalization pass — defeats common obfuscation techniques
# ---------------------------------------------------------------------------
def normalize(text):
    """Return a normalized copy of text that defeats common obfuscation.

    Techniques defeated:
    1. Zero-width character insertion (breaks keyword matching)
    2. HTML entity encoding (&#105;gn&#111;re -> ignore)
    3. Unicode compatibility characters (NFKC normalization)
    4. NFKC-resistant homoglyphs (replaced with ASCII equivalents)
    """
    # 1. Decode HTML entities
    normalized = html_mod.unescape(text)
    # 2. NFKC normalization
    normalized = unicodedata.normalize("NFKC", normalized)
    # 3. Replace homoglyphs with ASCII equivalents
    for ch, (ascii_equiv, _) in HOMOGLYPHS.items():
        normalized = normalized.replace(ch, ascii_equiv)
    # 4. Strip zero-width and invisible characters
    for ch in HIDDEN_CHARS:
        normalized = normalized.replace(ch, "")
    # 5. Strip Unicode tag characters
    normalized = TAG_BLOCK.sub("", normalized)
    # 6. Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def scan(text):
    """Scan text and return a list of (severity, finding) tuples."""
    findings = []
    seen_phrases = set()

    def add(severity, msg, phrase=None):
        if phrase is not None and phrase in seen_phrases:
            return
        if phrase is not None:
            seen_phrases.add(phrase)
        findings.append((severity, msg))

    # ------------------------------------------------------------------
    # 1. Scan ORIGINAL text
    # ------------------------------------------------------------------
    # 1a. Invisible characters (severity varies by char type)
    for ch, (name, sev) in HIDDEN_CHARS.items():
        count = text.count(ch)
        if count:
            add(sev, f"{count} x {name} (U+{ord(ch):04X})")

    # 1b. Unicode tag block characters
    tags = TAG_BLOCK.findall(text)
    if tags:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in tags)
        add(HIGH, f"invisible tag text decodes to: {hidden[:120]!r}")

    # 1c. Homoglyphs — HIGH only in Latin-script context (>= 20 ASCII letters)
    ascii_letter_count = sum(1 for c in text if c.isascii() and c.isalpha())
    homoglyph_hits = []
    for ch, (ascii_equiv, script) in HOMOGLYPHS.items():
        if ch in text:
            homoglyph_hits.append(f"{ascii_equiv} ({script}) (U+{ord(ch):04X})")
    if homoglyph_hits:
        sev = HIGH if ascii_letter_count >= 20 else MEDIUM
        add(sev, f"homoglyph characters found: {', '.join(homoglyph_hits)}")

    # 1d. Instruction-like phrases (original text)
    for m in INSTRUCTION_PHRASES.finditer(text):
        add(CRITICAL, f"instruction-like phrase: {m.group(0)!r}", phrase=m.group(0))

    # 1e. Hiding styles
    for m in HIDING_STYLES.finditer(text):
        add(MEDIUM, f"hiding style: {m.group(0)!r}")

    # 1f. HTML comments
    for m in HTML_COMMENT.finditer(text):
        comment_text = m.group(0)
        if len(comment_text) > 40:
            add(MEDIUM, f"long HTML comment ({len(comment_text)} chars): {comment_text[:80]!r}")

    # 1g. Suspiciously long attribute values
    for m in HIDDEN_ATTRS.finditer(text):
        add(MEDIUM, f"long attribute value: {m.group(0)[:80]!r}")

    # 1h. Base64 detection + decode-rescan
    for m in BASE64_PATTERN.finditer(text):
        token = m.group(0)
        # The regex threshold is deliberately lower; this guard is the real
        # minimum (it counts padding, which the regex does not).
        if len(token) < 40:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            add(LOW, f"unparseable base64-looking blob ({len(token)} chars) — treat as suspicious")
            continue
        # Scan decoded content for instruction phrases
        found_in_decoded = False
        for pm in INSTRUCTION_PHRASES.finditer(decoded):
            add(CRITICAL, f"instruction phrase found inside decoded base64: {pm.group(0)!r}",
                phrase=pm.group(0))
            found_in_decoded = True
        if not found_in_decoded:
            if not re.fullmatch(r"[\x20-\x7e\n\t\r]+", decoded or ""):
                add(MEDIUM, f"base64 decodes to non-text data ({len(decoded or '')} bytes)")
            else:
                add(LOW, f"base64 payload ({len(token)} chars) decodes to readable text — review manually")

    # ------------------------------------------------------------------
    # 2. Specific obfuscation passes (run BEFORE normalized catch-all
    #    so attribution labels fire first)
    # ------------------------------------------------------------------

    # 2a. Zero-width character removal
    had_hidden_chars = any(ch in text for ch in HIDDEN_CHARS)
    if had_hidden_chars:
        stripped = text
        for ch in HIDDEN_CHARS:
            stripped = stripped.replace(ch, "")
        for m in INSTRUCTION_PHRASES.finditer(stripped):
            phrase = m.group(0)
            if phrase not in seen_phrases:
                add(CRITICAL, f"instruction phrase hidden by zero-width characters: {phrase!r}",
                    phrase=phrase)

    # 2b. HTML entity decoding
    decoded = html_mod.unescape(text)
    if decoded != text:
        for m in INSTRUCTION_PHRASES.finditer(decoded):
            phrase = m.group(0)
            if phrase not in seen_phrases:
                add(CRITICAL, f"instruction phrase hidden via HTML entities: {phrase!r}",
                    phrase=phrase)

    # 2c. Homoglyph replacement
    homoglyph_replaced = text
    for ch, (ascii_equiv, _) in HOMOGLYPHS.items():
        homoglyph_replaced = homoglyph_replaced.replace(ch, ascii_equiv)
    if homoglyph_replaced != text:
        for m in INSTRUCTION_PHRASES.finditer(homoglyph_replaced):
            phrase = m.group(0)
            if phrase not in seen_phrases:
                add(CRITICAL, f"instruction phrase hidden via homoglyphs: {phrase!r}",
                    phrase=phrase)

    # ------------------------------------------------------------------
    # 3. Normalized catch-all (catches anything the specific passes missed)
    # ------------------------------------------------------------------
    normalized = normalize(text)
    for m in INSTRUCTION_PHRASES.finditer(normalized):
        phrase = m.group(0)
        if phrase not in seen_phrases:
            add(CRITICAL, f"hidden instruction revealed after normalization: {phrase!r}",
                phrase=phrase)

    return findings


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    filepath = sys.argv[1]
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: path is a directory: {filepath}", file=sys.stderr)
        sys.exit(1)

    results = scan(text)

    if results:
        results.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 99))

        print("REVIEW BEFORE USING WITH AI:")
        current_severity = None
        for severity, msg in results:
            if severity != current_severity:
                current_severity = severity
                print(f"\n  [{severity}]")
            print(f"   - {msg}")

        critical_count = sum(1 for s, _ in results if s == CRITICAL)
        high_count = sum(1 for s, _ in results if s == HIGH)
        medium_count = sum(1 for s, _ in results if s == MEDIUM)
        low_count = sum(1 for s, _ in results if s == LOW)
        print(f"\n{len(results)} finding(s): {critical_count} critical, {high_count} high, "
              f"{medium_count} medium, {low_count} low.")
        print("Investigate before passing this file to an AI tool.")
    else:
        print("No obvious signs found. This does not prove the file is safe.")

    # Exit code for CI gating: 2 = CRITICAL found, 0 = clean or non-critical only
    sys.exit(2 if any(s == CRITICAL for s, _ in results) else 0)


if __name__ == "__main__":
    main()
