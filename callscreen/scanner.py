import base64
import re
import unicodedata

# Tool output is data, not instructions. The old list was a handful of
# exact phrases, so the pentest bypassed it with paraphrases, a
# punctuation split, a zero-width character, a space-split, and a
# base64 blob — all of which a model can still understand. The fix is
# not a bigger exact-phrase list alone: scan the original text, a
# normalised copy (unicode-normalised, zero-width removed, punctuation
# stripped, leetspeak folded), and a space-squashed copy, plus decode
# base64 tokens and scan those. A regex list is still not a semantic
# classifier — that is the documented roadmap item, not a claim that
# this is unbreakable — but the easy paraphrase / obfuscation bypasses
# are closed.
INJECTION_PATTERNS = [
    r"ignore (all |previous |prior )?instructions",
    r"disregard (the )?(system|previous|prior) (prompt|instructions)",
    r"you are now (a|an|in)",
    r"send (the )?(api keys?|secrets?|passwords?) to",
    r"exfiltrate",
    r"override (the )?(system|previous) (prompt|instructions)",
    # Pentest additions: paraphrases and gaslighting shapes.
    r"forget (your )?(previous|earlier|prior) (instructions|directions|guidance)",
    r"reveal (your )?(system )?(prompt|instructions|directions)",
    r"print (your )?(system )?(prompt|instructions)",
    r"show (me )?(your )?(system )?(prompt|instructions)",
    r"ignore (the )?(above|previous|prior)",
    r"disregard (all )?(prior|previous|past) (guidance|directions|instructions|prompt)",
    r"you are now free",
    # V2 FP fix: bare "from now on" blocked benign reports ("From now
    # on, we will publish weekly"). Require an instruction verb after it.
    r"from now on (act|ignore|disregard|forget|follow|do)",
    r"new (system|developer) (message|instruction)",
    r"act as (an? )?(unrestricted|admin|root|system)",
    r"override (your )?(instructions|guidance)",
]

# Squashed (all whitespace removed) forms of the same ideas, so a
# space-split letter attack cannot hide the phrase.
SQUASHED_PHRASES = [
    "ignorepreviousinstructions", "ignoreallinstructions",
    "disregardsystemprompt", "forgetearlierdirections",
    "revealsystemprompt", "ignoreabove",
]

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+"), "api_key=[REDACTED]"),
    # Pentest additions: the token families the old list missed.
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"gho_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED_JWT]"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), "password=[REDACTED]"),
    (re.compile(r"(?i)(secret|token)\s*[:=]\s*\S+"), "secret=[REDACTED]"),
]

PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b\d{3}[ ]\d{2}[ ]\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b"), "[REDACTED_CARD]"),
]

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u00ad"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _normalise(text: str) -> str:
    """Normalised copy for injection matching only (output is unchanged)."""
    t = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    t = t.lower().translate(_LEET)
    t = re.sub(r"[^a-z0-9 ]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _is_injection(text: str) -> str | None:
    """Return the matching pattern, or None. Checks original, normalised,
    squashed, and any base64-decoded blob inside the text."""
    for pat in INJECTION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    norm = _normalise(text)
    for pat in INJECTION_PATTERNS:
        if re.search(pat, norm):
            return pat
    squashed = norm.replace(" ", "")
    for phrase in SQUASHED_PHRASES:
        if phrase in squashed:
            return phrase
    # Base64: decode printable blobs and scan them once (not recursively,
    # so a nested blob cannot loop this forever).
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        try:
            decoded = base64.b64decode(token, validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if not decoded.isprintable():
            continue
        for pat in INJECTION_PATTERNS:
            if re.search(pat, decoded, re.IGNORECASE):
                return f"base64:{pat}"
    return None


def scan_output(text: str):
    """Return (blocked, redacted_text, reasons).

    Injection -> blocked. Secrets/PII -> redacted, still allowed, so the
    agent gets useful data without the sensitive value.
    """
    reasons = []
    hit = _is_injection(text)
    if hit:
        reasons.append(f"indirect_injection:{hit}")
        return True, "[BLOCKED: tool output contained an instruction override]", reasons
    redacted = text
    for regex, repl in SECRET_PATTERNS + PII_PATTERNS:
        if regex.search(redacted):
            reasons.append(f"redacted:{regex.pattern[:30]}")
            redacted = regex.sub(repl, redacted)
    return False, redacted, reasons
