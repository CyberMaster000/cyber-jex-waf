"""Deterministic high-confidence attack signatures.

The transformer classifier is good at ranking suspicious traffic, but a
supervised model alone is not a safe blocker: small benign variations can be
scored highly, and novel payloads can slip through.  These rules provide a
high-confidence layer that only fires on well-known exploit syntax.  They are
intentionally narrow so that normal application traffic (JSON, SOAP, GraphQL,
multipart uploads, JWTs, apostrophes in search terms, "C++", etc.) is not
flagged unless it also contains explicit exploit syntax.

Rules are evaluated on a URL-decoded (up to two passes) and lower-cased
representation of the request.  Returned rule names are safe to expose in the
detection response and dashboard.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import xml.etree.ElementTree as ET

__all__ = [
    "canonicalize",
    "detect_attack_rules",
    "is_structurally_benign",
    "RULES",
]


def canonicalize(text: str, passes: int = 2) -> str:
    """Percent-decode text repeatedly so encoded payloads are inspected."""
    if not text:
        return text
    current = text
    for _ in range(passes):
        try:
            decoded = urllib.parse.unquote_plus(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
    return current


# name -> compiled regex.  Keep these narrow and tied to exploit syntax.
RULES: dict[str, re.Pattern[str]] = {
    # Log4Shell / JNDI lookup (including nested ${lower:j}ndi: obfuscation)
    "log4shell": re.compile(r"\$\{.{0,120}?j[^:]{0,12}ndi\s*:", re.DOTALL),
    # SQL injection
    "sqli_union": re.compile(
        r"\bunion\b(?:\s+(?:all|distinct))?[\s/*+!0-9-]{0,24}\bselect\b"
    ),
    "sqli_boolean": re.compile(
        r"(?:'\s*(?:or|and)\s*'?[0-9a-z_]+'?\s*=\s*'?[0-9a-z_]+)"
        r"|(?:\b(?:or|and)\b\s+[0-9]+\s*=\s*[0-9]+)"
    ),
    "sqli_stacked": re.compile(
        r";\s*(?:drop|insert|update|delete|truncate|alter|create)\b"
    ),
    "sqli_time": re.compile(
        r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*['\"]?\d+"
        r"|\bwaitfor\s+delay\s+['\"]?\d"
    ),
    "sqli_schema": re.compile(
        r"\b(?:information_schema|xp_cmdshell|load_file|into\s+(?:out|dump)file)\b"
    ),
    "sqli_comment_quote": re.compile(r"'\s*(?:--|#|/\*)"),
    "sqli_version_comment": re.compile(
        r"/\*!\s*[0-9]*\s*(?:union|select|insert|update|delete|drop)"
    ),
    # Cross-site scripting
    "xss_script_tag": re.compile(r"<\s*/?\s*script\b"),
    "xss_event_handler": re.compile(
        r"\bon(?:error|load|mouseover|focus|click|submit|toggle|begin)\s*="
    ),
    "xss_js_uri": re.compile(r"\bjavascript\s*:"),
    "xss_dom_sink": re.compile(
        r"\bdocument\s*\.\s*cookie\s*="
        r"|\bdocument\s*\.\s*(?:location|write)\s*[=(]"
        r"|\bwindow\s*\.\s*(?:location|open)\s*[=(]"
    ),
    "xss_dangerous_tag": re.compile(
        r"<\s*(?:svg|img|iframe|object|embed|marquee)\b"
    ),
    # Path traversal / local file inclusion
    "path_traversal": re.compile(
        r"(?:\.\./|\.\.\\|%2e%2e|%c0%ae|%c0%af|%e0%80%af)"
        r"|(?:/etc/(?:passwd|shadow|hosts)|boot\.ini|win\.ini|/proc/self/)"
    ),
    "null_byte": re.compile(r"%00|\\x00|\\u0000"),
    # OS command injection
    "command_injection": re.compile(
        r"[;&|`]\s*(?:id|whoami|uname|cat|ls|dir|curl|wget|nc|ncat|netcat|"
        r"bash|sh|zsh|python|perl|php|ping|nslookup|dig|powershell)"
        r"(?=\s|$|/|;|&|\|)"
        r"|\$\([^)]{1,120}\)"
    ),
    # Server-side request forgery helpers
    "ssrf_scheme": re.compile(r"\b(?:file|gopher|dict|ftp|tftp|ldap)://"),
    "ssrf_internal": re.compile(
        r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\."
        r"|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)"
    ),
    # Template injection
    "ssti": re.compile(
        r"\{\{[^}]{0,160}(?:os\.|__globals__|__class__|__mro__|__subclasses__|"
        r"cycler|config|request|popen|system|eval|import)[^}]{0,160}\}\}"
        r"|\{\{\s*\d+\s*[*/+]\s*\d+\s*\}\}"
    ),
    # XML external entity
    "xxe": re.compile(r"<!doctype[^>]{0,400}(?:\[|system|entity)|<!entity\b"),
    # Spring4Shell class loader manipulation
    "spring4shell": re.compile(
        r"class\s*\.\s*module\s*\.\s*classloader|classloader\s*\.\s*resources"
    ),
    # NoSQL operator injection in JSON
    "nosql_operator": re.compile(
        r'"?\$(?:ne|gt|gte|lt|lte|regex|where|exists|in)"?\s*:'
    ),
    # HTTP response splitting / CRLF header injection
    "crlf_injection": re.compile(r"%0d%0a|\r\n(?:set-cookie|location|content-length)\s*:"),
}


def _build_text(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str,
) -> str:
    header_text = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return f"{method} {url}\n{header_text}\n{body}"


def detect_attack_rules(
    method: str = "GET",
    url: str = "/",
    headers: dict[str, str] | None = None,
    body: str = "",
) -> list[str]:
    """Return names of high-confidence exploit rules matched by the request."""
    raw = _build_text(method, url, headers, body)
    text = canonicalize(raw).lower()
    # Also inspect the raw (still encoded) form for overlong-encoding bypasses.
    encoded = raw.lower()
    matches: list[str] = []
    for name, pattern in RULES.items():
        if pattern.search(text) or pattern.search(encoded):
            matches.append(name)
    return matches


def _valid_json(body: str) -> bool:
    body = body.strip()
    if not body or body[0] not in "[{":
        return False
    try:
        json.loads(body)
        return True
    except Exception:
        return False


def _valid_xml(body: str) -> bool:
    body = body.strip()
    lowered = body.lower()
    if not body.startswith("<") or lowered.startswith("<!doctype"):
        return False
    if any(token in lowered for token in ("<script", "onerror=", "onload=", "document.cookie")):
        return False
    try:
        ET.fromstring(body)
        return True
    except Exception:
        return False


def _is_multipart(headers: dict[str, str], body: str) -> bool:
    content_type = ""
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    if "multipart/form-data" not in content_type:
        return False
    return "--" in body[:4096] and "content-disposition" in body.lower()


def _is_form(headers: dict[str, str], body: str) -> bool:
    content_type = ""
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    if "application/x-www-form-urlencoded" not in content_type:
        return False
    if not body or "=" not in body:
        return False
    try:
        parsed = urllib.parse.parse_qs(body, strict_parsing=False)
        return bool(parsed)
    except Exception:
        return False


def _has_dangerous_syntax(text: str) -> bool:
    """Conservative check used only for body-less requests (GET/HEAD)."""
    suspicious = ("<", ">", "{", "}", ";", "|", "`", "$", "\\", "../", "..\\")
    return any(token in text for token in suspicious)


def is_structurally_benign(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str,
) -> str | None:
    """Return a reason string when the request is well-formed normal traffic.

    This is a false-positive guard, not a security bypass: it is only consulted
    after :func:`detect_attack_rules` found nothing and the model flagged the
    request.  Callers must still enforce a score ceiling before applying it.
    """
    headers = headers or {}
    decoded_body = canonicalize(body)

    if _valid_json(body):
        return "json"
    if _valid_xml(body):
        return "xml"
    if _is_multipart(headers, body):
        return "multipart"
    if _is_form(headers, body):
        return "form"
    if not body.strip() and method.upper() in {"GET", "HEAD", "OPTIONS", "DELETE"}:
        if not _has_dangerous_syntax(canonicalize(f"{url}\n{decoded_body}")):
            return "query"
    return None
