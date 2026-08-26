from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel


class ParsedRequest(BaseModel):
    method: str = ""
    path: str = ""
    query_params: dict[str, list[str]] = {}
    headers: dict[str, str] = {}
    body: str = ""
    raw: str = ""
    source_ip: str = ""
    user_agent: str = ""


def parse_http_request(
    method: str,
    url: str,
    headers: Optional[dict[str, str]] = None,
    body: str = "",
    raw_line: Optional[str] = None,
) -> ParsedRequest:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    return ParsedRequest(
        method=method.upper(),
        path=parsed.path,
        query_params=query_params,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        raw=raw_line or "",
        source_ip=(headers or {}).get("x-real-ip", (headers or {}).get("x-forwarded-for", "")),
        user_agent=(headers or {}).get("user-agent", ""),
    )


def parse_access_log_line(line: str) -> Optional[ParsedRequest]:
    parts = line.strip().split()
    if len(parts) < 9:
        return None

    method = parts[5].strip('"')
    path = parts[6]
    protocol = parts[7]
    status = parts[8]
    size = parts[9] if len(parts) > 9 else "0"

    query_string = ""
    if "?" in path:
        path, query_string = path.split("?", 1)

    return ParsedRequest(
        method=method,
        path=path,
        query_params=parse_qs(query_string),
        headers={},
        body="",
        raw=line,
        source_ip=parts[0] if parts else "",
        user_agent=" ".join(parts[11:]) if len(parts) > 11 else "",
    )
