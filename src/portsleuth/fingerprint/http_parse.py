"""HTTP response parsing for portsleuth CLI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedHTTPResponse:
    valid: bool
    http_version: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    raw_preview: str | None = None
    error: str | None = None


def parse_http_response(data: bytes, preview_limit: int = 240) -> ParsedHTTPResponse:
    # HTTP/1.x header bytes map to ISO-8859-1 (obs-text per RFC 7230 section 3.2.4).
    preview = data[:preview_limit].decode("iso-8859-1", errors="replace")
    if not data:
        return ParsedHTTPResponse(valid=False, raw_preview=preview, error="empty response")

    text = data.decode("iso-8859-1", errors="replace")
    header_text = text.split("\r\n\r\n", 1)[0]
    if "\r\n" not in header_text and "\n" in header_text:
        lines = header_text.split("\n")
    else:
        lines = header_text.split("\r\n")

    status_line = lines[0].strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return ParsedHTTPResponse(valid=False, raw_preview=preview, error="missing HTTP status line")

    try:
        status_code = int(parts[1])
    except ValueError:
        return ParsedHTTPResponse(valid=False, raw_preview=preview, error="invalid HTTP status code")

    reason = parts[2].strip() if len(parts) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return ParsedHTTPResponse(
        valid=True,
        http_version=parts[0],
        status_code=status_code,
        reason=reason,
        headers=headers,
        raw_preview=preview,
    )

