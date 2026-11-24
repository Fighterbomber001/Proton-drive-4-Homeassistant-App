from __future__ import annotations

import logging
import re
from urllib.parse import unquote, urlsplit, urlunsplit


REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_REDACTED_CHARS = 16_384

_HEADER = re.compile(
    r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)"
    r"[ \t]*+:[ \t]*+)(.*?)(?=(?<![ \t])[ \t]++(?:"
    r"(?:cookie|set-cookie)[ \t]*+:|https?://)|[\r\n]|$)"
)
_FOLDED_HEADER = re.compile(
    r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)"
    r"[ \t]*+:[ \t]*+)[^\r\n]*+(?:\r?\n[ \t]++[^\r\n]*+)+"
)
_JSON_SECRET = re.compile(
    r'''(?ix)
    ("(?:token|access[_-]?token|refresh[_-]?token|cookie|authorization|password|
       passwd|passphrase|otp|2fa[_-]?code)"\s*:\s*)
    ("(?:\\.|[^"\\])*")
    '''
)
_ASSIGNMENT_SECRET = re.compile(
    r'''(?ix)
    \b(token|access[_-]?token|refresh[_-]?token|cookie|authorization|password|
       passwd|passphrase|otp|2fa[_-]?code)\b
    (\s*[=:]\s*)
    ("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&]+)
    '''
)
_URL = re.compile(r"(?i)https?://[^\s<>\"']+")
_PRIVATE_PATH = re.compile(r"(?i)/data/private(?:/[^\s\"']*)?")
_POSIX_HOME_PATH = re.compile(r"/home/[^/\s\"']+(?:/[^\s\"']*)?")
_WINDOWS_HOME_PATH = re.compile(
    r"(?i)[a-z]:\\Users\\[^\\\s\"']+(?:\\[^\s\"']*)?"
)


def redact(text: str, *, max_chars: int = MAX_REDACTED_CHARS) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if type(max_chars) is not int or not MAX_REDACTED_CHARS <= max_chars <= 2_097_152:
        raise ValueError("invalid redaction output bound")

    safe = _FOLDED_HEADER.sub(lambda match: f"{match[1]}{REDACTED}", text)
    safe = _HEADER.sub(lambda match: f"{match[1]}{REDACTED}", safe)
    safe = _JSON_SECRET.sub(lambda match: f'{match[1]}"{REDACTED}"', safe)
    safe = _ASSIGNMENT_SECRET.sub(
        lambda match: f"{match[1]}{match[2]}{REDACTED}", safe
    )
    safe = _URL.sub(_sanitize_url, safe)
    safe = _PRIVATE_PATH.sub(REDACTED, safe)
    safe = _POSIX_HOME_PATH.sub(REDACTED, safe)
    safe = _WINDOWS_HOME_PATH.sub(REDACTED, safe)
    if len(safe) > max_chars:
        safe = safe[: max_chars - len(TRUNCATED)] + TRUNCATED
    return safe


def _sanitize_url(match: re.Match[str]) -> str:
    parsed = urlsplit(match.group(0))
    try:
        hostname = (parsed.hostname or "").casefold()
        has_userinfo = parsed.username is not None or parsed.password is not None
    except ValueError:
        return REDACTED
    if has_userinfo:
        return REDACTED
    decoded_path = unquote(parsed.path).casefold()
    is_proton_host = hostname == "proton.me" or hostname.endswith(".proton.me")
    if parsed.scheme.casefold() == "https" and is_proton_host and any(
        marker in decoded_path for marker in ("auth", "login")
    ):
        return REDACTED
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class SafeLogger:
    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def log(self, level: int, message: object, *args: object) -> None:
        try:
            rendered = str(message) % args if args else str(message)
            safe = redact(rendered)
        except Exception:
            safe = "Unable to safely format log message"
        try:
            self._logger.log(level, safe)
        except Exception:
            # A broken logging backend must not turn sensitive data into an error path.
            return

    def debug(self, message: object, *args: object) -> None:
        self.log(logging.DEBUG, message, *args)

    def info(self, message: object, *args: object) -> None:
        self.log(logging.INFO, message, *args)

    def warning(self, message: object, *args: object) -> None:
        self.log(logging.WARNING, message, *args)

    def error(self, message: object, *args: object) -> None:
        self.log(logging.ERROR, message, *args)

    def exception(self, message: object, *args: object) -> None:
        # Never forward exc_info: exception strings can contain CLI output or secrets.
        self.log(logging.ERROR, message, *args)

    def critical(self, message: object, *args: object) -> None:
        self.log(logging.CRITICAL, message, *args)
