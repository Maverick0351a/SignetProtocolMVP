import logging
import re
from typing import Iterable


_SENSITIVE_KEYS = re.compile(
    r"(authorization|token|secret|key|password)", re.IGNORECASE
)


class RedactingFilter(logging.Filter):
    """Redact common secret-bearing fields from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = str(record.getMessage())
            # Replace auth headers and token-like substrings
            msg = re.sub(
                r"(Authorization:?)\s+\S+", r"\1 ***", msg, flags=re.IGNORECASE
            )
            msg = re.sub(
                r"(token|secret|password|key)=\S+", r"\1=***", msg, flags=re.IGNORECASE
            )
            record.msg = msg
        except Exception:
            pass
        return True


def setup_logging(
    level: int = logging.INFO, loggers: Iterable[str] = ("uvicorn", "uvicorn.access")
) -> None:
    logging.basicConfig(level=level)
    f = RedactingFilter()
    for name in loggers:
        lg = logging.getLogger(name)
        lg.setLevel(level)
        lg.addFilter(f)
