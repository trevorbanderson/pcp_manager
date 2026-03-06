"""
Centralised logging configuration for PCP Manager.

Usage in app.py (after set_env.setup()):
    import pcp_logger
    pcp_logger.setup(_active_env)
    _log = pcp_logger.get_logger("pcp_manager")

Log strategy per environment:
    dev      – DEBUG, console (plain text) + file (JSON), rotating 10 MB × 5
    staging  – INFO,  console (plain text) + file (JSON), rotating 10 MB × 5
    prod     – WARNING, console (plain text) + file (JSON), rotating 10 MB × 5
"""

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone

# ── Level map ────────────────────────────────────────────────────────────
_ENV_LEVELS: dict[str, int] = {
    "dev":     logging.DEBUG,
    "staging": logging.INFO,
    "prod":    logging.WARNING,
}

_CONSOLE_FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FMT    = "%Y-%m-%d %H:%M:%S"

_initialised = False


# ── JSON formatter ────────────────────────────────────────────────────────
class JsonFormatter(logging.Formatter):
    """
    Emits one JSON object per log line.
    Standard LogRecord attributes are normalised; any extras passed via
    the `extra={}` kwarg are promoted to the top level of the JSON object.
    """

    # Keys that belong to the LogRecord internals – never promote these
    _SKIP = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
        "message", "asctime",
    }

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()

        payload: dict = {
            "ts":       datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level":    record.levelname,
            "logger":   record.name,
            "message":  record.message,
            "module":   record.module,
            "func":     record.funcName,
            "line":     record.lineno,
        }

        # Promote caller-supplied extras
        for key, value in record.__dict__.items():
            if key not in self._SKIP and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        return json.dumps(payload, default=str)


# ── Public API ────────────────────────────────────────────────────────────
def setup(environment: str = "dev") -> logging.Logger:
    """
    Configure the root logger for the given environment.
    Safe to call multiple times – only applies once.
    Returns the pcp_manager logger.
    """
    global _initialised
    if _initialised:
        return logging.getLogger("pcp_manager")

    env   = environment.lower()
    level = _ENV_LEVELS.get(env, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # ── Console handler (plain text) ─────────────────────────────────────
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(_CONSOLE_FMT, datefmt=_DATE_FMT))
    root.addHandler(console)

    # ── Rotating file handler (JSON) ─────────────────────────────────────
    log_dir_setting = os.getenv('LOG_DIR', 'logs')
    # If relative, resolve from the project root (same dir as pcp_logger.py)
    if not os.path.isabs(log_dir_setting):
        log_dir_setting = os.path.join(os.path.dirname(__file__), log_dir_setting)
    logs_dir = log_dir_setting
    os.makedirs(logs_dir, exist_ok=True)
    log_file = os.path.join(logs_dir, f"{env}.log")

    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes  = 10 * 1024 * 1024,   # 10 MB
        backupCount = 5,
        encoding  = "utf-8",
    )
    fh.setLevel(level)
    fh.setFormatter(JsonFormatter())
    root.addHandler(fh)

    # ── Suppress noisy third-party loggers ───────────────────────────────
    for noisy in ("azure", "azure.identity", "azure.core.pipeline",
                  "werkzeug", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _initialised = True

    logger = logging.getLogger("pcp_manager")
    logger.info(
        "Logging initialised",
        extra={
            "environment": env,
            "log_level":   logging.getLevelName(level),
            "log_file":    log_file,
        },
    )
    return logger


def get_logger(name: str = "pcp_manager") -> logging.Logger:
    """Return a child logger under the pcp_manager hierarchy."""
    if not name.startswith("pcp_manager"):
        name = f"pcp_manager.{name}"
    return logging.getLogger(name)
