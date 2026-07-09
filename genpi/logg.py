# genpi/logg.py -- Logging setup for GeneratorPi (roadmap #59, Stage 2). LAYER 1: depends only on
# genpi.config (SCRIPT_DIR + CONFIG + AUTH_USERS) and the stdlib. Imported early by
# genpi/__init__.py -- right after config -- so `log` is live before any other submodule needs it.
#
# Owns the application logger (`log`) and its on-disk path (`log_path`): a size-capped rotating
# file handler (N backups) plus a console/stderr handler so journald still captures output.
# Importing this module emits the two startup INFO lines (users loaded, log-file path) and
# silences Werkzeug's per-request access log -- EXACTLY as the old single file did -- which keeps
# the API-key leak vector (the "?key=..." query string in Werkzeug's access log) closed.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
import logging.handlers
from .config import SCRIPT_DIR, CONFIG, AUTH_USERS

log_path = SCRIPT_DIR / CONFIG["LOG_FILE"]
log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Rotating file handler
file_handler = logging.handlers.RotatingFileHandler(
    log_path,
    maxBytes=CONFIG["LOG_MAX_BYTES"],
    backupCount=CONFIG["LOG_BACKUP_COUNT"],
)
file_handler.setFormatter(log_formatter)

# Console handler (so journald still captures output)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

log = logging.getLogger("generator_control")
log.setLevel(getattr(logging, CONFIG["LOG_LEVEL"].upper(), logging.INFO))
log.addHandler(file_handler)
log.addHandler(console_handler)

log.info(f"Loaded {len(AUTH_USERS)} user(s): {', '.join(AUTH_USERS.keys()) or 'none'}")
log.info(f"Log file: {log_path} (max {CONFIG['LOG_MAX_BYTES'] // 1_048_576}MB x {CONFIG['LOG_BACKUP_COUNT']} backups)")

# Suppress Werkzeug's built-in per-request access log. That log prints the full
# request line -- INCLUDING the "?key=..." query string -- to stdout/journald,
# which would leak the API key into logs. Our own audit line (in auth_required)
# records only method + path (never the query string), so we lose nothing useful
# by silencing Werkzeug's access log while closing the key-leak vector.
logging.getLogger("werkzeug").setLevel(logging.ERROR)
