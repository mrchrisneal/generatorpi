# genpi/ssl_cert.py -- Self-signed TLS certificate management for GeneratorPi (roadmap #59, Stage 10).
# LAYER 2: depends only on genpi.config (CONFIG + SCRIPT_DIR) and genpi.logg (log). Imported by
# genpi/__init__.py before main() so the cert helpers are resident; no other submodule imports it.
#
# The app serves self-signed HTTPS on port 9400. In "auto" mode (default) a self-signed ECDSA
# P-256 cert is auto-provisioned on first start and auto-renewed when it nears expiry; in "manual"
# mode the operator supplies their own cert/key and we never generate or overwrite them. P-256 (not
# RSA) is a deliberate performance choice: on the weak single ARM core of a Pi Zero 2 W a fresh RSA
# handshake per un-kept-alive poll cost seconds under load, so the cheaper EC handshake is what makes
# HTTPS usable there (guarded by a test against a silent regression back to RSA). SANs are baked in so
# the cert matches how the Pi is actually reached (hostname/.local/localhost/127.0.0.1 + operator
# extras), which also lets a trusted self-signed cert satisfy the secure-context requirement for Web
# Push. NONE of this touches the relay -- it only provisions the TLS material main() serves with.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os                 # umask/chmod around key generation; os.access readability check (in main)
import sys                # sys.exit(1) when a manual cert/key is missing
import socket             # hostname discovery for the SubjectAltName list
from pathlib import Path  # resolve relative cert/key paths under SCRIPT_DIR
from .config import CONFIG, SCRIPT_DIR   # SSL_* config knobs + the script dir for relative paths
from .logg import log                    # cert provisioning / renewal / warning log lines

# ============================================================================
# SSL CERTIFICATE MANAGEMENT
# ============================================================================
# Self-signed cert is auto-generated on startup if missing or expiring soon.
# Uses openssl (pre-installed on Raspberry Pi OS).

def _resolve_ssl_path(value):
    """Resolve an SSL path from config: an absolute path is used as-is, a relative
    path is taken relative to the script directory."""
    p = Path(value)
    return p if p.is_absolute() else (SCRIPT_DIR / p)


# Cert/key locations come from config so an operator can point at their own files
# (e.g. a real cert) instead of the default self-signed ones next to the script.
SSL_CERT_PATH = _resolve_ssl_path(CONFIG["SSL_CERT_FILE"])
SSL_KEY_PATH = _resolve_ssl_path(CONFIG["SSL_KEY_FILE"])


def _cert_expires_within(days):
    """Check if the SSL cert expires within the given number of days.

    Uses 'openssl x509 -checkend' which returns exit code 0 if the cert is
    still valid after the specified seconds, or 1 if it will expire. This
    avoids fragile date string parsing and locale issues.
    """
    import subprocess
    seconds = days * 86400
    try:
        result = subprocess.run(
            ["openssl", "x509", "-checkend", str(seconds), "-noout",
             "-in", str(SSL_CERT_PATH)],
            capture_output=True, text=True, timeout=5,
        )
        # exit 0 = cert valid beyond the window, exit 1 = expires within window
        return result.returncode != 0
    except Exception as e:
        log.warning(f"Could not check cert expiry: {e}")
        return True  # Assume expired if we can't check


def _build_san():
    """Build the SubjectAltName string for the self-signed cert: the Pi's hostname
    (+ its .local mDNS name), localhost, 127.0.0.1, and any operator-configured extras
    (SSL_SAN). Modern browsers validate against SANs, not the CN, so this makes the
    self-signed cert actually match how the Pi is reached on the LAN (and lets a
    trusted self-signed cert satisfy the secure-context requirement for Web Push)."""
    entries = []
    try:
        hn = socket.gethostname()
        if hn:
            entries.append(f"DNS:{hn}")
            if not hn.endswith(".local"):
                entries.append(f"DNS:{hn}.local")
    except Exception:
        pass
    entries += ["DNS:localhost", "IP:127.0.0.1"]
    # Operator extras, e.g. the Pi's static LAN IP or a friendly hostname.
    extra = str(CONFIG.get("SSL_SAN", "") or "").strip()
    if extra:
        for e in extra.split(","):
            e = e.strip()
            if e:
                entries.append(e)
    # De-duplicate, preserving order.
    seen, out = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return ",".join(out)


def _generate_self_signed():
    """Generate a self-signed cert+key at the configured paths, with SANs. Falls back
    to a no-SAN cert if the local openssl predates -addext support (<1.1.1)."""
    import subprocess

    cert_days = CONFIG["SSL_CERT_DAYS"]
    # ECDSA P-256 (prime256v1) key, NOT RSA-2048: on a weak ARM core (Pi Zero 2 W) the server's
    # per-handshake private-key operation and the overall TLS handshake are dramatically cheaper
    # with an EC key, which matters because every un-kept-alive HTTPS poll pays a handshake. P-256
    # is universally supported by browsers and gives ~128-bit security. -nodes = unencrypted key.
    base = [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(SSL_KEY_PATH),
        "-out", str(SSL_CERT_PATH),
        "-days", str(cert_days),
        "-nodes",                           # No passphrase on the key
        "-subj", "/CN=generatorpi",         # CN kept for legacy display; SANs do the work
    ]
    san = _build_san()
    cmd = base + (["-addext", f"subjectAltName={san}"] if san else [])
    # Tighten the umask to 0o077 around the openssl run so the freshly-written private
    # key is owner-only from the instant of creation. Without this, openssl creates the
    # key under the process's ambient umask (commonly 0o022 -> world-readable 0644), so
    # the secret key would be briefly readable by other users in the window before the
    # os.chmod(0o600) below. Restore the prior umask in the finally so this side effect
    # never leaks out to the rest of the process.
    old_umask = os.umask(0o077)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0 and san:
            # Older openssl doesn't understand -addext; retry without a SAN rather than fail.
            log.warning(
                f"openssl -addext unsupported; generating cert without SAN "
                f"({result.stderr.strip()})"
            )
            result = subprocess.run(base, capture_output=True, text=True, timeout=30)
    finally:
        os.umask(old_umask)
    if result.returncode != 0:
        log.error(f"Failed to generate SSL cert: {result.stderr.strip()}")
        raise RuntimeError("SSL certificate generation failed")
    # Restrict key file permissions (owner read-only) -- we created it. (The tightened
    # umask above already makes it owner-only; this stays as belt-and-suspenders.)
    try:
        os.chmod(SSL_KEY_PATH, 0o600)
    except OSError:
        pass
    log.info(
        f"Generated self-signed SSL cert (valid {cert_days} days"
        + (f", SAN={san}" if san else "") + ")"
    )


def ensure_ssl_cert():
    """Ensure a usable cert + key exist at the configured paths.

    SSL_CERT_MODE controls how:
      * "auto"  (default) -- a SELF-SIGNED cert is auto-generated if missing or within
                 SSL_RENEW_DAYS of expiry, and auto-renewed on startup. Includes SANs.
      * "manual"         -- use the OPERATOR-PROVIDED cert/key as-is. Never generate or
                 overwrite them. Fail fast if they're missing; warn (don't touch) if
                 they're expiring. Point at them with SSL_CERT_FILE / SSL_KEY_FILE.
    """
    mode = str(CONFIG.get("SSL_CERT_MODE", "auto") or "auto").strip().lower()

    if mode == "manual":
        # Operator opted out of self-signing -- respect their files, never clobber them.
        missing = [str(p) for p in (SSL_CERT_PATH, SSL_KEY_PATH) if not p.exists()]
        if missing:
            log.critical(
                "SSL_CERT_MODE=manual but the cert/key file(s) are missing: "
                + ", ".join(missing)
                + ". Provide them via SSL_CERT_FILE/SSL_KEY_FILE, or set SSL_CERT_MODE=auto."
            )
            sys.exit(1)
        if _cert_expires_within(CONFIG["SSL_RENEW_DAYS"]):
            log.warning(
                f"Manual SSL cert {SSL_CERT_PATH} expires within "
                f"{CONFIG['SSL_RENEW_DAYS']} days -- renew it yourself "
                f"(auto-renew is disabled in manual mode)."
            )
        else:
            log.info(f"Using operator-provided SSL cert: {SSL_CERT_PATH}")
        return

    if mode != "auto":
        log.warning(f"Unknown SSL_CERT_MODE={mode!r}; falling back to 'auto'.")

    # auto mode: generate if missing, renew if expiring soon.
    if SSL_CERT_PATH.exists() and SSL_KEY_PATH.exists():
        if not _cert_expires_within(CONFIG["SSL_RENEW_DAYS"]):
            log.info(
                f"SSL cert still valid (renew threshold: {CONFIG['SSL_RENEW_DAYS']} days)"
            )
            return
        log.info(f"SSL cert expires within {CONFIG['SSL_RENEW_DAYS']} days, regenerating")
    else:
        log.info("No SSL cert found, generating self-signed certificate")
    _generate_self_signed()
