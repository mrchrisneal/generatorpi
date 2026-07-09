# conftest.py -- shared pytest fixtures + import-time environment setup for the
# generator_control test suite.
#
# CRITICAL: gpiozero is NOT installed (it needs real Raspberry Pi hardware/lgpio)
# and must never be. generator_control.py instantiates an OutputDevice at IMPORT
# time, so we register a MagicMock stand-in for the whole `gpiozero` module in
# sys.modules BEFORE the module under test is imported anywhere. Every OutputDevice
# call then returns a MagicMock -- no hardware is ever touched.
import sys
import copy
import time
import unittest.mock as mock
from pathlib import Path

import pytest

# --- Mock gpiozero before generator_control is imported (see module docstring) ---
sys.modules["gpiozero"] = mock.MagicMock()

# Make the app package importable regardless of pytest's rootdir/invocation cwd.
_APP_DIR = Path(__file__).resolve().parent.parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

# Import AFTER the gpiozero mock is in place. This triggers the module's import-time
# side effects: check_settings_file_security() (no env file -> ok), parse_env_file()
# (no env file -> {} users, no key), logging config, and relay OutputDevice(...) mock.
import genpi as gc  # noqa: E402

# The suite assumes a pristine, default CONFIG (no key set, key auth enabled, HTTPS on)
# and no users. But generator_control reads a real generator_control.env at import if
# one is present in the app dir -- and on a deployed Pi (or any dev box that has run the
# app) it always is, which would populate CONFIG["API_KEY"] / AUTH_USERS / SSL_ENABLED
# and skew the baseline the tests restore to. Neutralize those env-derived values here
# so the suite is HERMETIC regardless of a stray env file. (Tests that exercise real env
# parsing use the env_paths fixture, which redirects ENV_FILE to an isolated tmp dir.)
gc.CONFIG["API_KEY"] = ""
gc.CONFIG["API_KEY_ENABLED"] = 1
gc.CONFIG["SSL_ENABLED"] = 1
gc.AUTH_USERS.clear()

# The UI-redesign globals (lifetime run-hours + fuel model + alerts) are restored
# from a real events.db kv table by load_persisted_state() at import. Neutralize
# them to their code defaults here -- BEFORE the pristine snapshots below -- so the
# suite baseline is hermetic regardless of any on-disk kv values, exactly like the
# API_KEY/SSL neutralization above.
gc.generator_state["total_run_hours"] = 0.0
gc.generator_state["current_run_started_at"] = None
gc.fuel_state["fill_level"] = 100.0
gc.fuel_state["fill_run_hours"] = 0.0
gc.fuel_state["drain_rate"] = gc.FUEL_DEFAULT_RATE
gc.fuel_state["default_rate"] = gc.FUEL_DEFAULT_RATE
gc.alerts_state["alerts_on"] = True
gc.alerts_state["alert_threshold"] = 20
gc.alerts_state["fuel_enabled"] = True
# Web Push globals: default the suite to "push not configured" (no VAPID key) so
# push_available() is False unless a test opts in; keep it hermetic vs a real env file
# that may already carry generated VAPID keys. Also reset the low-fuel edge flag.
gc.CONFIG["VAPID_PRIVATE_KEY"] = ""
gc.CONFIG["VAPID_PUBLIC_KEY"] = ""
gc.state._low_fuel_alerted = False


# A pristine copy of CONFIG exactly as defined at import time. Used to fully restore
# CONFIG after every test so mutations (via monkeypatch.setitem or direct writes)
# never leak between tests.
_PRISTINE_CONFIG = copy.deepcopy(gc.CONFIG)

# The initial generator_state shape, snapshotted before any test mutates it.
_PRISTINE_STATE = copy.deepcopy(gc.generator_state)

# Fuel model + alert config are separate mutable module globals (added with the UI
# redesign); snapshot them too so reset_globals can restore them between tests.
_PRISTINE_FUEL = copy.deepcopy(gc.fuel_state)
_PRISTINE_ALERTS = copy.deepcopy(gc.alerts_state)


@pytest.fixture
def module():
    """The imported generator_control module under test."""
    return gc


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset every mutable module global between tests for full isolation.

    Restores CONFIG and generator_state to their import-time values, empties the
    loaded users + the rate-limiter fail tracker, and rewinds the cleanup clock.
    Runs automatically around every test (autouse).
    """
    # --- setup: give each test a clean slate ---
    gc.CONFIG.clear()
    gc.CONFIG.update(copy.deepcopy(_PRISTINE_CONFIG))

    gc.generator_state.clear()
    gc.generator_state.update(copy.deepcopy(_PRISTINE_STATE))

    gc.fuel_state.clear()
    gc.fuel_state.update(copy.deepcopy(_PRISTINE_FUEL))
    gc.alerts_state.clear()
    gc.alerts_state.update(copy.deepcopy(_PRISTINE_ALERTS))
    gc.state._low_fuel_alerted = False

    gc.AUTH_USERS.clear()
    gc._auth_cache.clear()          # isolate the Basic-auth verification cache between tests

    with gc._fail_tracker_lock:
        gc._fail_tracker.clear()
    gc.ratelimit._last_cleanup = time.monotonic()

    # Ensure no relay sequence lock is being held from a prior (failed) test.
    if gc.relay_lock.locked():
        try:
            gc.relay_lock.release()
        except RuntimeError:
            pass

    yield

    # --- teardown: restore again so nothing bleeds forward ---
    gc.CONFIG.clear()
    gc.CONFIG.update(copy.deepcopy(_PRISTINE_CONFIG))
    gc.generator_state.clear()
    gc.generator_state.update(copy.deepcopy(_PRISTINE_STATE))
    gc.fuel_state.clear()
    gc.fuel_state.update(copy.deepcopy(_PRISTINE_FUEL))
    gc.alerts_state.clear()
    gc.alerts_state.update(copy.deepcopy(_PRISTINE_ALERTS))
    gc.state._low_fuel_alerted = False
    gc.AUTH_USERS.clear()
    gc._auth_cache.clear()          # isolate the Basic-auth verification cache between tests
    with gc._fail_tracker_lock:
        gc._fail_tracker.clear()
    if gc.relay_lock.locked():
        try:
            gc.relay_lock.release()
        except RuntimeError:
            pass


@pytest.fixture
def client(module):
    """Flask test client for the app under test."""
    module.app.config.update(TESTING=True)
    return module.app.test_client()


@pytest.fixture
def no_sleep(module, monkeypatch):
    """Patch the module's time.sleep to a no-op so relay sequences run instantly
    and never actually block. The module references `time.sleep`, so patching the
    attribute on the module's `time` object is sufficient."""
    monkeypatch.setattr(module.time, "sleep", lambda *a, **k: None)


@pytest.fixture
def env_paths(module, monkeypatch, tmp_path):
    """Point the module's ENV_FILE and SCRIPT_DIR at an isolated tmp dir.

    parse_env_file() writes its atomic temp file into SCRIPT_DIR and renames it
    onto ENV_FILE, so both must live on the same filesystem/dir for os.rename to
    succeed -- hence patching both to tmp_path. Returns the env-file Path.
    """
    env_file = tmp_path / "generator_control.env"
    # SCRIPT_DIR/ENV_FILE + parse_env_file/check_settings_file_security now live in the
    # genpi.config submodule (roadmap #59, Stage 2), so patch the paths THERE -- that is the
    # binding those functions read. Patching the package re-export (module.SCRIPT_DIR) would
    # NOT be seen by the config-module code that consumes them.
    monkeypatch.setattr(module.config, "SCRIPT_DIR", tmp_path)
    monkeypatch.setattr(module.config, "ENV_FILE", env_file)
    return env_file
