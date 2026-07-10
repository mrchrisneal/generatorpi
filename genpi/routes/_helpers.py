# genpi/routes/_helpers.py -- tiny shared helpers for the route blueprints (roadmap #59, Stage 9).
# _json_number is the numeric-body parser shared by the core (runtime-hours) + fuel/alerts routes;
# it lives here (Layer 5, depends only on stdlib math) so both blueprints import it without either
# depending on the other. Re-exported from genpi/__init__ as gc._json_number for the test suite.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import math


def _json_number(data, field):
    """Pull a numeric `field` from a JSON dict body. Returns (value, error_message);
    error_message is None on success. Accepts numeric strings; rejects bools (a bool
    is an int subclass but is never a valid level/rate/threshold); rejects non-finite
    values (Infinity/-Infinity/NaN, incl. their string forms 'inf'/'nan'/'1e999')."""
    if not isinstance(data, dict) or field not in data:
        return None, f"missing '{field}'"
    v = data[field]
    if isinstance(v, bool):
        return None, f"'{field}' is not a number"
    if isinstance(v, (int, float)):
        parsed = float(v)
    elif isinstance(v, str):
        try:
            parsed = float(v.strip())
        except ValueError:
            return None, f"'{field}' is not a number"
    else:
        return None, f"'{field}' is not a number"
    # Reject non-finite values. float("inf"/"nan"/"1e999") all parse successfully but
    # a non-finite level/rate/threshold is meaningless and dangerous: it would persist
    # Infinity/NaN into the kv store (corrupting /api/state's JSON), and int(float("inf"))
    # raises OverflowError -> a 500 on the alerts threshold path. Fail closed with 400.
    if not math.isfinite(parsed):
        return None, f"'{field}' is not a finite number"
    return parsed, None

