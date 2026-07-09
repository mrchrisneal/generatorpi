#!/usr/bin/env python3
# =============================================================================
# genpi/__main__.py -- package entrypoint.
#
# `python3 -m genpi` (the systemd ExecStart) imports the `genpi` package, which
# EAGERLY loads every application submodule into RAM via genpi/__init__.py, then
# calls main() to bring up the server. Kept intentionally tiny: it holds NO
# application logic -- all of that lives in the package -- so the entrypoint can
# never diverge from the code the tests import as `genpi`.
#
# Importing this module (rather than running it) is side-effect-free: `main()` is
# invoked ONLY under the __main__ guard, so `import genpi.__main__` in a test just
# resolves the reference without starting threads, opening a socket, or (with mock
# GPIO) ever touching the relay.
# =============================================================================
from genpi import main

if __name__ == "__main__":  # pragma: no cover -- exercised by `python -m genpi`, not the suite
    main()
