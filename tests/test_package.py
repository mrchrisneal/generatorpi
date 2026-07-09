# test_package.py -- guarantees about the genpi PACKAGE itself (distinct from any one feature).
#
# Today this asserts the `python3 -m genpi` entrypoint imports cleanly and is wired to the
# package's main(). As the monolith is peeled into submodules (roadmap #59), the eager-import
# guarantee (every expected submodule resident in sys.modules) will be asserted here too.
import importlib
from pathlib import Path


def test_runtime_data_root_is_repo_root_not_package_dir(module):
    """Operator/runtime files (generator_control.env credentials, VERSION, TLS cert/key,
    events.db, logs) MUST resolve to the project root -- the dir CONTAINING genpi/ -- not the
    package dir. Splitting the monolith into genpi/__init__.py moved __file__ one level deeper;
    if SCRIPT_DIR followed it, a deployed Pi would look for its credentials + VERSION inside
    genpi/ and brick (no users loaded, version reads the 0.0.0 fallback). This guards that."""
    pkg_dir = Path(module.__file__).resolve().parent          # .../genpi
    assert module.SCRIPT_DIR == pkg_dir.parent                # the repo root, which contains genpi/
    assert (module.SCRIPT_DIR / "VERSION").is_file()          # VERSION really lives at the root
    # APP_VERSION must be the real file contents, NOT the missing-file sentinel.
    assert module.APP_VERSION == (module.SCRIPT_DIR / "VERSION").read_text(encoding="utf-8").strip()
    assert module.APP_VERSION != "0.0.0"
    assert module.ENV_FILE == module.SCRIPT_DIR / "generator_control.env"


def test_main_entrypoint_imports_cleanly_and_is_wired(module):
    """`python3 -m genpi` runs genpi/__main__.py. Importing it must be SIDE-EFFECT-FREE
    (it invokes main() only under the __main__ guard -- never on import, so with mock GPIO
    no relay is touched, no socket opened) and it must expose the package's own main()."""
    main_mod = importlib.import_module("genpi.__main__")
    # The entrypoint calls the SAME main() the tests exercise -- not a divergent copy.
    assert main_mod.main is module.main
