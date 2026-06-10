"""main.py — thin CLI wrapper around :mod:`xsoar_capture`.

Two responsibilities:

1. **Backwards-compatible re-export shim.** Existing code (notably
   :file:`create_ucp_instance.py`) imports helpers from this module via
   ``from main import get_instances_by_brand``. Those symbols all now live in
   :mod:`xsoar_capture`; this module re-exports them so existing imports
   continue to work without modification.

2. **CLI entry point** for ad-hoc XSOAR-side capture. When invoked as
   ``python main.py``, runs :func:`xsoar_capture.capture_xsoar_params`
   against the integration declared in the ``INTEGRATION_YML_PATH`` env var
   and prints the captured ``demisto.params()`` dict to stdout. Useful for
   debugging the legacy side in isolation, without involving UCP.

For the actual end-to-end parity test, use ``check_param_parity.py`` (the
orchestrator built in Phase 6), not this script.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader so env vars such
# as INTEGRATION_YML_PATH come from the repo-root .env.
load_env()

# Re-export every public symbol from xsoar_capture so legacy imports work.
from xsoar_capture import (  # noqa: F401  (re-exports are intentional)
    DEFAULT_API_KEY,
    DEFAULT_AUTH_ID,
    DEFAULT_BASE_URL,
    PARAM_TYPE_AUTH,
    PARAM_TYPE_BOOLEAN,
    PARAM_TYPE_ENCRYPTED,
    PARAM_TYPE_SHORT_TEXT,
    PARITY_DUMP_PARAM_KEY,
    PARITY_DUMP_PARAM_VALUE,
    PARITY_DUMP_SENTINEL,
    capture_xsoar_params,
    create_client,
    create_integration_instance,
    delete_integration_instance,
    fill_params_from_yml,
    generate_dummy_value_for_param,
    get_instances_by_brand,
    get_integration_config,
    parse_integration_yml,
    parse_params_dump_payload,
    run_test_module_and_capture_params,
    test_integration_instance,
)

log = logging.getLogger("xsoar_capture.cli")


# ============================================================================
# CONFIGURATION — Edit these values OR set them in .env before running
# ============================================================================

INTEGRATION_YML_PATH = os.getenv("INTEGRATION_YML_PATH", "")

# Per-param overrides keyed by param name OR display name. Use to inject
# non-default values like isFetch=true or a custom max_fetch. The probe
# magic key is added automatically by capture_xsoar_params() — do not add
# it here.
PARAM_OVERRIDES: dict = {
    # "isFetch": True,
    # "max_fetch": "50",
    # "insecure": True,
}


def main() -> int:
    log.info("=" * 60)
    log.info("XSOAR-side params capture (params-parity / xsoar_capture)")
    log.info("=" * 60)

    if not INTEGRATION_YML_PATH:
        log.error(
            "INTEGRATION_YML_PATH is not set. Set it in .env or as an env var "
            "(absolute path to the integration .yml)."
        )
        return 2

    captured = capture_xsoar_params(
        integration_yml_path=INTEGRATION_YML_PATH,
        overrides=PARAM_OVERRIDES,
    )

    if captured is None:
        log.error("Capture failed. See logs above for details.")
        return 1

    log.info("Captured demisto.params() (%d keys):", len(captured))
    print(json.dumps(captured, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
