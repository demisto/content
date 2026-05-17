"""Legacy top-level test file — INTENTIONALLY EMPTIED.

The original 2,777-line ``workflow_state_test.py`` predates the
2026-05 schema simplification AND the migration of the runtime engine
from a single top-level script (``connectus/workflow_state.py``) into
the :mod:`workflow_state` package. Among other things it imported
many symbols that no longer exist:

  * ``AUTH_PARITY_FLAG_COLUMN`` — the column was removed.
  * ``ALL_COLUMNS`` / ``CHECKPOINT_COLUMNS`` / ``DATA_COLUMNS`` /
    ``WORKFLOW_COLUMNS`` / ``WORKFLOW_DATA_COLUMNS`` / ``STEPS`` /
    ``STEP_BY_INDEX`` / ``STEP_BY_NAME`` / ``EXPECTED_COLUMN_COUNT`` /
    ``JSON_VALUED_COLUMNS`` / ``NON_CHECKPOINT_STEPS`` /
    ``VALID_AUTH_TYPES`` / ``VALID_FLAG_VALUES`` — all moved into the
    YAML-backed :class:`workflow_state.types.WorkflowConfig`.
  * ``cmd_set_auth_flag`` / ``cmd_set_shared_params`` /
    ``cmd_set_params_for_test`` — verbs removed in the 2026-05 schema
    simplification along with the columns they wrote to.

The replacement test suite lives in :mod:`workflow_state.tests`:

  * :mod:`workflow_state.tests.test_config_loader` — YAML loader and
    validation rules.
  * :mod:`workflow_state.tests.test_state_machine` — cascade-reset
    engine and step actions.
  * :mod:`workflow_state.tests.test_verify_button_placement` — the new
    ``verify button placement`` flag column.
  * :mod:`workflow_state.tests.test_column_addressability` — 1-based
    column-number resolution shared by ``markpass``/``skip``/``fail``/
    ``reset-to``/``show-step``.
  * :mod:`workflow_state.tests.test_wipe_workflow_data` — the destructive
    schema-alignment wipe.

This file is kept as a stub so that historical references (and any
CI configs that still glob ``connectus/workflow_state_test.py``)
continue to import cleanly with zero collected tests.
"""
