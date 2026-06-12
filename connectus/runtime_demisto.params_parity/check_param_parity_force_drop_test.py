"""Force-drop construction unit tests for the param-parity orchestrator.

Focused, hermetic tests (NO network / tenant / docker) that pin down the ONE
behavior: which resolver-ignored params get pushed into ``force_drop`` so they
are dropped on BOTH sides of the diff (and thus surface as ``OK_IGNORED`` rather
than ``MISSING_IN_CONNECTOR`` / ``EXTRA_IN_CONNECTOR``).

COMPARISON POLICY:
  A param is IGNORED iff its name is on ``HARD_IGNORE_PARAMS`` (reason
  ``"hard_ignore_list"``) OR it is hidden in the integration YML (reason
  ``"hidden"`` — hidden params are NOT migrated to the connector). Everything
  else is compared verbatim. Therefore ``_force_drop_from`` admits BOTH
  ``"hard_ignore_list"`` and ``"hidden"``; any other reason (e.g. the legacy
  ``"credentials_type9_interpolated"`` / ``"profile_not_interpolated"``, which the
  resolver no longer emits but is tested here defensively) is NOT force-dropped.

These tests target the ``_force_drop_from`` helper directly (the actual fix
point); driving the full ``main()`` is intentionally avoided because it pulls in
network deps.
"""
from __future__ import annotations

import check_param_parity


def test_force_drop_includes_hard_ignore_list_and_hidden():
    """hard-ignore-list AND hidden params go into force_drop; nothing else."""
    ignored = {
        "brand": "hard_ignore_list",
        "instance_name": "hard_ignore_list",
        "access_key": "hidden",
        "x": "some_other",
    }
    assert check_param_parity._force_drop_from(ignored) == {
        "brand",
        "instance_name",
        "access_key",
    }


def test_force_drop_includes_hidden_reason():
    """'hidden' params are NOT migrated to the connector → they MUST be
    force-dropped (dropped on BOTH sides) so they surface as OK_IGNORED."""
    ignored = {"access_key": "hidden", "brand": "hard_ignore_list"}
    result = check_param_parity._force_drop_from(ignored)
    assert result == {"access_key", "brand"}
    assert "access_key" in result


def test_force_drop_excludes_credentials_type9_reason():
    """'credentials_type9_interpolated' is no longer an ignore reason; a type-9
    credentials param is compared verbatim (the value mismatch is the desired
    finding), so it must NOT be force-dropped."""
    ignored = {
        "credentials": "credentials_type9_interpolated",
        "brand": "hard_ignore_list",
    }
    result = check_param_parity._force_drop_from(ignored)
    assert result == {"brand"}
    assert "credentials" not in result


def test_force_drop_excludes_arbitrary_reasons():
    """Any non-hard_ignore_list reason is excluded from force_drop."""
    ignored = {
        "brand": "hard_ignore_list",
        "x": "profile_not_interpolated",
        "y": "some_other",
    }
    result = check_param_parity._force_drop_from(ignored)
    assert result == {"brand"}
    assert "x" not in result
    assert "y" not in result


def test_force_drop_empty_when_no_hard_ignore_reasons():
    """No hard-ignore reasons → empty force_drop set."""
    ignored = {"x": "profile_not_interpolated", "y": "some_other"}
    assert check_param_parity._force_drop_from(ignored) == set()


def test_force_drop_empty_dict():
    """Empty ignored_params → empty force_drop set."""
    assert check_param_parity._force_drop_from({}) == set()


def test_main_uses_force_drop_helper():
    """The orchestrator's main() must delegate to _force_drop_from.

    Guards against a regression to an inline comprehension that drops the
    "hidden" reason from force_drop.
    """
    import inspect

    src = inspect.getsource(check_param_parity.main)
    assert "_force_drop_from" in src, (
        "check_param_parity.main() must build force_drop via "
        "_force_drop_from(parity_inputs.ignored_params)."
    )
