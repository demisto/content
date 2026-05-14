"""Focused tests of the cascade-reset engine driven by the YAML config.

These tests build an in-process WorkflowConfig fixture to prove that the
state-machine reads behaviour from the YAML rather than from Python
literals.
"""
from __future__ import annotations

import pytest

from workflow_state.config_loader import (
    _reset_config_for_testing,
    load_config,
)
from workflow_state.state_machine import (
    apply_step_action,
    is_checked,
    reset_after,
)


_FIXTURE_YAML = """\
schema_version: 1
identity_columns:
  - {"name": "Integration ID", "description": "id"}
markers:
  check: "✅"
  fail: "❌"
  na: "N/A"
  checkpoint_done_values: ["✅", "N/A"]
  flag_values: ["YES", "NO", "N/A"]
steps:
  - name: "alpha"
    kind: data
    optional: false
    setter: set-alpha
    cascade_on_set: true
    description: "first"
  - name: "beta"
    kind: checkpoint
    optional: false
    setter: null
    description: "second"
  - name: "gamma"
    kind: checkpoint
    optional: false
    setter: null
    description: "third"
"""


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


def _write_and_load(tmp_path, body: str):
    p = tmp_path / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return load_config(str(p))


class TestCascadeReset:
    def test_setting_alpha_clears_beta_and_gamma(self, tmp_path) -> None:
        cfg = _write_and_load(tmp_path, _FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "old",
            "beta": "✅",
            "gamma": "✅",
        }
        target = cfg.step_by_name["alpha"]
        cleared, no_op = apply_step_action(row, target, "new", verb="set-alpha")
        assert no_op is False
        assert row["alpha"] == "new"
        assert row["beta"] == ""
        assert row["gamma"] == ""
        assert "beta" in cleared and "gamma" in cleared

    def test_setting_a_step_with_cascade_on_set_false_does_not_reset(
        self, tmp_path
    ) -> None:
        body = _FIXTURE_YAML.replace(
            "    cascade_on_set: true\n",
            "    cascade_on_set: false\n",
        )
        cfg = _write_and_load(tmp_path, body)
        row = {
            "Integration ID": "X",
            "alpha": "old",
            "beta": "✅",
            "gamma": "✅",
        }
        target = cfg.step_by_name["alpha"]
        cleared, no_op = apply_step_action(row, target, "new", verb="set-alpha")
        assert no_op is False
        assert row["alpha"] == "new"
        # Carve-out: beta/gamma untouched.
        assert row["beta"] == "✅"
        assert row["gamma"] == "✅"
        assert cleared == []


class TestIsCheckedQ2BreakingChange:
    """Q2 BREAKING CHANGE: only canonical done values are accepted."""

    def test_canonical_check_is_done(self, tmp_path) -> None:
        _write_and_load(tmp_path, _FIXTURE_YAML)
        assert is_checked("✅") is True

    def test_canonical_na_is_done(self, tmp_path) -> None:
        _write_and_load(tmp_path, _FIXTURE_YAML)
        assert is_checked("N/A") is True

    @pytest.mark.parametrize("alias", ["YES", "true", "True", "done", "Done", "DONE"])
    def test_dropped_aliases_are_not_done(self, tmp_path, alias: str) -> None:
        # Q2 breaking change: dropped historical alias support.
        _write_and_load(tmp_path, _FIXTURE_YAML)
        assert is_checked(alias) is False, (
            f"Q2 breaking change: alias {alias!r} should no longer be "
            f"recognized as 'done'."
        )


class TestResetAfter:
    def test_reset_after_clears_only_strictly_later_steps(self, tmp_path) -> None:
        cfg = _write_and_load(tmp_path, _FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "v",
            "beta": "✅",
            "gamma": "✅",
        }
        cleared = reset_after(row, cfg.step_by_name["beta"])
        assert row["alpha"] == "v"
        assert row["beta"] == "✅"
        assert row["gamma"] == ""
        assert cleared == ["gamma"]
