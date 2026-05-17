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


_PRESERVE_FIXTURE_YAML = """\
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
    kind: data
    optional: false
    setter: set-beta
    preserve_on_reset: true
    description: "second (preserved)"
  - name: "gamma"
    kind: checkpoint
    optional: false
    setter: null
    description: "third"
  - name: "delta"
    kind: checkpoint
    optional: false
    setter: null
    description: "fourth"
"""


class TestResetAfter:
    def test_reset_after_clears_only_strictly_later_steps(self, tmp_path) -> None:
        cfg = _write_and_load(tmp_path, _FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "v",
            "beta": "✅",
            "gamma": "✅",
        }
        cleared, preserved = reset_after(row, cfg.step_by_name["beta"])
        assert row["alpha"] == "v"
        assert row["beta"] == "✅"
        assert row["gamma"] == ""
        assert cleared == ["gamma"]
        assert preserved == []

    def test_reset_after_default_ignores_preserve_flag(self, tmp_path) -> None:
        """Default ``respect_preserve=False`` keeps legacy set-auth cascade behaviour:
        every later step is wiped regardless of preserve_on_reset."""
        cfg = _write_and_load(tmp_path, _PRESERVE_FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "v",
            "beta": '["x"]',          # preserve_on_reset=true
            "gamma": "✅",
            "delta": "✅",
        }
        cleared, preserved = reset_after(row, cfg.step_by_name["alpha"])
        # Legacy default: beta is wiped despite preserve_on_reset.
        assert row["beta"] == ""
        assert row["gamma"] == ""
        assert row["delta"] == ""
        assert "beta" in cleared and "gamma" in cleared and "delta" in cleared
        assert preserved == []

    def test_reset_after_with_respect_preserve_keeps_tagged_columns(
        self, tmp_path
    ) -> None:
        """``respect_preserve=True`` keeps preserve_on_reset columns intact and
        reports them in the second tuple element."""
        cfg = _write_and_load(tmp_path, _PRESERVE_FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "v",
            "beta": '["x"]',          # preserve_on_reset=true
            "gamma": "✅",
            "delta": "✅",
        }
        cleared, preserved = reset_after(
            row, cfg.step_by_name["alpha"], respect_preserve=True
        )
        # beta is preserved; gamma + delta are still wiped.
        assert row["beta"] == '["x"]'
        assert row["gamma"] == ""
        assert row["delta"] == ""
        assert preserved == ["beta"]
        assert "gamma" in cleared and "delta" in cleared
        assert "beta" not in cleared

    def test_reset_after_respect_preserve_only_reports_non_empty_preserved(
        self, tmp_path
    ) -> None:
        """An empty preserved column is not noisy-reported."""
        cfg = _write_and_load(tmp_path, _PRESERVE_FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "v",
            "beta": "",                # preserve_on_reset=true but empty
            "gamma": "✅",
            "delta": "",
        }
        cleared, preserved = reset_after(
            row, cfg.step_by_name["alpha"], respect_preserve=True
        )
        # beta is still preserved (untouched), but not reported because empty.
        assert row["beta"] == ""
        assert row["gamma"] == ""
        assert preserved == []
        assert cleared == ["gamma"]


class TestPreserveOnResetIntegration:
    """End-to-end behaviour: set-auth still wipes preserved columns,
    but a hypothetical reset-to (callers that pass respect_preserve=True)
    keeps them.
    """

    def test_apply_step_action_set_auth_cascade_still_wipes_preserved(
        self, tmp_path
    ) -> None:
        """The set-auth cascade goes through apply_step_action, which calls
        reset_after with the legacy default (respect_preserve=False). Even
        a preserve_on_reset=true column gets wiped — by design (auth changes
        invalidate downstream artifacts)."""
        cfg = _write_and_load(tmp_path, _PRESERVE_FIXTURE_YAML)
        row = {
            "Integration ID": "X",
            "alpha": "old",
            "beta": '["preserved-data"]',
            "gamma": "✅",
            "delta": "✅",
        }
        target = cfg.step_by_name["alpha"]
        cleared, no_op = apply_step_action(row, target, "new", verb="set-alpha")
        assert no_op is False
        assert row["alpha"] == "new"
        # Even preserve_on_reset=true beta is wiped on set-alpha cascade.
        assert row["beta"] == ""
        assert row["gamma"] == ""
        assert row["delta"] == ""
        assert "beta" in cleared
