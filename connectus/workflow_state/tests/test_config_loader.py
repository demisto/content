"""Tests for :mod:`workflow_state.config_loader`.

Covers the YAML loader's happy path, the multi-error collection
pattern, and every validation rule listed in
``workflow_state_DESIGN.md`` §5.2.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from workflow_state.config_loader import (
    _reset_config_for_testing,
    default_config_path,
    get_config,
    load_config,
)
from workflow_state.exceptions import ConfigLoadError
from workflow_state.types import (
    IdentityColumn,
    MarkerSet,
    Step,
    StepInteraction,
    WorkflowConfig,
)
from workflow_state.validators import (
    get_named_validator,
    validate_auth_detail,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_VALID_YAML = """\
schema_version: 1
identity_columns:
  - {"name": "Integration ID", "description": "primary key"}
markers:
  check: "✅"
  fail: "❌"
  na: "N/A"
  checkpoint_done_values: ["✅", "N/A"]
  flag_values: ["YES", "NO", "N/A"]
steps:
  - name: "assignee"
    kind: data
    optional: false
    setter: set-assignee
    cascade_on_set: false
    description: "owner"
  - name: "manifest"
    kind: checkpoint
    optional: false
    setter: null
    description: "make manifest"
  - name: "needs parity"
    kind: flag
    optional: false
    setter: set-parity
    description: "decide"
  - name: "parity passes"
    kind: checkpoint
    optional: false
    setter: null
    description: "run parity"
step_interactions:
  - kind: flag_auto_na_target
    when_step: "needs parity"
    when_value_in: ["NO", "N/A"]
    target_step: "parity passes"
    write_value: "N/A"
"""


def _write_yaml(tmp_path: Path, body: str) -> str:
    """Write ``body`` to a fixture YAML and return its absolute path."""
    p = tmp_path / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return str(p)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Clear the cached config before AND after each test so we don't leak."""
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

class TestLoadDefault:
    def test_default_config_path_exists(self) -> None:
        assert os.path.isfile(default_config_path())

    def test_default_yaml_loads(self) -> None:
        cfg = load_config()
        assert isinstance(cfg, WorkflowConfig)
        # The bundled YAML has 14 steps and 3 identity columns.
        assert len(cfg.steps) == 14
        assert len(cfg.identity_columns) == 3
        # Markers match the expected sentinels.
        assert cfg.markers.check == "✅"
        assert cfg.markers.na == "N/A"

    def test_default_yaml_first_step_is_assignee_with_cascade_off(self) -> None:
        cfg = load_config()
        first = cfg.steps[0]
        assert first.name == "assignee"
        assert first.cascade_on_set is False

    def test_default_yaml_has_no_step_interactions(self) -> None:
        # The 2026-05 schema simplification removed the
        # ``requires auth parity test`` flag and its ``flag_auto_na_target``
        # interaction. The bundled YAML now ships with an empty
        # ``step_interactions`` list. The loader is still capable of parsing
        # ``flag_auto_na_target`` interactions; that capability is
        # exercised by :class:`TestMinimalFixture` below using a synthetic
        # fixture.
        cfg = load_config()
        assert len(cfg.step_interactions) == 0

    def test_get_config_singleton_caches(self) -> None:
        a = get_config()
        b = get_config()
        assert a is b


class TestMinimalFixture:
    def test_loads_minimal_valid_yaml(self, tmp_path) -> None:
        p = _write_yaml(tmp_path, MINIMAL_VALID_YAML)
        cfg = load_config(p)
        assert len(cfg.steps) == 4
        assert cfg.steps[0].cascade_on_set is False
        assert cfg.steps[1].cascade_on_set is True  # default

    def test_reset_for_testing_clears_cache(self, tmp_path) -> None:
        p = _write_yaml(tmp_path, MINIMAL_VALID_YAML)
        cfg1 = load_config(p)
        # Same path, second call → singleton hit (same instance).
        cfg2 = load_config(p)
        assert cfg1 is cfg2
        # Reset → new instance.
        _reset_config_for_testing()
        cfg3 = load_config(p)
        assert cfg3 is not cfg1
        assert cfg3.steps == cfg1.steps

    def test_step_interaction_resolves(self, tmp_path) -> None:
        p = _write_yaml(tmp_path, MINIMAL_VALID_YAML)
        cfg = load_config(p)
        inter = cfg.find_flag_auto_na_target("needs parity")
        assert inter is not None
        assert inter.target_step == "parity passes"
        assert inter.write_value == "N/A"

    def test_validator_binding_resolves_to_callable(self) -> None:
        # The default YAML binds Auth Details → 'auth_details' validator.
        cfg = load_config()
        auth_step = cfg.step_by_name["Auth Details"]
        assert auth_step.json_schema == "auth_details"
        validator = get_named_validator(auth_step.json_schema)
        assert validator is validate_auth_detail


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestLoadErrors:
    def test_missing_file_raises(self, tmp_path) -> None:
        bogus = str(tmp_path / "does_not_exist.yml")
        with pytest.raises(ConfigLoadError) as exc:
            load_config(bogus)
        assert "not found" in exc.value.message
        assert bogus in exc.value.message

    def test_invalid_yaml_syntax_raises(self, tmp_path) -> None:
        p = tmp_path / "bad.yml"
        p.write_text("this: is: not valid yaml: [", encoding="utf-8")
        with pytest.raises(ConfigLoadError) as exc:
            load_config(str(p))
        assert "YAML parse error" in exc.value.message

    def test_unknown_schema_version_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace("schema_version: 1", "schema_version: 99")
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("schema_version" in e for e in exc.value.errors)

    def test_missing_required_top_level_section(self, tmp_path) -> None:
        # Drop the `steps:` key entirely.
        body = MINIMAL_VALID_YAML.split("steps:")[0]
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("steps" in e for e in exc.value.errors)

    def test_extra_top_level_key_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML + "\nrandom_extra_key: value\n"
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("random_extra_key" in e for e in exc.value.errors)

    def test_identity_column_duplicate_name_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'identity_columns:\n  - {"name": "Integration ID", "description": "primary key"}',
            'identity_columns:\n'
            '  - {"name": "Integration ID", "description": "a"}\n'
            '  - {"name": "Integration ID", "description": "b"}',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("duplicate" in e.lower() for e in exc.value.errors)

    def test_identity_column_collides_with_step_name(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'identity_columns:\n  - {"name": "Integration ID", "description": "primary key"}',
            'identity_columns:\n  - {"name": "assignee", "description": "collides"}',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("collide" in e.lower() for e in exc.value.errors)

    def test_step_kind_invalid_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace("kind: data", "kind: bogus", 1)
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("bogus" in e for e in exc.value.errors)

    def test_data_step_without_setter_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            "    setter: set-assignee\n",
            "    setter: null\n",
            1,
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("setter" in e for e in exc.value.errors)

    def test_checkpoint_step_with_setter_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            '  - name: "manifest"\n'
            '    kind: checkpoint\n'
            '    optional: false\n'
            '    setter: null\n',
            '  - name: "manifest"\n'
            '    kind: checkpoint\n'
            '    optional: false\n'
            '    setter: set-manifest\n',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("setter must be null" in e or "set-manifest" in e for e in exc.value.errors)

    def test_duplicate_step_name_rejected(self, tmp_path) -> None:
        # Rename "parity passes" -> "manifest" so two steps share that name.
        body = MINIMAL_VALID_YAML.replace('"parity passes"', '"manifest"')
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("duplicate step name" in e for e in exc.value.errors)

    def test_duplicate_setter_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            "    setter: set-parity",
            "    setter: set-assignee",  # collide with first step's setter
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("duplicate setter" in e for e in exc.value.errors)

    def test_unknown_json_schema_name_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            '    setter: set-assignee\n'
            '    cascade_on_set: false\n',
            '    setter: set-assignee\n'
            '    cascade_on_set: false\n'
            '    json_schema: {"validator": "definitely_unknown"}\n',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("definitely_unknown" in e for e in exc.value.errors)

    def test_unknown_cross_check_name_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            '    setter: set-assignee\n'
            '    cascade_on_set: false\n',
            '    setter: set-assignee\n'
            '    cascade_on_set: false\n'
            '    cross_check: {"validator": "no_such_check"}\n',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("no_such_check" in e for e in exc.value.errors)

    def test_markers_check_must_be_in_done_values(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'checkpoint_done_values: ["✅", "N/A"]',
            'checkpoint_done_values: ["N/A"]',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("✅" in e for e in exc.value.errors)

    def test_step_interaction_unknown_step_rejected(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'when_step: "needs parity"',
            'when_step: "ghost step"',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("ghost step" in e for e in exc.value.errors)

    def test_step_interaction_when_step_must_be_flag(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'when_step: "needs parity"',
            'when_step: "manifest"',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("must be" in e and "flag" in e for e in exc.value.errors)

    def test_step_interaction_target_step_must_be_checkpoint(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'target_step: "parity passes"',
            'target_step: "needs parity"',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("checkpoint" in e for e in exc.value.errors)

    def test_step_interaction_when_value_in_must_be_subset(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'when_value_in: ["NO", "N/A"]',
            'when_value_in: ["INVALID"]',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("INVALID" in e for e in exc.value.errors)

    def test_step_interaction_write_value_must_be_in_done_values(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML.replace(
            'write_value: "N/A"',
            'write_value: "GARBAGE"',
        )
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert any("GARBAGE" in e for e in exc.value.errors)

    def test_multi_error_collection(self, tmp_path) -> None:
        # Three problems at once.
        body = MINIMAL_VALID_YAML
        body = body.replace("schema_version: 1", "schema_version: 42")
        body = body.replace("kind: data", "kind: bogus", 1)
        body = body + "\nrandom_extra_key: x\n"
        p = _write_yaml(tmp_path, body)
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert len(exc.value.errors) >= 3


# ---------------------------------------------------------------------------
# Cascade-on-set defaulting
# ---------------------------------------------------------------------------

class TestCascadeOnSet:
    def test_default_true_when_unspecified(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML
        p = _write_yaml(tmp_path, body)
        cfg = load_config(p)
        # Step 2 ("manifest") doesn't specify cascade_on_set; default is True.
        assert cfg.step_by_name["manifest"].cascade_on_set is True

    def test_explicit_false_on_assignee(self, tmp_path) -> None:
        body = MINIMAL_VALID_YAML
        p = _write_yaml(tmp_path, body)
        cfg = load_config(p)
        assert cfg.step_by_name["assignee"].cascade_on_set is False
