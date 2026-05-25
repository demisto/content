"""Tests for the per-cell validators registered in
:mod:`workflow_state.validators`.

Currently exercises :func:`validate_shadowed_commands`. Other
validators have historically been exercised indirectly via the CLI tests
and via :mod:`auth_config_parser.tests`; we add direct-validator
coverage here as new validators are introduced.
"""
from __future__ import annotations

import pytest

from workflow_state.validators import validate_shadowed_commands


class TestValidateShadowedCommands:
    """Cover :func:`validate_shadowed_commands` schema rules."""

    def test_empty_object_is_valid(self) -> None:
        assert validate_shadowed_commands("{}") == []

    def test_valid_single_entry(self) -> None:
        assert validate_shadowed_commands('{"foo": "foo-mybrand"}') == []

    def test_valid_multi_entry(self) -> None:
        raw = '{"foo": "foo-mybrand", "bar-baz": "bar-baz-mybrand"}'
        assert validate_shadowed_commands(raw) == []

    def test_invalid_json_returns_parse_error(self) -> None:
        errs = validate_shadowed_commands("{not json")
        assert len(errs) == 1
        assert errs[0].startswith("invalid JSON")

    @pytest.mark.parametrize("raw", ['[]', '"x"', '5', 'true', 'null'])
    def test_non_object_top_level_rejected(self, raw: str) -> None:
        errs = validate_shadowed_commands(raw)
        assert errs == ["top-level value must be a JSON object"]

    def test_empty_string_key_rejected(self) -> None:
        errs = validate_shadowed_commands('{"": "foo-brand"}')
        assert any("non-empty string" in e for e in errs)

    def test_empty_string_value_rejected(self) -> None:
        errs = validate_shadowed_commands('{"foo": ""}')
        assert any("non-empty string" in e for e in errs)

    def test_renamed_missing_prefix_rejected(self) -> None:
        # Does not start with "foo-".
        errs = validate_shadowed_commands('{"foo": "bar-brand"}')
        assert any("must equal '<original>-<brand>'" in e for e in errs)

    def test_renamed_with_empty_brand_suffix_rejected(self) -> None:
        # "foo-" — starts with prefix but brand is empty.
        errs = validate_shadowed_commands('{"foo": "foo-"}')
        assert any("must equal '<original>-<brand>'" in e for e in errs)

    def test_two_keys_mapping_to_same_renamed_rejected(self) -> None:
        # Construct a pathological case where two distinct originals
        # happen to map to the same renamed value. Choose keys such that
        # the prefix check still passes for both.
        # Example: original "foo" with brand "brand-foo" → "foo-brand-foo".
        # Original "foo-brand" with brand "foo" → "foo-brand-foo".
        raw = '{"foo": "foo-brand-foo", "foo-brand": "foo-brand-foo"}'
        errs = validate_shadowed_commands(raw)
        assert any("duplicate renamed value" in e for e in errs)

    def test_renamed_with_disallowed_chars_rejected(self) -> None:
        errs = validate_shadowed_commands('{"foo": "foo-my brand"}')
        assert any("disallowed characters" in e for e in errs)
