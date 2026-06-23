"""Tests for the per-cell validators registered in
:mod:`workflow_state.validators`.

Currently exercises :func:`validate_shadowed_commands`. Other
validators have historically been exercised indirectly via the CLI tests
and via :mod:`auth_config_parser.tests`; we add direct-validator
coverage here as new validators are introduced.
"""
from __future__ import annotations

import pytest

from workflow_state.validators import (
    validate_release_notes,
    validate_shadowed_commands,
)


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


class TestValidateReleaseNotes:
    """Cover :func:`validate_release_notes` schema rules.

    Added 2026-05-31 with the new Release Notes workflow step (FIXES-TODO
    combined #4+#6+New_RN execution plan).
    """

    def test_valid_required_with_path_and_verified(self) -> None:
        raw = (
            '{"required": true, '
            '"path": "Packs/MyPack/ReleaseNotes/1_2_3.md", '
            '"verified": true}'
        )
        assert validate_release_notes(raw) == []

    def test_valid_required_with_path_but_not_yet_verified(self) -> None:
        raw = (
            '{"required": true, '
            '"path": "Packs/MyPack/ReleaseNotes/1_2_3.md", '
            '"verified": false}'
        )
        assert validate_release_notes(raw) == []

    def test_valid_not_required(self) -> None:
        raw = '{"required": false, "path": null, "verified": false}'
        assert validate_release_notes(raw) == []

    def test_invalid_json_returns_parse_error(self) -> None:
        errs = validate_release_notes("{not json")
        assert errs and "Invalid JSON" in errs[0]

    def test_top_level_must_be_object(self) -> None:
        errs = validate_release_notes('["a","b"]')
        assert errs and "Expected a JSON object" in errs[0]

    def test_extra_keys_rejected(self) -> None:
        raw = (
            '{"required": true, "path": "x", "verified": true, '
            '"extra": "key"}'
        )
        errs = validate_release_notes(raw)
        assert any("Unexpected top-level keys" in e for e in errs)

    def test_missing_keys_rejected(self) -> None:
        errs = validate_release_notes('{"required": true}')
        assert any("Missing required keys" in e for e in errs)

    def test_required_not_bool_rejected(self) -> None:
        raw = '{"required": "yes", "path": "x", "verified": true}'
        errs = validate_release_notes(raw)
        assert any("'required' must be a boolean" in e for e in errs)

    def test_verified_not_bool_rejected(self) -> None:
        raw = '{"required": true, "path": "x", "verified": "yes"}'
        errs = validate_release_notes(raw)
        assert any("'verified' must be a boolean" in e for e in errs)

    def test_path_not_string_or_null_rejected(self) -> None:
        raw = '{"required": true, "path": 42, "verified": false}'
        errs = validate_release_notes(raw)
        assert any("'path' must be a string or null" in e for e in errs)

    def test_required_true_without_path_rejected(self) -> None:
        raw = '{"required": true, "path": null, "verified": false}'
        errs = validate_release_notes(raw)
        assert any(
            "When 'required' is true, 'path' must be a non-empty string" in e
            for e in errs
        )

    def test_required_true_empty_path_rejected(self) -> None:
        raw = '{"required": true, "path": "", "verified": false}'
        errs = validate_release_notes(raw)
        assert any(
            "When 'required' is true, 'path' must be a non-empty string" in e
            for e in errs
        )

    def test_required_false_with_path_rejected(self) -> None:
        raw = '{"required": false, "path": "Packs/.../x.md", "verified": false}'
        errs = validate_release_notes(raw)
        assert any(
            "When 'required' is false, 'path' must be null" in e for e in errs
        )

    def test_required_false_with_verified_rejected(self) -> None:
        raw = '{"required": false, "path": null, "verified": true}'
        errs = validate_release_notes(raw)
        assert any(
            "When 'required' is false, 'verified' must be false" in e
            for e in errs
        )
