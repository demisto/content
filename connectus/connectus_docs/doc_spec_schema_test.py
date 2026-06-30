"""Schema tests for the OPTIONAL connection.profiles[] fragment (§8.3a.2).

Validates a doc-spec directly against doc-spec.schema.json (Draft7) so the
``anyOf`` (at-least-one of title/description) and ``additionalProperties: false``
rules on the new ``connection.profiles`` array are exercised independently of the
custom §9 rules. Run from the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest doc_spec_schema_test.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, os.path.dirname(__file__))

_SCHEMA_PATH = Path(__file__).resolve().parent / "doc-spec.schema.json"


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _base_spec() -> dict:
    """A minimal schema-valid doc-spec (no connection.profiles by default)."""
    return {
        "connector_slug": "demo",
        "members": [{"integration_id": "Demo One", "view_group_id": "demo-one"}],
        "connector": {"description": "A demo connector description."},
        "capabilities": {
            "items": [{"id": "automation-and-remediation", "description": "x"}]
        },
        "connection": {
            "view_groups": [
                {"id": "demo-one", "label": "Demo One", "help_text": "Help."}
            ]
        },
        "configurations": {"view_groups": []},
        "summary": {"metadata": {"next_steps": None}},
    }


def _errors(spec: dict):
    validator = jsonschema.Draft7Validator(_schema())
    return list(validator.iter_errors(spec))


def test_schema_accepts_connection_profiles_title_only():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo", "title": "API Key"}]
    assert _errors(spec) == []


def test_schema_accepts_connection_profiles_description_only():
    spec = _base_spec()
    spec["connection"]["profiles"] = [
        {"id": "plain.demo", "description": "Authenticate to the demo service."}
    ]
    assert _errors(spec) == []


def test_schema_rejects_connection_profiles_id_only():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo"}]
    assert _errors(spec)  # anyOf (title|description) violated


def test_schema_rejects_connection_profiles_unknown_field():
    spec = _base_spec()
    spec["connection"]["profiles"] = [
        {"id": "plain.demo", "title": "API Key", "color": "red"}
    ]
    assert _errors(spec)  # additionalProperties: false


def test_schema_accepts_missing_connection_profiles_key():
    spec = _base_spec()
    assert "profiles" not in spec["connection"]
    assert _errors(spec) == []


# --------------------------------------------------------------------------- #
# 8.3a.2 / 8.3a.5 - description (and symmetric title) string | null sentinel
# --------------------------------------------------------------------------- #
def test_schema_accepts_connection_profile_description_null():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo", "description": None}]
    assert _errors(spec) == []


def test_schema_accepts_connection_profile_description_string():
    spec = _base_spec()
    spec["connection"]["profiles"] = [
        {"id": "plain.demo", "description": "Authenticate to the demo service."}
    ]
    assert _errors(spec) == []


def test_schema_accepts_id_only_with_description_null_entry():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo", "description": None}]
    assert _errors(spec) == []


def test_schema_rejects_connection_profile_id_only_no_keys():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo"}]
    assert _errors(spec)


def test_schema_rejects_connection_profile_description_empty_string():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo", "description": ""}]
    assert _errors(spec)


def test_schema_accepts_connection_profile_title_null():
    spec = _base_spec()
    spec["connection"]["profiles"] = [{"id": "plain.demo", "title": None}]
    assert _errors(spec) == []


# --------------------------------------------------------------------------- #
# §9.13a help_text string | null, non-required (§8.3b)
# --------------------------------------------------------------------------- #
def test_schema_accepts_connection_help_text_string():
    spec = _base_spec()
    spec["connection"]["view_groups"][0]["help_text"] = "Substantive guidance."
    assert _errors(spec) == []


def test_schema_accepts_connection_help_text_null():
    spec = _base_spec()
    spec["connection"]["view_groups"][0]["help_text"] = None
    assert _errors(spec) == []


def test_schema_accepts_omitted_connection_view_group():
    spec = _base_spec()
    # No help_text key at all on the member view_group (help_text non-required).
    spec["connection"]["view_groups"] = [{"id": "demo-one", "label": "Demo One"}]
    assert _errors(spec) == []


def test_schema_rejects_connection_help_text_empty_string():
    spec = _base_spec()
    spec["connection"]["view_groups"][0]["help_text"] = ""
    assert _errors(spec)  # fails minLength:1, not null


def test_schema_accepts_config_help_text_null_and_omitted():
    # null on a config view_group.
    spec_null = _base_spec()
    spec_null["configurations"]["view_groups"] = [
        {"id": "demo-one", "label": "Demo One", "help_text": None}
    ]
    assert _errors(spec_null) == []
    # omitted help_text key on a config view_group.
    spec_omit = _base_spec()
    spec_omit["configurations"]["view_groups"] = [
        {"id": "demo-one", "label": "Demo One"}
    ]
    assert _errors(spec_omit) == []
