"""Unit tests for apply_doc_spec (stage E).

Hermetic: builds a connector folder under tmp_path, points resolve_connector at
it, and exercises dry-run / write / idempotency / comment-preservation. Run from
the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest apply_doc_spec_test.py
"""

from __future__ import annotations

import os
import sys
import textwrap

import pytest
from ruamel.yaml import YAML

sys.path.insert(0, os.path.dirname(__file__))

import apply_doc_spec  # noqa: E402
from apply_doc_spec import CANONICAL_METADATA  # noqa: E402
from apply_doc_spec import apply_doc_spec as run_apply  # noqa: E402
from apply_doc_spec import normalize_help_text_markdown  # noqa: E402
from resolvers import resolve_connector  # noqa: E402


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


@pytest.fixture
def connector(tmp_path, monkeypatch):
    """A connector folder with placeholder metadata + one capability + 1 vg."""
    folder = tmp_path / "connectors" / "demo"
    _write(
        folder / "connector.yaml",
        """
        # yaml-language-server: $schema=../../schema/connector.schema.json
        id: demo
        enabled: true
        metadata:
          title: Demo
          description: placeholder lowercase desc.
        settings:
          grouped: true
        """,
    )
    _write(
        folder / "capabilities.yaml",
        """
        # yaml-language-server: $schema=../../schema/capabilities.schema.json
        metadata:
          title: Capabilities
          description: Configure the capabilities for this instance
        capabilities:
        - id: automation-and-remediation
          title: Automation and Remediation
          description: Old placeholder description.
          sub_capabilities:
          - id: automation-and-remediation_demo
            title: Demo
        """,
    )
    _write(
        folder / "connection.yaml",
        """
        # yaml-language-server: $schema=../../schema/connection.schema.json
        metadata:
          title: Connection
          description: WRONG placeholder
        view_groups:
        - id: demo-one
          label: Demo One
          help_text: placeholder help
        profiles:
        - id: plain.demo
          type: plain
          view_group: demo-one
          title: Old Title  # inline comment to preserve
          description: Old passthrough description.
        - id: api_key.demo
          type: api_key
          view_group: demo-one
        """,
    )
    _write(
        folder / "configurations.yaml",
        """
        # yaml-language-server: $schema=../../schema/configurations.schema.json
        metadata:
          title: Configuration
          description: WRONG placeholder
        view_groups:
        - id: demo-one
          label: Demo One
          help_text: placeholder config help
        """,
    )
    _write(
        folder / "summary.yaml",
        """
        # yaml-language-server: $schema=../../schema/summary.schema.json
        metadata:
          title: Summary
          description: Summary for connector Demo
        """,
    )

    # Point the real resolve_connector at the fixture's connectors root.
    import resolvers
    monkeypatch.setattr(resolvers, "connectors_root", lambda: tmp_path / "connectors")
    monkeypatch.setattr(apply_doc_spec, "resolve_connector", resolvers.resolve_connector)
    return folder


def _spec(next_steps=None, with_config=True):
    spec = {
        "connector_slug": "demo",
        "members": [{"integration_id": "Demo One", "view_group_id": "demo-one"}],
        "connector": {"description": "Demo connector for security operations and automation."},
        "capabilities": {"items": [{"id": "automation-and-remediation", "description": "ignored"}]},
        "connection": {
            "view_groups": [
                {"id": "demo-one", "label": "Demo One",
                 "help_text": "Generate an API key in the [Demo console](https://demo.example.com)."}
            ]
        },
        "configurations": {"view_groups": []},
        "summary": {"metadata": {"next_steps": next_steps}},
    }
    if with_config:
        spec["configurations"]["view_groups"] = [
            {"id": "demo-one", "label": "Demo One", "help_text": "Set the fetch interval."}
        ]
    return spec


def _read(folder, name):
    return (folder / name).read_text(encoding="utf-8")


def _load(folder, name):
    return YAML().load(_read(folder, name))


# --------------------------------------------------------------------------- #
# Dry-run vs write
# --------------------------------------------------------------------------- #
def test_dry_run_writes_nothing(connector):
    before = _read(connector, "connector.yaml")
    result = run_apply("demo", _spec(), write=False)
    assert result.written is False
    assert result.changed_files  # there ARE pending changes
    assert _read(connector, "connector.yaml") == before  # but file unchanged


def test_apply_writes_files(connector):
    result = run_apply("demo", _spec(), write=True)
    assert result.written is True
    assert not result.errors


# --------------------------------------------------------------------------- #
# Content correctness
# --------------------------------------------------------------------------- #
def test_connector_description_overridden(connector):
    run_apply("demo", _spec(), write=True)
    doc = _load(connector, "connector.yaml")
    assert doc["metadata"]["description"].startswith("Demo connector for security")


def test_canonical_metadata_silently_set(connector):
    run_apply("demo", _spec(), write=True)
    for name, key in (
        ("capabilities.yaml", "capabilities"),
        ("connection.yaml", "connection"),
        ("configurations.yaml", "configurations"),
        ("summary.yaml", "summary"),
    ):
        doc = _load(connector, name)
        title, desc = CANONICAL_METADATA[key]
        assert doc["metadata"]["title"] == title
        assert doc["metadata"]["description"] == desc


def test_capability_description_from_table(connector):
    run_apply("demo", _spec(), write=True)
    doc = _load(connector, "capabilities.yaml")
    cap = doc["capabilities"][0]
    assert cap["description"] == (
        "Run automated actions and remediation commands against the connected service."
    )
    # sub_capabilities are untouched (no description added).
    assert "description" not in cap["sub_capabilities"][0]


def test_connection_help_text_applied(connector):
    run_apply("demo", _spec(), write=True)
    doc = _load(connector, "connection.yaml")
    assert "[Demo console](https://demo.example.com)" in doc["view_groups"][0]["help_text"]


def test_config_help_applied_when_present(connector):
    run_apply("demo", _spec(with_config=True), write=True)
    doc = _load(connector, "configurations.yaml")
    # Emitted as a literal block scalar (clip style), so a single trailing
    # newline is preserved; the Markdown content is what matters.
    assert doc["view_groups"][0]["help_text"].rstrip("\n") == "Set the fetch interval."


def test_config_help_untouched_when_absent(connector):
    before = _load(connector, "configurations.yaml")["view_groups"][0]["help_text"]
    run_apply("demo", _spec(with_config=False), write=True)
    after = _load(connector, "configurations.yaml")["view_groups"][0]["help_text"]
    assert after == before  # placeholder left as-is (§8.4 optional)


# --------------------------------------------------------------------------- #
# next_steps add/remove (§8.5)
# --------------------------------------------------------------------------- #
def test_next_steps_added_when_provided(connector):
    run_apply("demo", _spec(next_steps="Enable fetching."), write=True)
    doc = _load(connector, "summary.yaml")
    assert doc["metadata"]["next_steps"] == "Enable fetching."


def test_next_steps_absent_by_default(connector):
    run_apply("demo", _spec(next_steps=None), write=True)
    doc = _load(connector, "summary.yaml")
    assert "next_steps" not in doc["metadata"]


# --------------------------------------------------------------------------- #
# Round-trip + idempotency
# --------------------------------------------------------------------------- #
def test_schema_comment_preserved(connector):
    run_apply("demo", _spec(), write=True)
    assert _read(connector, "connector.yaml").startswith("# yaml-language-server:")
    assert "# yaml-language-server:" in _read(connector, "capabilities.yaml")


def test_idempotent_second_apply_no_change(connector):
    run_apply("demo", _spec(), write=True)
    snapshot = {n: _read(connector, n) for n in (
        "connector.yaml", "capabilities.yaml", "connection.yaml",
        "configurations.yaml", "summary.yaml")}
    result2 = run_apply("demo", _spec(), write=True)
    assert result2.changed_files == []  # nothing changes the second time
    for n, text in snapshot.items():
        assert _read(connector, n) == text


def test_unknown_capability_id_errors_and_aborts(connector):
    spec = _spec()
    spec["capabilities"]["items"] = [{"id": "ghost-capability", "description": "x"}]
    # Inject an unknown id into the on-disk capabilities so the table lookup fails.
    cap_path = connector / "capabilities.yaml"
    text = cap_path.read_text(encoding="utf-8").replace(
        "automation-and-remediation\n", "ghost-capability\n", 1
    )
    cap_path.write_text(text, encoding="utf-8")
    before = cap_path.read_text(encoding="utf-8")
    result = run_apply("demo", spec, write=True)
    assert result.errors
    assert result.written is False
    assert cap_path.read_text(encoding="utf-8") == before  # aborted, no write


# --------------------------------------------------------------------------- #
# normalize_help_text_markdown (tooltip renderer blank-line fix)
# --------------------------------------------------------------------------- #
class TestNormalizeHelpText:
    def test_blank_line_before_ordered_list_after_heading(self):
        src = "## API keys generating steps\n1. First\n2. Second"
        out = normalize_help_text_markdown(src)
        assert out == "## API keys generating steps\n\n1. First\n2. Second"

    def test_blank_line_before_list_after_paragraph(self):
        src = "Enter your credentials:\n- Username\n- Password"
        out = normalize_help_text_markdown(src)
        assert out == "Enter your credentials:\n\n- Username\n- Password"

    def test_blank_line_before_heading_after_paragraph(self):
        src = "Intro paragraph.\n## Heading"
        out = normalize_help_text_markdown(src)
        assert out == "Intro paragraph.\n\n## Heading"

    def test_existing_blank_line_preserved_idempotent(self):
        src = "Intro.\n\n1. First\n2. Second"
        assert normalize_help_text_markdown(src) == src
        assert normalize_help_text_markdown(normalize_help_text_markdown(src)) == src

    def test_list_items_not_separated_from_each_other(self):
        src = "Intro.\n\n1. First\n2. Second\n3. Third"
        out = normalize_help_text_markdown(src)
        assert "1. First\n2. Second\n3. Third" in out

    def test_plain_paragraph_untouched(self):
        src = "Just a single paragraph with a [link](https://x.example.com)."
        assert normalize_help_text_markdown(src) == src

    def test_links_and_code_preserved(self):
        src = "## Steps\n1. [Open](https://control.akamai.com/) and login.\n2. Use `menu`."
        out = normalize_help_text_markdown(src)
        assert "[Open](https://control.akamai.com/)" in out
        assert "`menu`" in out
        assert "## Steps\n\n1. " in out

    def test_empty_string(self):
        assert normalize_help_text_markdown("") == ""

    def test_normalizer_runs_during_apply(self, connector):
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = (
            "## Steps\n1. Do a thing.\n2. Do another."
        )
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        assert "## Steps\n\n1. Do a thing." in doc["view_groups"][0]["help_text"]

    def test_help_text_serialized_as_block_scalar(self, connector):
        """help_text must be a YAML literal block scalar (``|``) with REAL line
        breaks — NOT a double-quoted scalar with literal ``\\n`` escapes, which
        the tooltip renderer would show verbatim (matches salesforce-example)."""
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = (
            "## Steps\n1. Do a thing.\n2. Do another."
        )
        run_apply("demo", spec, write=True)
        raw = _read(connector, "connection.yaml")
        # Block-scalar marker present; literal backslash-n NOT present in source.
        assert "help_text: |" in raw
        assert "\\n" not in raw
        # The numbered list lines appear as real, separate lines in the file.
        assert "\n    1. Do a thing." in raw

    def test_block_scalar_idempotent_second_apply(self, connector):
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = (
            "## Steps\n1. Do a thing.\n2. Do another."
        )
        run_apply("demo", spec, write=True)
        first = _read(connector, "connection.yaml")
        result = run_apply("demo", spec, write=True)
        assert _read(connector, "connection.yaml") == first
        assert "connection.yaml" not in {os.path.basename(f) for f in result.changed_files}


# --------------------------------------------------------------------------- #
# _apply_profiles (§8.3a.4)
# --------------------------------------------------------------------------- #
def _spec_with_profiles(profiles):
    spec = _spec()
    spec["connection"]["profiles"] = profiles
    return spec


class TestApplyProfiles:
    def test_apply_profiles_sets_only_provided_fields(self, connector):
        # description-only entry: description changes, title untouched.
        spec = _spec_with_profiles(
            [{"id": "plain.demo", "description": "Authenticate with an API token."}]
        )
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        prof = next(p for p in doc["profiles"] if p["id"] == "plain.demo")
        assert prof["description"] == "Authenticate with an API token."
        assert prof["title"] == "Old Title"  # left exactly as-is

        # title-only entry on a fresh apply: title changes, description untouched.
        spec2 = _spec_with_profiles([{"id": "plain.demo", "title": "API Token"}])
        run_apply("demo", spec2, write=True)
        doc2 = _load(connector, "connection.yaml")
        prof2 = next(p for p in doc2["profiles"] if p["id"] == "plain.demo")
        assert prof2["title"] == "API Token"
        # description unchanged from the first apply.
        assert prof2["description"] == "Authenticate with an API token."

    def test_apply_profiles_leaves_omitted_profiles_untouched(self, connector):
        before = _read(connector, "connection.yaml")
        # Only touch api_key.demo; plain.demo (with its inline comment) is omitted.
        spec = _spec_with_profiles([{"id": "api_key.demo", "title": "API Key"}])
        run_apply("demo", spec, write=True)
        after = _read(connector, "connection.yaml")
        # plain.demo's inline comment survives untouched.
        assert "inline comment to preserve" in after
        assert "Old Title" in after
        assert "Old passthrough description." in after

    def test_apply_profiles_unknown_id_appends_error_and_aborts(self, connector):
        before = _read(connector, "connection.yaml")
        spec = _spec_with_profiles([{"id": "ghost.profile", "title": "Token"}])
        result = run_apply("demo", spec, write=True)
        assert result.errors
        assert any("ghost.profile" in e for e in result.errors)
        assert result.written is False
        assert _read(connector, "connection.yaml") == before  # aborted, no write

    def test_apply_profiles_idempotent_second_apply_no_change(self, connector):
        spec = _spec_with_profiles(
            [{"id": "plain.demo", "title": "API Token", "description": "Use an API token."}]
        )
        run_apply("demo", spec, write=True)
        first = _read(connector, "connection.yaml")
        result = run_apply("demo", spec, write=True)
        assert _read(connector, "connection.yaml") == first
        assert "connection.yaml" not in {
            os.path.basename(f) for f in result.changed_files
        }

    def test_apply_profiles_writes_plain_scalar_not_block(self, connector):
        spec = _spec_with_profiles(
            [
                {
                    "id": "plain.demo",
                    "title": "API Token",
                    "description": "Authenticate using an API token.",
                }
            ]
        )
        run_apply("demo", spec, write=True)
        raw = _read(connector, "connection.yaml")
        # Plain inline scalar — no block-scalar indicators, no escaped newlines.
        assert "description: |" not in raw
        assert "title: |" not in raw
        assert "\\n" not in raw
        assert "description: Authenticate using an API token." in raw

    def test_apply_profiles_round_trip_preserves_comments(self, connector):
        spec = _spec_with_profiles(
            [{"id": "plain.demo", "description": "Authenticate using an API token."}]
        )
        run_apply("demo", spec, write=True)
        raw = _read(connector, "connection.yaml")
        # The schema comment AND the inline profile comment both survive.
        assert raw.startswith("# yaml-language-server:")
        assert "inline comment to preserve" in raw

    def test_apply_profiles_description_null_deletes_existing_key(self, connector):
        # plain.demo has a description on disk; null removes the key (§8.3a.5).
        spec = _spec_with_profiles([{"id": "plain.demo", "description": None}])
        result = run_apply("demo", spec, write=True)
        assert not result.errors
        doc = _load(connector, "connection.yaml")
        prof = next(p for p in doc["profiles"] if p["id"] == "plain.demo")
        assert "description" not in prof
        # title untouched (key absent in entry).
        assert prof["title"] == "Old Title"

    def test_apply_profiles_description_null_idempotent_second_apply_no_change(
        self, connector
    ):
        spec = _spec_with_profiles([{"id": "plain.demo", "description": None}])
        run_apply("demo", spec, write=True)
        first = _read(connector, "connection.yaml")
        result = run_apply("demo", spec, write=True)
        assert _read(connector, "connection.yaml") == first
        assert "connection.yaml" not in {
            os.path.basename(f) for f in result.changed_files
        }

    def test_apply_profiles_description_null_on_absent_key_is_noop(self, connector):
        # api_key.demo has NO description on disk; null delete is a no-op (not an
        # error) and the profile gains no description key.
        spec = _spec_with_profiles([{"id": "api_key.demo", "description": None}])
        result = run_apply("demo", spec, write=True)
        assert not result.errors
        doc = _load(connector, "connection.yaml")
        prof = next(p for p in doc["profiles"] if p["id"] == "api_key.demo")
        assert "description" not in prof
        # Re-applying the same null delete is idempotent (file unchanged).
        first = _read(connector, "connection.yaml")
        run_apply("demo", spec, write=True)
        assert _read(connector, "connection.yaml") == first

    def test_apply_profiles_description_omitted_leaves_existing_untouched(
        self, connector
    ):
        # Entry sets only title; the existing description key is left intact.
        spec = _spec_with_profiles([{"id": "plain.demo", "title": "API Token"}])
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        prof = next(p for p in doc["profiles"] if p["id"] == "plain.demo")
        assert prof["title"] == "API Token"
        assert prof["description"] == "Old passthrough description."

    def test_apply_profiles_description_string_and_null_mixed(self, connector):
        # One profile gets a string description; another gets its description
        # nulled (deleted) in the same apply.
        spec = _spec_with_profiles(
            [
                {"id": "plain.demo", "description": None},
                {"id": "api_key.demo", "description": "Authenticate with an API key."},
            ]
        )
        result = run_apply("demo", spec, write=True)
        assert not result.errors
        doc = _load(connector, "connection.yaml")
        plain = next(p for p in doc["profiles"] if p["id"] == "plain.demo")
        api = next(p for p in doc["profiles"] if p["id"] == "api_key.demo")
        assert "description" not in plain
        assert api["description"] == "Authenticate with an API key."


# --------------------------------------------------------------------------- #
# help_text three states: string (set) / null (delete) / absent (untouched)
# (§8.3b / §9.13b)
# --------------------------------------------------------------------------- #
class TestApplyHelpTextStates:
    def test_apply_help_text_string_sets_block_scalar(self, connector):
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = (
            "## Steps\n1. Do a thing.\n2. Do another."
        )
        run_apply("demo", spec, write=True)
        raw = _read(connector, "connection.yaml")
        assert "help_text: |" in raw
        doc = _load(connector, "connection.yaml")
        assert "## Steps" in doc["view_groups"][0]["help_text"]

    def test_apply_help_text_null_deletes_existing_key(self, connector):
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = None
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        assert "help_text" not in doc["view_groups"][0]

    def test_apply_help_text_null_idempotent_second_apply_no_change(self, connector):
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = None
        run_apply("demo", spec, write=True)
        first = _read(connector, "connection.yaml")
        result = run_apply("demo", spec, write=True)
        assert _read(connector, "connection.yaml") == first
        assert "connection.yaml" not in {
            os.path.basename(f) for f in result.changed_files
        }

    def test_apply_help_text_null_on_absent_key_is_noop(self, connector):
        # First removal deletes the key; a fresh apply on the now-absent key is a no-op.
        spec = _spec()
        spec["connection"]["view_groups"][0]["help_text"] = None
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        assert "help_text" not in doc["view_groups"][0]
        # Apply null again — no error, no change.
        result = run_apply("demo", spec, write=True)
        assert not result.errors
        doc2 = _load(connector, "connection.yaml")
        assert "help_text" not in doc2["view_groups"][0]

    def test_apply_omitted_view_group_leaves_help_text_untouched(self, connector):
        before = _load(connector, "connection.yaml")["view_groups"][0]["help_text"]
        spec = _spec()
        # No view_group entries -> connector help_text left exactly as-is.
        spec["connection"]["view_groups"] = []
        run_apply("demo", spec, write=True)
        after = _load(connector, "connection.yaml")["view_groups"][0]["help_text"]
        assert after == before

    def test_apply_help_text_null_and_string_mixed(self, connector):
        # Two view_groups: one set to a string (overwrite), one to null (delete).
        # Add a second view_group to the connector connection.yaml.
        conn_path = connector / "connection.yaml"
        text = conn_path.read_text(encoding="utf-8").replace(
            "view_groups:\n",
            "view_groups:\n"
            "- id: demo-two\n"
            "  label: Demo Two\n"
            "  help_text: placeholder two\n",
            1,
        )
        conn_path.write_text(text, encoding="utf-8")

        spec = _spec()
        spec["members"].append(
            {"integration_id": "Demo Two", "view_group_id": "demo-two"}
        )
        spec["connection"]["view_groups"] = [
            {"id": "demo-one", "label": "Demo One", "help_text": "Real guidance here."},
            {"id": "demo-two", "label": "Demo Two", "help_text": None},
        ]
        run_apply("demo", spec, write=True)
        doc = _load(connector, "connection.yaml")
        by_id = {vg["id"]: vg for vg in doc["view_groups"]}
        assert "Real guidance here." in by_id["demo-one"]["help_text"]
        assert "help_text" not in by_id["demo-two"]
