"""Unit tests for ``demisto_sdk.scripts.manifest_generator``.

Covers the connector.yaml-generation logic introduced in the first iteration:
helper functions plus the two dispatch entry points
(:func:`create_manifest_from_scratch` and
:func:`add_handler_to_existing_connector`).
"""

import json
from pathlib import Path

import pytest
import yaml
from manifest_generator import (
    ASSETSFETCHINTERVAL_FALLBACK_DEFAULT,
    ASSETSFETCHINTERVAL_PARAM_NAME,
    CANONICAL_CAPABILITY_DESCRIPTIONS,
    CAPABILITIES_SCHEMA_DIRECTIVE,
    DURATION_UNITS,
    EVENTFETCHINTERVAL_FALLBACK_DEFAULT,
    EVENTFETCHINTERVAL_PARAM_NAME,
    FEED_BYPASS_EXCLUSION_ADDITIONAL_INFO,
    FEED_EXPIRATION_POLICY_DEFAULT,
    FEED_EXPIRATION_POLICY_VALUES,
    FEED_RELIABILITY_ADDITIONAL_INFO,
    FEED_RELIABILITY_DEFAULT,
    FEED_REPUTATION_ADDITIONAL_INFO,
    FEED_REPUTATION_DEFAULT,
    INCIDENTFETCHINTERVAL_PARAM_NAME,
    INCIDENTTYPE_PARAM_NAME,
    INDICATOR_REPUTATION_VALUES,
    ISFETCH_PARAM_NAME,
    TRIGGERS_SCHEMA_DIRECTIVE,
    _minutes_to_duration_default,
    HANDLER_SCHEMA_DIRECTIVE,
    ISFETCHASSETS_PARAM_NAME,
    ISFETCHCREDENTIALS_PARAM_NAME,
    ISFETCHEVENTS_PARAM_NAME,
    add_assets_capability,
    add_connector_to_code_owners,
    add_fetch_issues_capability,
    add_handler_to_existing_connector,
    add_indicators_capability,
    add_log_collection_capability,
    add_secret_capability,
    CAPABILITY_ACTIONS,
    _actions_for_capability,
    append_capability_to_files,
    build_sub_capability_entry,
    make_sub_capability_id,
    handler_id_to_integration_slug,
    build_per_handler_general_config,
    build_default_ignore_capability_field,
    build_capabilities_yaml,
    build_configurations_yaml,
    build_connector_yaml,
    build_handler_yaml,
    build_summary_yaml,
    build_synthetic_hidden_toggle,
    build_triggers_yaml,
    build_fetch_mutex_triggers,
    collect_fetch_sub_cap_ids,
    _FETCH_MUTEX_BUCKET_KEYS,
    _FETCH_MUTEX_MESSAGE,
    collect_existing_field_ids,
    create_manifest_from_scratch,
    dedup_field_id_and_register,
    deep_merge_dicts,
    derive_connector_id_and_title,
    derive_connector_suffix,
    derive_handler_id,
    emit_field_for_param,
    find_existing_handler_for_capability,
    get_pack_tags,
    merge_general_configurations,
    merge_tags_case_insensitive,
    build_capability_gated_computed_field,
    register_computed_field_entry,
    register_renamed_field_serializer_entry,
    register_serializer_entry,
    SWEEP_EXCLUDED_PARAMS,
    collect_swept_hidden_default_params,
    connection_param_names_from_auth,
    sweep_hidden_defaults_to_serializer,
    assert_no_hidden_defaults_in_configurations,
    rename_handler_capability_id,
    slugify_capability_name,
    write_capabilities_yaml,
    write_handler_yaml,
    write_triggers_yaml,
    split_fields_blocks,
    normalize_connection_field_blocks,
    normalize_configurations_field_blocks,
)

import manifest_generator as _mg


# ---------------------------------------------------------------------------
# License-lookup test stub
# ---------------------------------------------------------------------------
# Licenses are resolved per sub-capability from
# sub_capabilities_to_licenses.json, and an unknown sub_capability_id is a
# hard RuntimeError. Most integration-flow tests use SYNTHETIC integration
# ids (e.g. "hello-world-iam") that are not in the real JSON, so this autouse
# fixture stubs the lookup to return the real value when present and a
# deterministic default otherwise. Tests that must exercise the REAL JSON /
# missing-id behavior opt out with @pytest.mark.no_license_stub.
_DEFAULT_STUB_LICENSES = ["agentix", "xsiam"]


@pytest.fixture(autouse=True)
def _stub_sub_capability_licenses(request, monkeypatch):
    if "no_license_stub" in request.keywords:
        return
    real_table = _mg._load_sub_capability_licenses()

    def _stub(sub_cap_id: str) -> list[str]:
        if sub_cap_id in real_table:
            return list(real_table[sub_cap_id])
        return list(_DEFAULT_STUB_LICENSES)

    monkeypatch.setattr(_mg, "licenses_for_sub_capability", _stub)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
def _make_pack_with_integration(
    base: Path,
    pack_name: str,
    integration_name: str,
    pack_metadata: dict | None,
) -> Path:
    """Build a fake ``Packs/<pack>/Integrations/<int>/<int>.yml`` tree.

    Optionally writes ``pack_metadata.json`` at the pack root if ``pack_metadata``
    is not ``None``. Returns the path to the integration YML file.
    """
    pack_root = base / "Packs" / pack_name
    integration_dir = pack_root / "Integrations" / integration_name
    integration_dir.mkdir(parents=True, exist_ok=True)
    integration_yml = integration_dir / f"{integration_name}.yml"
    integration_yml.write_text("name: dummy\n")
    if pack_metadata is not None:
        with open(pack_root / "pack_metadata.json", "w") as fh:
            json.dump(pack_metadata, fh)
    return integration_yml


# ---------------------------------------------------------------------------
# get_pack_tags
# ---------------------------------------------------------------------------
def test_get_pack_tags_returns_tags_from_metadata(tmp_path: Path) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["a", "b"]}
    )
    assert get_pack_tags(integration_yml) == ["a", "b"]


def test_get_pack_tags_returns_empty_when_metadata_missing(tmp_path: Path) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", pack_metadata=None
    )
    assert get_pack_tags(integration_yml) == []


def test_get_pack_tags_returns_empty_when_tags_field_missing(tmp_path: Path) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"name": "MyPack"}
    )
    assert get_pack_tags(integration_yml) == []


# ---------------------------------------------------------------------------
# merge_tags_case_insensitive
# ---------------------------------------------------------------------------
def test_merge_tags_case_insensitive_preserves_existing_casing_and_appends_new() -> None:
    result = merge_tags_case_insensitive(
        ["Forensics", "endpoint"], ["forensics", "Network", "ENDPOINT"]
    )
    assert result == ["Forensics", "endpoint", "Network"]


def test_merge_tags_case_insensitive_handles_empty_inputs() -> None:
    assert merge_tags_case_insensitive([], []) == []
    assert merge_tags_case_insensitive(["a"], []) == ["a"]
    assert merge_tags_case_insensitive([], ["b"]) == ["b"]
    assert merge_tags_case_insensitive(["a"], ["b", "c"]) == ["a", "b", "c"]

# ---------------------------------------------------------------------------
# create_manifest_from_scratch
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_correct_connector_yaml(
    tmp_path: Path,
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["forensics"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    connector_yaml_path = connector_dir / "connector.yaml"
    assert connector_yaml_path.is_file()

    with open(connector_yaml_path) as fh:
        data = yaml.safe_load(fh)
    assert data["id"] == "my-connector"
    metadata = data["metadata"]
    assert metadata["title"] == "My Connector"
    assert metadata["description"] == ""
    assert metadata["version"] == "1.0.0"
    # Per guide §3.3 + connector.schema: plural ``categories`` array (not
    # the singular ``category`` string). Defaults to empty list.
    assert metadata["categories"] == []
    assert list(metadata["tags"]) == ["forensics"]
    assert metadata["vendor"] == ""
    assert metadata["publisher"] == "Palo Alto Networks"
    # No --author-image-path provided → author_image defaults to ""
    assert metadata["author_image"] == ""
    assert metadata["ownership"]["team"] == "xsoar"
    assert list(metadata["ownership"]["maintainers"]) == ["@xsoar-content"]
    # Per guide §3.3: "Always true unless the vendor explicitly requires
    # successful verification".
    assert data["settings"]["allow_skip_verification"] is True
    # Emitted for every generated connector.
    assert data["settings"]["skip_cut_off_check"] is True


def test_create_manifest_from_scratch_creates_directory_if_missing(
    tmp_path: Path,
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "does" / "not" / "exist" / "myconnector"
    assert not connector_dir.exists()

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    assert connector_dir.is_dir()
    assert (connector_dir / "connector.yaml").is_file()



def test_create_manifest_from_scratch_missing_author_image_raises(
    tmp_path: Path,
) -> None:
    """
    Given: --author-image-path pointing to a NON-existent file.
    When:  create_manifest_from_scratch is called.
    Then:  FileNotFoundError is raised; nothing is written.
    """
    import pytest

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    nonexistent_image = tmp_path / "no_such_image.png"

    with pytest.raises(FileNotFoundError, match="Author image not found"):
        create_manifest_from_scratch(
            connector_dir=connector_dir,
            integration_yml={"name": "MyInt"},
            integration_path=integration_yml,
            connector_title="My Connector",
            mapped_params={},
            auth_methods={},
            author_image_path=nonexistent_image,
        )


def test_add_handler_to_existing_connector_silently_ignores_author_image(
    tmp_path: Path,
) -> None:
    """
    Given: An existing connector + --author-image-path on the append path.
    When:  add_handler_to_existing_connector is called.
    Then:  Per spec, the image is NOT copied and the existing
           connector.yaml's author_image field is NOT touched.
    """
    from manifest_generator import add_handler_to_existing_connector

    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=[]
    )

    # Also write the existing capabilities.yaml + configurations.yaml +
    # a first handler so the append path's preconditions are met.
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    capabilities_yaml_path.write_text(
        "metadata:\n  title: x\n  description: y\n"
        "general_configurations:\n  configurations:\n  - fields: []\n"
        "capabilities: []\n"
    )
    configurations_yaml_path = connector_dir / "configurations.yaml"
    configurations_yaml_path.write_text(
        "metadata:\n  title: x\n  description: y\nconfigurations: []\n"
    )

    source_image = tmp_path / "would_be_copied.png"
    source_image.write_bytes(b"png-content")

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "MyInt"}, "name": "MyInt", "display": "My Int"},
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={"auth_types": []},
        author_image_path=source_image,
    )

    # Image was NOT copied into the connector root.
    assert not (connector_dir / "myconnector.png").exists()
    # connector.yaml's author_image was preserved as written by the fixture.
    with open(connector_dir / "connector.yaml") as fh:
        data = yaml.safe_load(fh)
    assert data["metadata"]["author_image"] == ""


# ---------------------------------------------------------------------------
# build_connector_yaml (sanity check on the dict shape)
# ---------------------------------------------------------------------------
def test_build_connector_yaml_shape() -> None:
    data = build_connector_yaml("My Connector", ["forensics"])
    assert data["id"] == "my-connector"
    assert data["metadata"]["title"] == "My Connector"
    assert data["metadata"]["tags"] == ["forensics"]
    # Ensure the returned tags list is a copy, not the same object
    data["metadata"]["tags"].append("mutated")
    assert data["metadata"]["tags"] == ["forensics", "mutated"]


# ---------------------------------------------------------------------------
# add_handler_to_existing_connector
# ---------------------------------------------------------------------------
def _write_existing_connector_yaml(
    connector_dir: Path, version: str, tags: list[str]
) -> Path:
    """Create an existing connector.yaml at ``connector_dir`` with the given
    version + tags and return its path."""
    connector_dir.mkdir(parents=True, exist_ok=True)
    connector_yaml_path = connector_dir / "connector.yaml"
    payload = {
        "id": "myconnector",
        "metadata": {
            "title": "My Connector",
            "description": "",
            "version": version,
            "categories": [],
            "tags": list(tags),
            "domain": "",
            "vendor": "",
            "publisher": "Palo Alto Networks",
            "author_image": "",
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "settings": {"allow_skip_verification": True},
    }
    with open(connector_yaml_path, "w") as fh:
        yaml.safe_dump(payload, fh)
    return connector_yaml_path


# ---------------------------------------------------------------------------
# derive_connector_suffix / derive_connector_id_and_title
# (per guide §3.3.1 — Connector ID and title naming convention)
# ---------------------------------------------------------------------------
def test_derive_connector_suffix_only_automation() -> None:
    """Per guide §3.3.1: only ``automation-and-remediation`` capability
    → suffix ``("automation", "Automation")``."""
    mapped = {"general_configurations": [], "Automation": ["timeout"]}
    assert derive_connector_suffix(mapped) == ("automation", "Automation")


def test_derive_connector_suffix_only_collection_single_capability() -> None:
    """Per guide §3.3.1: any single collection capability →
    ``("collection", "Collection")`` regardless of which one."""
    for cap in (
        "Fetch Issues",
        "Log Collection",
        "Fetch Secrets",
        "Threat Intelligence & Enrichment",
        "Fetch Assets and Vulnerabilities",
    ):
        mapped = {"general_configurations": [], cap: ["p"]}
        result = derive_connector_suffix(mapped)
        assert result == ("collection", "Collection"), (
            f"{cap} should yield Collection suffix, got {result}"
        )


def test_derive_connector_suffix_multiple_collections_still_single_word() -> None:
    """Per guide §3.3.1: even multiple collection capabilities yield
    just ``Collection`` (the suffix does NOT enumerate which)."""
    mapped = {
        "general_configurations": [],
        "Fetch Issues": ["a"],
        "Log Collection": ["b"],
        "Fetch Secrets": ["c"],
    }
    assert derive_connector_suffix(mapped) == ("collection", "Collection")


def test_derive_connector_suffix_automation_and_collection_mix() -> None:
    """Per guide §3.3.1: automation + ≥1 collection →
    ``("automation-and-collection", "Automation and Collection")``."""
    mapped = {
        "general_configurations": [],
        "Automation": ["x"],
        "Fetch Issues": ["y"],
    }
    assert derive_connector_suffix(mapped) == (
        "automation-and-collection",
        "Automation and Collection",
    )


def test_derive_connector_suffix_raises_on_zero_capabilities() -> None:
    """Per guide §3.3.1 *Flags*: zero capabilities must raise — every
    connector must expose at least one capability family."""
    with pytest.raises(ValueError, match="zero capabilities"):
        derive_connector_suffix({"general_configurations": ["url"]})
    with pytest.raises(ValueError, match="zero capabilities"):
        derive_connector_suffix({})


def test_derive_connector_id_and_title_okta_mixed() -> None:
    """Worked example from guide §3.3.1 (line 582)."""
    mapped = {
        "general_configurations": [],
        "Automation": ["x"],
        "Log Collection": ["y"],
    }
    assert derive_connector_id_and_title("Okta", mapped) == (
        "okta-automation-and-collection",
        "Okta Automation and Collection",
    )


def test_derive_connector_id_and_title_okta_automation_only() -> None:
    """Worked example from guide §3.3.1 (line 583)."""
    mapped = {"general_configurations": [], "Automation": ["x"]}
    assert derive_connector_id_and_title("Okta", mapped) == (
        "okta-automation",
        "Okta Automation",
    )


def test_derive_connector_id_and_title_okta_collection_only() -> None:
    """Worked example from guide §3.3.1 (line 584)."""
    mapped = {"general_configurations": [], "Log Collection": ["x"]}
    assert derive_connector_id_and_title("Okta", mapped) == (
        "okta-collection",
        "Okta Collection",
    )


def test_derive_connector_id_and_title_palo_alto_networks() -> None:
    """Worked example from guide §3.3.1 (line 586) — multi-word vendor
    with three collection caps + automation. Validates that the title
    form preserves spaces and Title Cases each word."""
    mapped = {
        "general_configurations": [],
        "Automation": ["a"],
        "Fetch Issues": ["b"],
        "Threat Intelligence & Enrichment": ["c"],
    }
    assert derive_connector_id_and_title("Palo Alto Networks", mapped) == (
        "palo-alto-networks-automation-and-collection",
        "Palo Alto Networks Automation and Collection",
    )


def test_derive_connector_id_and_title_strips_special_chars_in_vendor() -> None:
    """Per guide §3.3.1: any non-[a-z0-9-] character in the vendor
    slug is replaced with a dash and collapsed."""
    mapped = {"general_configurations": [], "Automation": ["x"]}
    # Vendor with ampersand, period, etc.
    cid, ctitle = derive_connector_id_and_title("Foo & Bar, Inc.", mapped)
    assert cid == "foo-bar-inc-automation"
    # Title preserves original casing/spaces of the vendor input.
    assert ctitle == "Foo & Bar, Inc. Automation"


def test_derive_connector_id_and_title_raises_on_unparseable_vendor() -> None:
    """Per guide §3.3.1 *Flags*: a vendor name that yields no [a-z0-9]
    chars (e.g. pure symbols) must raise — manual id required."""
    mapped = {"general_configurations": [], "Automation": ["x"]}
    with pytest.raises(ValueError, match="manual id selection"):
        derive_connector_id_and_title("---", mapped)
    with pytest.raises(ValueError, match="manual id selection"):
        derive_connector_id_and_title("", mapped)


# ---------------------------------------------------------------------------
# derive_handler_id
# ---------------------------------------------------------------------------
def test_derive_handler_id_basic() -> None:
    """Per Batch 4 (Part A.4.1) + guide §3.8 + §4.6 Salesforce
    reference: handler id is ``xsoar-<integration-id>`` (dash separator,
    NOT underscore; preserves internal word boundaries as dashes)."""
    assert derive_handler_id("Salesforce") == "xsoar-salesforce"
    assert derive_handler_id("My Integration") == "xsoar-my-integration"
    assert derive_handler_id("CrowdStrike Falcon") == "xsoar-crowdstrike-falcon"
    # Multi-space + numeric suffix.
    assert derive_handler_id("EWS v2") == "xsoar-ews-v2"


def test_derive_handler_id_handles_whitespace() -> None:
    assert derive_handler_id("  Salesforce  ") == "xsoar-salesforce"
    assert derive_handler_id("\tMy Integration\n") == "xsoar-my-integration"


# ---------------------------------------------------------------------------
# write_handler_yaml
# ---------------------------------------------------------------------------
def test_write_handler_yaml_includes_schema_directive(tmp_path: Path) -> None:
    handler_yaml_path = tmp_path / "handler.yaml"
    sample = {"id": "xsoar_sample", "enabled": True}
    write_handler_yaml(handler_yaml_path, sample)

    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
    assert first_line == HANDLER_SCHEMA_DIRECTIVE


def test_write_handler_yaml_creates_parent_directories(tmp_path: Path) -> None:
    handler_yaml_path = (
        tmp_path / "deep" / "nested" / "path" / "components" / "handlers"
        / "xsoar_x" / "handler.yaml"
    )
    assert not handler_yaml_path.parent.exists()

    write_handler_yaml(handler_yaml_path, {"id": "xsoar_x"})

    assert handler_yaml_path.is_file()
    assert handler_yaml_path.parent.is_dir()


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — handler.yaml integration
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_handler_yaml_at_correct_path(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["forensics"]}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params={},
        auth_methods={},
    )

    handler_yaml_path = (
        connector_dir / "components" / "handlers" / "xsoar-salesforce" / "handler.yaml"
    )
    assert handler_yaml_path.is_file()


def test_create_manifest_from_scratch_handler_includes_schema_directive(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params={},
        auth_methods={},
    )

    handler_yaml_path = (
        connector_dir / "components" / "handlers" / "xsoar-salesforce" / "handler.yaml"
    )
    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
    assert first_line == HANDLER_SCHEMA_DIRECTIVE


# ---------------------------------------------------------------------------
# add_handler_to_existing_connector — handler.yaml integration
# ---------------------------------------------------------------------------
def test_add_handler_to_existing_connector_generates_handler_yaml(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["new"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=["existing"]
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    handler_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-my-integration"
        / "handler.yaml"
    )
    assert handler_yaml_path.is_file()
    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
    assert first_line == HANDLER_SCHEMA_DIRECTIVE


def test_add_handler_to_existing_connector_raises_if_handler_already_exists(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=[]
    )

    # Pre-create the handler file at the expected path
    handler_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-my-integration"
        / "handler.yaml"
    )
    handler_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    handler_yaml_path.write_text("id: xsoar-my-integration\n")

    with pytest.raises(FileExistsError):
        add_handler_to_existing_connector(
            connector_dir=connector_dir,
            integration_yml={
                "commonfields": {"id": "My Integration"},
                "display": "My Integration",
            },
            integration_path=integration_yml_path,
            connector_title="My Connector",
            mapped_params={},
            auth_methods={},
        )


# ---------------------------------------------------------------------------
# build_summary_yaml
# ---------------------------------------------------------------------------
def test_build_summary_yaml_shape() -> None:
    data = build_summary_yaml("Salesforce")
    # Per guide §4.5 (Salesforce reference) + summary.schema: ``link`` and
    # ``next_steps`` are OPTIONAL and omitted when not provided by the
    # caller. Only the required ``title`` + ``description`` are emitted.
    assert data == {
        "metadata": {
            "title": "Summary",
            "description": "Summary for connector Salesforce",
        },
    }
    metadata = data["metadata"]
    assert metadata["title"] == "Summary"
    assert metadata["description"] == "Summary for connector Salesforce"
    assert "link" not in metadata
    assert "next_steps" not in metadata


def test_build_summary_yaml_uses_connector_title_in_description() -> None:
    title = "My Awesome Connector"
    data = build_summary_yaml(title)
    assert title in data["metadata"]["description"]
    assert data["metadata"]["description"] == f"Summary for connector {title}"


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — summary.yaml integration
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_summary_yaml(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params={},
        auth_methods={},
    )

    summary_yaml_path = connector_dir / "summary.yaml"
    assert summary_yaml_path.is_file()

    with open(summary_yaml_path) as fh:
        data = yaml.safe_load(fh)

    # Per guide §4.5 + summary.schema: optional ``link`` / ``next_steps``
    # omitted from defaults.
    assert data == {
        "metadata": {
            "title": "Summary",
            "description": "Summary for connector Salesforce",
        },
    }


# ---------------------------------------------------------------------------
# add_handler_to_existing_connector — summary.yaml is NOT touched
# ---------------------------------------------------------------------------
def test_add_handler_to_existing_connector_does_NOT_create_or_modify_summary_yaml(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=[]
    )

    # Pre-existing summary.yaml with a USER-EDITED marker.
    summary_yaml_path = connector_dir / "summary.yaml"
    user_edited_payload = {
        "metadata": {
            "title": "Summary",
            "description": "USER-EDITED",
            "link": "",
            "next_steps": "",
        },
    }
    with open(summary_yaml_path, "w") as fh:
        yaml.safe_dump(user_edited_payload, fh)

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    # File still exists and is unchanged.
    assert summary_yaml_path.is_file()
    with open(summary_yaml_path) as fh:
        data = yaml.safe_load(fh)
    assert data["metadata"]["description"] == "USER-EDITED"
    assert data == user_edited_payload


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — serializer.yaml integration
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_serializer_yaml_alongside_handler(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params={},
        auth_methods={},
    )

    # With no collisions, the per-handler general_config field keeps its
    # bare canonical id (integrationLogLevel) and registers NO serializer
    # entries, so serializer.yaml is not created. (No Automation capability
    # here, so no defaultIgnore field is emitted either.)
    serializer_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-salesforce"
        / "serializer.yaml"
    )
    assert not serializer_yaml_path.exists()


# ---------------------------------------------------------------------------
# add_handler_to_existing_connector — serializer.yaml integration
# ---------------------------------------------------------------------------
def test_add_handler_to_existing_connector_generates_serializer_yaml(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=[]
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    # With no collisions, the per-handler general_config fields keep their
    # bare canonical ids and register NO serializer entries — so
    # serializer.yaml is not created.
    handler_dir = (
        connector_dir / "components" / "handlers" / "xsoar-my-integration"
    )
    handler_yaml_path = handler_dir / "handler.yaml"
    serializer_yaml_path = handler_dir / "serializer.yaml"
    assert handler_yaml_path.is_file()
    assert not serializer_yaml_path.exists()


def test_add_handler_to_existing_connector_raises_if_serializer_already_exists(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=[]
    )

    # Pre-create both the handler.yaml AND serializer.yaml at the expected paths.
    handler_dir = (
        connector_dir / "components" / "handlers" / "xsoar-my-integration"
    )
    handler_dir.mkdir(parents=True, exist_ok=True)
    (handler_dir / "handler.yaml").write_text("id: xsoar-my-integration\n")
    (handler_dir / "serializer.yaml").write_text("# pre-existing\n")

    with pytest.raises(FileExistsError):
        add_handler_to_existing_connector(
            connector_dir=connector_dir,
            integration_yml={
                "commonfields": {"id": "My Integration"},
                "display": "My Integration",
            },
            integration_path=integration_yml_path,
            connector_title="My Connector",
            mapped_params={},
            auth_methods={},
        )


# ---------------------------------------------------------------------------
# slugify_capability_name — canonical capability id mapping (per guide §3.4
# + CO119 validator). The function is now a hardcoded lookup table rather
# than a generic regex slugifier — see CANONICAL_CAPABILITY_IDS.
# ---------------------------------------------------------------------------
def test_slugify_capability_name_returns_canonical_ids_for_all_six_buckets() -> None:
    """Every mapper bucket key must resolve to its canonical capability id."""
    assert slugify_capability_name("Fetch Issues") == "fetch-issues"
    assert slugify_capability_name("Fetch Assets and Vulnerabilities") == (
        "fetch-assets-and-vulnerabilities"
    )
    # CRITICAL: "Automation" must include the "-and-remediation" suffix.
    # The previous regex-slugifier produced just "automation", which
    # fails CO119 IsCapabilityNameValid.
    assert slugify_capability_name("Automation") == "automation-and-remediation"
    assert slugify_capability_name("Fetch Secrets") == "fetch-secrets"
    assert slugify_capability_name("Log Collection") == "log-collection"
    # CRITICAL: the "& Enrichment" segment must round-trip to "and-enrichment".
    # The previous regex-slugifier produced "threat-intelligence-enrichment",
    # which fails CO119.
    assert slugify_capability_name("Threat Intelligence & Enrichment") == (
        "threat-intelligence-and-enrichment"
    )


def test_slugify_capability_name_raises_on_unknown_bucket_key() -> None:
    """Unknown bucket keys must raise ValueError loudly (no silent fallback
    to a non-canonical id that would fail CO119 downstream)."""
    with pytest.raises(ValueError, match="Unknown capability bucket key"):
        slugify_capability_name("Foo  Bar  Baz")
    with pytest.raises(ValueError, match="Unknown capability bucket key"):
        slugify_capability_name("automation")  # case-sensitive: lowercase fails


# ---------------------------------------------------------------------------
# build_capabilities_yaml
# ---------------------------------------------------------------------------
def test_build_capabilities_yaml_shape() -> None:
    """Per guide §3.4 + §4.3 Salesforce reference:
    - Only ``instance_name`` is in capabilities.yaml general_configurations.
    - ``integrationLogLevel`` and user-mapped params are now in
      configurations.yaml (per grouped-example reference).
    - Each capability entry has the REQUIRED schema fields:
      id + title + default_enabled + required.
    - Canonical capability ids use the "and" form.
    """
    mapped_params = {
        "general_configurations": ["url", "verify_ssl"],
        "Fetch Issues": ["fetch_limit"],
        "Threat Intelligence & Enrichment": ["ti_param"],
    }
    data = build_capabilities_yaml(mapped_params)

    assert data["metadata"] == {
        "title": "Capabilities",
        "description": "Configure the capabilities for this instance",
    }
    assert data["general_configurations"]["description"] == (
        "General configurations for all capabilities"
    )
    # Only instance_name in capabilities.yaml general_configurations.
    # integrationLogLevel + user params → configurations.yaml.
    fields = data["general_configurations"]["configurations"][0]["fields"]
    assert fields[0]["id"] == "instance_name"
    assert fields[0]["field_type"] == "input"
    assert fields[0]["metadata"]["connector"]["parameter"] == "instance_name"
    assert len(fields) == 1
    # Called without handler_id -> no sub_capabilities. Licenses are resolved
    # per sub-capability from sub_capabilities_to_licenses.json, so without a
    # handler_id (hence no sub-cap id) the parent carries NO config block.
    assert data["capabilities"] == [
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS["fetch-issues"],
            "default_enabled": False,
            "required": False,
        },
        {
            "id": "threat-intelligence-and-enrichment",
            "title": "Threat Intelligence and Enrichment",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[
                "threat-intelligence-and-enrichment"
            ],
            "default_enabled": False,
            "required": False,
        },
    ]


def test_build_capabilities_yaml_with_empty_mapped_params() -> None:
    """Even with no mapped params, instance_name MUST still be emitted."""
    data = build_capabilities_yaml({})
    assert data["capabilities"] == []
    fields = data["general_configurations"]["configurations"][0]["fields"]
    assert [f["id"] for f in fields] == ["instance_name"]


def test_build_capabilities_yaml_instance_name_shape_matches_salesforce_reference() -> None:
    """Regression: the exact ``instance_name`` field shape must match the
    Salesforce reference in guide §4.3 lines 1318-1341. The shape is
    consumed by the BE for instance creation and by the FE for rendering;
    any drift breaks both ends."""
    data = build_capabilities_yaml({})
    fields = data["general_configurations"]["configurations"][0]["fields"]
    inst = next(f for f in fields if f["id"] == "instance_name")
    assert inst["title"] == "Instance name"
    assert inst["field_type"] == "input"
    assert inst["metadata"] == {"connector": {"parameter": "instance_name"}}
    # Validations: change-trigger with pattern + async uniqueness.
    val = inst["validations"][0]
    assert val["trigger"] == "change"
    rule_types = [r["type"] for r in val["rules"]]
    assert rule_types == ["pattern", "async"]
    assert val["rules"][0]["value"] == "^[a-zA-Z0-9 _-]+$"
    assert val["rules"][1]["validation_type"] == "uniqueness"
    # Modifiers: required on both create + edit, never hidden, never read-only.
    for mod_key in ("create_modifiers", "edit_modifiers"):
        mod = inst["options"][mod_key]
        assert mod["required"] is True
        assert mod["hidden"] is False
        assert mod["read_only"] is False


def test_per_handler_integration_log_level_shape_matches_reference() -> None:
    """Regression: the per-handler ``integrationLogLevel`` field shape
    must match the grouped-example reference. The field now lives in
    configurations.yaml (via build_per_handler_general_config), NOT
    in capabilities.yaml."""
    from manifest_generator import _per_handler_log_level_field

    log = _per_handler_log_level_field("xsoar-test", "integrationLogLevel")
    assert log["id"] == "integrationLogLevel"
    assert log["title"] == "Log Level"
    assert log["field_type"] == "select"
    assert log["metadata"] == {"xsoar": {"config_type": "backend"}}
    assert log["options"]["default_value"] == "Off"
    keys = [v["key"] for v in log["options"]["values"]]
    assert keys == ["Off", "Debug", "Verbose"]


def test_build_per_handler_general_config_skips_user_param_colliding_with_mandatory_field(
    tmp_path: Path, caplog
) -> None:
    """Defensive: if the upstream mapper places a user-param literally
    named ``instance_name`` or ``integrationLogLevel`` in
    general_configurations, the platform-mandated version wins and a
    warning is logged. The collision check now happens in
    build_per_handler_general_config (configurations.yaml), not in
    build_capabilities_yaml."""
    import logging as _logging

    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    mapped_params = {
        "general_configurations": ["instance_name", "integrationLogLevel", "url"],
        "Automation": ["p1"],
    }
    with caplog.at_level(_logging.WARNING, logger="manifest_generator"):
        result = build_per_handler_general_config(
            "xsoar-test", handler_dir, mapped_params=mapped_params
        )
    field_ids = [f["id"] for f in result["fields"]]
    # integrationLogLevel is always first (platform-mandated). With no
    # collisions it keeps its bare canonical id (no prefix). instance_name
    # and integrationLogLevel from user params are skipped. Only "url" from
    # user params should appear. defaultIgnore is NOT emitted here anymore —
    # it is injected under the automation capability by the caller.
    assert "integrationLogLevel" in field_ids
    assert "defaultIgnore" not in field_ids
    assert "url" in field_ids  # user param that didn't collide
    # No duplicate integrationLogLevel from user params.
    assert field_ids.count("integrationLogLevel") == 1
    assert any(
        "collides with a platform-mandated field" in rec.message
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# build_configurations_yaml
# ---------------------------------------------------------------------------
def test_build_configurations_yaml_shape() -> None:
    """Per guide §3.4: ``Automation`` bucket key resolves to the canonical
    ``automation-and-remediation`` capability id (not bare ``automation``)."""
    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Issues": ["fetch_limit", "first_fetch"],
        "Automation": ["timeout"],
    }
    data = build_configurations_yaml(mapped_params)

    assert data["metadata"] == {
        "title": "Configuration",
        "description": "Adjust and refine your configuration",
    }
    assert data["configurations"] == [
        {
            "id": "fetch-issues",
            "configurations": [
                {"fields": [{"id": "fetch_limit"}, {"id": "first_fetch"}]}
            ],
        },
        {
            "id": "automation-and-remediation",
            "configurations": [{"fields": [{"id": "timeout"}]}],
        },
    ]


def test_build_configurations_yaml_with_only_general_configurations() -> None:
    data = build_configurations_yaml({"general_configurations": ["url"]})
    assert data["configurations"] == []


def test_actions_for_capability_empty_for_action_free_family() -> None:
    assert _actions_for_capability("Automation") == []
    assert _actions_for_capability("Fetch Secrets") == []


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — capabilities.yaml
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_log_collection_emits_fetch_fields(
    tmp_path: Path,
) -> None:
    """
    Given: a from-scratch run whose mapped_params declares a Log Collection
           capability with ``longRunning`` routed into its bucket (the Akamai
           WAF SIEM scenario).
    When:  create_manifest_from_scratch runs end-to-end.
    Then:  the configurations.yaml ``log-collection_<slug>`` sub-cap entry
           contains the platform fetch fields — isFetchEvents (toggle),
           eventFetchInterval (duration) AND longRunning (checkbox). Because
           BOTH checkboxes are present, the "count both checkboxes together"
           rule shows them (hidden=False) and defaults them to False. This is
           the regression guard for the orchestration wiring gap where the Log
           Collection builder was never dispatched (only longRunning leaked
           through the generic param pass).
    """
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["network"]}
    )
    connector_dir = tmp_path / "connectors" / "akamai"

    mapped_params = {
        "general_configurations": [],
        "Log Collection": ["longRunning"],
    }
    auth_methods = {"auth_types": [{"name": "oauth2"}]}

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Akamai WAF SIEM"},
            "display": "Akamai WAF SIEM",
            "script": {"longRunning": True},
        },
        integration_path=integration_yml_path,
        connector_title="Akamai",
        mapped_params=mapped_params,
        auth_methods=auth_methods,
    )

    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)

    lc_entry = next(
        c
        for c in cfg_data["configurations"]
        if c["id"].startswith("log-collection_")
    )
    lc_fields = {
        f["id"]: f
        for grp in lc_entry["configurations"]
        for f in grp["fields"]
    }
    # Akamai WAF SIEM declares no script.isfetchevents and no isFetchEvents
    # param — the Log Collection capability only exists because longRunning is
    # routed to it. So the synthetic isFetchEvents toggle appears NOWHERE and
    # longRunning is moved to the serializer (not configurations). Only the
    # eventFetchInterval picker remains as a visible field.
    assert "isFetchEvents" not in lc_fields
    assert "longRunning" not in lc_fields
    assert "eventFetchInterval" in lc_fields
    assert lc_fields["eventFetchInterval"]["field_type"] == "duration"

    # longRunning is serialized via computed_fields gated on the sub-capability;
    # the synthetic isFetchEvents toggle is NOT serialized (appears nowhere).
    handler_dir = (
        connector_dir / "components" / "handlers" / "xsoar-akamai-waf-siem"
    )
    with open(handler_dir / "serializer.yaml") as fh:
        ser_body = fh.read().split("\n", 1)[1]
    serializer = yaml.safe_load(ser_body) or {}
    outputs = [
        out["id"]
        for rule in serializer.get("computed_fields", [])
        for out in rule["output"]
    ]
    assert "longRunning" in outputs
    assert "isFetchEvents" not in outputs


# ---------------------------------------------------------------------------
# Append-path test helpers — set up a pre-existing connector on disk
# ---------------------------------------------------------------------------
def _write_existing_handler_yaml(
    handler_dir: Path, handler_id: str, capabilities: list
) -> Path:
    """Write a handler.yaml file (with schema directive) under ``handler_dir``."""
    handler_dir.mkdir(parents=True, exist_ok=True)
    handler_yaml_path = handler_dir / "handler.yaml"
    payload = {
        "id": handler_id,
        "metadata": {"version": "1.0.0"},
        "enabled": True,
        "capabilities": capabilities,
    }
    with open(handler_yaml_path, "w") as fh:
        fh.write(HANDLER_SCHEMA_DIRECTIVE)
        yaml.safe_dump(payload, fh)
    return handler_yaml_path


def _write_existing_capabilities_yaml(
    connector_dir: Path,
    capabilities: list,
    general_fields: list | None = None,
) -> Path:
    """Write capabilities.yaml at the connector root with the given capabilities."""
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    payload = {
        "metadata": {
            "title": "Capabilities",
            "description": "Configure the capabilities for this instance",
        },
        "general_configurations": {
            "description": "General configurations for all capabilities",
            "configurations": [{"fields": general_fields or []}],
        },
        "capabilities": capabilities,
    }
    write_capabilities_yaml(capabilities_yaml_path, payload)
    return capabilities_yaml_path


def _write_existing_configurations_yaml(
    connector_dir: Path, configurations: list
) -> Path:
    """Write configurations.yaml at the connector root."""
    configurations_yaml_path = connector_dir / "configurations.yaml"
    payload = {
        "metadata": {
            "title": "Configuration",
            "description": "Adjust and refine your configuration",
        },
        "configurations": configurations,
    }
    with open(configurations_yaml_path, "w") as fh:
        yaml.safe_dump(payload, fh)
    return configurations_yaml_path


# ---------------------------------------------------------------------------
# find_existing_handler_for_capability (3 helper tests)
# ---------------------------------------------------------------------------
def test_find_existing_handler_for_capability_finds_single_match(
    tmp_path: Path,
) -> None:
    connector_dir = tmp_path / "connectors" / "myconnector"
    handlers_dir = connector_dir / "components" / "handlers"
    _write_existing_handler_yaml(
        handlers_dir / "xsoar-one",
        "xsoar-one",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        handlers_dir / "xsoar-two",
        "xsoar-two",
        [{"id": "automation", "auth_options": []}],
    )

    result = find_existing_handler_for_capability(connector_dir, "fetch-issues")
    assert result == handlers_dir / "xsoar-one" / "handler.yaml"


def test_find_existing_handler_raises_on_no_match(tmp_path: Path) -> None:
    connector_dir = tmp_path / "connectors" / "myconnector"
    handlers_dir = connector_dir / "components" / "handlers"
    _write_existing_handler_yaml(
        handlers_dir / "xsoar-one",
        "xsoar-one",
        [{"id": "automation", "auth_options": []}],
    )

    with pytest.raises(RuntimeError, match="No existing handler found"):
        find_existing_handler_for_capability(connector_dir, "fetch-issues")


def test_find_existing_handler_raises_on_multiple_matches(tmp_path: Path) -> None:
    connector_dir = tmp_path / "connectors" / "myconnector"
    handlers_dir = connector_dir / "components" / "handlers"
    _write_existing_handler_yaml(
        handlers_dir / "xsoar-one",
        "xsoar-one",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        handlers_dir / "xsoar-two",
        "xsoar-two",
        [{"id": "fetch-issues", "auth_options": []}],
    )

    with pytest.raises(RuntimeError, match="Multiple handlers reference"):
        find_existing_handler_for_capability(connector_dir, "fetch-issues")

# ---------------------------------------------------------------------------
# Case 3 — new capability
# ---------------------------------------------------------------------------


def test_append_handler_general_configurations_appended_dedup(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-existing",
        "xsoar-existing",
        [],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        capabilities=[],
        general_fields=[{"id": "url"}, {"id": "verify_ssl"}],
    )
    _write_existing_configurations_yaml(connector_dir, configurations=[])

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={
            # url overlaps; proxy + new_param are new.
            "general_configurations": ["url", "proxy", "new_param", "verify_ssl"],
        },
        auth_methods={},
    )

    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()
        cap_data = yaml.safe_load(fh)
    fields = cap_data["general_configurations"]["configurations"][0]["fields"]
    assert fields == [
        {"id": "url"},
        {"id": "verify_ssl"},
        {"id": "proxy"},
        {"id": "new_param"},
    ]


# ---------------------------------------------------------------------------
# Case 1 — existing cap with sub-caps
# ---------------------------------------------------------------------------
def test_append_handler_case1_does_not_modify_existing_handlers(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    existing_handler_yaml = _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-one",
        "xsoar-one",
        [{"id": "fetch-issues_one", "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}]}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "sub_capabilities": [{"id": "fetch-issues_one"}],
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues_one",
                "configurations": [{"fields": [{"id": "p1"}]}],
            },
        ],
    )

    pre_bytes = existing_handler_yaml.read_bytes()

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_p"]},
        auth_methods={},
    )

    assert existing_handler_yaml.read_bytes() == pre_bytes


# ---------------------------------------------------------------------------
# Case 2 — promotion
# ---------------------------------------------------------------------------
def _setup_case2_connector(
    tmp_path: Path,
    integration_yml_path: Path,
    extra_capabilities: list | None = None,
    extra_configurations: list | None = None,
) -> Path:
    """Pre-create a connector in the Case 2 starting state.

    - Single existing handler ``xsoar-existing`` holding flat cap ``fetch-issues``.
    - capabilities.yaml has ``fetch-issues`` (no sub-caps) + any extras.
    - configurations.yaml has ``fetch-issues`` top-level entry + any extras.
    """
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-existing",
        "xsoar-existing",
        [{"id": "fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}]}],
    )
    capabilities = [{"id": "fetch-issues"}] + (extra_capabilities or [])
    _write_existing_capabilities_yaml(connector_dir, capabilities)
    configurations = [
        {
            "id": "fetch-issues",
            "configurations": [
                {"fields": [{"id": "old_param1"}, {"id": "old_param2"}]}
            ],
        }
    ] + (extra_configurations or [])
    _write_existing_configurations_yaml(connector_dir, configurations)
    return connector_dir


def test_append_handler_case2_preserves_existing_handler_auth_options(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = _setup_case2_connector(tmp_path, integration_yml_path)
    existing_handler_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-existing" / "handler.yaml"
    )

    # Capture pre-state auth_options.
    with open(existing_handler_yaml) as fh:
        fh.readline()
        pre_data = yaml.safe_load(fh)
    pre_auth_options = pre_data["capabilities"][0]["auth_options"]

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Jira"},
            "display": "Jira",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_param1"]},
        auth_methods={"auth_types": [{"name": "api_key"}]},
    )

    with open(existing_handler_yaml) as fh:
        fh.readline()
        post_data = yaml.safe_load(fh)
    post_auth_options = post_data["capabilities"][0]["auth_options"]
    assert list(post_auth_options) == list(pre_auth_options)


def test_append_handler_case2_with_two_caps_only_promotes_relevant(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    # Existing connector: flat "fetch-issues" + already-split "automation"
    # (two existing handlers under it).
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-existing",
        "xsoar-existing",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_auto1",
        "xsoar_auto1",
        [{"id": "xsoar_auto1-automation", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_auto2",
        "xsoar_auto2",
        [{"id": "xsoar_auto2-automation", "auth_options": []}],
    )
    automation_cap = {
        "id": "automation",
        "sub_capabilities": [
            {"id": "xsoar_auto1-automation"},
            {"id": "xsoar_auto2-automation"},
        ],
    }
    _write_existing_capabilities_yaml(
        connector_dir,
        [{"id": "fetch-issues"}, automation_cap],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "configurations": [{"fields": [{"id": "old_p"}]}],
            },
            {
                "id": "xsoar_auto1-automation",
                "configurations": [{"fields": [{"id": "a1"}]}],
            },
            {
                "id": "xsoar_auto2-automation",
                "configurations": [{"fields": [{"id": "a2"}]}],
            },
        ],
    )

    # Snapshot the automation handlers' bytes for byte-identical assertion.
    auto1_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_auto1" / "handler.yaml"
    )
    auto2_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_auto2" / "handler.yaml"
    )
    auto1_bytes_pre = auto1_yaml.read_bytes()
    auto2_bytes_pre = auto2_yaml.read_bytes()

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Jira"},
            "display": "Jira",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_p"]},
        auth_methods={},
    )

    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()
        cap_data = yaml.safe_load(fh)
    # automation untouched.
    automation_after = next(
        c for c in cap_data["capabilities"] if c["id"] == "automation"
    )
    assert automation_after == automation_cap
    # fetch-issues promoted with both sub-caps.
    fetch_after = next(
        c for c in cap_data["capabilities"] if c["id"] == "fetch-issues"
    )
    assert fetch_after["sub_capabilities"] == [
        build_sub_capability_entry(
            "fetch-issues_existing", "Fetch Issues", integration_name="Existing"
        ),
        build_sub_capability_entry("fetch-issues_jira", "Fetch Issues"),
    ]

    # automation handlers' files are byte-identical.
    assert auto1_yaml.read_bytes() == auto1_bytes_pre
    assert auto2_yaml.read_bytes() == auto2_bytes_pre


# ---------------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------------
def test_append_handler_does_not_break_existing_summary_yaml(tmp_path: Path) -> None:
    """Regression: append path with capabilities updates still doesn't touch summary.yaml."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-existing",
        "xsoar-existing",
        [{"id": "automation", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(connector_dir, [{"id": "automation"}])
    _write_existing_configurations_yaml(
        connector_dir,
        [{"id": "automation", "configurations": [{"fields": []}]}],
    )

    summary_yaml_path = connector_dir / "summary.yaml"
    user_payload = {
        "metadata": {
            "title": "Summary",
            "description": "USER-EDITED",
            "link": "",
            "next_steps": "",
        }
    }
    with open(summary_yaml_path, "w") as fh:
        yaml.safe_dump(user_payload, fh)
    pre_bytes = summary_yaml_path.read_bytes()

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Jira"},
            "display": "Jira",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_p"]},
        auth_methods={},
    )

    assert summary_yaml_path.read_bytes() == pre_bytes


# ---------------------------------------------------------------------------
# merge_general_configurations + append_capability_to_files unit tests
# ---------------------------------------------------------------------------
def test_merge_general_configurations_creates_section_when_missing() -> None:
    cap_data: dict = {}
    merge_general_configurations(cap_data, ["a", "b"])
    assert cap_data["general_configurations"]["configurations"] == [
        {"fields": [{"id": "a"}, {"id": "b"}]}
    ]


def test_merge_general_configurations_noop_on_empty_input() -> None:
    cap_data = {
        "general_configurations": {
            "description": "x",
            "configurations": [{"fields": [{"id": "url"}]}],
        }
    }
    merge_general_configurations(cap_data, [])
    assert cap_data["general_configurations"]["configurations"] == [
        {"fields": [{"id": "url"}]}
    ]


# ---------------------------------------------------------------------------
# deep_merge_dicts (Group A — unit tests)
# ---------------------------------------------------------------------------
def test_deep_merge_empty_overrides_returns_base_copy() -> None:
    base = {"a": 1, "b": {"c": 2}}
    result = deep_merge_dicts(base, {})
    assert result == {"a": 1, "b": {"c": 2}}
    # Top-level should be a copy (different object)
    assert result is not base


def test_deep_merge_empty_base_returns_overrides_copy() -> None:
    overrides = {"a": 1, "b": {"c": 2}}
    result = deep_merge_dicts({}, overrides)
    assert result == {"a": 1, "b": {"c": 2}}
    assert result is not overrides


def test_deep_merge_both_empty_returns_empty() -> None:
    assert deep_merge_dicts({}, {}) == {}


def test_deep_merge_disjoint_keys_combined() -> None:
    assert deep_merge_dicts({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}


def test_deep_merge_scalar_conflict_overrides_wins() -> None:
    assert deep_merge_dicts({"a": 1}, {"a": 2}) == {"a": 2}


def test_deep_merge_nested_dict_siblings_preserved() -> None:
    base = {"a": {"b": 1, "x": [1, 2]}, "c": "hello"}
    overrides = {"a": {"c": 2, "x": [9]}, "d": "new"}
    expected = {"a": {"b": 1, "c": 2, "x": [9]}, "c": "hello", "d": "new"}
    assert deep_merge_dicts(base, overrides) == expected


def test_deep_merge_lists_replaced_not_merged() -> None:
    assert deep_merge_dicts({"a": [1, 2]}, {"a": [9]}) == {"a": [9]}


def test_deep_merge_does_not_mutate_inputs() -> None:
    base = {"a": {"b": 1, "x": [1, 2]}, "c": "hello"}
    overrides = {"a": {"c": 2, "x": [9]}, "d": "new"}
    base_snapshot = json.loads(json.dumps(base))
    overrides_snapshot = json.loads(json.dumps(overrides))
    _ = deep_merge_dicts(base, overrides)
    assert base == base_snapshot
    assert overrides == overrides_snapshot


# ---------------------------------------------------------------------------
# Manual override end-to-end (Group B)
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_applies_manual_connector_fields(
    tmp_path: Path,
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["forensics"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "MyInt"}, "display": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
        manual_connector_fields={
            "metadata": {"description": "MANUAL_DESC", "domain": "security"}
        },
    )

    with open(connector_dir / "connector.yaml") as fh:
        data = yaml.safe_load(fh)
    metadata = data["metadata"]
    # Manual overrides applied
    assert metadata["description"] == "MANUAL_DESC"
    assert metadata["domain"] == "security"
    # Auto-built sibling preserved
    assert metadata["title"] == "My Connector"
    # Other auto fields still present
    assert metadata["publisher"] == "Palo Alto Networks"
    assert list(metadata["tags"]) == ["forensics"]


def test_create_manifest_from_scratch_manual_handler_fields_replaces_list(
    tmp_path: Path,
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["forensics", "endpoint"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "MyInt"}, "display": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
        manual_handler_fields={"metadata": {"tags": ["MANUAL_TAG"]}},
    )

    handler_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-myint"
        / "handler.yaml"
    )
    assert handler_yaml_path.is_file()
    with open(handler_yaml_path) as fh:
        # Skip the schema directive line
        first = fh.readline()
        rest = fh.read()
        if not first.startswith("# yaml-language-server"):
            rest = first + rest
    data = yaml.safe_load(rest)
    # List replaced wholesale by manual override
    assert list(data["metadata"]["tags"]) == ["MANUAL_TAG"]
    # Sibling auto-built fields preserved
    assert data["metadata"]["module"] == "xsoar"
    assert data["metadata"]["version"] == "1.0.0"


def test_add_handler_to_existing_connector_applies_manual_handler_fields(
    tmp_path: Path,
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["new"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=["existing"]
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "MyInt"}, "display": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
        manual_handler_fields={
            "metadata": {"description": "MANUAL_HANDLER_DESC"}
        },
    )

    handler_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-myint"
        / "handler.yaml"
    )
    assert handler_yaml_path.is_file()
    with open(handler_yaml_path) as fh:
        first = fh.readline()
        rest = fh.read()
        if not first.startswith("# yaml-language-server"):
            rest = first + rest
    data = yaml.safe_load(rest)
    # Manual override applied
    assert data["metadata"]["description"] == "MANUAL_HANDLER_DESC"
    # Sibling auto-built fields preserved
    assert data["metadata"]["module"] == "xsoar"
    assert data["metadata"]["version"] == "1.0.0"


def test_serializer_manual_fields_logged_and_connection_manual_fields_applied(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    import logging as _logging

    with caplog.at_level(_logging.INFO, logger="manifest_generator"):
        create_manifest_from_scratch(
            connector_dir=connector_dir,
            integration_yml={"commonfields": {"id": "MyInt"}, "display": "MyInt"},
            integration_path=integration_yml,
            connector_title="My Connector",
            mapped_params={},
            auth_methods={"auth_types": [{"type": "APIKey", "name": "k"}]},
            manual_serializer_fields={"foo": "bar"},
            manual_connection_fields={"baz": "qux"},
        )

    # serializer.yaml is still a string stub — manual_serializer_fields are
    # logged but NOT applied.
    log_messages = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "manual_serializer_fields received" in log_messages
    assert "serializer.yaml is a string stub" in log_messages

    # connection.yaml IS now generated (auth_types present) and
    # manual_connection_fields ARE deep-merged onto it.
    connection_yaml_path = connector_dir / "connection.yaml"
    assert connection_yaml_path.exists()
    with open(connection_yaml_path) as fh:
        fh.readline()  # skip schema directive
        connection_data = yaml.safe_load(fh)
    assert connection_data.get("baz") == "qux"
    # Sanity: the auth profile was emitted too.
    assert connection_data["profiles"][0]["id"] == "api_key.myint"

    serializer_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-myint"
        / "serializer.yaml"
    )
    # With no field-id collisions, no serializer entries are written, so
    # serializer.yaml is not created.
    assert not serializer_yaml_path.exists()


# ---------------------------------------------------------------------------
# Dedup-via-rename + serializer-mapping
# (per Q1=a / Q2=a / Q3=a / Q4=b in the design discussion)
# ---------------------------------------------------------------------------


def _read_serializer_dict(handler_dir: Path) -> dict:
    """Helper: load handler_dir/serializer.yaml stripping the directive line."""
    path = handler_dir / "serializer.yaml"
    raw = path.read_text()
    # Strip leading comment lines
    lines = raw.splitlines(keepends=True)
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("#") or stripped == "":
            idx += 1
            continue
        break
    body = "".join(lines[idx:])
    return yaml.safe_load(body) or {}


def test_collect_existing_field_ids_walks_all_three_files():
    """All three input dicts contribute their field ids to the returned set."""
    capabilities = {
        "general_configurations": {
            "configurations": [
                {"fields": [{"id": "alpha"}, {"id": "beta"}]},
            ]
        }
    }
    configurations = {
        "configurations": [
            {
                "id": "cap-1",
                "configurations": [
                    {"fields": [{"id": "gamma"}, {"id": "delta"}]},
                ],
            },
        ]
    }
    connection = {
        "profiles": [
            {
                "id": "profile-1",
                "configurations": [
                    {"fields": [{"id": "epsilon"}]},
                ],
            },
        ]
    }
    result = collect_existing_field_ids(capabilities, configurations, connection)
    assert result == {"alpha", "beta", "gamma", "delta", "epsilon"}


def test_collect_existing_field_ids_tolerates_partial_inputs():
    """Missing keys / None inputs collapse to empty contribution."""
    assert collect_existing_field_ids(None, None, None) == set()
    assert collect_existing_field_ids({}, {}, {}) == set()
    # Only configurations populated
    assert collect_existing_field_ids(
        {},
        {"configurations": [{"id": "c", "configurations": [{"fields": [{"id": "x"}]}]}]},
        None,
    ) == {"x"}


def test_register_serializer_entry_creates_file_with_directive(tmp_path: Path):
    """First call creates the file with schema directive + a single mapping."""
    handler_dir = tmp_path / "h"
    register_serializer_entry(handler_dir, new_id="h_team", original_id="team")
    serializer_path = handler_dir / "serializer.yaml"
    assert serializer_path.is_file()
    raw = serializer_path.read_text()
    assert raw.startswith("# yaml-language-server: $schema=")
    data = _read_serializer_dict(handler_dir)
    assert data == {
        "field_mappings": [{"id": "h_team", "field_name": "team"}]
    }


def test_register_serializer_entry_appends_to_existing_dict_file(tmp_path: Path):
    """Second call (different mapping) appends without overwriting the first."""
    handler_dir = tmp_path / "h"
    register_serializer_entry(handler_dir, new_id="h_a", original_id="a")
    register_serializer_entry(handler_dir, new_id="h_b", original_id="b")
    data = _read_serializer_dict(handler_dir)
    assert data["field_mappings"] == [
        {"id": "h_a", "field_name": "a"},
        {"id": "h_b", "field_name": "b"},
    ]


def test_register_serializer_entry_is_idempotent(tmp_path: Path):
    """Calling twice with the same (new_id, original_id) does not duplicate."""
    handler_dir = tmp_path / "h"
    register_serializer_entry(handler_dir, new_id="h_x", original_id="x")
    register_serializer_entry(handler_dir, new_id="h_x", original_id="x")
    data = _read_serializer_dict(handler_dir)
    assert data["field_mappings"] == [{"id": "h_x", "field_name": "x"}]


def test_register_serializer_entry_preserves_existing_computed_fields(tmp_path: Path):
    """An existing serializer.yaml with computed_fields (Salesforce example
    style) keeps them intact when a new field_mappings entry is appended."""
    handler_dir = tmp_path / "h"
    handler_dir.mkdir(parents=True)
    serializer_path = handler_dir / "serializer.yaml"
    # Seed with a comment line + computed_fields + a pre-existing field_mappings entry
    serializer_path.write_text(
        "# yaml-language-server: $schema=foo\n"
        "field_mappings:\n"
        "  - id: preexisting\n"
        "    field_name: pre\n"
        "computed_fields:\n"
        "  - output:\n"
        "      - id: fetch_event\n"
        "        value: true\n"
        "    any_of:\n"
        "      - conditions: []\n"
    )

    register_serializer_entry(handler_dir, new_id="h_new", original_id="new")
    data = _read_serializer_dict(handler_dir)
    # Existing entries preserved
    assert {"id": "preexisting", "field_name": "pre"} in data["field_mappings"]
    # New entry appended
    assert {"id": "h_new", "field_name": "new"} in data["field_mappings"]
    # computed_fields untouched
    assert data["computed_fields"][0]["output"][0]["id"] == "fetch_event"


def test_dedup_field_id_returns_unchanged_when_no_conflict(tmp_path: Path):
    """When the id is not in existing_ids, it's returned as-is, no serializer
    side-effect, and the set is updated."""
    handler_dir = tmp_path / "h"
    existing: set = set()
    result = dedup_field_id_and_register(existing, "h", handler_dir, "team")
    assert result == "team"
    assert existing == {"team"}
    assert not (handler_dir / "serializer.yaml").exists()


def test_dedup_field_id_renames_and_registers_on_conflict(tmp_path: Path):
    """When the id IS in existing_ids, returns prefixed id, adds prefixed id
    to the set, and creates a serializer.yaml mapping prefixed -> original."""
    handler_dir = tmp_path / "h"
    existing: set = {"team"}
    result = dedup_field_id_and_register(existing, "h", handler_dir, "team")
    assert result == "h_team"
    assert existing == {"team", "h_team"}
    data = _read_serializer_dict(handler_dir)
    assert data["field_mappings"] == [{"id": "h_team", "field_name": "team"}]


def _write_integration_yml(path: Path, integration_id: str) -> dict:
    """Write a minimal integration YAML with an explicit ``commonfields.id``
    and return the parsed dict. Used by the dedup tests to give each
    integration a unique handler-id (so the per-handler dir paths don't
    collide between two-handler scenarios)."""
    yml = {
        "name": integration_id,
        "commonfields": {"id": integration_id, "version": -1},
        "display": integration_id,
        "configuration": [],
        "script": {"commands": [], "type": "python", "subtype": "python3"},
    }
    path.write_text(yaml.safe_dump(yml))
    return yml


def test_create_manifest_from_scratch_dedup_inside_same_handler(tmp_path: Path):
    """Same-handler cross-bucket collision (a field appears in BOTH
    general_configurations AND a per-capability bucket): the first emission
    keeps the bare id; the second is renamed and serializer.yaml gets an
    entry mapping the renamed id back to the original.
    """
    integration_yml_path = _make_pack_with_integration(
        tmp_path / "ws",
        pack_name="TestPack",
        integration_name="MyInt",
        pack_metadata=None,
    )
    integration_yml = _write_integration_yml(integration_yml_path, "MyInt")
    connector_dir = tmp_path / "connectors" / "test_conn"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_yml_path,
        connector_title="test_conn",
        mapped_params={
            "general_configurations": ["server_url"],
            "Automation": ["server_url", "extra"],
        },
        auth_methods={},
    )

    # User-mapped general_configurations params are now in
    # configurations.yaml general_configurations (not capabilities.yaml).
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data_check = yaml.safe_load(fh)
    gc_entries = cfg_data_check.get("general_configurations", {}).get(
        "configurations", []
    )
    gc_field_ids = [
        f["id"]
        for g in gc_entries
        for f in g.get("fields", [])
    ]
    # server_url may be prefixed with handler id due to dedup.
    assert any("server_url" in fid for fid in gc_field_ids)

    # The Automation bucket is emitted first (via build_configurations_yaml),
    # so its server_url gets the bare id. The general_configurations
    # server_url (emitted second via build_per_handler_general_config)
    # gets renamed to xsoar-myint_server_url.
    automation_field_ids = [
        f["id"]
        for cfg in cfg_data_check["configurations"]
        for g in cfg["configurations"]
        for f in g["fields"]
    ]
    handler_id = "xsoar-myint"
    # Automation bucket keeps the bare id (emitted first).
    assert "server_url" in automation_field_ids
    assert "extra" in automation_field_ids  # untouched

    # The general_configurations server_url got renamed (emitted second).
    renamed = f"{handler_id}_server_url"
    assert renamed in gc_field_ids

    # Handler serializer.yaml has the dedup mapping for the renamed one.
    serializer_data = _read_serializer_dict(
        connector_dir / "components" / "handlers" / handler_id
    )
    assert {"id": renamed, "field_name": "server_url"} in serializer_data["field_mappings"]


def test_add_handler_dedup_against_existing_capabilities_yaml_field(tmp_path: Path):
    """Append a 2nd handler to an existing connector whose configurations.yaml
    already has the field id 'team'. The new handler's same-named param is
    renamed; the existing 'team' field is left untouched.
    """
    integration_yml_path_1 = _make_pack_with_integration(
        tmp_path / "ws1",
        pack_name="Pack1",
        integration_name="FirstInt",
        pack_metadata=None,
    )
    integration_yml_1 = _write_integration_yml(integration_yml_path_1, "FirstInt")
    connector_dir = tmp_path / "connectors" / "shared"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml_1,
        integration_path=integration_yml_path_1,
        connector_title="shared",
        mapped_params={"Automation": ["team"]},
        auth_methods={},
    )

    # 2nd integration (different commonfields.id so derive_handler_id yields a
    # distinct handler dir name)
    integration_yml_path_2 = _make_pack_with_integration(
        tmp_path / "ws2",
        pack_name="Pack2",
        integration_name="SecondInt",
        pack_metadata=None,
    )
    integration_yml_2 = _write_integration_yml(integration_yml_path_2, "SecondInt")
    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml=integration_yml_2,
        integration_path=integration_yml_path_2,
        connector_title="shared",
        mapped_params={"Automation": ["team"]},
        auth_methods={},
    )

    # Verify configurations.yaml
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    all_field_ids = [
        f["id"]
        for cfg in cfg_data["configurations"]
        for g in cfg["configurations"]
        for f in g["fields"]
    ]
    # Per Batch 4 (Part A.4.1): handler id uses dash separator.
    assert "team" in all_field_ids  # original handler's field still there
    new_handler_id = "xsoar-secondint"
    renamed = f"{new_handler_id}_team"
    assert renamed in all_field_ids
    # No duplicate
    assert all_field_ids.count("team") == 1
    assert all_field_ids.count(renamed) == 1

    # Verify new handler's serializer.yaml has the dedup mapping
    serializer_data = _read_serializer_dict(
        connector_dir / "components" / "handlers" / new_handler_id
    )
    assert {"id": renamed, "field_name": "team"} in serializer_data["field_mappings"]


# ---------------------------------------------------------------------------
# Rich field materializer wiring
# (per Q1=a / Q2=a / Q3=c / Q4=a / Q5=a in the design discussion)
# ---------------------------------------------------------------------------


def test_emit_field_for_param_rich_type_0_input():
    """Type 0 (short text) yml param yields a single input field with
    title from display, options.description from additionalinfo, and
    create/edit_modifiers gated on required + hidden."""
    yml = {
        "type": 0,
        "name": "url",
        "display": "Server URL",
        "additionalinfo": "Base URL for the service.",
        "required": True,
        "defaultvalue": "https://example.com",
    }
    out = emit_field_for_param("url", {"url": yml})
    assert len(out) == 1
    field = out[0]
    assert field["id"] == "url"
    assert field["field_type"] == "input"
    assert field["title"] == "Server URL"
    assert field["options"]["description"] == "Base URL for the service."
    assert field["options"]["default_value"] == "https://example.com"
    assert field["options"]["create_modifiers"] == {"required": True, "hidden": False}
    assert field["options"]["edit_modifiers"] == {"required": True, "hidden": False}


def test_emit_field_for_param_rich_type_8_checkbox_coerces_bool_default():
    """Type 8 (boolean) yml param with defaultvalue='true' (string) is
    coerced to a Python bool True in options.default_value.

    Per Batch 3 (Part A.11.1) + guide Appendix A: type 8 emits
    ``checkbox`` (NOT ``toggle`` — the two render differently in the UI).
    """
    yml = {
        "type": 8,
        "name": "isFetch",
        "display": "Fetch incidents",
        "defaultvalue": "true",
        "required": False,
    }
    field = emit_field_for_param("isFetch", {"isFetch": yml})[0]
    assert field["field_type"] == "checkbox"
    assert field["options"]["default_value"] is True


def test_emit_field_for_param_type_18_indicator_reputation_hardcoded_values():
    """Per Batch 3 (Part A.11.3) + guide Appendix A: type 18 ('Indicator
    / Feed Reputation') maps to ``select`` with hardcoded values
    (Unknown / Benign / Suspicious / Malicious — the 'new mapped
    values' replacing the legacy None / Good / Suspicious / Bad)."""
    yml = {
        "type": 18,
        "name": "feedReputation",
        "display": "Indicator Reputation",
        # Legacy XSOAR options — must NOT appear in the output.
        "options": ["None", "Good", "Suspicious", "Bad"],
    }
    field = emit_field_for_param("feedReputation", {"feedReputation": yml})[0]
    assert field["field_type"] == "select"
    keys = [v["key"] for v in field["options"]["values"]]
    assert keys == ["Unknown", "Benign", "Suspicious", "Malicious"]


def test_emit_field_for_param_skips_platform_hidden_param(caplog):
    """Per Batch 6 (Part A.3.8) + guide §3.1 *Assumptions #4*: a yml
    param with ``hidden: [platform]`` (marketplace-keyed form) is
    excluded entirely — emit returns an EMPTY list and logs an info
    message. Callers must be tolerant of empty results."""
    import logging as _logging

    yml = {
        "type": 0,
        "name": "platform_only_secret",
        "display": "Some Hidden Param",
        "hidden": ["platform"],
    }
    with caplog.at_level(_logging.INFO, logger="manifest_generator"):
        result = emit_field_for_param(
            "platform_only_secret", {"platform_only_secret": yml}
        )
    assert result == [], "Platform-hidden param must yield NO fields"
    assert any(
        "hidden on platform marketplace" in rec.message
        for rec in caplog.records
    )


def test_emit_field_for_param_does_NOT_skip_non_platform_hidden_param():
    """Regression: ``hidden: [xsoar_on_prem]`` (a non-platform
    marketplace) MUST NOT trigger the platform-only skip — the param
    should still be emitted (visible on Platform; hidden elsewhere)."""
    yml = {
        "type": 0,
        "name": "platform_visible",
        "display": "Visible on Platform",
        "hidden": ["xsoar_on_prem", "marketplacev2"],
    }
    result = emit_field_for_param("platform_visible", {"platform_visible": yml})
    assert len(result) == 1
    assert result[0]["id"] == "platform_visible"


def test_emit_field_for_param_ALSO_skips_when_hidden_is_bool_true():
    """Per :func:`_is_hidden_on_platform`: ``hidden: true`` (boolean
    form) means "hidden in every marketplace including platform" and
    is treated as platform-hidden. The mapper's
    ``_collect_hidden_params`` applies the same rule — this keeps the
    manifest generator in lockstep so we never emit a field for a
    param the mapper already excluded from capability routing."""
    yml = {
        "type": 0,
        "name": "always_hidden",
        "display": "Always Hidden",
        "hidden": True,
    }
    result = emit_field_for_param("always_hidden", {"always_hidden": yml})
    assert result == []


def test_emit_field_for_param_hidden_with_default_moves_to_computed_field(
    tmp_path: Path,
):
    """A platform-hidden param that carries a ``defaultvalue`` is NOT emitted
    as a manifest field; instead its default is pushed via a serializer
    computed_fields rule (output id = original yml param name, value = coerced
    default), gated on the supplied capability id(s)."""
    yml = {
        "type": 8,
        "name": "trust_any_certificate",
        "display": "Trust any cert",
        "hidden": True,
        "defaultvalue": "true",
    }
    result = emit_field_for_param(
        "trust_any_certificate",
        {"trust_any_certificate": yml},
        handler_id="xsoar",
        handler_dir=tmp_path,
        existing_ids=set(),
        gating_capability_ids=["log-collection_acme"],
    )
    assert result == []  # no manifest field emitted

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"] == [
        {
            "output": [{"id": "trust_any_certificate", "value": True}],
            "any_of": [
                {
                    "conditions": [
                        {
                            "type": "capability",
                            "options": {
                                "capability_id": "log-collection_acme",
                                "value": "on",
                            },
                        }
                    ]
                }
            ],
        }
    ]


def test_emit_field_for_param_hidden_no_default_is_dropped(tmp_path: Path):
    """A platform-hidden param with NO ``defaultvalue`` is dropped entirely —
    no manifest field AND no serializer computed_fields rule (there is nothing
    meaningful to inject)."""
    yml = {
        "type": 0,
        "name": "legacy_flag",
        "display": "Legacy",
        "hidden": True,
    }
    result = emit_field_for_param(
        "legacy_flag",
        {"legacy_flag": yml},
        handler_id="xsoar",
        handler_dir=tmp_path,
        existing_ids=set(),
        gating_capability_ids=["log-collection_acme"],
    )
    assert result == []
    assert not (tmp_path / "serializer.yaml").exists()


def test_emit_field_for_param_hidden_default_or_gated_across_capabilities(
    tmp_path: Path,
):
    """When multiple gating capability ids are supplied (e.g. a
    general_configurations hidden-default param not attached to a single
    capability), the computed_fields rule lists one ``any_of`` group per
    capability (OR logic)."""
    yml = {
        "type": 8,
        "name": "use_proxy",
        "hidden": True,
        "defaultvalue": "false",
    }
    emit_field_for_param(
        "use_proxy",
        {"use_proxy": yml},
        handler_id="xsoar",
        handler_dir=tmp_path,
        existing_ids=set(),
        gating_capability_ids=["log-collection_acme", "fetch-issues_acme"],
    )
    serializer = _read_serializer_dict(tmp_path)
    rule = serializer["computed_fields"][0]
    assert rule["output"] == [{"id": "use_proxy", "value": False}]
    cap_ids = [
        g["conditions"][0]["options"]["capability_id"] for g in rule["any_of"]
    ]
    assert cap_ids == ["log-collection_acme", "fetch-issues_acme"]


def test_build_capability_gated_computed_field_single_and_multi():
    """The helper builds one ``any_of`` group for a single capability id and
    one group per id (OR) for multiple ids."""
    single = build_capability_gated_computed_field(
        output_id="x", value=True, sub_capability_ids=["cap-a"]
    )
    assert single == {
        "output": [{"id": "x", "value": True}],
        "any_of": [
            {
                "conditions": [
                    {
                        "type": "capability",
                        "options": {"capability_id": "cap-a", "value": "on"},
                    }
                ]
            }
        ],
    }
    multi = build_capability_gated_computed_field(
        output_id="y", value=5, sub_capability_ids=["cap-a", "cap-b"]
    )
    assert len(multi["any_of"]) == 2
    assert multi["output"] == [{"id": "y", "value": 5}]


def test_register_computed_field_entry_idempotent_and_preserves_field_mappings(
    tmp_path: Path,
):
    """register_computed_field_entry appends to computed_fields, preserves any
    existing field_mappings, and is idempotent for identical rules."""
    # Seed with a field_mappings entry first.
    register_serializer_entry(tmp_path, new_id="renamed", original_id="orig")

    rule = build_capability_gated_computed_field(
        output_id="z", value=True, sub_capability_ids=["cap-a"]
    )
    register_computed_field_entry(tmp_path, rule)
    register_computed_field_entry(tmp_path, rule)  # idempotent — no duplicate

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["field_mappings"] == [
        {"id": "renamed", "field_name": "orig"}
    ]
    assert serializer["computed_fields"] == [rule]


def test_emit_field_for_param_type_22_copy_to_clipboard_emits_label():
    """Per Batch 3 (Part A.11.5) + guide Appendix A: type 22 ('Copy to
    Clipboard') maps to ``label`` — a read-only display field with no
    input affordance, no default_value, no modifiers."""
    yml = {
        "type": 22,
        "name": "redirectUri",
        "display": "Redirect URI",
        "additionalinfo": "Copy this value into your OAuth app config.",
    }
    field = emit_field_for_param("redirectUri", {"redirectUri": yml})[0]
    assert field["field_type"] == "label"
    assert field["title"] == "Redirect URI"
    assert field["options"]["description"] == (
        "Copy this value into your OAuth app config."
    )
    # No editable surface.
    assert "default_value" not in field.get("options", {})
    assert "create_modifiers" not in field.get("options", {})
    assert "edit_modifiers" not in field.get("options", {})


def test_emit_field_for_param_rich_type_15_select_with_options_values():
    """Type 15 (single-select) yml param emits a select field with
    options.values mapped from yml.options."""
    yml = {
        "type": 15,
        "name": "auth_type",
        "display": "Authentication Type",
        "options": ["Client Credentials", "Authorization Code"],
        "defaultvalue": "Client Credentials",
        "required": False,
    }
    field = emit_field_for_param("auth_type", {"auth_type": yml})[0]
    assert field["field_type"] == "select"
    values = field["options"]["values"]
    # Live field-options.schema requires {key, label} for select fields.
    assert {"key": "Client Credentials", "label": "Client Credentials"} in values
    assert {"key": "Authorization Code", "label": "Authorization Code"} in values


def test_emit_field_for_param_type_9_credentials_splits_into_two_fields():
    """Type 9 (credentials) yml param without hiddenusername emits TWO
    connectus fields: <name>_username (input) + <name>_password (input
    with mask). Title on the username half is yml.display; title on the
    password half is yml.displaypassword (if present)."""
    yml = {
        "type": 9,
        "name": "creds",
        "display": "Bot ID",
        "displaypassword": "Bot Password",
        "required": False,
    }
    out = emit_field_for_param("creds", {"creds": yml})
    assert len(out) == 2
    user, pwd = out
    assert user["id"] == "creds_username"
    assert user["field_type"] == "input"
    assert user["title"] == "Bot ID"
    assert pwd["id"] == "creds_password"
    assert pwd["field_type"] == "input"
    assert pwd["options"]["mask"] is True
    assert pwd["title"] == "Bot Password"


def test_emit_field_for_param_type_9_hiddenusername_emits_only_password():
    """Type 9 credentials with hiddenusername=true emits ONLY the password
    half, and its id equals the yml param name (no _password suffix)."""
    yml = {
        "type": 9,
        "name": "auth_code_creds",
        "displaypassword": "Authorization code",
        "hiddenusername": True,
        "required": False,
    }
    out = emit_field_for_param("auth_code_creds", {"auth_code_creds": yml})
    assert len(out) == 1
    pwd = out[0]
    assert pwd["id"] == "auth_code_creds"
    assert pwd["options"]["mask"] is True
    assert pwd["title"] == "Authorization code"


def test_emit_field_for_param_bare_id_fallback_when_yml_missing(caplog):
    """When yml_params_by_name is provided but the name is missing from
    it, fall back to a single bare-id field and log a warning (Q3=c)."""
    import logging
    with caplog.at_level(logging.WARNING, logger="manifest_generator"):
        out = emit_field_for_param("phantom", yml_params_by_name={"other": {"type": 0, "name": "other"}})
    assert out == [{"id": "phantom"}]
    assert any("phantom" in rec.message for rec in caplog.records)


def test_create_manifest_from_scratch_emits_rich_fields_with_titles(tmp_path: Path):
    """End-to-end: the from-scratch path threads yml_params_by_name through
    the builders so emitted fields in configurations.yaml have title,
    field_type, and options — not just id."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path / "ws",
        pack_name="PackX",
        integration_name="MyInt",
        pack_metadata=None,
    )
    # Override the integration YML with a real configuration list.
    integration_yml = {
        "name": "MyInt",
        "commonfields": {"id": "MyInt", "version": -1},
        "display": "MyInt",
        "configuration": [
            {
                "type": 0,
                "name": "domain",
                "display": "Domain",
                "required": True,
                "defaultvalue": "example.com",
            },
            {
                "type": 8,
                "name": "useFetch",
                "display": "Use Fetch",
                "defaultvalue": "false",
            },
        ],
        "script": {"commands": [], "type": "python", "subtype": "python3"},
    }
    integration_yml_path.write_text(yaml.safe_dump(integration_yml))

    connector_dir = tmp_path / "connectors" / "rich_test"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_yml_path,
        connector_title="rich_test",
        mapped_params={"Automation": ["domain", "useFetch"]},
        auth_methods={},
    )

    with open(connector_dir / "configurations.yaml") as fh:
        cfg = yaml.safe_load(fh)

    fields_by_id = {
        f["id"]: f
        for cfg_entry in cfg["configurations"]
        for group in cfg_entry["configurations"]
        for f in group["fields"]
    }
    # Both fields are present with rich shape
    assert fields_by_id["domain"]["field_type"] == "input"
    assert fields_by_id["domain"]["title"] == "Domain"
    assert fields_by_id["domain"]["options"]["default_value"] == "example.com"
    assert fields_by_id["domain"]["options"]["create_modifiers"]["required"] is True

    # Per Batch 3 (Part A.11.1): type 8 → ``checkbox`` (not toggle).
    assert fields_by_id["useFetch"]["field_type"] == "checkbox"
    assert fields_by_id["useFetch"]["options"]["default_value"] is False  # coerced


# ============================================================
# Synthetic-field helpers: build_synthetic_hidden_toggle /
# register_renamed_field_serializer_entry /
# add_secret_capability
# ============================================================


def test_build_synthetic_hidden_toggle_default_shape():
    """
    Given: build_synthetic_hidden_toggle called with the minimum args
           (field_id + title), accepting defaults for default_value (False)
           and required (False).
    When:  Inspecting the returned dict.
    Then:  field_type is 'toggle', default_value is False, BOTH
           create_modifiers AND edit_modifiers carry hidden=True and
           required=False.
    """
    field = build_synthetic_hidden_toggle(field_id="my_toggle", title="My Toggle")

    assert field == {
        "id": "my_toggle",
        "title": "My Toggle",
        "field_type": "toggle",
        "options": {
            "default_value": False,
            "create_modifiers": {"required": False, "hidden": True},
            "edit_modifiers": {"required": False, "hidden": True},
        },
    }


def test_build_synthetic_hidden_toggle_respects_overrides():
    """
    Given: build_synthetic_hidden_toggle called with default_value=True
           and required=True.
    When:  Inspecting the returned dict.
    Then:  Both modifier blocks carry required=True (still hidden=True —
           hiddenness is a hardcoded characteristic of the helper) and
           options.default_value is True.
    """
    field = build_synthetic_hidden_toggle(
        field_id="forced_on",
        title="Forced On",
        default_value=True,
        required=True,
    )

    assert field["options"]["default_value"] is True
    assert field["options"]["create_modifiers"] == {"required": True, "hidden": True}
    assert field["options"]["edit_modifiers"] == {"required": True, "hidden": True}


def test_register_renamed_field_serializer_entry_writes_bridge(tmp_path: Path):
    """
    Given: A handler dir without an existing serializer.yaml.
    When:  register_renamed_field_serializer_entry is called with
           original_id='isFetchCredentials' and renamed_id=
           'fetch-secrets-myhandler_isFetchCredentials'.
    Then:  A serializer.yaml is created with a field_mappings entry
           bridging the renamed id back to the original id. The thin
           wrapper just delegates to register_serializer_entry — so the
           file shape matches what other dedup callers produce.
    """
    register_renamed_field_serializer_entry(
        tmp_path,
        original_id="isFetchCredentials",
        renamed_id="fetch-secrets-myhandler_isFetchCredentials",
    )
    serializer = _read_serializer_dict(tmp_path)
    assert serializer["field_mappings"] == [
        {
            "id": "fetch-secrets-myhandler_isFetchCredentials",
            "field_name": "isFetchCredentials",
        }
    ]


# ---------------------------------------------------------------------------
# Per-handler general_configurations (integrationLogLevel + defaultIgnore)
# ---------------------------------------------------------------------------
def test_build_per_handler_general_config_shape(tmp_path: Path):
    """build_per_handler_general_config returns a view_group-pinned
    field group with exactly 1 field: integrationLogLevel (select). With
    no collisions the field id keeps its bare canonical name (no handler-id
    prefix). defaultIgnore is NO longer emitted here — it is injected under
    the automation capability instead."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    result = build_per_handler_general_config("xsoar-salesforce", handler_dir)

    assert result["view_group"] == "salesforce"
    fields = result["fields"]
    assert len(fields) == 1

    log_level = fields[0]
    assert log_level["id"] == "integrationLogLevel"
    assert log_level["title"] == "Log Level"
    assert log_level["field_type"] == "select"
    assert log_level["metadata"]["xsoar"]["config_type"] == "backend"
    values = log_level["options"]["values"]
    assert [v["key"] for v in values] == ["Off", "Debug", "Verbose"]
    assert log_level["options"]["default_value"] == "Off"

    # defaultIgnore is not part of the general_configurations group anymore.
    assert "defaultIgnore" not in [f["id"] for f in fields]


def test_build_per_handler_general_config_no_serializer_entries_without_collision(
    tmp_path: Path,
):
    """build_per_handler_general_config does NOT write serializer
    field_mappings entries when the canonical id doesn't collide — the
    bare id is used directly, so no bridge is needed and serializer.yaml
    is not created."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    build_per_handler_general_config("xsoar-myint", handler_dir)

    assert not (handler_dir / "serializer.yaml").exists()


def test_build_per_handler_general_config_prefixes_and_bridges_on_collision(
    tmp_path: Path,
):
    """When the canonical id already collides (pre-seeded existing_ids),
    build_per_handler_general_config renames to ``<handler_id>_<id>`` and
    registers a serializer field_mappings entry bridging back to the
    canonical param name. Only integrationLogLevel is handled here now
    (defaultIgnore moved to the automation capability)."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    existing = {"integrationLogLevel"}
    result = build_per_handler_general_config(
        "xsoar-myint", handler_dir, existing_ids=existing
    )

    field_ids = [f["id"] for f in result["fields"]]
    assert "xsoar-myint_integrationLogLevel" in field_ids

    serializer_data = _read_serializer_dict(handler_dir)
    mappings = serializer_data.get("field_mappings", [])
    assert len(mappings) == 1
    mapping_by_id = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_by_id["xsoar-myint_integrationLogLevel"] == "integrationLogLevel"


def test_build_default_ignore_capability_field_shape(tmp_path: Path):
    """build_default_ignore_capability_field returns the defaultIgnore
    checkbox field with the bare canonical id when there is no collision."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    field = build_default_ignore_capability_field("xsoar-salesforce", handler_dir)

    assert field["id"] == "defaultIgnore"
    assert field["title"] == "Do not use in CLI by default"
    assert field["field_type"] == "checkbox"
    assert field["metadata"]["xsoar"]["config_type"] == "backend"
    assert field["options"]["default_value"] is False
    # No collision -> no serializer.yaml bridge.
    assert not (handler_dir / "serializer.yaml").exists()


def test_build_default_ignore_capability_field_bridges_on_collision(tmp_path: Path):
    """When ``defaultIgnore`` already collides (pre-seeded existing_ids),
    build_default_ignore_capability_field renames to
    ``<handler_id>_defaultIgnore`` and registers a serializer field_mappings
    entry bridging back to the canonical ``defaultIgnore`` param name."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    existing = {"defaultIgnore"}
    field = build_default_ignore_capability_field(
        "xsoar-myint", handler_dir, existing_ids=existing
    )

    assert field["id"] == "xsoar-myint_defaultIgnore"

    serializer_data = _read_serializer_dict(handler_dir)
    mappings = serializer_data.get("field_mappings", [])
    assert len(mappings) == 1
    assert mappings[0]["id"] == "xsoar-myint_defaultIgnore"
    assert mappings[0]["field_name"] == "defaultIgnore"


def test_from_scratch_emits_per_handler_general_config_in_configurations_yaml(
    tmp_path: Path,
):
    """End-to-end: create_manifest_from_scratch emits the per-handler
    general_configurations field group + view_groups registry entry
    in configurations.yaml. With an Automation capability, defaultIgnore
    is injected under the automation-and-remediation sub-cap entry (NOT in
    general_configurations)."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "test_conn"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "MyInt"},
            "display": "MyInt",
        },
        integration_path=integration_yml_path,
        connector_title="test_conn",
        mapped_params={"Automation": ["p1"]},
        auth_methods={},
    )

    with open(connector_dir / "configurations.yaml") as fh:
        cfg = yaml.safe_load(fh)

    # view_groups registry has the handler id.
    vg_ids = [vg["id"] for vg in cfg.get("view_groups", [])]
    assert "myint" in vg_ids

    # general_configurations has a view_group-pinned field group with only
    # integrationLogLevel — defaultIgnore is no longer here.
    gc_entries = cfg.get("general_configurations", {}).get("configurations", [])
    handler_gc = [e for e in gc_entries if e.get("view_group") == "myint"]
    assert len(handler_gc) == 1
    field_ids = [f["id"] for f in handler_gc[0]["fields"]]
    assert "integrationLogLevel" in field_ids
    assert "defaultIgnore" not in field_ids

    # defaultIgnore is injected under the automation-and-remediation sub-cap.
    automation_entry = next(
        c
        for c in cfg["configurations"]
        if c["id"] == "automation-and-remediation_myint"
    )
    automation_field_ids = [
        f["id"]
        for grp in automation_entry["configurations"]
        for f in grp["fields"]
    ]
    assert "defaultIgnore" in automation_field_ids


def test_from_scratch_omits_default_ignore_without_automation_capability(
    tmp_path: Path,
):
    """When the connector has NO Automation capability, defaultIgnore is not
    emitted anywhere — neither in general_configurations nor in any capability
    entry."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "test_conn"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "MyInt"},
            "display": "MyInt",
        },
        integration_path=integration_yml_path,
        connector_title="test_conn",
        mapped_params={"Fetch Issues": ["p1"]},
        auth_methods={},
    )

    with open(connector_dir / "configurations.yaml") as fh:
        cfg = yaml.safe_load(fh)

    # general_configurations has only integrationLogLevel — no defaultIgnore.
    gc_entries = cfg.get("general_configurations", {}).get("configurations", [])
    handler_gc = [e for e in gc_entries if e.get("view_group") == "myint"]
    assert len(handler_gc) == 1
    field_ids = [f["id"] for f in handler_gc[0]["fields"]]
    assert "integrationLogLevel" in field_ids
    assert "defaultIgnore" not in field_ids

    # No capability entry carries defaultIgnore either.
    all_cap_field_ids = [
        f["id"]
        for c in cfg.get("configurations", [])
        for grp in c.get("configurations", [])
        for f in grp.get("fields", [])
    ]
    assert "defaultIgnore" not in all_cap_field_ids


def test_add_secret_capability_top_level_emits_no_field_only_computed(
    tmp_path: Path,
):
    """
    Given: A mapped_params dict that DOES NOT have a Fetch Secrets bucket.
           add_secret_capability is called with is_sub_capability=False and
           capability_id='fetch-secrets' plus a handler_dir.
    When:  add_secret_capability runs.
    Then:  The returned template emits NO manifest field (no more hidden
           default-True toggle). Instead a serializer computed_fields rule
           is registered injecting isFetchCredentials=true gated on this
           capability being 'on'.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Automation": ["some_param"],
    }

    template = add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    assert template["capability_id"] == "fetch-secrets"
    assert template["fields"] == []

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"] == [
        {
            "output": [{"id": "isFetchCredentials", "value": True}],
            "any_of": [
                {
                    "conditions": [
                        {
                            "type": "capability",
                            "options": {
                                "capability_id": "fetch-secrets",
                                "value": "on",
                            },
                        }
                    ]
                }
            ],
        }
    ]


def test_add_secret_capability_sub_capability_gates_on_sub_cap_id(
    tmp_path: Path,
):
    """
    Given: add_secret_capability is called with is_sub_capability=True
           and a sub-cap id 'fetch-secrets-xsoar-mygraphmail'.
    When:  Inspecting the returned template + serializer.
    Then:  No manifest field is emitted; the computed_fields rule is gated
           on the sub-capability id.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_secret_capability(
        capability_id="fetch-secrets-xsoar-mygraphmail",
        is_sub_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    assert template["capability_id"] == "fetch-secrets-xsoar-mygraphmail"
    assert template["fields"] == []

    serializer = _read_serializer_dict(tmp_path)
    rule = serializer["computed_fields"][0]
    assert rule["output"] == [{"id": "isFetchCredentials", "value": True}]
    assert rule["any_of"][0]["conditions"][0]["options"]["capability_id"] == (
        "fetch-secrets-xsoar-mygraphmail"
    )


def test_add_secret_capability_strips_isfetchcredentials_from_mapper_results():
    """
    Given: A mapper output where 'isFetchCredentials' was placed in TWO
           buckets (general_configurations AND a Fetch Secrets bucket).
    When:  add_secret_capability runs.
    Then:  'isFetchCredentials' is stripped from BOTH buckets in place
           so the standard param-mapping pass doesn't re-emit it. Other
           param names are preserved.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": ["isFetchCredentials", "timeout"],
        "Fetch Secrets": ["isFetchCredentials"],
        "Automation": ["unrelated"],
    }

    add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
    )

    assert mapped["general_configurations"] == ["timeout"]
    assert mapped["Fetch Secrets"] == []
    assert mapped["Automation"] == ["unrelated"]


def test_add_secret_capability_sub_cap_path_writes_computed_field(tmp_path: Path):
    """
    Given: A sub-capability call with handler_dir set.
    When:  add_secret_capability runs.
    Then:  serializer.yaml at handler_dir contains a computed_fields rule
           injecting isFetchCredentials=true gated on the sub-capability —
           NOT a field_mappings bridge (no manifest field exists anymore).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_secret_capability(
        capability_id="fetch-secrets-xsoar-mygraphmail",
        is_sub_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    assert "field_mappings" not in serializer
    assert serializer["computed_fields"] == [
        {
            "output": [{"id": "isFetchCredentials", "value": True}],
            "any_of": [
                {
                    "conditions": [
                        {
                            "type": "capability",
                            "options": {
                                "capability_id": (
                                    "fetch-secrets-xsoar-mygraphmail"
                                ),
                                "value": "on",
                            },
                        }
                    ]
                }
            ],
        }
    ]


def test_add_secret_capability_top_level_writes_computed_field(tmp_path: Path):
    """
    Given: A top-level call (is_sub_capability=False) with handler_dir.
    When:  add_secret_capability runs.
    Then:  serializer.yaml IS created with a computed_fields rule (the
           value is always injected via the serializer now — there is no
           hidden toggle field).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchCredentials", "value": True}
    ]


def test_isfetchcredentials_param_name_constant_matches_xsoar_yaml_name():
    """
    Given: The ISFETCHCREDENTIALS_PARAM_NAME constant exported by
           manifest_generator.
    When:  Inspected.
    Then:  It equals exactly 'isFetchCredentials' — the literal XSOAR
           YAML name (camelCase, no underscores). This is the name the
           mapper's Rule 1 in decide_capabilities() checks for, and
           must stay in lockstep with that source.
    """
    assert ISFETCHCREDENTIALS_PARAM_NAME == "isFetchCredentials"


# ============================================================
# Log Collection capability builder: add_log_collection_capability
# ============================================================


def test_log_collection_constants_match_xsoar_yaml_names():
    """
    Given: The ISFETCHEVENTS_PARAM_NAME / EVENTFETCHINTERVAL_PARAM_NAME /
           EVENTFETCHINTERVAL_FALLBACK_DEFAULT constants exported by
           manifest_generator.
    When:  Inspected.
    Then:  They equal the literal XSOAR YAML names ('isFetchEvents' /
           'eventFetchInterval' — camelCase) and the documented "1"
           string fallback default (E1=a). Constants must stay in
           lockstep with what real Packs/*/Integrations/*.yml files use.
    """
    assert ISFETCHEVENTS_PARAM_NAME == "isFetchEvents"
    assert EVENTFETCHINTERVAL_PARAM_NAME == "eventFetchInterval"
    assert EVENTFETCHINTERVAL_FALLBACK_DEFAULT == "1"


def test_log_collection_scenario_A_lone_isFetchEvents_dropped_to_computed(
    tmp_path: Path,
):
    """
    Given: add_log_collection_capability called with
           is_long_running_capability=False, is_sub_capability=False,
           NO yml param for isFetchEvents (and no longRunning routed here),
           plus a handler_dir.
    When:  Inspecting the returned fields + serializer.
    Then:  Per the "count both checkboxes together" rule isFetchEvents is the
           lone fetch checkbox → it is NOT emitted as a manifest field and its
           ``true`` value is pushed via a serializer computed_fields rule gated
           on this capability being 'on'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in fields_by_id

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"] == [
        {
            "output": [{"id": "isFetchEvents", "value": True}],
            "any_of": [
                {
                    "conditions": [
                        {
                            "type": "capability",
                            "options": {
                                "capability_id": "log-collection",
                                "value": "on",
                            },
                        }
                    ]
                }
            ],
        }
    ]


def test_log_collection_scenario_A_not_long_running_synthetic_eventFetchInterval_no_yml():
    """
    Given: is_long_running_capability=False, NO yml param for
           eventFetchInterval.
    When:  Inspecting the returned eventFetchInterval field.
    Then:  Duration picker — field_type 'duration', units
           [days, hours, minutes], default {minutes: 1} (the "no
           default → 1 minute" rule), VISIBLE in both modifier blocks
           (hidden=False), required False, title fallback
           'Events Fetch Interval'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "eventFetchInterval" in fields_by_id
    efi = fields_by_id["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["title"] == "Events Fetch Interval"
    assert efi["options"]["units"] == ["days", "hours", "minutes"]
    assert efi["options"]["default_value"] == {"minutes": 1}
    assert "is_number_input" not in efi["options"]
    assert efi["options"]["create_modifiers"] == {"required": False, "hidden": False}
    assert efi["options"]["edit_modifiers"] == {"required": False, "hidden": False}


def test_log_collection_scenario_A_yml_eventFetchInterval_with_defaultvalue_is_honored():
    """
    Given: is_long_running_capability=False AND the yml carries an
           eventFetchInterval param with defaultvalue='5' (5 minutes).
    When:  add_log_collection_capability runs.
    Then:  In scenario A (not long-running) the isFetchEvents toggle is
           synthetic, but eventFetchInterval is still emitted from the
           yml path → duration default {minutes: 5} (5 minutes
           converted). hidden defaults to False (yml does not set it).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
            "defaultvalue": "5",
        }
    }

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    efi = fields_by_id["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["options"]["default_value"] == {"minutes": 5}
    assert efi["options"]["create_modifiers"]["hidden"] is False


def test_log_collection_scenario_A_yml_eventFetchInterval_without_defaultvalue_falls_back_to_one_minute():
    """
    Given: is_long_running_capability=False, yml carries
           eventFetchInterval but WITHOUT a defaultvalue key.
    When:  add_log_collection_capability runs.
    Then:  The "no default → 1 minute" rule applies → duration default
           {minutes: 1}. We never let the field render blank.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
        }
    }

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert fields_by_id["eventFetchInterval"]["options"]["default_value"] == {
        "minutes": 1
    }


def test_log_collection_scenario_B_lone_isFetchEvents_dropped_interval_kept(
    tmp_path: Path,
):
    """
    Given: is_long_running_capability=True AND the yml carries BOTH
           isFetchEvents (defaultvalue 'true') and eventFetchInterval
           (defaultvalue '5'). longRunning is NOT routed into this bucket,
           so isFetchEvents is the lone fetch checkbox.
    When:  add_log_collection_capability runs.
    Then:  isFetchEvents is dropped to a serializer computed_fields rule
           (value True). eventFetchInterval is STILL emitted as a duration
           field with default {minutes: 5}.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchEvents": {
            "name": "isFetchEvents",
            "type": 8,
            "defaultvalue": "true",
        },
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
            "defaultvalue": "5",
        },
    }

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
        handler_dir=tmp_path,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in fields_by_id
    assert fields_by_id["eventFetchInterval"]["field_type"] == "duration"
    assert fields_by_id["eventFetchInterval"]["options"]["default_value"] == {
        "minutes": 5
    }

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchEvents", "value": True}
    ]


def test_log_collection_scenario_C_long_running_no_yml_drops_isFetchEvents(
    tmp_path: Path,
):
    """
    Given: is_long_running_capability=True AND neither isFetchEvents nor
           eventFetchInterval is in the yml, and longRunning is NOT routed
           into the Log Collection bucket (E4 — long-running cap with no
           related yml params).
    When:  add_log_collection_capability runs.
    Then:  isFetchEvents is the lone fetch checkbox → dropped to a serializer
           computed_fields rule (value True). eventFetchInterval stays a
           VISIBLE duration default {minutes: 1}.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in fields_by_id
    assert "eventFetchInterval" in fields_by_id
    efi = fields_by_id["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["options"]["default_value"] == {"minutes": 1}
    assert efi["options"]["create_modifiers"]["hidden"] is False

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchEvents", "value": True}
    ]


def test_log_collection_sub_capability_renames_interval_field_id():
    """
    Given: is_sub_capability=True with a sub-cap id
           'log-collection-xsoar-myhandler'.
    When:  add_log_collection_capability runs.
    Then:  Only eventFetchInterval remains as a renamed field. isFetchEvents
           is the lone fetch checkbox → dropped to serializer computed_fields
           (no manifest field).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection-xsoar-myhandler",
        is_sub_capability=True,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    field_ids = {f["id"] for f in template["fields"]}
    assert "log-collection-xsoar-myhandler_isFetchEvents" not in field_ids
    assert "log-collection-xsoar-myhandler_eventFetchInterval" in field_ids


def test_log_collection_strips_both_param_names_from_mapper_results():
    """
    Given: mapped_params has both 'isFetchEvents' and
           'eventFetchInterval' placed in multiple buckets.
    When:  add_log_collection_capability runs.
    Then:  Both names are removed from every bucket in place. Other
           param names are preserved.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": ["isFetchEvents", "timeout"],
        "Log Collection": ["isFetchEvents", "eventFetchInterval", "url"],
        "Automation": ["eventFetchInterval", "unrelated"],
    }

    add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    assert mapped["general_configurations"] == ["timeout"]
    assert mapped["Log Collection"] == ["url"]
    assert mapped["Automation"] == ["unrelated"]


def test_log_collection_sub_cap_path_writes_interval_bridge_and_computed(
    tmp_path: Path,
):
    """
    Given: sub-cap path AND handler_dir supplied. is_long_running=False so
           isFetchEvents is the lone fetch checkbox.
    When:  add_log_collection_capability runs.
    Then:  serializer.yaml contains ONE field_mappings entry bridging
           '<sub_cap_id>_eventFetchInterval' → 'eventFetchInterval', a
           computed_fields rule injecting isFetchEvents=true, and NO
           field_mappings bridge for isFetchEvents (it has no manifest field).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_log_collection_capability(
        capability_id="log-collection-xsoar-myhandler",
        is_sub_capability=True,
        is_long_running_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    by_id = {fm["id"]: fm for fm in serializer["field_mappings"]}
    assert (
        by_id["log-collection-xsoar-myhandler_eventFetchInterval"]["field_name"]
        == "eventFetchInterval"
    )
    assert "log-collection-xsoar-myhandler_isFetchEvents" not in by_id
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchEvents", "value": True}
    ]


def test_log_collection_top_level_writes_only_computed_field(tmp_path: Path):
    """
    Given: top-level call (is_sub_capability=False) with handler_dir.
    When:  add_log_collection_capability runs.
    Then:  serializer.yaml IS created with a computed_fields rule for
           isFetchEvents (always injected via the serializer now). The
           eventFetchInterval field keeps its plain id so there is no
           field_mappings bridge on the top-level path.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    assert "field_mappings" not in serializer
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchEvents", "value": True}
    ]


def test_log_collection_uses_yml_display_for_interval_title_when_present():
    """
    Given: yml_params_by_name carries eventFetchInterval with
           display='Polling interval (minutes)'.
    When:  add_log_collection_capability runs (scenario A — isFetchEvents
           dropped to serializer, interval still emitted).
    Then:  The eventFetchInterval field uses the vendor-supplied display
           string as its title. isFetchEvents is no longer a field.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchEvents": {
            "name": "isFetchEvents",
            "type": 8,
            "display": "Enable event ingestion",
        },
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
            "display": "Polling interval (minutes)",
        },
    }

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in fields_by_id
    assert fields_by_id["eventFetchInterval"]["title"] == "Polling interval (minutes)"


# ============================================================
# Fetch Assets and Vulnerabilities capability builder:
# add_assets_capability
# ============================================================


def test_assets_constants_match_xsoar_yaml_names():
    """
    Given: The ISFETCHASSETS_PARAM_NAME / ASSETSFETCHINTERVAL_PARAM_NAME /
           ASSETSFETCHINTERVAL_FALLBACK_DEFAULT constants exported by
           manifest_generator.
    When:  Inspected.
    Then:  They equal the literal XSOAR YAML names ('isFetchAssets' /
           'assetsFetchInterval' — camelCase) and the documented '720'
           string fallback default (E1=a). Constants must stay in
           lockstep with what real Packs/*/Integrations/*.yml files use.
    """
    assert ISFETCHASSETS_PARAM_NAME == "isFetchAssets"
    assert ASSETSFETCHINTERVAL_PARAM_NAME == "assetsFetchInterval"
    assert ASSETSFETCHINTERVAL_FALLBACK_DEFAULT == "720"


def test_assets_isFetchAssets_is_not_emitted_only_computed_field(tmp_path: Path):
    """
    Given: add_assets_capability called with NO yml param for
           isFetchAssets (and a handler_dir).
    When:  Inspecting the returned fields + serializer.
    Then:  isFetchAssets is NOT emitted as a manifest field anymore. Its
           ``true`` value is pushed via a serializer computed_fields rule
           gated on this capability being 'on'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchAssets" not in fields_by_id

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"] == [
        {
            "output": [{"id": "isFetchAssets", "value": True}],
            "any_of": [
                {
                    "conditions": [
                        {
                            "type": "capability",
                            "options": {
                                "capability_id": (
                                    "fetch-assets-and-vulnerabilities"
                                ),
                                "value": "on",
                            },
                        }
                    ]
                }
            ],
        }
    ]


def test_assets_isFetchAssets_computed_field_even_when_yml_carries_it(
    tmp_path: Path,
):
    """
    Given: The yml CARRIES isFetchAssets (with defaultvalue / hidden).
    When:  add_assets_capability runs.
    Then:  isFetchAssets is STILL not emitted as a field; the computed
           field injects ``true`` regardless of the yml's defaultvalue.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchAssets": {
            "name": "isFetchAssets",
            "type": 8,
            "defaultvalue": "true",
            "hidden": False,
        }
    }

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
        handler_dir=tmp_path,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchAssets" not in fields_by_id
    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchAssets", "value": True}
    ]


def test_assets_assetsFetchInterval_no_yml_synthetic_visible_with_fallback_720():
    """
    Given: NO yml param for assetsFetchInterval.
    When:  Inspecting the returned assetsFetchInterval field.
    Then:  Duration picker — field_type 'duration', units
           [days, hours, minutes], default {hours: 12} (the 720-minute
           fallback converted), VISIBLE in both modifier blocks
           (hidden=False), required False, title fallback
           'Assets Fetch Interval'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "assetsFetchInterval" in fields_by_id
    afi = fields_by_id["assetsFetchInterval"]
    assert afi["field_type"] == "duration"
    assert afi["title"] == "Assets Fetch Interval"
    assert afi["options"]["units"] == ["days", "hours", "minutes"]
    assert afi["options"]["default_value"] == {"hours": 12}
    assert "is_number_input" not in afi["options"]
    assert afi["options"]["create_modifiers"] == {"required": False, "hidden": False}
    assert afi["options"]["edit_modifiers"] == {"required": False, "hidden": False}


def test_assets_assetsFetchInterval_yml_with_defaultvalue_is_honored():
    """
    Given: yml carries assetsFetchInterval with defaultvalue='1440'
           (1440 minutes = 1 day).
    When:  add_assets_capability runs.
    Then:  The emitted duration default is {days: 1} (the vendor's
           minute count converted). hidden defaults to False because
           the yml does not set 'hidden'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
            "defaultvalue": "1440",
        }
    }

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    afi = fields_by_id["assetsFetchInterval"]
    assert afi["field_type"] == "duration"
    assert afi["options"]["default_value"] == {"days": 1}
    assert afi["options"]["create_modifiers"]["hidden"] is False


def test_assets_assetsFetchInterval_yml_without_defaultvalue_falls_back_to_one_minute():
    """
    Given: yml carries assetsFetchInterval but WITHOUT a defaultvalue
           key.
    When:  add_assets_capability runs.
    Then:  The "no default → 1 minute" rule applies → duration default
           {minutes: 1}. We never let the field render blank.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
        }
    }

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert fields_by_id["assetsFetchInterval"]["options"]["default_value"] == {
        "minutes": 1
    }


def test_assets_assetsFetchInterval_yml_hidden_true_is_respected():
    """
    Given: yml carries assetsFetchInterval with explicit hidden=True.
    When:  add_assets_capability runs.
    Then:  Both modifier blocks honor hidden=True. The "not hidden
           unless mentioned in the yml" rule from the spec means: if
           the yml explicitly says hidden, we DO respect it.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
            "defaultvalue": "1440",
            "hidden": True,
        }
    }

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    afi = fields_by_id["assetsFetchInterval"]
    assert afi["options"]["create_modifiers"]["hidden"] is True
    assert afi["options"]["edit_modifiers"]["hidden"] is True


def test_assets_sub_capability_renames_interval_field_id():
    """
    Given: is_sub_capability=True with a sub-cap id
           'fetch-assets-and-vulnerabilities-xsoar-myhandler'.
    When:  add_assets_capability runs.
    Then:  Only assetsFetchInterval remains as a field (renamed to the
           sub-cap-prefixed id). isFetchAssets is no longer a field (moved
           to serializer computed_fields).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities-xsoar-myhandler",
        is_sub_capability=True,
        mapped_params=mapped,
    )

    field_ids = {f["id"] for f in template["fields"]}
    assert (
        "fetch-assets-and-vulnerabilities-xsoar-myhandler_isFetchAssets"
        not in field_ids
    )
    assert (
        "fetch-assets-and-vulnerabilities-xsoar-myhandler_assetsFetchInterval"
        in field_ids
    )


def test_assets_strips_both_param_names_from_mapper_results():
    """
    Given: mapped_params has both 'isFetchAssets' and
           'assetsFetchInterval' placed in multiple buckets.
    When:  add_assets_capability runs.
    Then:  Both names are removed from every bucket in place. Other
           param names are preserved.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": ["isFetchAssets", "timeout"],
        "Fetch Assets and Vulnerabilities": [
            "isFetchAssets",
            "assetsFetchInterval",
            "url",
        ],
        "Automation": ["assetsFetchInterval", "unrelated"],
    }

    add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
    )

    assert mapped["general_configurations"] == ["timeout"]
    assert mapped["Fetch Assets and Vulnerabilities"] == ["url"]
    assert mapped["Automation"] == ["unrelated"]


def test_assets_sub_cap_path_writes_interval_bridge_and_computed(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied.
    When:  add_assets_capability runs.
    Then:  serializer.yaml contains ONE field_mappings entry bridging
           '<sub_cap_id>_assetsFetchInterval' → 'assetsFetchInterval', AND
           a computed_fields rule injecting isFetchAssets=true (gated on the
           sub-capability). isFetchAssets has NO field_mappings bridge.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities-xsoar-myhandler",
        is_sub_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    by_id = {fm["id"]: fm for fm in serializer["field_mappings"]}
    assert (
        by_id["fetch-assets-and-vulnerabilities-xsoar-myhandler_assetsFetchInterval"][
            "field_name"
        ]
        == "assetsFetchInterval"
    )
    assert (
        "fetch-assets-and-vulnerabilities-xsoar-myhandler_isFetchAssets"
        not in by_id
    )
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchAssets", "value": True}
    ]


def test_assets_top_level_writes_computed_field(tmp_path: Path):
    """
    Given: top-level call (is_sub_capability=False) with handler_dir.
    When:  add_assets_capability runs.
    Then:  serializer.yaml IS created — with a computed_fields rule for
           isFetchAssets (always injected via the serializer now). The
           assetsFetchInterval field keeps its plain id so there is no
           field_mappings bridge on the top-level path.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    assert "field_mappings" not in serializer
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchAssets", "value": True}
    ]


def test_assets_uses_yml_display_for_interval_title_when_present():
    """
    Given: yml_params_by_name carries assetsFetchInterval with display
           'Asset polling interval'.
    When:  add_assets_capability runs.
    Then:  The assetsFetchInterval field uses the vendor-supplied display
           string as its title. isFetchAssets is no longer a field (moved
           to serializer computed_fields), so only the interval title is
           asserted.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchAssets": {
            "name": "isFetchAssets",
            "type": 8,
            "display": "Enable asset ingestion",
        },
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
            "display": "Asset polling interval",
        },
    }

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchAssets" not in fields_by_id
    assert fields_by_id["assetsFetchInterval"]["title"] == "Asset polling interval"


def test_eventfetchinterval_still_works_after_helper_extraction():
    """
    Given: The _build_eventfetchinterval_field function (now a thin
           wrapper around the generic _build_numeric_fetch_interval_field
           after the F1=a extraction) is exercised via
           add_log_collection_capability scenario A.
    When:  Inspecting the resulting field.
    Then:  Same shape as before the refactor — field_type 'input',
           is_number_input True, default_value '1' fallback constant
           (NOT the '720' fallback of the assets variant — confirming
           the two thin wrappers correctly bind to different fallback
           constants).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    efi = fields_by_id["eventFetchInterval"]
    # Regression checks — values that would change if the extraction
    # accidentally cross-wired the two wrappers. After the duration
    # migration the field is a ``duration`` picker; the event wrapper
    # binds to a "1" (minute) fallback → {minutes: 1}, the assets
    # wrapper binds to "720" (minutes) → {hours: 12}.
    assert efi["field_type"] == "duration"
    assert efi["options"]["default_value"] == {"minutes": 1}


# ===========================================================================
# Duration field type for fetch intervals
# (per ../unified-connectors-content/plans/duration-field-type.md)
#
# Conversion rule: the XSOAR fetch-interval default is expressed in
# MINUTES. The connectus ``duration`` field decomposes that minute count
# into a per-unit object {days, hours, minutes}. When no default exists,
# the field defaults to 1 minute ({minutes: 1}).
# ===========================================================================


def test_minutes_to_duration_default_minutes_only():
    """60 minutes → 1 hour (carries up into the hours box)."""
    assert _minutes_to_duration_default(60) == {"hours": 1}


def test_minutes_to_duration_default_sub_hour_stays_minutes():
    """5 minutes → {minutes: 5} (no carry)."""
    assert _minutes_to_duration_default(5) == {"minutes": 5}


def test_minutes_to_duration_default_multi_unit_decomposition():
    """1500 minutes → 1 day, 1 hour, 0 minutes → {days: 1, hours: 1}."""
    assert _minutes_to_duration_default(1500) == {"days": 1, "hours": 1}


def test_minutes_to_duration_default_full_day():
    """1440 minutes → exactly 1 day → {days: 1}."""
    assert _minutes_to_duration_default(1440) == {"days": 1}


def test_minutes_to_duration_default_twelve_hours():
    """720 minutes (assets fallback) → 12 hours → {hours: 12}."""
    assert _minutes_to_duration_default(720) == {"hours": 12}


def test_minutes_to_duration_default_one_minute():
    """1 minute (events fallback) → {minutes: 1}."""
    assert _minutes_to_duration_default(1) == {"minutes": 1}


def test_minutes_to_duration_default_zero_falls_back_to_one_minute():
    """A zero/empty interval is meaningless → coerced to 1 minute."""
    assert _minutes_to_duration_default(0) == {"minutes": 1}


def test_duration_units_constant_is_days_hours_minutes():
    """The render-order units array is days → hours → minutes."""
    assert DURATION_UNITS == ["days", "hours", "minutes"]


def test_eventfetchinterval_no_yml_is_duration_one_minute():
    """
    Given: is_long_running_capability=False, NO yml param for
           eventFetchInterval.
    When:  add_log_collection_capability runs.
    Then:  The eventFetchInterval field is a ``duration`` picker with
           units [days, hours, minutes] and default {minutes: 1}
           (the "no default → 1 minute" rule), still visible/optional.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
    )
    efi = {f["id"]: f for f in template["fields"]}["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["options"]["units"] == ["days", "hours", "minutes"]
    assert efi["options"]["default_value"] == {"minutes": 1}
    assert "is_number_input" not in efi["options"]
    assert efi["options"]["create_modifiers"]["hidden"] is False
    assert efi["options"]["edit_modifiers"]["hidden"] is False


def test_eventfetchinterval_yml_default_converted_to_duration():
    """
    Given: yml carries eventFetchInterval with defaultvalue='60'
           (60 minutes).
    When:  add_log_collection_capability runs (long-running so the yml
           path is taken).
    Then:  The duration default is {hours: 1} — 60 minutes converted.
    """
    yml_lookup = {
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
            "defaultvalue": "60",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    efi = {f["id"]: f for f in template["fields"]}["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["options"]["default_value"] == {"hours": 1}


def test_eventfetchinterval_yml_without_defaultvalue_falls_back_to_one_minute():
    """
    Given: yml carries eventFetchInterval but WITHOUT a defaultvalue.
    When:  add_log_collection_capability runs (long-running).
    Then:  default → {minutes: 1} ("no default → 1 minute" rule).
    """
    yml_lookup = {
        "eventFetchInterval": {
            "name": "eventFetchInterval",
            "type": 19,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    efi = {f["id"]: f for f in template["fields"]}["eventFetchInterval"]
    assert efi["options"]["default_value"] == {"minutes": 1}


def test_assetsfetchinterval_no_yml_is_duration_twelve_hours():
    """
    Given: NO yml param for assetsFetchInterval.
    When:  add_assets_capability runs.
    Then:  duration field, default {hours: 12} (720 minute fallback
           converted), units [days, hours, minutes], visible.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    afi = {f["id"]: f for f in template["fields"]}["assetsFetchInterval"]
    assert afi["field_type"] == "duration"
    assert afi["options"]["units"] == ["days", "hours", "minutes"]
    assert afi["options"]["default_value"] == {"hours": 12}
    assert "is_number_input" not in afi["options"]


def test_assetsfetchinterval_yml_default_converted_to_duration():
    """
    Given: yml carries assetsFetchInterval with defaultvalue='1500'
           (1 day, 1 hour).
    When:  add_assets_capability runs.
    Then:  default → {days: 1, hours: 1}.
    """
    yml_lookup = {
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
            "defaultvalue": "1500",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    afi = {f["id"]: f for f in template["fields"]}["assetsFetchInterval"]
    assert afi["field_type"] == "duration"
    assert afi["options"]["default_value"] == {"days": 1, "hours": 1}


def test_assetsfetchinterval_yml_without_defaultvalue_falls_back_to_one_minute():
    """
    Given: yml carries assetsFetchInterval but WITHOUT a defaultvalue.
    When:  add_assets_capability runs.
    Then:  default → {minutes: 1}.
    """
    yml_lookup = {
        "assetsFetchInterval": {
            "name": "assetsFetchInterval",
            "type": 19,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    afi = {f["id"]: f for f in template["fields"]}["assetsFetchInterval"]
    assert afi["options"]["default_value"] == {"minutes": 1}


# ============================================================
# Threat Intelligence & Enrichment capability builder:
# add_indicators_capability
# ============================================================
def test_add_indicators_capability_feed_auto_enabled_via_serializer(tmp_path: Path):
    """
    Given: add_indicators_capability with a handler_dir (yml may carry a
           'feed' param — its values are irrelevant).
    When:  add_indicators_capability runs.
    Then:  ``feed`` is NOT emitted as a configurations field. Instead a
           serializer computed_fields rule injects ``feed: true`` gated on
           the capability being ``on`` (like isFetch / isFetchEvents).
    """
    yml_lookup = {
        "feed": {
            "name": "feed",
            "type": 8,
            "display": "Custom Feed Label",
            "defaultvalue": "false",
            "hidden": False,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "threat-intelligence-and-enrichment"
    template = add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
        handler_dir=tmp_path,
    )
    # feed is not a configurations field.
    assert "feed" not in {f["id"] for f in template["fields"]}

    # serializer.yaml carries a computed_fields rule for feed.
    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        data = yaml.safe_load(fh.read().split("\n", 1)[1])  # skip directive
    computed = data["computed_fields"]
    feed_rules = [
        cf for cf in computed
        if cf["output"] == [{"id": "feed", "value": True}]
    ]
    assert len(feed_rules) == 1
    rule = feed_rules[0]
    assert rule["any_of"] == [
        {
            "conditions": [
                {
                    "type": "capability",
                    "options": {"capability_id": cap_id, "value": "on"},
                }
            ]
        }
    ]


def test_add_indicators_capability_strips_feed_params_from_mapped_params():
    """
    Given: mapped_params has all 7 feed param names in multiple buckets.
    When:  add_indicators_capability runs.
    Then:  All 7 names are removed from every bucket in place. Other
           params (like tlp_color, feedTags) are preserved.
    """
    mapped = {
        "general_configurations": ["feed", "feedReliability", "tlp_color"],
        "Threat Intelligence & Enrichment": [
            "feedFetchInterval",
            "feedExpirationPolicy",
            "feedExpirationInterval",
            "feedReputation",
            "feedBypassExclusionList",
            "feedTags",
        ],
    }
    add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    # Feed params stripped; tlp_color and feedTags preserved.
    assert mapped["general_configurations"] == ["tlp_color"]
    assert mapped["Threat Intelligence & Enrichment"] == ["feedTags"]


def test_add_indicators_capability_sub_capability_renames_field_ids():
    """
    Given: add_indicators_capability called with is_sub_capability=True
           and a sub-cap id.
    When:  add_indicators_capability runs.
    Then:  All emitted field ids are renamed to f"{capability_id}_{original}".
           ``feed`` is not emitted as a field (serializer computed_fields).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "threat-intelligence-and-enrichment-xsoar-myfeed"
    template = add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        mapped_params=mapped,
    )
    field_ids = [f["id"] for f in template["fields"]]
    assert f"{cap_id}_feed" not in field_ids
    assert f"{cap_id}_feedFetchInterval" in field_ids
    assert f"{cap_id}_feedReliability" in field_ids
    assert f"{cap_id}_feedExpirationPolicy" in field_ids
    assert f"{cap_id}_feedExpirationInterval" in field_ids
    assert f"{cap_id}_feedReputation" in field_ids
    assert f"{cap_id}_feedBypassExclusionList" in field_ids


def test_add_indicators_capability_sub_cap_writes_serializer_bridges(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied.
    When:  add_indicators_capability runs.
    Then:  serializer.yaml at handler_dir contains 6 field_mappings entries
           bridging the renamed ids back to the original param names. ``feed``
           gets NO field_mapping (it is not a field — it is handled via
           computed_fields instead).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "threat-intelligence-and-enrichment-xsoar-myfeed"
    add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])  # skip directive
    mappings = data["field_mappings"]
    assert len(mappings) == 6
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert f"{cap_id}_feed" not in mapping_dict
    assert mapping_dict[f"{cap_id}_feedFetchInterval"] == "feedFetchInterval"
    assert mapping_dict[f"{cap_id}_feedReliability"] == "feedReliability"
    assert mapping_dict[f"{cap_id}_feedExpirationPolicy"] == "feedExpirationPolicy"
    assert mapping_dict[f"{cap_id}_feedExpirationInterval"] == "feedExpirationInterval"
    assert mapping_dict[f"{cap_id}_feedReputation"] == "feedReputation"
    assert mapping_dict[f"{cap_id}_feedBypassExclusionList"] == "feedBypassExclusionList"

    # The feed auto-enable computed_fields rule is gated on the sub-cap id.
    feed_rules = [
        cf for cf in data.get("computed_fields", [])
        if cf["output"] == [{"id": "feed", "value": True}]
    ]
    assert len(feed_rules) == 1
    assert feed_rules[0]["any_of"][0]["conditions"][0]["options"][
        "capability_id"
    ] == cap_id


def test_add_indicators_capability_top_level_writes_only_feed_computed_field(
    tmp_path: Path,
):
    """
    Given: top-level path (is_sub_capability=False) with handler_dir.
    When:  add_indicators_capability runs.
    Then:  serializer.yaml is written with ONLY a computed_fields rule for
           ``feed`` (field names are 1:1 so no field_mappings are needed).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        data = yaml.safe_load(fh.read().split("\n", 1)[1])  # skip directive
    # No field_mappings on the top-level path.
    assert not data.get("field_mappings")
    feed_rules = [
        cf for cf in data["computed_fields"]
        if cf["output"] == [{"id": "feed", "value": True}]
    ]
    assert len(feed_rules) == 1


def test_add_indicators_capability_trigger_spec_top_level():
    """
    Given: add_indicators_capability called with is_sub_capability=False.
    When:  add_indicators_capability runs.
    Then:  The returned triggers list contains exactly 1 trigger that
           reveals feedExpirationInterval when feedExpirationPolicy == 'interval'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    triggers = template["triggers"]
    assert len(triggers) == 1
    trigger = triggers[0]
    assert trigger["conditions"]["id"] == "feedExpirationPolicy"
    assert trigger["conditions"]["behavior"] == "value"
    assert trigger["conditions"]["operator"] == "eq"
    assert trigger["conditions"]["value"] == "interval"
    assert len(trigger["effects"]) == 1
    assert trigger["effects"][0]["id"] == "feedExpirationInterval"
    assert trigger["effects"][0]["action"]["hidden"] is False


def test_add_indicators_capability_trigger_spec_sub_cap_uses_renamed_ids():
    """
    Given: add_indicators_capability called with is_sub_capability=True.
    When:  add_indicators_capability runs.
    Then:  The trigger references the renamed field ids.
    """
    cap_id = "threat-intelligence-and-enrichment-xsoar-myfeed"
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        mapped_params=mapped,
    )
    trigger = template["triggers"][0]
    assert trigger["conditions"]["id"] == f"{cap_id}_feedExpirationPolicy"
    assert trigger["effects"][0]["id"] == f"{cap_id}_feedExpirationInterval"


def test_add_indicators_capability_yml_driven_feedreliability():
    """
    Given: yml carries feedReliability with custom options and default.
    When:  add_indicators_capability runs.
    Then:  The field uses the yml's options and default, not the fallback.
    """
    yml_lookup = {
        "feedReliability": {
            "name": "feedReliability",
            "type": 15,
            "display": "Custom Reliability",
            "defaultvalue": "B - Usually reliable",
            "required": True,
            "options": ["A - Completely reliable", "B - Usually reliable"],
            "additionalinfo": "Custom reliability info",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    fr = {f["id"]: f for f in template["fields"]}["feedReliability"]
    assert fr["title"] == "Custom Reliability"
    assert fr["options"]["default_value"] == "B - Usually reliable"
    assert fr["options"]["description"] == "Custom reliability info"


def test_add_indicators_capability_yml_driven_feedfetchinterval():
    """
    Given: yml carries feedFetchInterval with defaultvalue='60' (1 hour).
    When:  add_indicators_capability runs.
    Then:  The duration field default is {hours: 1}.
    """
    yml_lookup = {
        "feedFetchInterval": {
            "name": "feedFetchInterval",
            "type": 19,
            "display": "Custom Fetch Interval",
            "defaultvalue": "60",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    ffi = {f["id"]: f for f in template["fields"]}["feedFetchInterval"]
    assert ffi["field_type"] == "duration"
    assert ffi["options"]["default_value"] == {"hours": 1}


def test_add_indicators_capability_feedfetchinterval_no_yml_uses_240_min_fallback():
    """
    Given: No yml param for feedFetchInterval.
    When:  add_indicators_capability runs.
    Then:  duration field, default {hours: 4} (240 minute fallback = 4h).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    ffi = {f["id"]: f for f in template["fields"]}["feedFetchInterval"]
    assert ffi["field_type"] == "duration"
    assert ffi["options"]["default_value"] == {"hours": 4}


def test_add_indicators_capability_uses_yml_display_for_titles():
    """
    Given: yml carries display strings for feed params.
    When:  add_indicators_capability runs.
    Then:  The emitted fields use the vendor-supplied display strings.
    """
    yml_lookup = {
        "feedReputation": {
            "name": "feedReputation",
            "type": 18,
            "display": "Custom Reputation",
        },
        "feedBypassExclusionList": {
            "name": "feedBypassExclusionList",
            "type": 8,
            "display": "Skip Exclusions",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert by_id["feedReputation"]["title"] == "Custom Reputation"
    assert by_id["feedBypassExclusionList"]["title"] == "Skip Exclusions"


# ------------------------------------------------------------
# feedIncremental — conditional 8th field (only when in the yml)
# ------------------------------------------------------------


def test_add_indicators_capability_no_feedincremental_when_absent_from_yml():
    """
    Given: add_indicators_capability called with no yml params (or yml
           without a feedIncremental entry).
    When:  add_indicators_capability runs.
    Then:  No feedIncremental field is emitted — the field list stays at
           the 6 standard feed fields (``feed`` is handled via the
           serializer, not as a field).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    field_ids = [f["id"] for f in template["fields"]]
    assert "feedIncremental" not in field_ids
    assert len(template["fields"]) == 6


def test_add_indicators_capability_emits_feedincremental_when_present_in_yml():
    """
    Given: yml carries a feedIncremental param (type 8) with display,
           defaultvalue='true', and hidden=True.
    When:  add_indicators_capability runs.
    Then:  A 7th checkbox field is appended (last) whose hidden, title
           (display) and default_value are taken verbatim from the yml.
    """
    yml_lookup = {
        "feedIncremental": {
            "name": "feedIncremental",
            "type": 8,
            "display": "Incremental Feed",
            "defaultvalue": "true",
            "hidden": True,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    fields = template["fields"]
    # Emitted as the last (7th) field.
    assert len(fields) == 7
    assert fields[-1]["id"] == "feedIncremental"

    fi = fields[-1]
    assert fi["field_type"] == "checkbox"
    assert fi["title"] == "Incremental Feed"
    # default_value honored from yml (coerced "true" -> True).
    assert fi["options"]["default_value"] is True
    # hidden honored from yml.
    assert fi["options"]["create_modifiers"]["hidden"] is True
    assert fi["options"]["edit_modifiers"]["hidden"] is True


def test_add_indicators_capability_feedincremental_honors_visible_and_false_default():
    """
    Given: yml carries a visible (hidden False) feedIncremental with
           defaultvalue='false' and a custom display.
    When:  add_indicators_capability runs.
    Then:  The field is visible (hidden False), default_value False, and
           uses the custom display as its title.
    """
    yml_lookup = {
        "feedIncremental": {
            "name": "feedIncremental",
            "type": 8,
            "display": "Pull only new/modified",
            "defaultvalue": "false",
            "hidden": False,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    fi = {f["id"]: f for f in template["fields"]}["feedIncremental"]
    assert fi["title"] == "Pull only new/modified"
    assert fi["options"]["default_value"] is False
    assert fi["options"]["create_modifiers"]["hidden"] is False
    assert fi["options"]["edit_modifiers"]["hidden"] is False


def test_add_indicators_capability_feedincremental_blank_display_falls_back_title():
    """
    Given: yml carries feedIncremental with no display.
    When:  add_indicators_capability runs.
    Then:  The field title falls back to the default "Incremental Feed".
    """
    yml_lookup = {
        "feedIncremental": {
            "name": "feedIncremental",
            "type": 8,
            "defaultvalue": "true",
            "hidden": True,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    fi = {f["id"]: f for f in template["fields"]}["feedIncremental"]
    assert fi["title"] == "Incremental Feed"


def test_add_indicators_capability_feedincremental_stripped_from_mapped_params():
    """
    Given: mapped_params contains feedIncremental in a bucket and the yml
           carries the param.
    When:  add_indicators_capability runs.
    Then:  feedIncremental is removed from mapped_params so the standard
           param-mapping pass does not re-emit it.
    """
    yml_lookup = {
        "feedIncremental": {
            "name": "feedIncremental",
            "type": 8,
            "display": "Incremental Feed",
            "defaultvalue": "true",
            "hidden": True,
        },
    }
    mapped = {
        "general_configurations": ["feedIncremental", "tlp_color"],
        "Threat Intelligence & Enrichment": ["feedIncremental"],
    }
    add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    assert "feedIncremental" not in mapped["general_configurations"]
    assert mapped["general_configurations"] == ["tlp_color"]
    assert "feedIncremental" not in mapped["Threat Intelligence & Enrichment"]


def test_add_indicators_capability_feedincremental_sub_cap_renames_and_bridges(
    tmp_path: Path,
):
    """
    Given: sub-cap path with handler_dir and a yml carrying feedIncremental.
    When:  add_indicators_capability runs.
    Then:  The feedIncremental field id is renamed to
           f"{cap_id}_feedIncremental" AND the serializer.yaml bridges it
           back to the original "feedIncremental".
    """
    yml_lookup = {
        "feedIncremental": {
            "name": "feedIncremental",
            "type": 8,
            "display": "Incremental Feed",
            "defaultvalue": "true",
            "hidden": True,
        },
    }
    cap_id = "threat-intelligence-and-enrichment-xsoar-myfeed"
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
        handler_dir=tmp_path,
    )
    field_ids = [f["id"] for f in template["fields"]]
    assert f"{cap_id}_feedIncremental" in field_ids

    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])  # skip directive
    mapping_dict = {m["id"]: m["field_name"] for m in data["field_mappings"]}
    assert mapping_dict[f"{cap_id}_feedIncremental"] == "feedIncremental"


# ============================================================
# triggers.yaml emission: build_triggers_yaml / write_triggers_yaml
# ============================================================


def test_build_triggers_yaml_wraps_in_triggers_key():
    """
    Given: A list of trigger dicts.
    When:  build_triggers_yaml is called.
    Then:  Returns {"triggers": [<the list>]}.
    """
    triggers = [{"conditions": {"id": "x"}, "effects": []}]
    result = build_triggers_yaml(triggers)
    assert result == {"triggers": triggers}


def test_write_triggers_yaml_prepends_schema_directive(tmp_path: Path):
    """
    Given: A triggers data dict.
    When:  write_triggers_yaml is called.
    Then:  The file starts with the schema directive line.
    """
    triggers_data = {"triggers": [{"conditions": {"id": "x"}, "effects": []}]}
    path = tmp_path / "triggers.yaml"
    write_triggers_yaml(path, triggers_data)
    content = path.read_text()
    assert content.startswith(TRIGGERS_SCHEMA_DIRECTIVE)
    # The YAML body follows the directive.
    body = content[len(TRIGGERS_SCHEMA_DIRECTIVE):]
    parsed = yaml.safe_load(body)
    assert parsed["triggers"][0]["conditions"]["id"] == "x"


# ============================================================
# End-to-end: from-scratch with TI&E capability produces triggers.yaml
# ============================================================


def test_create_manifest_from_scratch_with_ti_capability_produces_triggers_yaml(
    tmp_path: Path,
):
    """
    Given: mapped_params includes a 'Threat Intelligence & Enrichment' bucket.
    When:  create_manifest_from_scratch runs.
    Then:  triggers.yaml is generated at the connector root with the
           feedExpirationInterval reveal trigger.
    """
    connector_dir = tmp_path / "connectors" / "myfeed"
    integration_yml = {
        "commonfields": {"id": "MyFeed"},
        "display": "My Feed Integration",
        "configuration": [],
    }
    integration_path = (
        tmp_path / "Packs" / "MyFeed" / "Integrations" / "MyFeed" / "MyFeed.yml"
    )
    integration_path.parent.mkdir(parents=True, exist_ok=True)
    integration_path.touch()

    mapped_params = {
        "general_configurations": [],
        "Threat Intelligence & Enrichment": [],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_path,
        connector_title="My Feed",
        mapped_params=mapped_params,
        auth_methods={"auth_types": []},
    )

    triggers_yaml_path = connector_dir / "triggers.yaml"
    assert triggers_yaml_path.exists()
    content = triggers_yaml_path.read_text()
    assert content.startswith(TRIGGERS_SCHEMA_DIRECTIVE)
    body = content[len(TRIGGERS_SCHEMA_DIRECTIVE):]
    data = yaml.safe_load(body)
    assert len(data["triggers"]) == 1
    trigger = data["triggers"][0]
    assert trigger["conditions"]["id"] == "feedExpirationPolicy"
    assert trigger["effects"][0]["id"] == "feedExpirationInterval"


def test_create_manifest_from_scratch_without_ti_capability_no_triggers_yaml(
    tmp_path: Path,
):
    """
    Given: mapped_params does NOT include a TI&E bucket.
    When:  create_manifest_from_scratch runs.
    Then:  No triggers.yaml is generated.
    """
    connector_dir = tmp_path / "connectors" / "myint"
    integration_yml = {
        "commonfields": {"id": "MyInt"},
        "display": "My Integration",
        "configuration": [],
    }
    integration_path = (
        tmp_path / "Packs" / "MyInt" / "Integrations" / "MyInt" / "MyInt.yml"
    )
    integration_path.parent.mkdir(parents=True, exist_ok=True)
    integration_path.touch()

    mapped_params = {
        "general_configurations": [],
        "Automation": [],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_path,
        connector_title="My Int",
        mapped_params=mapped_params,
        auth_methods={"auth_types": []},
    )

    triggers_yaml_path = connector_dir / "triggers.yaml"
    assert not triggers_yaml_path.exists()


# ============================================================
# Fetch mutex: collect_fetch_sub_cap_ids / build_fetch_mutex_triggers
# (guide §3.4 note 7 + §3.5)
# ============================================================


def test_fetch_mutex_bucket_keys_are_the_five_fetch_families():
    """The mutex bucket-key set is exactly the five fetch (collection)
    mapper bucket keys — never Automation."""
    assert _FETCH_MUTEX_BUCKET_KEYS == {
        "Fetch Issues",
        "Log Collection",
        "Fetch Assets and Vulnerabilities",
        "Threat Intelligence & Enrichment",
        "Fetch Secrets",
    }
    assert "Automation" not in _FETCH_MUTEX_BUCKET_KEYS


def test_collect_fetch_sub_cap_ids_only_fetch_buckets():
    """
    Given: mapped_params with two fetch buckets + Automation + general.
    When:  collect_fetch_sub_cap_ids runs for a handler.
    Then:  Only the two fetch sub-cap ids are returned (sorted), Automation
           and general_configurations are excluded.
    """
    mapped_params = {
        "general_configurations": ["x"],
        "Automation": ["cmd"],
        "Fetch Issues": [],
        "Log Collection": [],
    }
    result = collect_fetch_sub_cap_ids(mapped_params, "xsoar-myint")
    assert result == sorted(
        ["fetch-issues_myint", "log-collection_myint"]
    )


def test_collect_fetch_sub_cap_ids_single_fetch_bucket():
    """A handler with one fetch bucket yields exactly one sub-cap id."""
    mapped_params = {"general_configurations": [], "Fetch Issues": []}
    assert collect_fetch_sub_cap_ids(mapped_params, "xsoar-myint") == [
        "fetch-issues_myint"
    ]


def test_collect_fetch_sub_cap_ids_no_fetch_bucket():
    """A handler with only Automation yields no fetch sub-cap ids."""
    mapped_params = {"general_configurations": [], "Automation": []}
    assert collect_fetch_sub_cap_ids(mapped_params, "xsoar-myint") == []


def test_build_fetch_mutex_triggers_empty_and_single():
    """0 or 1 fetch sub-cap → no mutex triggers."""
    assert build_fetch_mutex_triggers([]) == []
    assert build_fetch_mutex_triggers(["only-one"]) == []


def test_build_fetch_mutex_triggers_two_caps_shape():
    """
    Given: two fetch sub-cap ids.
    When:  build_fetch_mutex_triggers runs.
    Then:  Exactly 2 triggers (one per direction), each using the v2
           capability-state condition (behavior: selected / operator: eq /
           value: true), a read_only effect on the OTHER cap, and the mutex
           message.
    """
    a = "fetch-issues_h"
    b = "log-collection_h"
    triggers = build_fetch_mutex_triggers([a, b])
    assert len(triggers) == 2

    # Each trigger condition reads one cap's selected state; the effect locks
    # the OTHER cap.
    pairs = {
        (t["conditions"]["id"], t["effects"][0]["id"]) for t in triggers
    }
    assert pairs == {(a, b), (b, a)}

    for t in triggers:
        cond = t["conditions"]
        assert cond["behavior"] == "selected"
        assert cond["operator"] == "eq"
        assert cond["value"] is True
        eff = t["effects"][0]
        assert eff["action"] == {"read_only": True}
        assert eff["message"] == _FETCH_MUTEX_MESSAGE
        # condition cap and effect cap must differ (never self-lock).
        assert cond["id"] != eff["id"]


def test_build_fetch_mutex_triggers_three_caps_count():
    """n=3 fetch sub-caps → n*(n-1) = 6 triggers, no self-pairs."""
    ids = ["a", "b", "c"]
    triggers = build_fetch_mutex_triggers(ids)
    assert len(triggers) == 6
    for t in triggers:
        assert t["conditions"]["id"] != t["effects"][0]["id"]


def test_create_manifest_from_scratch_two_fetch_caps_emits_mutex_triggers(
    tmp_path: Path,
):
    """
    Given: a handler declaring BOTH Fetch Issues and Log Collection.
    When:  create_manifest_from_scratch runs.
    Then:  triggers.yaml contains the 2 per-handler fetch-mutex triggers
           pairing the handler's fetch-issues ↔ log-collection sub-caps.
    """
    connector_dir = tmp_path / "connectors" / "dualfetch"
    integration_yml = {
        "commonfields": {"id": "DualFetch"},
        "display": "Dual Fetch Integration",
        "configuration": [],
        "script": {"isfetch": True, "isfetchevents": True},
    }
    integration_path = (
        tmp_path
        / "Packs"
        / "DualFetch"
        / "Integrations"
        / "DualFetch"
        / "DualFetch.yml"
    )
    integration_path.parent.mkdir(parents=True, exist_ok=True)
    integration_path.touch()

    mapped_params = {
        "general_configurations": [],
        "Fetch Issues": [],
        "Log Collection": [],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_path,
        connector_title="Dual Fetch",
        mapped_params=mapped_params,
        auth_methods={"auth_types": []},
    )

    triggers_yaml_path = connector_dir / "triggers.yaml"
    assert triggers_yaml_path.exists()
    body = triggers_yaml_path.read_text()[len(TRIGGERS_SCHEMA_DIRECTIVE):]
    data = yaml.safe_load(body)

    integration_slug = "dualfetch"
    fi = f"fetch-issues_{integration_slug}"
    lc = f"log-collection_{integration_slug}"

    mutex_pairs = {
        (t["conditions"]["id"], t["effects"][0]["id"])
        for t in data["triggers"]
        if t["effects"][0]["action"] == {"read_only": True}
        and t["effects"][0].get("message") == _FETCH_MUTEX_MESSAGE
    }
    assert mutex_pairs == {(fi, lc), (lc, fi)}


# ============================================================
# Fetch Issues capability builder: add_fetch_issues_capability
# ============================================================


def _make_integration_yml(
    integration_id: str = "TestIntegration",
    display: str = "Test Integration",
    default_mapper_in: str = "",
    default_classifier: str = "",
    is_long_running: bool = False,
    configuration: list | None = None,
    is_fetch: bool = False,
    is_fetch_events: bool = False,
) -> dict:
    """Helper to build a minimal integration yml dict for fetch-issues tests."""
    yml: dict = {
        "commonfields": {"id": integration_id},
        "display": display,
        "script": {},
    }
    if is_long_running:
        yml["script"]["longRunning"] = True
    if is_fetch:
        yml["script"]["isfetch"] = True
    if is_fetch_events:
        yml["script"]["isfetchevents"] = True
    if default_mapper_in:
        yml["defaultmapperin"] = default_mapper_in
    if default_classifier:
        yml["defaultclassifier"] = default_classifier
    if configuration is not None:
        yml["configuration"] = configuration
    return yml


# Issue #8: the alert fields (alertType / alertFetchInterval) are emitted ONLY
# when their source XSOAR params (incidentType / incidentFetchInterval) exist in
# the integration yml config params. This shared lookup declares both so the
# fetch-issues tests that expect the alert fields keep exercising the full
# 5-/6-field shape.
_FETCH_ISSUES_YML_PARAMS = {
    INCIDENTTYPE_PARAM_NAME: {
        "name": INCIDENTTYPE_PARAM_NAME,
        "display": "Incident type",
    },
    INCIDENTFETCHINTERVAL_PARAM_NAME: {
        "name": INCIDENTFETCHINTERVAL_PARAM_NAME,
        "display": "Incidents Fetch Interval",
    },
}


def test_add_fetch_issues_capability_top_level_emits_4_fields_standard():
    """
    Given: add_fetch_issues_capability called with is_long_running=False, and
           the integration yml DOES declare incidentType / incidentFetchInterval
           (so the alert fields are migrated — Issue #8).
    When:  add_fetch_issues_capability runs.
    Then:  4 fields are emitted. isFetch is the lone fetch checkbox → it is
           NOT emitted as a manifest field (moved to serializer
           computed_fields); the remaining 4 are alertType, alertFetchInterval,
           incomingMapperId, mappingId. No longRunning field.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    # Issue #8: alertType / alertFetchInterval are emitted ONLY when the source
    # XSOAR params exist in the integration yml. Supply them so all 4 fields
    # are emitted (the realistic fetch-issues migration case).
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    assert template["capability_id"] == "fetch-issues"
    fields = template["fields"]
    assert len(fields) == 4

    by_id = {f["id"]: f for f in fields}

    # 1. isFetch — the lone fetch checkbox is dropped to serializer
    # computed_fields (no manifest field).
    assert "isFetch" not in by_id

    # 2. alertType (XSOAR incidentType) — dynamic select. Per migration
    # guide §line 889-890 the connector-side id is the Platform "alertType",
    # the title is hardcoded "Issue Type", and the field carries a tooltip +
    # placeholder. The dynamicField provider hint stays "incident-type".
    inctype = by_id["alertType"]
    assert inctype["title"] == "Issue Type"
    assert inctype["field_type"] == "select"
    assert inctype["metadata"]["dynamic_values"]["provider"] == "xsoar"
    assert inctype["metadata"]["dynamic_values"]["params"]["dynamicField"] == "incident-type"
    assert inctype["metadata"]["dynamic_values"]["params"]["integrationID"] == "TestIntegration"
    assert "default_value" not in inctype["options"]  # no default when yml has none
    assert inctype["options"]["help_text"] == "select if classifier doesn't exist"
    assert inctype["options"]["placeholder"] == "Select an issue type"

    # 3. alertFetchInterval (XSOAR incidentFetchInterval) — duration,
    # fallback 1 min. Connector-side id is the Platform "alertFetchInterval".
    incfi = by_id["alertFetchInterval"]
    assert incfi["field_type"] == "duration"
    assert incfi["options"]["default_value"] == {"minutes": 1}
    assert incfi["options"]["units"] == DURATION_UNITS

    # 4. incomingMapperId — dynamic select
    mapper = by_id["incomingMapperId"]
    assert mapper["field_type"] == "select"
    assert mapper["metadata"]["dynamic_values"]["params"]["dynamicField"] == "mapper-incoming"

    # 5. mappingId (Classifier) — dynamic select
    classifier = by_id["mappingId"]
    assert classifier["field_type"] == "select"
    assert classifier["metadata"]["dynamic_values"]["params"]["dynamicField"] == "classifier"

    # No triggers for fetch-issues
    assert template["triggers"] == []


def test_add_fetch_issues_capability_classifier_field_id_is_mappingId():
    """
    Given: add_fetch_issues_capability on the top-level path.
    When:  the classifier field is emitted.
    Then:  its connector field id is "mappingId" (the XSOAR instance-level
           classifier field per migration guide Appendix J / §3.7), while the
           runtime provider hint dynamicField stays "classifier".
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(),
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "mappingId" in by_id
    assert "classifier" not in by_id
    classifier = by_id["mappingId"]
    assert classifier["metadata"]["dynamic_values"]["params"]["dynamicField"] == "classifier"


def test_add_fetch_issues_capability_mapper_field_id_is_incomingMapperId():
    """
    Given: add_fetch_issues_capability on the top-level path.
    When:  the incoming-mapper field is emitted.
    Then:  its connector field id is "incomingMapperId" (the XSOAR
           instance-level field per migration guide Appendix J / §3.7), while
           the runtime provider hint dynamicField stays "mapper-incoming".
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(),
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "incomingMapperId" in by_id
    assert "mapper_incoming" not in by_id
    mapper = by_id["incomingMapperId"]
    assert mapper["metadata"]["dynamic_values"]["params"]["dynamicField"] == "mapper-incoming"


def test_add_fetch_issues_capability_classifier_and_mapper_are_backend_managed():
    """
    Given: add_fetch_issues_capability on the top-level path.
    When:  the classifier (mappingId) and mapper (incomingMapperId) fields are
           emitted.
    Then:  both carry metadata.xsoar.config_type == "backend" (Appendix J),
           while the user-visible alertType field does NOT.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(),
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert by_id["mappingId"]["metadata"]["xsoar"]["config_type"] == "backend"
    assert by_id["incomingMapperId"]["metadata"]["xsoar"]["config_type"] == "backend"
    # alertType is user-visible — must NOT be backend-managed.
    assert "xsoar" not in by_id["alertType"]["metadata"]


def test_add_fetch_issues_capability_replaces_incidents_with_issues_in_titles():
    """
    Given: an integration yml whose isFetch/incidentType params carry a
           display string containing "Incidents".
    When:  add_fetch_issues_capability runs.
    Then:  the isFetch title uses "Issues" (Platform terminology), proving
           align_incidents_to_issues actually performs the replacement
           (guide §3.7 field rule 2 / Appendix A). The alertType title is
           NOT derived from the yml display — per guide §line 890 it is the
           hardcoded Platform label "Issue Type" regardless of the yml.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_params_by_name = {
        ISFETCH_PARAM_NAME: {"display": "Fetch Incidents"},
        INCIDENTTYPE_PARAM_NAME: {"display": "Incidents Type"},
    }
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(),
        yml_params_by_name=yml_params_by_name,
    )
    by_id = {f["id"]: f for f in template["fields"]}
    # isFetch is the lone fetch checkbox → dropped to serializer; no field.
    assert "isFetch" not in by_id
    # alertType title is hardcoded, ignoring the yml "Incidents Type" display.
    assert by_id["alertType"]["title"] == "Issue Type"


def test_add_fetch_issues_capability_long_running_emits_6_fields():
    """
    Given: add_fetch_issues_capability called when the param-capability mapper
           routed ``longRunning`` to the ``"Fetch Issues"`` bucket.
    When:  add_fetch_issues_capability runs.
    Then:  6 fields are emitted (includes the visible longRunning checkbox).
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    # The integration declares a real fetch flag (script.isfetch), so the
    # fetch checkbox is a genuine user choice and BOTH checkboxes are shown.
    integration_yml = _make_integration_yml(is_long_running=True, is_fetch=True)
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    fields = template["fields"]
    assert len(fields) == 6

    by_id = {f["id"]: f for f in fields}
    lr = by_id["longRunning"]
    assert lr["field_type"] == "checkbox"
    assert lr["options"]["default_value"] is False
    assert lr["options"]["create_modifiers"]["hidden"] is False


def test_add_fetch_issues_capability_isfetch_lone_checkbox_dropped_to_computed(
    tmp_path: Path,
):
    """
    Given: yml carries an isFetch param, and NO longRunning is routed to this
           capability (isFetch is the lone fetch checkbox), plus a handler_dir.
    When:  add_fetch_issues_capability runs.
    Then:  Per the "count both checkboxes together" rule the lone isFetch
           checkbox is NOT emitted as a manifest field. Its ``true`` value is
           pushed via a serializer computed_fields rule gated on this
           capability being 'on'.
    """
    yml_lookup = {
        "isFetch": {
            "name": "isFetch",
            "type": 8,
            "display": "Custom Fetch Label",
            "defaultvalue": "true",
            "hidden": True,
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=yml_lookup,
        handler_dir=tmp_path,
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetch" not in by_id

    serializer = _read_serializer_dict(tmp_path)
    assert {
        "output": [{"id": "isFetch", "value": True}],
        "any_of": [
            {
                "conditions": [
                    {
                        "type": "capability",
                        "options": {
                            "capability_id": "fetch-issues",
                            "value": "on",
                        },
                    }
                ]
            }
        ],
    } in serializer["computed_fields"]


def test_add_fetch_issues_capability_strips_params_from_mapped_params():
    """
    Given: mapped_params has fetch-issues param names in multiple buckets.
    When:  add_fetch_issues_capability runs (standard, not long-running).
    Then:  isFetch, incidentType, incidentFetchInterval, alertFetchInterval
           are removed. Other params are preserved.
    """
    mapped = {
        "general_configurations": ["isFetch", "some_other_param"],
        "Fetch Issues": [
            "incidentType",
            "incidentFetchInterval",
            "alertFetchInterval",
            "custom_param",
        ],
    }
    integration_yml = _make_integration_yml()
    add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    assert mapped["general_configurations"] == ["some_other_param"]
    assert mapped["Fetch Issues"] == ["custom_param"]


def test_add_fetch_issues_capability_long_running_strips_longrunning():
    """
    Given: the param-capability mapper routed longRunning to the Fetch Issues
           bucket.
    When:  add_fetch_issues_capability runs.
    Then:  longRunning is emitted here AND stripped from the bucket.
    """
    mapped = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning", "custom_param"],
    }
    integration_yml = _make_integration_yml(is_long_running=True)
    add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    assert mapped["Fetch Issues"] == ["custom_param"]


def test_add_fetch_issues_capability_longrunning_not_in_bucket_not_emitted():
    """
    Given: script.longRunning is True but the param-capability mapper routed
           longRunning to a DIFFERENT capability (it is NOT in the Fetch Issues
           bucket).
    When:  add_fetch_issues_capability runs.
    Then:  NO longRunning field is emitted here — emission follows the mapper,
           not the raw script flag.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Log Collection": ["longRunning"],
    }
    integration_yml = _make_integration_yml(is_long_running=True)
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    assert "longRunning" not in {f["id"] for f in template["fields"]}
    # longRunning stays in the Log Collection bucket (not stripped here).
    assert mapped["Log Collection"] == ["longRunning"]


def test_log_collection_emits_longrunning_when_mapped_to_log_collection():
    """
    Given: the param-capability mapper routed longRunning to the Log Collection
           bucket (e.g. Akamai WAF SIEM via INTEGRATION_TO_LONGRUNNING_CAPABILITY).
    When:  add_log_collection_capability runs.
    Then:  a VISIBLE longRunning checkbox (default False) is emitted here AND
           longRunning is stripped from the bucket so the generic param pass
           does not re-emit it.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Log Collection": ["longRunning"],
    }
    # Real fetch flag present → fetch checkbox is a genuine user choice, so the
    # longRunning checkbox is shown alongside it.
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(is_fetch_events=True),
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "longRunning" in by_id
    lr = by_id["longRunning"]
    assert lr["field_type"] == "checkbox"
    assert lr["options"]["default_value"] is False
    assert lr["options"]["create_modifiers"]["hidden"] is False
    assert lr["options"]["edit_modifiers"]["hidden"] is False
    # Stripped from the bucket (owned by this builder now).
    assert mapped["Log Collection"] == []


def test_log_collection_longrunning_not_in_bucket_not_emitted():
    """
    Given: longRunning is NOT in the Log Collection bucket (the mapper routed it
           elsewhere, or there is no long-running concept for this capability).
    When:  add_log_collection_capability runs.
    Then:  NO longRunning field is emitted, and any longRunning in another
           bucket is left untouched.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
    )
    assert "longRunning" not in {f["id"] for f in template["fields"]}
    # longRunning stays in the Fetch Issues bucket (not stripped here).
    assert mapped["Fetch Issues"] == ["longRunning"]


# ============================================================
# "Count both checkboxes together" hide/default rule
#
# Per the fetch-checkbox visibility rule: within a fetch capability the set
# of fetch checkboxes is {fetch_toggle, longRunning} — isFetchEvents for Log
# Collection, isFetch for Fetch Issues. If EXACTLY ONE of the two is emitted,
# it is hidden (create+edit) and defaulted to True. If BOTH are emitted, both
# are shown (hidden=False) and defaulted to False. The interval / dynamic
# fields are unaffected.
# ============================================================


def test_log_collection_only_isfetchevents_dropped_to_computed(tmp_path: Path):
    """
    Given: Log Collection with NO longRunning in the bucket (only the
           always-emitted isFetchEvents checkbox is present), plus handler_dir.
    When:  add_log_collection_capability runs.
    Then:  isFetchEvents (the single fetch checkbox) is NOT emitted as a field
           and is injected via serializer computed_fields instead.
           eventFetchInterval stays VISIBLE.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in by_id
    # The interval field is still emitted and visible.
    assert by_id["eventFetchInterval"]["options"]["create_modifiers"]["hidden"] is False

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetchEvents", "value": True}
    ]


def test_log_collection_both_checkboxes_are_shown_and_default_false():
    """
    Given: Log Collection WITH longRunning routed into the bucket (both
           isFetchEvents and longRunning emitted).
    When:  add_log_collection_capability runs.
    Then:  BOTH checkboxes are shown (hidden=False) and default False — the
           user explicitly chooses which fetch mode to enable.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Log Collection": ["longRunning"],
    }

    # Real fetch flag present → both checkboxes are shown.
    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(is_fetch_events=True),
    )

    by_id = {f["id"]: f for f in template["fields"]}
    for fid in ("isFetchEvents", "longRunning"):
        opts = by_id[fid]["options"]
        assert opts["default_value"] is False
        assert opts["create_modifiers"]["hidden"] is False
        assert opts["edit_modifiers"]["hidden"] is False


def test_fetch_issues_only_isfetch_dropped_to_computed(tmp_path: Path):
    """
    Given: Fetch Issues with NO longRunning in the bucket (only the
           always-emitted isFetch checkbox is present) — e.g. Akamai WAF SIEM,
           whose longRunning is routed to Log Collection. Plus handler_dir.
    When:  add_fetch_issues_capability runs.
    Then:  isFetch (the single fetch checkbox) is NOT emitted as a field and is
           injected via serializer computed_fields instead. The interval /
           dynamic fields are unaffected.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()

    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
        handler_dir=tmp_path,
    )

    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetch" not in by_id

    serializer = _read_serializer_dict(tmp_path)
    assert {
        "output": [{"id": "isFetch", "value": True}],
        "any_of": [
            {
                "conditions": [
                    {
                        "type": "capability",
                        "options": {
                            "capability_id": "fetch-issues",
                            "value": "on",
                        },
                    }
                ]
            }
        ],
    } in serializer["computed_fields"]


def test_fetch_issues_both_checkboxes_are_shown_and_default_false():
    """
    Given: Fetch Issues WITH longRunning routed into the bucket (both isFetch
           and longRunning emitted).
    When:  add_fetch_issues_capability runs.
    Then:  BOTH isFetch and longRunning are shown (hidden=False) and default
           False.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    # Real fetch flag present → fetch checkbox is a genuine user choice, so
    # both checkboxes are shown.
    integration_yml = _make_integration_yml(is_long_running=True, is_fetch=True)

    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )

    by_id = {f["id"]: f for f in template["fields"]}
    for fid in ("isFetch", "longRunning"):
        opts = by_id[fid]["options"]
        assert opts["default_value"] is False
        assert opts["create_modifiers"]["hidden"] is False
        assert opts["edit_modifiers"]["hidden"] is False


def test_fetch_issues_preserves_unrelated_params_and_strips_only_owned():
    """
    Regression (Task 4): a param that is neither owned by the builder nor a
    capability-gate toggle must NOT be emitted as a synthetic field and must be
    LEFT untouched in its bucket. Only the builder-owned params (isFetch /
    incidentType / incidentFetchInterval / alertFetchInterval) are stripped.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": ["unrelated_global"],
        "Fetch Issues": [
            "isFetch",
            "incidentType",
            "incidentFetchInterval",
            "alertFetchInterval",
            "some_vendor_param",
        ],
    }
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    emitted_ids = {f["id"] for f in template["fields"]}
    # The unrelated params are NOT emitted as synthetic capability fields.
    assert "some_vendor_param" not in emitted_ids
    assert "unrelated_global" not in emitted_ids
    # Owned params are stripped; unrelated ones are preserved verbatim.
    assert mapped["Fetch Issues"] == ["some_vendor_param"]
    assert mapped["general_configurations"] == ["unrelated_global"]


def test_add_fetch_issues_capability_mapper_default_from_yml():
    """
    Given: integration yml has defaultmapperin='QRadar - Generic Incoming Mapper'.
    When:  add_fetch_issues_capability runs.
    Then:  The mapper_incoming field has default_value set.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml(
        default_mapper_in="QRadar - Generic Incoming Mapper",
    )
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    mapper = {f["id"]: f for f in template["fields"]}["incomingMapperId"]
    assert mapper["options"]["default_value"] == "QRadar - Generic Incoming Mapper"


def test_add_fetch_issues_capability_classifier_default_from_yml():
    """
    Given: integration yml has defaultclassifier='QRadar'.
    When:  add_fetch_issues_capability runs.
    Then:  The classifier field has default_value set.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml(
        default_classifier="QRadar",
    )
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    classifier = {f["id"]: f for f in template["fields"]}["mappingId"]
    assert classifier["options"]["default_value"] == "QRadar"


def test_add_fetch_issues_capability_no_mapper_classifier_defaults():
    """
    Given: integration yml has NO defaultmapperin or defaultclassifier.
    When:  add_fetch_issues_capability runs.
    Then:  incomingMapperId and mappingId fields have no default_value.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "default_value" not in by_id["incomingMapperId"]["options"]
    assert "default_value" not in by_id["mappingId"]["options"]


def test_add_fetch_issues_capability_incidenttype_default_from_yml():
    """
    Given: yml carries incidentType param with defaultvalue='Phishing'.
    When:  add_fetch_issues_capability runs.
    Then:  The alertType field (XSOAR incidentType) has default_value='Phishing'
           — the default is sourced from the XSOAR yml param, the connector-side
           id is the Platform "alertType".
    """
    yml_lookup = {
        "incidentType": {
            "name": "incidentType",
            "type": 13,
            "display": "Incident type",
            "defaultvalue": "Phishing",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=yml_lookup,
    )
    inctype = {f["id"]: f for f in template["fields"]}["alertType"]
    assert inctype["options"]["default_value"] == "Phishing"


def test_add_fetch_issues_capability_incidentfetchinterval_yml_driven():
    """
    Given: yml carries incidentFetchInterval with defaultvalue='60' (1 hour).
    When:  add_fetch_issues_capability runs.
    Then:  The duration field default is {hours: 1}.
    """
    yml_lookup = {
        "incidentFetchInterval": {
            "name": "incidentFetchInterval",
            "type": 19,
            "display": "Custom Fetch Interval",
            "defaultvalue": "60",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=yml_lookup,
    )
    incfi = {f["id"]: f for f in template["fields"]}["alertFetchInterval"]
    assert incfi["field_type"] == "duration"
    assert incfi["options"]["default_value"] == {"hours": 1}


def test_add_fetch_issues_capability_sub_capability_renames_field_ids():
    """
    Given: add_fetch_issues_capability called with is_sub_capability=True.
    When:  add_fetch_issues_capability runs.
    Then:  All field ids are renamed to f"{capability_id}_{original}".
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "fetch-issues-xsoar-myhandler"
    integration_yml = _make_integration_yml()
    template = add_fetch_issues_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    field_ids = [f["id"] for f in template["fields"]]
    # isFetch is the lone fetch checkbox → dropped to serializer (no field).
    assert f"{cap_id}_isFetch" not in field_ids
    # Platform "alert" ids (guide §line 889-890), still sub-cap prefixed.
    assert f"{cap_id}_alertType" in field_ids
    assert f"{cap_id}_alertFetchInterval" in field_ids
    assert f"{cap_id}_incomingMapperId" in field_ids
    assert f"{cap_id}_mappingId" in field_ids


def test_add_fetch_issues_capability_sub_cap_writes_serializer_bridges(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied.
    When:  add_fetch_issues_capability runs.
    Then:  serializer.yaml at handler_dir contains field_mappings entries for
           the sub-cap-prefixed fields. Per Issue #8 the alert fields
           (alertType / alertFetchInterval) are NOT bridged. isFetch is the
           lone fetch checkbox → dropped to computed_fields (NOT a
           field_mappings bridge) — so only incomingMapperId / mappingId get
           bridges, plus the isFetch computed_fields rule.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "fetch-issues-xsoar-myhandler"
    integration_yml = _make_integration_yml()
    add_fetch_issues_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])  # skip directive
    mappings = data["field_mappings"]
    assert len(mappings) == 2  # incomingMapperId + mappingId
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_dict[f"{cap_id}_incomingMapperId"] == "incomingMapperId"
    assert mapping_dict[f"{cap_id}_mappingId"] == "mappingId"
    # isFetch is NOT a field_mappings bridge (moved to computed_fields).
    assert f"{cap_id}_isFetch" not in mapping_dict
    # Issue #8: alert fields are NOT bridged (no incident* mapping).
    assert f"{cap_id}_alertType" not in mapping_dict
    assert f"{cap_id}_alertFetchInterval" not in mapping_dict
    # isFetch value flows via computed_fields gated on the sub-capability.
    assert data["computed_fields"][0]["output"] == [
        {"id": "isFetch", "value": True}
    ]


def test_add_fetch_issues_capability_long_running_sub_cap_writes_4_bridges(tmp_path: Path):
    """
    Given: sub-cap path where the mapper routed longRunning to the Fetch Issues
           bucket.
    When:  add_fetch_issues_capability runs.
    Then:  serializer.yaml has 4 field_mappings entries (isFetch +
           incomingMapperId + mappingId + longRunning). Per Issue #8 the alert
           fields are NOT bridged.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    cap_id = "fetch-issues-xsoar-myhandler"
    # Real fetch flag present → both isFetch and longRunning are real shown
    # checkboxes and get serializer rename bridges.
    integration_yml = _make_integration_yml(is_long_running=True, is_fetch=True)
    add_fetch_issues_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])
    mappings = data["field_mappings"]
    assert len(mappings) == 4
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_dict[f"{cap_id}_longRunning"] == "longRunning"
    # Issue #8: alert fields are NOT bridged.
    assert f"{cap_id}_alertType" not in mapping_dict
    assert f"{cap_id}_alertFetchInterval" not in mapping_dict


def test_add_fetch_issues_capability_top_level_writes_no_serializer_bridges(
    tmp_path: Path,
):
    """
    Given: top-level path (is_sub_capability=False) with handler_dir.
    When:  add_fetch_issues_capability runs.
    Then:  serializer.yaml IS created, but with NO field_mappings bridges (on
           the top-level path every emitted field is 1:1 and the alert fields
           are not bridged per Issue #8). The only serializer content is the
           isFetch computed_fields rule (the lone fetch checkbox value).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
        handler_dir=tmp_path,
    )
    serializer = _read_serializer_dict(tmp_path)
    assert "field_mappings" not in serializer
    assert serializer["computed_fields"][0]["output"] == [
        {"id": "isFetch", "value": True}
    ]


def test_add_fetch_issues_capability_dynamic_fields_use_integration_id():
    """
    Given: integration yml with commonfields.id='Salesforce'.
    When:  add_fetch_issues_capability runs.
    Then:  All dynamic fields use integrationID='Salesforce'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml(integration_id="Salesforce")
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
    )
    by_id = {f["id"]: f for f in template["fields"]}
    for field_id in ["alertType", "incomingMapperId", "mappingId"]:
        dv = by_id[field_id]["metadata"]["dynamic_values"]
        assert dv["params"]["integrationID"] == "Salesforce"


def test_create_manifest_from_scratch_with_fetch_issues_capability(tmp_path: Path):
    """
    Given: mapped_params includes a 'Fetch Issues' bucket.
    When:  create_manifest_from_scratch runs.
    Then:  The connector is created successfully (no crash).
    """
    connector_dir = tmp_path / "connectors" / "myint"
    integration_yml = {
        "commonfields": {"id": "MyInt"},
        "display": "My Integration",
        "configuration": [],
        "script": {"isfetch": True},
        "defaultmapperin": "MyMapper",
        "defaultclassifier": "MyClassifier",
    }
    integration_path = (
        tmp_path / "Packs" / "MyInt" / "Integrations" / "MyInt" / "MyInt.yml"
    )
    integration_path.parent.mkdir(parents=True, exist_ok=True)
    integration_path.touch()

    mapped_params = {
        "general_configurations": [],
        "Fetch Issues": [],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_path,
        connector_title="My Int",
        mapped_params=mapped_params,
        auth_methods={"auth_types": []},
    )

    # Verify the connector was created
    assert (connector_dir / "connector.yaml").exists()
    assert (connector_dir / "capabilities.yaml").exists()
    assert (connector_dir / "configurations.yaml").exists()


def test_create_manifest_from_scratch_fetch_secrets_emits_serializer_computed_field(
    tmp_path: Path,
):
    """
    Given: mapped_params includes a 'Fetch Secrets' bucket (the integration
           declares an isFetchCredentials param).
    When:  create_manifest_from_scratch runs end-to-end.
    Then:  serializer.yaml is generated alongside the handler with a
           computed_fields rule whose output id is 'isFetchCredentials'
           (value True), AND configurations.yaml exposes NO isFetchCredentials
           field anywhere (the toggle lives in the serializer, not the
           sub-cap configurations).
    """
    connector_dir = tmp_path / "connectors" / "myint"
    integration_yml = {
        "commonfields": {"id": "MyInt"},
        "display": "My Integration",
        "configuration": [
            {"name": "isFetchCredentials", "type": 8, "display": "Fetches credentials"}
        ],
        "script": {},
    }
    integration_path = (
        tmp_path / "Packs" / "MyInt" / "Integrations" / "MyInt" / "MyInt.yml"
    )
    integration_path.parent.mkdir(parents=True, exist_ok=True)
    integration_path.touch()

    mapped_params = {
        "general_configurations": [],
        "Fetch Secrets": ["isFetchCredentials"],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml=integration_yml,
        integration_path=integration_path,
        connector_title="My Int",
        mapped_params=mapped_params,
        auth_methods={"auth_types": []},
    )

    # serializer.yaml must exist and carry the isFetchCredentials computed field.
    handlers_root = connector_dir / "components" / "handlers"
    serializer_paths = list(handlers_root.rglob("serializer.yaml"))
    assert serializer_paths, "expected a serializer.yaml to be generated"
    serializer_path = serializer_paths[0]
    with open(serializer_path) as fh:
        body = fh.read()
    # Strip the schema-directive comment line(s) before parsing.
    serializer_doc = yaml.safe_load(
        "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
    )
    computed_fields = serializer_doc.get("computed_fields", []) or []
    output_ids = {
        out.get("id")
        for rule in computed_fields
        for out in (rule.get("output", []) or [])
    }
    assert "isFetchCredentials" in output_ids

    # configurations.yaml must NOT expose isFetchCredentials as a field.
    with open(connector_dir / "configurations.yaml") as fh:
        configurations_text = fh.read()
    assert "isFetchCredentials" not in configurations_text


# ---------------------------------------------------------------------------
# connection.yaml wiring — create_manifest_from_scratch + append path
# ---------------------------------------------------------------------------
def _read_connection_yaml(connector_dir: Path) -> dict:
    """Load connector_dir/connection.yaml stripping the schema directive."""
    path = connector_dir / "connection.yaml"
    with open(path) as fh:
        fh.readline()  # skip schema directive
        return yaml.safe_load(fh)


def _real_shape_auth_methods() -> dict:
    """A real-workflow-shaped auth_methods (type + xsoar_param_map +
    other_connection) exercising Parts A–D + engine triggers."""
    return {
        "auth_types": [
            {
                "type": "Passthrough",
                "name": "passthrough",
                "xsoar_param_map": {
                    "creds.identifier": "username",
                    "creds.password": "password",
                },
            }
        ],
        # host → general_configurations (Part D); proxy/insecure → per-profile
        # (Part B); engine emitted per-profile (Part C, MyInt is not excluded).
        "other_connection": ["host", "proxy", "insecure"],
    }


def test_create_manifest_from_scratch_generates_connection_yaml(tmp_path: Path):
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "MyInt"},
            "display": "My Integration",
            "configuration": [
                {"name": "host", "type": 0, "display": "Host URL"},
                {"name": "creds", "type": 9, "display": "Credentials"},
            ],
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"general_configurations": []},
        auth_methods=_real_shape_auth_methods(),
    )

    conn = _read_connection_yaml(connector_dir)

    # Part A — one auth profile, id == handler auth_option id.
    assert [p["id"] for p in conn["profiles"]] == ["passthrough.myint"]

    # view_groups registry — one tile per integration.
    assert [vg["id"] for vg in conn["view_groups"]] == ["myint"]

    # ALL non-auth connection fields (host + proxy/insecure/engine) are
    # attached to the profile with event.publish — connection.yaml has NO
    # general_configurations.
    assert "general_configurations" not in conn
    profile_field_ids = {
        f["id"]
        for cfg in conn["profiles"][0]["configurations"]
        for f in cfg["fields"]
    }
    assert "proxy" in profile_field_ids
    assert "insecure" in profile_field_ids
    assert "engine_mode" in profile_field_ids
    # host (the rest of other_connection) is now per-profile too.
    assert "host" in profile_field_ids

    # Handler auth_option id is in lockstep with the profile id + carries
    # the view_group tile.
    handler_yaml = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-myint"
        / "handler.yaml"
    )
    with open(handler_yaml) as fh:
        fh.readline()
        handler_data = yaml.safe_load(fh)
    # No capabilities mapped → handler still emits no caps; verify the
    # connection profile id matches what build_handler_yaml would derive.
    from manifest_generator import derive_profile_id

    assert (
        derive_profile_id(
            {"type": "Passthrough", "name": "passthrough"}, "MyInt"
        )
        == "passthrough.myint"
    )

    # Engine visibility triggers folded into the single triggers.yaml.
    triggers_yaml = connector_dir / "triggers.yaml"
    assert triggers_yaml.exists()


def test_create_manifest_from_scratch_emits_interpolation_mapping(tmp_path: Path):
    """End-to-end: the from-scratch path writes
    metadata.xsoar.interpolation_mapping + interpolated onto the connection
    profile in the written connection.yaml."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "interp"

    auth_methods = {
        "auth_types": [
            {
                "type": "Passthrough",
                "name": "passthrough",
                "interpolated": True,
                "xsoar_param_map": {
                    "creds.identifier": "username",
                    "creds.password": "password",
                },
            }
        ],
        "other_connection": ["host"],
    }
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "MyInt"},
            "display": "My Integration",
            "configuration": [
                {"name": "host", "type": 0, "display": "Host URL"},
                {"name": "creds", "type": 9, "display": "Credentials"},
            ],
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"general_configurations": []},
        auth_methods=auth_methods,
    )

    conn = _read_connection_yaml(connector_dir)
    profile = conn["profiles"][0]
    assert profile["metadata"]["xsoar"]["interpolation_mapping"] == (
        "username:creds.identifier,password:creds.password"
    )


def test_create_manifest_from_scratch_anonymous_skips_connection_yaml(
    tmp_path: Path,
):
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "anon"

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "MyInt"}, "display": "MyInt"},
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"general_configurations": []},
        auth_methods={"auth_types": []},
    )

    # No auth_types → anonymous connector → no connection.yaml.
    assert not (connector_dir / "connection.yaml").exists()


def test_append_handler_adds_profile_view_group_and_general_config(
    tmp_path: Path,
):
    # First, create a connector from scratch (handler A with one profile).
    integration_a_path = _make_pack_with_integration(
        tmp_path, "PackA", "IntA", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "shared"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "IntA"},
            "display": "Integration A",
            "configuration": [
                {"name": "host", "type": 0, "display": "Host URL"},
                {"name": "creds", "type": 9, "display": "Credentials"},
            ],
        },
        integration_path=integration_a_path,
        connector_title="Shared Connector",
        mapped_params={"general_configurations": []},
        auth_methods={
            "auth_types": [
                {
                    "type": "Passthrough",
                    "name": "passthrough",
                    "xsoar_param_map": {"creds.password": "password"},
                }
            ],
            "other_connection": ["host"],
        },
    )
    conn_before = _read_connection_yaml(connector_dir)
    assert [p["id"] for p in conn_before["profiles"]] == ["passthrough.inta"]
    assert [vg["id"] for vg in conn_before["view_groups"]] == ["inta"]

    # Now append handler B (different integration) with its own profile.
    integration_b_path = _make_pack_with_integration(
        tmp_path, "PackB", "IntB", {"tags": []}
    )
    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "IntB"},
            "display": "Integration B",
            "configuration": [
                {"name": "server", "type": 0, "display": "Server URL"},
                {"name": "apikey", "type": 4, "display": "API Key"},
            ],
        },
        integration_path=integration_b_path,
        connector_title="Shared Connector",
        mapped_params={"general_configurations": []},
        auth_methods={
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_key",
                    "xsoar_param_map": {"apikey": "key"},
                }
            ],
            "other_connection": ["server"],
        },
    )

    conn_after = _read_connection_yaml(connector_dir)

    # Both profiles present (A preserved, B appended).
    assert [p["id"] for p in conn_after["profiles"]] == [
        "passthrough.inta",
        "api_key.intb",
    ]
    # Both view-group tiles present.
    assert {vg["id"] for vg in conn_after["view_groups"]} == {"inta", "intb"}

    # connection.yaml has NO general_configurations — each handler's non-auth
    # field lives inside its own auth profile. IntA's "host" is in the
    # passthrough profile; IntB's "server" is in the api_key profile.
    assert "general_configurations" not in conn_after
    profiles_by_id = {p["id"]: p for p in conn_after["profiles"]}
    inta_fields = {
        f["id"]
        for cfg in profiles_by_id["passthrough.inta"]["configurations"]
        for f in cfg["fields"]
    }
    intb_fields = {
        f["id"]
        for cfg in profiles_by_id["api_key.intb"]["configurations"]
        for f in cfg["fields"]
    }
    assert any(fid.endswith("host") for fid in inta_fields)
    assert any(fid.endswith("server") for fid in intb_fields)

    # Both profiles carry their own metadata.xsoar.interpolation_mapping +
    # interpolated (append path preserves A's and adds B's).
    inta_xsoar = profiles_by_id["passthrough.inta"]["metadata"]["xsoar"]
    intb_xsoar = profiles_by_id["api_key.intb"]["metadata"]["xsoar"]
    assert inta_xsoar["interpolation_mapping"] == "password:creds.password"
    assert intb_xsoar["interpolation_mapping"] == "api_key:apikey"
    # The interpolated boolean is always True on each profile (ALWAYS-INTERPOLATE
    # gate / Plan B INV-5); the append path preserves A's and adds B's.
    assert inta_xsoar["interpolated"] is True
    assert intb_xsoar["interpolated"] is True


def test_append_handler_anonymous_leaves_connection_untouched(tmp_path: Path):
    integration_a_path = _make_pack_with_integration(
        tmp_path, "PackA", "IntA", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "shared2"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "IntA"},
            "display": "Integration A",
            "configuration": [
                {"name": "creds", "type": 9, "display": "Credentials"},
            ],
        },
        integration_path=integration_a_path,
        connector_title="Shared Connector",
        mapped_params={"general_configurations": []},
        auth_methods={
            "auth_types": [
                {
                    "type": "Passthrough",
                    "name": "passthrough",
                    "xsoar_param_map": {"creds.password": "password"},
                }
            ],
            "other_connection": [],
        },
    )
    before = _read_connection_yaml(connector_dir)

    integration_b_path = _make_pack_with_integration(
        tmp_path, "PackB", "IntB", {"tags": []}
    )
    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={"commonfields": {"id": "IntB"}, "display": "IntB"},
        integration_path=integration_b_path,
        connector_title="Shared Connector",
        mapped_params={"general_configurations": []},
        auth_methods={"auth_types": []},
    )
    after = _read_connection_yaml(connector_dir)

    # Anonymous new handler contributes nothing to connection.yaml.
    assert [p["id"] for p in after["profiles"]] == [
        p["id"] for p in before["profiles"]
    ]


# ---------------------------------------------------------------------------
# Review point 1 — vendor-driven connector.yaml
# ---------------------------------------------------------------------------
def test_get_pack_categories_returns_categories_from_metadata(tmp_path: Path) -> None:
    from manifest_generator import get_pack_categories

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"categories": ["Case Management"]}
    )
    assert get_pack_categories(integration_yml) == ["Case Management"]


def test_get_pack_categories_empty_when_missing(tmp_path: Path) -> None:
    from manifest_generator import get_pack_categories

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", pack_metadata=None
    )
    assert get_pack_categories(integration_yml) == []


def test_get_supported_modules_prefers_integration_field(tmp_path: Path) -> None:
    from manifest_generator import get_supported_modules

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"supported_modules": ["xsoar"]}
    )
    # Integration YML field wins over the pack metadata fallback.
    assert get_supported_modules(
        {"supportedModules": ["agentix", "xsiam"]}, integration_yml
    ) == ["agentix", "xsiam"]


def test_get_supported_modules_falls_back_to_pack_metadata(tmp_path: Path) -> None:
    from manifest_generator import get_supported_modules

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"supported_modules": ["xsoar", "xsiam"]}
    )
    assert get_supported_modules({}, integration_yml) == ["xsoar", "xsiam"]


@pytest.mark.no_license_stub
def test_licenses_for_sub_capability_reads_json() -> None:
    """A known sub_capability_id resolves to its JSON license list."""
    from manifest_generator import licenses_for_sub_capability

    # absolute -> ["xsiam", "agentix"] in sub_capabilities_to_licenses.json.
    assert sorted(
        licenses_for_sub_capability("automation-and-remediation_absolute")
    ) == ["agentix", "xsiam"]


@pytest.mark.no_license_stub
def test_licenses_for_sub_capability_missing_raises() -> None:
    """An unknown sub_capability_id is a hard failure (RuntimeError)."""
    from manifest_generator import licenses_for_sub_capability

    with pytest.raises(RuntimeError, match="not found"):
        licenses_for_sub_capability("automation-and-remediation_does-not-exist")


@pytest.mark.no_license_stub
def test_union_licenses_for_sub_caps_dedupes() -> None:
    """The capability license set is the deduped union of its sub-caps."""
    from manifest_generator import union_licenses_for_sub_caps

    # absolute -> {xsiam, agentix}; abuseipdb adds cloud/cloud_runtime/edr.
    result = union_licenses_for_sub_caps(
        [
            "automation-and-remediation_absolute",
            "automation-and-remediation_abuseipdb",
        ]
    )
    assert set(result) == {
        "agentix",
        "cloud",
        "cloud_runtime_security",
        "edr",
        "xsiam",
    }
    # No duplicates in the returned list.
    assert len(result) == len(set(result))


@pytest.mark.no_license_stub
def test_required_license_for_capability_unions_sub_caps() -> None:
    """_required_license_for_capability is the union over its sub-caps."""
    from manifest_generator import _required_license_for_capability

    assert set(
        _required_license_for_capability(
            ["automation-and-remediation_absolute"]
        )
    ) == {"agentix", "xsiam"}


def test_create_manifest_from_scratch_connector_yaml_has_schema_directive(
    tmp_path: Path,
) -> None:
    """Review point 11: connector.yaml starts with the yaml-language-server
    schema directive line."""
    from manifest_generator import CONNECTOR_SCHEMA_DIRECTIVE

    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )
    with open(connector_dir / "connector.yaml") as fh:
        assert fh.readline() == CONNECTOR_SCHEMA_DIRECTIVE
    with open(connector_dir / "summary.yaml") as fh:
        from manifest_generator import SUMMARY_SCHEMA_DIRECTIVE

        assert fh.readline() == SUMMARY_SCHEMA_DIRECTIVE


def test_create_manifest_from_scratch_handler_yaml_has_no_yaml_aliases(
    tmp_path: Path,
) -> None:
    """Review point 10: handler.yaml must not contain YAML anchors/aliases
    (&idNNN / *idNNN) even when scopes/workloads lists are shared across
    capabilities."""
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "MyInt"},
            "display": "My Integration",
        },
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["a"], "Automation": ["b"]},
        auth_methods={
            "auth_types": [{"type": "Passthrough", "name": "passthrough"}]
        },
    )
    handler_path = (
        connector_dir / "components" / "handlers" / "xsoar-myint" / "handler.yaml"
    )
    text = handler_path.read_text()
    assert "&id" not in text
    assert "*id" not in text


# ---------------------------------------------------------------------------
# Connector id / title similarity guard (check_connector_id_title_similarity)
# ---------------------------------------------------------------------------
def _write_existing_connector(
    connectors_root: Path, slug: str, connector_id: str, title: str
) -> Path:
    """Create ``<connectors_root>/<slug>/connector.yaml`` with id + title."""
    connector_dir = connectors_root / slug
    connector_dir.mkdir(parents=True, exist_ok=True)
    data = {"id": connector_id, "metadata": {"title": title}}
    with open(connector_dir / "connector.yaml", "w") as fh:
        yaml.safe_dump(data, fh)
    return connector_dir

# ---------------------------------------------------------------------------
# Sub-capability id/title derived from the integration name
# ---------------------------------------------------------------------------
def test_handler_id_to_integration_slug_strips_xsoar_prefix() -> None:
    assert handler_id_to_integration_slug("xsoar-salesforce") == "salesforce"
    assert (
        handler_id_to_integration_slug("xsoar-hello-world-iam")
        == "hello-world-iam"
    )
    # No prefix -> returned unchanged.
    assert handler_id_to_integration_slug("salesforce") == "salesforce"


def test_make_sub_capability_id_uses_capability_then_integration_slug() -> None:
    """id format is ``<capability_id>_<integration-id-slug>``."""
    assert (
        make_sub_capability_id("xsoar-hello-world-iam", "Automation")
        == "automation-and-remediation_hello-world-iam"
    )
    assert (
        make_sub_capability_id("xsoar-salesforce", "Fetch Issues")
        == "fetch-issues_salesforce"
    )


def test_build_sub_capability_entry_title_is_integration_name() -> None:
    """When an integration name is supplied, it becomes the sub-cap title."""
    entry = build_sub_capability_entry(
        "automation-and-remediation_salesforce-iam",
        "Automation",
        required=True,
        integration_name="Salesforce IAM",
    )
    assert entry == {
        "id": "automation-and-remediation_salesforce-iam",
        "title": "Salesforce IAM",
        "default_enabled": False,
        "required": True,
        "config": {'required_license': ['agentix', 'xsiam']}
    }


def test_build_sub_capability_entry_falls_back_to_canonical_title() -> None:
    """Legacy callers (no integration_name) keep the canonical family title."""
    entry = build_sub_capability_entry("fetch-issues_x", "Fetch Issues")
    assert entry["title"] == "Fetch Issues"
    assert entry["id"] == "fetch-issues_x"



# ---------------------------------------------------------------------------
# One-field-per-fields-block normalization (guide §3.7 item 2)
# ---------------------------------------------------------------------------
def test_split_fields_blocks_multi_field() -> None:
    """A block with N fields becomes N single-field blocks, sibling keys kept."""
    block = {
        "id": "fetch-issues_x",
        "view_group": "x",
        "fields": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
    }
    result = split_fields_blocks(block)
    assert result == [
        {"id": "fetch-issues_x", "view_group": "x", "fields": [{"id": "a"}]},
        {"id": "fetch-issues_x", "view_group": "x", "fields": [{"id": "b"}]},
        {"id": "fetch-issues_x", "view_group": "x", "fields": [{"id": "c"}]},
    ]


def test_split_fields_blocks_single_field_unchanged() -> None:
    """A block already holding one field round-trips to one block."""
    block = {"view_group": "x", "fields": [{"id": "a"}]}
    assert split_fields_blocks(block) == [
        {"view_group": "x", "fields": [{"id": "a"}]}
    ]


def test_split_fields_blocks_empty_preserves_sibling_keys() -> None:
    """An empty block keeps its view_group binding (guide §3.7 rule 4)."""
    block = {"id": "automation-and-remediation_x", "view_group": "x", "fields": []}
    assert split_fields_blocks(block) == [
        {"id": "automation-and-remediation_x", "view_group": "x", "fields": []}
    ]


def test_split_fields_blocks_leaves_checkbox_group_inner_fields_untouched() -> None:
    """Only the block-level fields list is split; a checkbox_group's inner
    ``fields[]`` (its items) belong to the field object and stay intact."""
    cbg = {
        "id": "user_operations",
        "field_type": "checkbox_group",
        "fields": [{"id": "create_user_enabled"}, {"id": "update_user_enabled"}],
    }
    block = {"view_group": "x", "fields": [cbg, {"id": "other"}]}
    result = split_fields_blocks(block)
    assert result == [
        {"view_group": "x", "fields": [cbg]},
        {"view_group": "x", "fields": [{"id": "other"}]},
    ]
    # The checkbox_group's inner items are NOT split.
    assert result[0]["fields"][0]["fields"] == [
        {"id": "create_user_enabled"},
        {"id": "update_user_enabled"},
    ]


def test_normalize_connection_field_blocks_splits_per_profile() -> None:
    """Each profiles[].configurations[] block is split one-field-per-block."""
    data = {
        "profiles": [
            {
                "id": "p1",
                "configurations": [
                    {"fields": [{"id": "a"}, {"id": "b"}]},
                ],
            }
        ]
    }
    out = normalize_connection_field_blocks(data)
    cfgs = out["profiles"][0]["configurations"]
    assert [c["fields"][0]["id"] for c in cfgs] == ["a", "b"]
    assert all(len(c["fields"]) == 1 for c in cfgs)
    # Input is not mutated (deep-copied).
    assert len(data["profiles"][0]["configurations"]) == 1


def test_normalize_configurations_field_blocks_splits_subcaps_and_general() -> None:
    """Both general_configurations and per-sub-cap blocks are split."""
    data = {
        "general_configurations": {
            "configurations": [
                {"view_group": "x", "fields": [{"id": "log"}, {"id": "extra"}]},
            ]
        },
        "configurations": [
            {
                "id": "fetch-issues_x",
                "view_group": "x",
                "configurations": [{"fields": [{"id": "a"}, {"id": "b"}]}],
            }
        ],
    }
    out = normalize_configurations_field_blocks(data)

    gen = out["general_configurations"]["configurations"]
    assert [g["fields"][0]["id"] for g in gen] == ["log", "extra"]
    assert all(g["view_group"] == "x" for g in gen)

    sub = out["configurations"][0]["configurations"]
    assert [s["fields"][0]["id"] for s in sub] == ["a", "b"]
    # Input untouched.
    assert len(data["configurations"][0]["configurations"]) == 1


# ---------------------------------------------------------------------------
# longRunning routed to a fetch capability that has NO real fetch flag
# (no script.isfetch / no script.isfetchevents, no fetch checkbox param).
# The synthetic fetch toggle must appear NOWHERE; longRunning moves to the
# serializer computed_fields gated on the sub-capability.
# ---------------------------------------------------------------------------
def test_fetch_issues_no_real_fetch_flag_longrunning_moves_to_serializer(
    tmp_path: Path,
):
    """QRadar v3 / Retarus shape: longRunning routed to Fetch Issues but the
    integration declares no script.isfetch and no isFetch param. Expect:
      - no isFetch field AND no longRunning field in the manifest;
      - isFetch is NOT serialized (appears nowhere);
      - longRunning IS serialized via computed_fields gated on the sub-cap.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    cap_id = "fetch-issues_qradar-v3"
    integration_yml = _make_integration_yml(
        integration_id="QRadar v3", is_long_running=True
    )
    template = add_fetch_issues_capability(
        capability_id=cap_id,
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        yml_params_by_name=dict(_FETCH_ISSUES_YML_PARAMS),
        handler_dir=tmp_path,
    )

    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetch" not in by_id
    assert "longRunning" not in by_id

    serializer = _read_serializer_dict(tmp_path)
    outputs = [
        out["id"]
        for rule in serializer.get("computed_fields", [])
        for out in rule["output"]
    ]
    # longRunning moved to the serializer, gated on the sub-capability.
    assert "longRunning" in outputs
    lr_rule = next(
        r
        for r in serializer["computed_fields"]
        if r["output"] == [{"id": "longRunning", "value": True}]
    )
    assert lr_rule["any_of"] == [
        {
            "conditions": [
                {
                    "type": "capability",
                    "options": {"capability_id": cap_id, "value": "on"},
                }
            ]
        }
    ]
    # The synthetic isFetch toggle appears NOWHERE (no computed_fields rule).
    assert "isFetch" not in outputs
    # No field_mappings bridge for the dropped longRunning either.
    assert all(
        m.get("field_name") != "longRunning"
        for m in serializer.get("field_mappings", [])
    )


def test_log_collection_no_real_fetch_flag_longrunning_moves_to_serializer(
    tmp_path: Path,
):
    """Same shape as the fetch-issues case but for Log Collection: longRunning
    routed here with no script.isfetchevents / no isFetchEvents param. Expect
    no isFetchEvents/longRunning fields, isFetchEvents serialized nowhere, and
    longRunning moved to a computed_fields rule gated on the sub-capability.
    """
    cap_id = "log-collection_retarus"
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Log Collection": ["longRunning"],
    }
    integration_yml = _make_integration_yml(
        integration_id="Retarus", is_long_running=True
    )
    template = add_log_collection_capability(
        capability_id=cap_id,
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        handler_dir=tmp_path,
    )

    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" not in by_id
    assert "longRunning" not in by_id
    # The interval field is still emitted.
    assert "eventFetchInterval" in by_id

    serializer = _read_serializer_dict(tmp_path)
    outputs = [
        out["id"]
        for rule in serializer.get("computed_fields", [])
        for out in rule["output"]
    ]
    assert "longRunning" in outputs
    assert "isFetchEvents" not in outputs
    lr_rule = next(
        r
        for r in serializer["computed_fields"]
        if r["output"] == [{"id": "longRunning", "value": True}]
    )
    assert lr_rule["any_of"] == [
        {
            "conditions": [
                {
                    "type": "capability",
                    "options": {"capability_id": cap_id, "value": "on"},
                }
            ]
        }
    ]


def test_fetch_issues_real_fetch_flag_via_param_keeps_both_shown():
    """When the integration carries an ``isFetch`` config PARAM (even without
    script.isfetch), it counts as a real fetch flag → both checkboxes shown.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Fetch Issues": ["longRunning"],
    }
    yml_params: dict = dict(_FETCH_ISSUES_YML_PARAMS)
    yml_params["isFetch"] = {"name": "isFetch", "type": 8, "display": "Fetch"}
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=_make_integration_yml(is_long_running=True),
        yml_params_by_name=yml_params,
    )
    by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetch" in by_id
    assert "longRunning" in by_id


# ===========================================================================
# Hidden-default → serializer sweep (final authoritative pass)
# ===========================================================================
def _hidden_default_yml(extra_params: list[dict] | None = None) -> dict:
    """Minimal integration yml with a mix of params for sweep testing."""
    config = [
        # hidden:true + default → MUST be swept
        {"name": "max_concurrent_tasks", "type": 0, "hidden": True,
         "defaultvalue": "100"},
        # hidden:[platform] + default → MUST be swept
        {"name": "eventFetchInterval", "type": 19,
         "hidden": ["platform"], "defaultvalue": "1"},
        # hidden:true + default bool → swept, coerced to bool
        {"name": "someHiddenToggle", "type": 8, "hidden": True,
         "defaultvalue": "true"},
        # hidden but NO default → NOT swept
        {"name": "hiddenNoDefault", "type": 0, "hidden": True},
        # visible + default → NOT swept
        {"name": "visibleWithDefault", "type": 0, "defaultvalue": "x"},
        # hidden only on xsoar (visible on platform) → NOT swept
        {"name": "xsoarOnlyHidden", "type": 0, "hidden": ["xsoar"],
         "defaultvalue": "y"},
        # excluded: feedExpirationInterval (trigger-revealed)
        {"name": "feedExpirationInterval", "type": 19, "hidden": True,
         "defaultvalue": "20160"},
        # excluded: defaultIgnore
        {"name": "defaultIgnore", "type": 8, "hidden": True,
         "defaultvalue": "false"},
    ]
    if extra_params:
        config.extend(extra_params)
    return {"commonfields": {"id": "Test Int"}, "configuration": config}


def test_collect_swept_hidden_default_params_basic():
    swept = collect_swept_hidden_default_params(_hidden_default_yml())
    assert swept["max_concurrent_tasks"] == "100"
    assert swept["eventFetchInterval"] == "1"
    # type-8 default coerced to native bool.
    assert swept["someHiddenToggle"] is True
    # Excluded / non-qualifying params absent.
    assert "hiddenNoDefault" not in swept
    assert "visibleWithDefault" not in swept
    assert "xsoarOnlyHidden" not in swept
    assert "feedExpirationInterval" not in swept
    assert "defaultIgnore" not in swept


def test_collect_swept_excludes_connection_params():
    yml = _hidden_default_yml(
        extra_params=[
            {"name": "clientToken", "type": 4, "hidden": True,
             "defaultvalue": "secret-default"},
        ]
    )
    swept = collect_swept_hidden_default_params(
        yml, connection_param_names={"clientToken"}
    )
    assert "clientToken" not in swept
    # Other params still swept.
    assert "max_concurrent_tasks" in swept


def test_connection_param_names_from_auth():
    auth = {
        "auth_types": [
            {"type": "Passthrough", "name": "p",
             "xsoar_param_map": {
                 "clientToken": "clientToken",
                 "creds.password": "creds",
             }},
        ],
        "other_connection": ["host", "configIds"],
    }
    names = connection_param_names_from_auth(auth)
    assert names == {"clientToken", "creds", "host", "configIds"}
    assert connection_param_names_from_auth(None) == set()
    assert connection_param_names_from_auth({}) == set()


def _make_configurations_with_field(field_id: str, field: dict) -> dict:
    return {
        "configurations": [
            {
                "id": "log-collection_test-int",
                "configurations": [{"fields": [field]}],
            }
        ],
        "general_configurations": {"configurations": []},
    }


def test_sweep_removes_field_and_registers_serializer(tmp_path):
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    efi_field = {
        "id": "eventFetchInterval",
        "field_type": "duration",
        "options": {
            "default_value": {"minutes": 1},
            "create_modifiers": {"hidden": True},
            "edit_modifiers": {"hidden": True},
        },
    }
    configurations_data = _make_configurations_with_field(
        "eventFetchInterval", efi_field
    )
    mapped = {
        "general_configurations": [],
        "Log Collection": ["eventFetchInterval"],
    }
    swept = sweep_hidden_defaults_to_serializer(
        configurations_data,
        _hidden_default_yml(),
        handler_id="xsoar-test-int",
        handler_dir=handler_dir,
        mapped_params=mapped,
    )
    # eventFetchInterval swept + removed from configurations.
    assert "eventFetchInterval" in swept
    remaining_ids = [
        f["id"]
        for entry in configurations_data["configurations"]
        for grp in entry["configurations"]
        for f in grp.get("fields", [])
    ]
    assert "eventFetchInterval" not in remaining_ids
    # Serializer computed_fields written with original param name as output id.
    serializer = yaml.safe_load(
        (handler_dir / "serializer.yaml").read_text().split("\n", 1)[1]
    )
    outputs = [
        o["id"] for r in serializer["computed_fields"] for o in r["output"]
    ]
    assert "eventFetchInterval" in outputs
    assert "max_concurrent_tasks" in outputs  # orphan param also swept

    def _cap_ids_for(output_id: str) -> list[str]:
        rule = next(
            r for r in serializer["computed_fields"]
            if r["output"][0]["id"] == output_id
        )
        return [
            c["options"]["capability_id"]
            for grp in rule["any_of"]
            for c in grp["conditions"]
        ]

    # eventFetchInterval is a builder param attached to Log Collection ONLY —
    # it must gate on EXACTLY that single sub-capability (not all of them).
    lc_id = make_sub_capability_id("xsoar-test-int", "Log Collection")
    assert _cap_ids_for("eventFetchInterval") == [lc_id]

    # max_concurrent_tasks is an unattached orphan (config-only, not routed to
    # any bucket) → OR-gated across ALL of the handler's sub-capabilities.
    assert set(_cap_ids_for("max_concurrent_tasks")) == {lc_id}


def test_sweep_no_qualifying_params_is_noop(tmp_path):
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    yml = {"commonfields": {"id": "X"}, "configuration": [
        {"name": "visible", "type": 0, "defaultvalue": "v"},
    ]}
    configurations_data = {"configurations": [], "general_configurations":
                           {"configurations": []}}
    swept = sweep_hidden_defaults_to_serializer(
        configurations_data, yml, "h", handler_dir, mapped_params={}
    )
    assert swept == {}
    assert not (handler_dir / "serializer.yaml").exists()


def test_sweep_matches_renamed_field_via_field_mappings(tmp_path):
    """A field renamed away from its bare yml name (recorded in serializer
    field_mappings) is still found and removed by the sweep."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    # Pre-seed a field_mappings entry: renamed id -> original name.
    register_serializer_entry(
        handler_dir,
        new_id="xsoar-test-int_eventFetchInterval",
        original_id="eventFetchInterval",
    )
    renamed_field = {
        "id": "xsoar-test-int_eventFetchInterval",
        "field_type": "duration",
        "options": {
            "default_value": {"minutes": 1},
            "create_modifiers": {"hidden": True},
            "edit_modifiers": {"hidden": True},
        },
    }
    configurations_data = _make_configurations_with_field(
        "xsoar-test-int_eventFetchInterval", renamed_field
    )
    sweep_hidden_defaults_to_serializer(
        configurations_data,
        _hidden_default_yml(),
        handler_id="xsoar-test-int",
        handler_dir=handler_dir,
        mapped_params={"general_configurations": [],
                       "Log Collection": ["eventFetchInterval"]},
    )
    remaining_ids = [
        f["id"]
        for entry in configurations_data["configurations"]
        for grp in entry["configurations"]
        for f in grp.get("fields", [])
    ]
    assert "xsoar-test-int_eventFetchInterval" not in remaining_ids


def test_guard_raises_on_hidden_field_with_default():
    configurations_data = _make_configurations_with_field(
        "bad",
        {
            "id": "bad",
            "options": {
                "default_value": "x",
                "create_modifiers": {"hidden": True},
                "edit_modifiers": {"hidden": True},
            },
        },
    )
    with pytest.raises(ValueError, match="hidden fields that still carry"):
        assert_no_hidden_defaults_in_configurations(configurations_data)


def test_guard_allows_hidden_without_default():
    configurations_data = _make_configurations_with_field(
        "ok",
        {
            "id": "ok",
            "options": {
                "create_modifiers": {"hidden": True},
                "edit_modifiers": {"hidden": True},
            },
        },
    )
    # No default_value → not a violation.
    assert_no_hidden_defaults_in_configurations(configurations_data)


def test_guard_allows_visible_with_default():
    configurations_data = _make_configurations_with_field(
        "ok",
        {
            "id": "ok",
            "options": {
                "default_value": False,
                "create_modifiers": {"hidden": False},
                "edit_modifiers": {"hidden": False},
            },
        },
    )
    # Visible + default (e.g. shown longRunning) → not a violation.
    assert_no_hidden_defaults_in_configurations(configurations_data)


def test_guard_allows_feedexpirationinterval_exception():
    configurations_data = _make_configurations_with_field(
        "feedExpirationInterval",
        {
            "id": "feedExpirationInterval",
            "options": {
                "default_value": {"minutes": 1},
                "create_modifiers": {"hidden": True},
                "edit_modifiers": {"hidden": True},
            },
        },
    )
    # feedExpirationInterval is the sanctioned exception (revealed via trigger).
    assert "feedExpirationInterval" in SWEEP_EXCLUDED_PARAMS
    assert_no_hidden_defaults_in_configurations(configurations_data)


def test_sweep_builder_renamed_incidentfetchinterval_to_alertfetchinterval(
    tmp_path,
):
    """incidentFetchInterval (XSOAR) is rendered by the fetch-issues builder as
    ``alertFetchInterval`` with NO field_mappings bridge (platform consumes it
    directly). The sweep must remove the ``alertFetchInterval`` field AND emit
    the computed_fields output id as ``alertFetchInterval`` (not the XSOAR name).
    """
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    yml = {
        "commonfields": {"id": "Akamai WAF SIEM"},
        "configuration": [
            {"name": "incidentFetchInterval", "type": 19,
             "hidden": ["marketplacev2", "platform"], "defaultvalue": "1"},
        ],
    }
    afi_field = {
        "id": "alertFetchInterval",
        "field_type": "duration",
        "options": {
            "default_value": {"minutes": 1},
            "create_modifiers": {"hidden": True},
            "edit_modifiers": {"hidden": True},
        },
    }
    configurations_data = _make_configurations_with_field(
        "alertFetchInterval", afi_field
    )
    swept = sweep_hidden_defaults_to_serializer(
        configurations_data,
        yml,
        handler_id="xsoar-akamai-waf-siem",
        handler_dir=handler_dir,
        mapped_params={"general_configurations": [],
                       "Fetch Issues": ["isFetch"]},
    )
    # Swept under the XSOAR param name (collect step reads the yml).
    assert "incidentFetchInterval" in swept
    # alertFetchInterval field removed from configurations.
    remaining_ids = [
        f["id"]
        for entry in configurations_data["configurations"]
        for grp in entry["configurations"]
        for f in grp.get("fields", [])
    ]
    assert "alertFetchInterval" not in remaining_ids
    # computed_fields output id is the RENAMED id (alertFetchInterval).
    serializer = yaml.safe_load(
        (handler_dir / "serializer.yaml").read_text().split("\n", 1)[1]
    )
    outputs = [
        o["id"] for r in serializer["computed_fields"] for o in r["output"]
    ]
    assert "alertFetchInterval" in outputs
    assert "incidentFetchInterval" not in outputs
    # alertFetchInterval (incidentFetchInterval) is owned by Fetch Issues — it
    # must gate on EXACTLY that single sub-capability.
    afi_rule = next(
        r for r in serializer["computed_fields"]
        if r["output"][0]["id"] == "alertFetchInterval"
    )
    afi_cap_ids = [
        c["options"]["capability_id"]
        for grp in afi_rule["any_of"]
        for c in grp["conditions"]
    ]
    assert afi_cap_ids == [
        make_sub_capability_id("xsoar-akamai-waf-siem", "Fetch Issues")
    ]
    # Guard passes on the cleaned configurations.
    assert_no_hidden_defaults_in_configurations(configurations_data)


def test_sweep_per_param_gating_builder_vs_orphan_multi_capability(tmp_path):
    """With MULTIPLE capabilities present, builder params gate on their single
    owning capability while unattached orphans OR-gate across all of them.
    """
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    yml = {
        "commonfields": {"id": "Akamai WAF SIEM"},
        "configuration": [
            # builder param owned by Log Collection
            {"name": "eventFetchInterval", "type": 19,
             "hidden": ["platform"], "defaultvalue": "1"},
            # builder param owned by Fetch Issues (renamed -> alertFetchInterval)
            {"name": "incidentFetchInterval", "type": 19,
             "hidden": ["platform"], "defaultvalue": "1"},
            # unattached orphan (config-only, not routed anywhere)
            {"name": "max_concurrent_tasks", "type": 0,
             "hidden": True, "defaultvalue": "100"},
        ],
    }
    configurations_data = {"configurations": [],
                           "general_configurations": {"configurations": []}}
    mapped = {
        "general_configurations": [],
        "Log Collection": ["isFetchEvents"],
        "Fetch Issues": ["isFetch"],
        "Automation": ["someAutomationParam"],
    }
    sweep_hidden_defaults_to_serializer(
        configurations_data,
        yml,
        handler_id="xsoar-akamai-waf-siem",
        handler_dir=handler_dir,
        mapped_params=mapped,
    )
    serializer = yaml.safe_load(
        (handler_dir / "serializer.yaml").read_text().split("\n", 1)[1]
    )

    def _cap_ids_for(output_id: str) -> list[str]:
        rule = next(
            r for r in serializer["computed_fields"]
            if r["output"][0]["id"] == output_id
        )
        return [
            c["options"]["capability_id"]
            for grp in rule["any_of"]
            for c in grp["conditions"]
        ]

    lc_id = make_sub_capability_id("xsoar-akamai-waf-siem", "Log Collection")
    fi_id = make_sub_capability_id("xsoar-akamai-waf-siem", "Fetch Issues")
    auto_id = make_sub_capability_id("xsoar-akamai-waf-siem", "Automation")

    # Builder params → single owning capability.
    assert _cap_ids_for("eventFetchInterval") == [lc_id]
    assert _cap_ids_for("alertFetchInterval") == [fi_id]
    # Orphan → OR-gated across ALL sub-capabilities.
    assert set(_cap_ids_for("max_concurrent_tasks")) == {lc_id, fi_id, auto_id}
