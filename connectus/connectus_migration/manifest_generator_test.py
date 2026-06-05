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
    FEED_EXPIRATION_INTERVAL_DEFAULT,
    FEED_EXPIRATION_POLICY_DEFAULT,
    FEED_EXPIRATION_POLICY_VALUES,
    FEED_PARAM_NAME,
    FEED_RELIABILITY_ADDITIONAL_INFO,
    FEED_RELIABILITY_DEFAULT,
    FEED_RELIABILITY_OPTIONS,
    FEED_REPUTATION_ADDITIONAL_INFO,
    FEED_REPUTATION_DEFAULT,
    FEEDBYPASSEXCLUSIONLIST_PARAM_NAME,
    FEEDEXPIRATIONINTERVAL_PARAM_NAME,
    FEEDEXPIRATIONPOLICY_PARAM_NAME,
    FEEDFETCHINTERVAL_FALLBACK_DEFAULT,
    FEEDFETCHINTERVAL_PARAM_NAME,
    FEEDRELIABILITY_PARAM_NAME,
    FEEDREPUTATION_PARAM_NAME,
    INCIDENTFETCHINTERVAL_FALLBACK_DEFAULT,
    INCIDENTFETCHINTERVAL_PARAM_NAME,
    INCIDENTTYPE_PARAM_NAME,
    INDICATOR_REPUTATION_VALUES,
    ISFETCH_PARAM_NAME,
    CLASSIFIER_FIELD_ID,
    LONGRUNNING_PARAM_NAME,
    MAPPER_INCOMING_FIELD_ID,
    TRIGGERS_SCHEMA_DIRECTIVE,
    _minutes_to_duration_default,
    HANDLER_SCHEMA_DIRECTIVE,
    ISFETCHASSETS_PARAM_NAME,
    ISFETCHCREDENTIALS_PARAM_NAME,
    ISFETCHEVENTS_PARAM_NAME,
    SERIALIZER_PLACEHOLDER,
    SERIALIZER_SCHEMA_DIRECTIVE,
    add_assets_capability,
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
    build_per_handler_general_config,
    build_capabilities_yaml,
    build_configurations_yaml,
    build_connector_yaml,
    build_handler_yaml,
    build_summary_yaml,
    build_synthetic_hidden_toggle,
    build_triggers_yaml,
    bump_minor_version,
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
    register_renamed_field_serializer_entry,
    register_serializer_entry,
    rename_handler_capability_id,
    slugify_capability_name,
    write_capabilities_yaml,
    write_handler_yaml,
    write_serializer_yaml,
    write_triggers_yaml,
)


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
# bump_minor_version
# ---------------------------------------------------------------------------
def test_bump_minor_version_basic() -> None:
    assert bump_minor_version("1.0.0") == "1.1.0"
    assert bump_minor_version("2.3.5") == "2.4.0"


def test_bump_minor_version_raises_on_malformed() -> None:
    for bad in ("v1", "1.2", "abc.def.ghi", "", "1.2.3.4"):
        with pytest.raises(ValueError):
            bump_minor_version(bad)


def test_bump_minor_version_zero_minor() -> None:
    assert bump_minor_version("0.0.0") == "0.1.0"


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

    assert data["id"] == "myconnector"
    metadata = data["metadata"]
    assert metadata["title"] == "My Connector"
    assert metadata["description"] == ""
    assert metadata["version"] == "1.0.0"
    # Per guide §3.3 + connector.schema: plural ``categories`` array (not
    # the singular ``category`` string). Defaults to empty list.
    assert metadata["categories"] == []
    assert list(metadata["tags"]) == ["forensics"]
    assert metadata["domain"] == ""
    assert metadata["vendor"] == ""
    assert metadata["publisher"] == "Palo Alto Networks"
    # No --author-image-path provided → author_image defaults to ""
    assert metadata["author_image"] == ""
    assert metadata["ownership"]["team"] == "xsoar"
    assert list(metadata["ownership"]["maintainers"]) == ["@xsoar-content"]
    # Per guide §3.3: "Always true unless the vendor explicitly requires
    # successful verification".
    assert data["settings"]["allow_skip_verification"] is True


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


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — author image copy + connector.yaml field
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_copies_author_image_and_records_filename(
    tmp_path: Path,
) -> None:
    """
    Given: --author-image-path pointing to a real PNG file.
    When:  create_manifest_from_scratch is called.
    Then:  The image is copied into the connector root as
           '<connector_id>.png', AND connector.yaml's metadata.author_image
           contains just that filename (relative to the connector root).
    """
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"

    # Create a source author image (any binary content works for a copy test).
    source_image = tmp_path / "source_image.png"
    source_image.write_bytes(b"\x89PNG\r\n\x1a\nfake-png-bytes")

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
        author_image_path=source_image,
    )

    # Image was copied under the expected name (connector_id + suffix).
    copied_image = connector_dir / "myconnector.png"
    assert copied_image.is_file()
    assert copied_image.read_bytes() == source_image.read_bytes()

    # connector.yaml records the relative filename (sibling of connector.yaml).
    with open(connector_dir / "connector.yaml") as fh:
        data = yaml.safe_load(fh)
    assert data["metadata"]["author_image"] == "myconnector.png"


def test_create_manifest_from_scratch_preserves_svg_extension(
    tmp_path: Path,
) -> None:
    """
    Given: --author-image-path pointing to a .svg file.
    When:  create_manifest_from_scratch is called.
    Then:  The dest filename preserves the .svg extension.
    """
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    source_image = tmp_path / "logo.svg"
    source_image.write_text("<svg></svg>")

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
        author_image_path=source_image,
    )

    assert (connector_dir / "myconnector.svg").is_file()
    with open(connector_dir / "connector.yaml") as fh:
        data = yaml.safe_load(fh)
    assert data["metadata"]["author_image"] == "myconnector.svg"


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
    assert data["id"] == "myconnector"
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


def test_add_handler_merges_tags_and_bumps_version(tmp_path: Path) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["new"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    connector_yaml_path = _write_existing_connector_yaml(
        connector_dir, version="1.0.0", tags=["existing"]
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    with open(connector_yaml_path) as fh:
        data = yaml.safe_load(fh)
    assert list(data["metadata"]["tags"]) == ["existing", "new"]
    assert data["metadata"]["version"] == "1.1.0"


def test_add_handler_dedupes_tags_case_insensitive(tmp_path: Path) -> None:
    integration_yml = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["endpoint", "Network"]}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    connector_yaml_path = _write_existing_connector_yaml(
        connector_dir, version="1.2.5", tags=["Endpoint"]
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={"name": "MyInt"},
        integration_path=integration_yml,
        connector_title="My Connector",
        mapped_params={},
        auth_methods={},
    )

    with open(connector_yaml_path) as fh:
        data = yaml.safe_load(fh)
    assert list(data["metadata"]["tags"]) == ["Endpoint", "Network"]
    assert data["metadata"]["version"] == "1.3.0"


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
# build_handler_yaml
# ---------------------------------------------------------------------------
def test_build_handler_yaml_shape() -> None:
    integration_yml = {
        "commonfields": {"id": "Salesforce"},
        "display": "Salesforce",
    }
    pack_tags = ["forensics", "endpoint"]
    data = build_handler_yaml(integration_yml, "Salesforce", pack_tags, {}, {})

    # id
    assert data["id"] == "xsoar-salesforce"

    # metadata
    metadata = data["metadata"]
    assert metadata["version"] == "1.0.0"
    description = metadata["description"]
    assert "Salesforce" in description
    # Both display and connector title appear in the description template
    assert (
        description
        == "XSOAR handler for Salesforce integration for Salesforce connector"
    )
    assert metadata["module"] == "xsoar"
    assert list(metadata["tags"]) == ["forensics", "endpoint"]
    assert metadata["ownership"]["team"] == "xsoar"
    assert list(metadata["ownership"]["maintainers"]) == ["@xsoar-content"]

    # enabled
    assert data["enabled"] is True

    # triggering — per Batch 4 (Part A.4.4) + Salesforce §4.6 reference:
    # both ``xsoar-integration-id`` and ``xsoar-pack-id`` labels are
    # emitted. With no pack_id passed, xsoar-pack-id falls back to the
    # integration id (matching the Salesforce reference's behavior).
    triggering = data["triggering"]
    assert triggering["type"] == "PUB_SUB"
    assert triggering["labels"]["xsoar-integration-id"] == "Salesforce"
    assert triggering["labels"]["xsoar-pack-id"] == "Salesforce"
    assert "xsoar-content-id" not in triggering["labels"]
    assert triggering["args"] == {}

    # capabilities: empty mapped_params → no capability entries.
    assert data["capabilities"] == []

    # test_connection — per Batch 4 (Part A.4.2) + guide §3.8 + §4.6
    # Salesforce reference: every XSOAR handler routes verification
    # through the platform's standard service endpoint.
    tc = data["test_connection"]
    assert tc["type"] == "service"
    assert tc["service"] == "xsoar"
    assert tc["endpoint"] == "/settings/integration/connector/verification"
    assert "host" not in tc

    # tags list is a copy, not the same object
    data["metadata"]["tags"].append("mutated")
    assert pack_tags == ["forensics", "endpoint"]


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
# write_serializer_yaml
# ---------------------------------------------------------------------------
def test_write_serializer_yaml_creates_placeholder_file(tmp_path: Path) -> None:
    serializer_yaml_path = tmp_path / "serializer.yaml"
    write_serializer_yaml(serializer_yaml_path)

    assert serializer_yaml_path.is_file()
    assert serializer_yaml_path.read_text() == "# TODO: serializer config\n"
    # Sanity-check the constant matches the on-disk content.
    assert serializer_yaml_path.read_text() == SERIALIZER_PLACEHOLDER


def test_write_serializer_yaml_creates_parent_directories(tmp_path: Path) -> None:
    serializer_yaml_path = (
        tmp_path / "components" / "handlers" / "xsoar_test" / "serializer.yaml"
    )
    assert not serializer_yaml_path.parent.exists()

    write_serializer_yaml(serializer_yaml_path)

    assert serializer_yaml_path.is_file()
    assert serializer_yaml_path.parent.is_dir()


def test_write_serializer_yaml_raises_if_exists(tmp_path: Path) -> None:
    serializer_yaml_path = tmp_path / "serializer.yaml"
    original_content = "# CUSTOM SERIALIZER CONFIG — DO NOT OVERWRITE\n"
    serializer_yaml_path.write_text(original_content)

    with pytest.raises(FileExistsError):
        write_serializer_yaml(serializer_yaml_path)

    # Original content must be untouched.
    assert serializer_yaml_path.read_text() == original_content


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

    # Per-handler general_config always registers 2 serializer entries
    # (integrationLogLevel + defaultIgnore), so serializer.yaml is
    # always created even with empty mapped_params.
    serializer_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-salesforce"
        / "serializer.yaml"
    )
    assert serializer_yaml_path.is_file()
    serializer_data = _read_serializer_dict(
        connector_dir / "components" / "handlers" / "xsoar-salesforce"
    )
    mappings = serializer_data.get("field_mappings", [])
    mapping_ids = {m["id"] for m in mappings}
    assert "xsoar-salesforce_integrationLogLevel" in mapping_ids
    assert "xsoar-salesforce_defaultIgnore" in mapping_ids


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

    # Per-handler general_config always registers serializer entries.
    handler_dir = (
        connector_dir / "components" / "handlers" / "xsoar-my-integration"
    )
    handler_yaml_path = handler_dir / "handler.yaml"
    serializer_yaml_path = handler_dir / "serializer.yaml"
    assert handler_yaml_path.is_file()
    assert serializer_yaml_path.is_file()
    serializer_data = _read_serializer_dict(handler_dir)
    mappings = serializer_data.get("field_mappings", [])
    mapping_ids = {m["id"] for m in mappings}
    assert "xsoar-my-integration_integrationLogLevel" in mapping_ids
    assert "xsoar-my-integration_defaultIgnore" in mapping_ids


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
    # Called without handler_id -> no sub_capabilities; parents now carry
    # description + config.required_license (review point 7). fetch-issues
    # is license-restricted -> agentix/xsiam; TI&E is unrestricted -> [].
    assert data["capabilities"] == [
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS["fetch-issues"],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": ["agentix", "xsiam"]},
        },
        {
            "id": "threat-intelligence-and-enrichment",
            "title": "Threat Intelligence and Enrichment",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[
                "threat-intelligence-and-enrichment"
            ],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": []},
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

    log = _per_handler_log_level_field("xsoar-test")
    assert log["id"] == "xsoar-test_integrationLogLevel"
    assert log["title"] == "Integration Log Level"
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
    # integrationLogLevel + defaultIgnore are always first (platform-mandated).
    # instance_name and integrationLogLevel from user params are skipped.
    # Only "url" from user params should appear.
    assert "xsoar-test_integrationLogLevel" in field_ids
    assert "xsoar-test_defaultIgnore" in field_ids
    assert "url" in field_ids  # user param that didn't collide
    # No duplicate instance_name or integrationLogLevel from user params.
    assert field_ids.count("xsoar-test_integrationLogLevel") == 1
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


# ---------------------------------------------------------------------------
# build_handler_yaml — capabilities population
# ---------------------------------------------------------------------------
def test_build_handler_yaml_capabilities_with_empty_auth_methods() -> None:
    """Per guide §3.4: handler capability ids must use canonical names —
    ``Automation`` → ``automation-and-remediation`` (not bare
    ``automation``)."""
    integration_yml = {
        "commonfields": {"id": "Salesforce"},
        "display": "Salesforce",
    }
    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Issues": ["fetch_limit"],
        "Automation": ["timeout"],
    }
    data = build_handler_yaml(
        integration_yml, "Salesforce", [], mapped_params, {}
    )
    # Per Batch 4 (Part A.4.3 + handler.schema oneOf): with empty
    # ``auth_methods``, capabilities use the anonymous shape (auth='none'
    # + capability-level workloads), NOT empty auth_options (which fails
    # the schema's minItems: 1 on auth_options).
    # ``fetch-issues`` carries a capability-scoped reset action;
    # ``automation-and-remediation`` is action-free (no ``actions`` key).
    # Capabilities are always sub-capabilities — handler references the
    # ``xsoar-salesforce-<cap_slug>`` sub-cap ids.
    assert data["capabilities"] == [
        {
            "id": "xsoar-salesforce-fetch-issues",
            "auth": "none",
            "workloads": ["xsoar-pod"],
            "actions": [
                {
                    "type": "reset_incidents_last_run",
                    "display": "Reset Incidents Last Run",
                    "description": CAPABILITY_ACTIONS["fetch-issues"]["description"],
                }
            ],
        },
        {
            "id": "xsoar-salesforce-automation-and-remediation",
            "auth": "none",
            "workloads": ["xsoar-pod"],
        },
    ]


# ---------------------------------------------------------------------------
# build_handler_yaml — capability-scoped actions[]
# ---------------------------------------------------------------------------
_INTEGRATION_YML_FOR_ACTIONS = {
    "commonfields": {"id": "Salesforce"},
    "display": "Salesforce",
}


def _expected_action(canonical_cap_id: str) -> list[dict]:
    """The expected ``actions`` list a handler capability of this family emits.

    Mirrors :data:`CAPABILITY_ACTIONS` so handler-output assertions stay in
    sync with the generator without re-hardcoding the strings.
    """
    return [dict(CAPABILITY_ACTIONS[canonical_cap_id])]


@pytest.mark.parametrize(
    ("bucket_key", "expected_cap_id", "expected_type", "expected_display"),
    [
        (
            "Fetch Assets and Vulnerabilities",
            "fetch-assets-and-vulnerabilities",
            "reset_assets_last_run",
            "Reset Assets Last Run",
        ),
        (
            "Fetch Issues",
            "fetch-issues",
            "reset_incidents_last_run",
            "Reset Incidents Last Run",
        ),
        (
            "Threat Intelligence & Enrichment",
            "threat-intelligence-and-enrichment",
            "reset_feed_last_run",
            "Reset Feed Last Run",
        ),
        (
            "Log Collection",
            "log-collection",
            "reset_events_last_run",
            "Reset Events Last Run",
        ),
    ],
)
def test_build_handler_yaml_emits_capability_action(
    bucket_key: str,
    expected_cap_id: str,
    expected_type: str,
    expected_display: str,
) -> None:
    """Each of the four deterministic capability families emits its single
    reset action with type + display + description."""
    mapped_params = {
        "general_configurations": ["url"],
        bucket_key: ["some_param"],
    }
    data = build_handler_yaml(
        _INTEGRATION_YML_FOR_ACTIONS, "Salesforce", [], mapped_params, {}
    )
    (cap_entry,) = data["capabilities"]
    # Capabilities are always sub-capabilities — the handler references the
    # sub-cap id ``xsoar-salesforce-<cap_slug>``.
    assert cap_entry["id"] == f"xsoar-salesforce-{expected_cap_id}"
    assert cap_entry["actions"] == [
        {
            "type": expected_type,
            "display": expected_display,
            "description": CAPABILITY_ACTIONS[expected_cap_id]["description"],
        }
    ]


@pytest.mark.parametrize(
    "bucket_key", ["Automation", "Fetch Secrets"]
)
def test_build_handler_yaml_omits_actions_for_action_free_families(
    bucket_key: str,
) -> None:
    """Capability families without a defined reset action must NOT carry an
    ``actions`` key — output stays byte-identical to the pre-actions shape."""
    mapped_params = {
        "general_configurations": ["url"],
        bucket_key: ["some_param"],
    }
    data = build_handler_yaml(
        _INTEGRATION_YML_FOR_ACTIONS, "Salesforce", [], mapped_params, {}
    )
    (cap_entry,) = data["capabilities"]
    assert "actions" not in cap_entry


def test_build_handler_yaml_action_coexists_with_auth_options() -> None:
    """In the authenticated shape, the action sits alongside auth_options."""
    auth_methods = {"auth_types": [{"name": "oauth2.client.credentials.identity"}]}
    mapped_params = {
        "general_configurations": ["url"],
        "Log Collection": ["events_limit"],
    }
    data = build_handler_yaml(
        _INTEGRATION_YML_FOR_ACTIONS,
        "Salesforce",
        [],
        mapped_params,
        auth_methods,
    )
    (cap_entry,) = data["capabilities"]
    assert cap_entry["id"] == "xsoar-salesforce-log-collection"
    assert "auth_options" in cap_entry
    assert cap_entry["actions"][0]["type"] == "reset_events_last_run"


def test_build_handler_yaml_action_resolves_through_sub_cap_override() -> None:
    """On the append path, the handler cap id is a sub-cap id
    (``<handler>-<cap_slug>``) via cap_name_to_handler_cap_id, but the action
    still resolves from the family bucket key."""
    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Assets and Vulnerabilities": ["assets_limit"],
    }
    override = {
        "Fetch Assets and Vulnerabilities": (
            "xsoar-salesforce-fetch-assets-and-vulnerabilities"
        )
    }
    data = build_handler_yaml(
        _INTEGRATION_YML_FOR_ACTIONS,
        "Salesforce",
        [],
        mapped_params,
        {},
        cap_name_to_handler_cap_id=override,
    )
    (cap_entry,) = data["capabilities"]
    assert cap_entry["id"] == (
        "xsoar-salesforce-fetch-assets-and-vulnerabilities"
    )
    assert cap_entry["actions"][0]["type"] == "reset_assets_last_run"


def test_actions_for_capability_returns_fresh_copies() -> None:
    """The helper must return fresh dicts so callers can't mutate the shared
    CAPABILITY_ACTIONS registry."""
    first = _actions_for_capability("Fetch Issues")
    first[0]["display"] = "MUTATED"
    second = _actions_for_capability("Fetch Issues")
    assert second[0]["display"] == "Reset Incidents Last Run"


def test_actions_for_capability_empty_for_action_free_family() -> None:
    assert _actions_for_capability("Automation") == []
    assert _actions_for_capability("Fetch Secrets") == []


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — capabilities.yaml
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_capabilities_yaml_with_schema_directive(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    mapped_params = {
        "general_configurations": ["url", "verify_ssl"],
        "Fetch Issues": ["fetch_limit"],
        "Automation": ["timeout"],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params=mapped_params,
        auth_methods={},
    )

    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    assert capabilities_yaml_path.is_file()

    with open(capabilities_yaml_path) as fh:
        first_line = fh.readline()
    assert first_line == CAPABILITIES_SCHEMA_DIRECTIVE

    with open(capabilities_yaml_path) as fh:
        data = yaml.safe_load(fh)

    assert data["metadata"]["title"] == "Capabilities"
    # Only instance_name in capabilities.yaml general_configurations.
    # integrationLogLevel + user params → configurations.yaml.
    fields = data["general_configurations"]["configurations"][0]["fields"]
    assert [f["id"] for f in fields] == ["instance_name"]
    # Per Batch 2 (A.2.3 + A.2.5 + A.2.6): canonical capability ids with
    # required schema fields (title/default_enabled/required).
    # Capabilities are always modelled as parent + one sub-capability. The
    # lone sub-capability is keyed by the handler's sub-cap id.
    assert data["capabilities"] == [
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS["fetch-issues"],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": ["agentix", "xsiam"]},
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-salesforce-fetch-issues", "Fetch Issues", required=True
                )
            ],
        },
        {
            "id": "automation-and-remediation",
            "title": "Automation and Remediation",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[
                "automation-and-remediation"
            ],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": []},
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-salesforce-automation-and-remediation",
                    "Automation",
                    required=True,
                )
            ],
        },
    ]


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — configurations.yaml
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_generates_configurations_yaml_without_schema_directive(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Issues": ["fetch_limit", "first_fetch"],
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params=mapped_params,
        auth_methods={},
    )

    configurations_yaml_path = connector_dir / "configurations.yaml"
    assert configurations_yaml_path.is_file()

    with open(configurations_yaml_path) as fh:
        first_line = fh.readline()
    # No schema directive — first line should NOT be the capabilities directive
    assert not first_line.startswith("# yaml-language-server")

    with open(configurations_yaml_path) as fh:
        data = yaml.safe_load(fh)

    assert data["metadata"] == {
        "title": "Configuration",
        "description": "Adjust and refine your configuration",
    }
    # Per-capability entries now carry view_group.
    cfg_entries = data["configurations"]
    assert len(cfg_entries) == 1
    # Per-capability config entries are keyed by the sub-cap id.
    assert cfg_entries[0]["id"] == "xsoar-salesforce-fetch-issues"
    assert cfg_entries[0]["view_group"] == "xsoar-salesforce"
    assert cfg_entries[0]["configurations"] == [
        {"fields": [{"id": "fetch_limit"}, {"id": "first_fetch"}]}
    ]


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — handler.yaml capabilities populated
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_handler_capabilities_populated(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Issues": ["fetch_limit"],
        "Automation": ["timeout"],
    }
    auth_methods = {
        "auth_types": [
            {"name": "oauth2"},
            {"name": "api_key"},
        ]
    }

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params=mapped_params,
        auth_methods=auth_methods,
    )

    handler_yaml_path = (
        connector_dir / "components" / "handlers" / "xsoar-salesforce" / "handler.yaml"
    )
    with open(handler_yaml_path) as fh:
        # Skip the schema directive line
        fh.readline()
        data = yaml.safe_load(fh)

    # Per Batch 4 (Part A.4.3 + AuthOption schema): each auth_option
    # entry carries its own ``workloads`` (the per-handler default
    # ``["xsoar-pod"]``). The previous design that left workloads off
    # would fail the AuthOption schema (workloads is REQUIRED).
    # Each auth_option ``id`` is the connection profile id
    # (``<profile_type>.<integration_slug>``) and carries ``view_group`` =
    # the integration tile id so handler and connection.yaml stay in lockstep.
    expected_auth_options = [
        {
            "id": "oauth2.salesforce",
            "view_group": "salesforce",
            "scopes": ["api"],
            "workloads": ["xsoar-pod"],
        },
        {
            "id": "api_key.salesforce",
            "view_group": "salesforce",
            "scopes": ["api"],
            "workloads": ["xsoar-pod"],
        },
    ]
    # Per Batch 2 (A.2.3): canonical capability ids — Automation →
    # automation-and-remediation.
    assert data["capabilities"] == [
        {
            "id": "xsoar-salesforce-fetch-issues",
            "auth_options": expected_auth_options,
            "actions": _expected_action("fetch-issues"),
        },
        {
            "id": "xsoar-salesforce-automation-and-remediation",
            "auth_options": expected_auth_options,
        },
    ]


# ---------------------------------------------------------------------------
# create_manifest_from_scratch — full pipeline with typical inputs
# ---------------------------------------------------------------------------
def test_create_manifest_from_scratch_full_pipeline_with_typical_inputs(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": ["forensics"]}
    )
    connector_dir = tmp_path / "connectors" / "salesforce"

    mapped_params = {
        "general_configurations": ["url", "verify_ssl", "proxy"],
        "Fetch Issues": ["fetch_limit"],
        "Automation": ["timeout"],
    }
    auth_methods = {"auth_types": [{"name": "oauth2"}]}

    create_manifest_from_scratch(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Salesforce"},
            "display": "Salesforce",
        },
        integration_path=integration_yml_path,
        connector_title="Salesforce",
        mapped_params=mapped_params,
        auth_methods=auth_methods,
    )

    # Verify all 6 files exist
    connector_yaml = connector_dir / "connector.yaml"
    summary_yaml = connector_dir / "summary.yaml"
    capabilities_yaml = connector_dir / "capabilities.yaml"
    configurations_yaml = connector_dir / "configurations.yaml"
    handler_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-salesforce" / "handler.yaml"
    )
    serializer_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-salesforce" / "serializer.yaml"
    )

    assert connector_yaml.is_file()
    assert summary_yaml.is_file()
    assert capabilities_yaml.is_file()
    assert configurations_yaml.is_file()
    assert handler_yaml.is_file()
    # Per Batch 7 (Part A.7.1) + guide §3.9: serializer.yaml is OPTIONAL.
    # With user params ``url``/``verify_ssl``/``proxy``/``fetch_limit``/
    # ``timeout`` all unique (no collision between general_configurations
    # and the per-capability buckets), no field_mappings entries are
    # Per-handler general_config always writes serializer entries
    # (integrationLogLevel + defaultIgnore mappings).
    assert serializer_yaml.exists()

    # Spot-check shapes
    with open(connector_yaml) as fh:
        connector_data = yaml.safe_load(fh)
    assert connector_data["id"] == "salesforce"
    assert connector_data["metadata"]["title"] == "Salesforce"

    with open(summary_yaml) as fh:
        summary_data = yaml.safe_load(fh)
    assert summary_data["metadata"]["title"] == "Summary"

    with open(capabilities_yaml) as fh:
        first_line = fh.readline()
        capabilities_data = yaml.safe_load(fh)
    assert first_line == CAPABILITIES_SCHEMA_DIRECTIVE
    # Per Batch 2 + review point 7: canonical capability ids + required
    # schema fields, now including description + config.required_license,
    # sub-cap default_enabled:false, and lone sub-cap required:true.
    # No supported_modules supplied -> fetch-issues defaults to the
    # agentix/xsiam restriction; automation-and-remediation gets [].
    assert capabilities_data["capabilities"] == [
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS["fetch-issues"],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": ["agentix", "xsiam"]},
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-salesforce-fetch-issues", "Fetch Issues", required=True
                )
            ],
        },
        {
            "id": "automation-and-remediation",
            "title": "Automation and Remediation",
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[
                "automation-and-remediation"
            ],
            "default_enabled": True,
            "required": False,
            "config": {"required_license": []},
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-salesforce-automation-and-remediation",
                    "Automation",
                    required=True,
                )
            ],
        },
    ]
    # Only instance_name in capabilities.yaml general_configurations.
    # integrationLogLevel + user params → configurations.yaml.
    fields = (
        capabilities_data["general_configurations"]["configurations"][0]["fields"]
    )
    assert [f["id"] for f in fields] == ["instance_name"]

    # User-mapped general_configurations params are now in
    # configurations.yaml general_configurations with view_group.
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    gc_entries = cfg_data.get("general_configurations", {}).get(
        "configurations", []
    )
    handler_gc = [e for e in gc_entries if e.get("view_group") == "xsoar-salesforce"]
    assert len(handler_gc) >= 1
    handler_field_ids = [f["id"] for f in handler_gc[0]["fields"]]
    assert "xsoar-salesforce_integrationLogLevel" in handler_field_ids
    assert "xsoar-salesforce_defaultIgnore" in handler_field_ids
    # User-mapped params (url, verify_ssl, proxy) also present.
    assert "url" in handler_field_ids or any(
        "url" in fid for fid in handler_field_ids
    )

    with open(configurations_yaml) as fh:
        configurations_data = yaml.safe_load(fh)
    assert [c["id"] for c in configurations_data["configurations"]] == [
        "xsoar-salesforce-fetch-issues",
        "xsoar-salesforce-automation-and-remediation",
    ]

    with open(handler_yaml) as fh:
        fh.readline()  # skip schema directive
        handler_data = yaml.safe_load(fh)
    # Capabilities are always sub-capabilities — handler references the
    # ``xsoar-salesforce-<cap_slug>`` sub-cap ids.
    _expected_auth_options = [
        {
            "id": "oauth2.salesforce",
            "view_group": "salesforce",
            "scopes": ["api"],
            "workloads": ["xsoar-pod"],
        }
    ]
    assert handler_data["capabilities"] == [
        {
            "id": "xsoar-salesforce-fetch-issues",
            "auth_options": _expected_auth_options,
            "actions": _expected_action("fetch-issues"),
        },
        {
            "id": "xsoar-salesforce-automation-and-remediation",
            "auth_options": _expected_auth_options,
        },
    ]

    # Per-handler general_config always writes serializer entries.
    assert serializer_yaml.exists()


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
# rename_handler_capability_id — preserves directive & other fields
# ---------------------------------------------------------------------------
def test_rename_handler_capability_id_preserves_schema_directive_and_other_fields(
    tmp_path: Path,
) -> None:
    handler_dir = tmp_path / "components" / "handlers" / "xsoar-one"
    handler_yaml_path = _write_existing_handler_yaml(
        handler_dir,
        "xsoar-one",
        [
            {"id": "fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}]},
            {"id": "automation", "auth_options": []},
        ],
    )

    rename_handler_capability_id(handler_yaml_path, "fetch-issues", "xsoar-one-fetch-issues")

    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
        data = yaml.safe_load(fh)
    assert first_line == HANDLER_SCHEMA_DIRECTIVE
    assert data["id"] == "xsoar-one"
    assert data["capabilities"] == [
        {
            "id": "xsoar-one-fetch-issues",
            "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}],
        },
        {"id": "automation", "auth_options": []},
    ]


# ---------------------------------------------------------------------------
# Case 3 — new capability
# ---------------------------------------------------------------------------
def test_append_handler_with_new_capability_adds_to_all_files(
    tmp_path: Path,
) -> None:
    """Pre-existing connector has cap A; new handler brings cap B (Case 3).

    Updated for Batch 2: pre-existing fixture uses the canonical
    ``automation-and-remediation`` capability id (the form real connectors
    have on disk once generated by the post-Batch-2 generator).
    """
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    # Pre-existing handler holds canonical "automation-and-remediation".
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-existing",
        "xsoar-existing",
        [{"id": "automation-and-remediation", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "automation-and-remediation",
                "title": "Automation and Remediation",
                "default_enabled": True,
                "required": False,
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "automation-and-remediation",
                "configurations": [{"fields": [{"id": "old_param"}]}],
            }
        ],
    )

    # New handler brings cap "Fetch Issues" (not seen before).
    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "My Integration"},
            "display": "My Integration",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_param"]},
        auth_methods={"auth_types": [{"name": "oauth2"}]},
    )

    # capabilities.yaml — the pre-existing (flat) automation cap is untouched;
    # the brand-new Fetch Issues cap (Case 3) is added as parent + one
    # sub-capability (capabilities are ALWAYS modelled as sub-capabilities).
    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()  # skip directive
        cap_data = yaml.safe_load(fh)
    assert cap_data["capabilities"] == [
        {
            "id": "automation-and-remediation",
            "title": "Automation and Remediation",
            "default_enabled": True,
            "required": False,
        },
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "default_enabled": True,
            "required": False,
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-my-integration-fetch-issues", "Fetch Issues"
                )
            ],
        },
    ]

    # configurations.yaml — the new entry is keyed by the sub-cap id.
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    assert [c["id"] for c in cfg_data["configurations"]] == [
        "automation-and-remediation",
        "xsoar-my-integration-fetch-issues",
    ]

    # New handler's cap entry id is the sub-cap id (Case 3).
    new_handler_yaml = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-my-integration"
        / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    assert new_handler_data["capabilities"] == [
        {
            "id": "xsoar-my-integration-fetch-issues",
            "auth_options": [
                {
                    "id": "oauth2.my_integration",
                    "view_group": "my-integration",
                    "scopes": ["api"],
                    "workloads": ["xsoar-pod"],
                }
            ],
            "actions": _expected_action("fetch-issues"),
        },
    ]


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
def test_append_handler_to_capability_already_split_adds_subcap_only(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    # Pre-existing: 2 handlers each holding a sub-cap of "fetch-issues".
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-one",
        "xsoar-one",
        [{"id": "xsoar-one-fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-two",
        "xsoar-two",
        [{"id": "xsoar-two-fetch-issues", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "sub_capabilities": [
                    {"id": "xsoar-one-fetch-issues"},
                    {"id": "xsoar-two-fetch-issues"},
                ],
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "xsoar-one-fetch-issues",
                "configurations": [{"fields": [{"id": "p1"}]}],
            },
            {
                "id": "xsoar-two-fetch-issues",
                "configurations": [{"fields": [{"id": "p2"}]}],
            },
        ],
    )

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

    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()
        cap_data = yaml.safe_load(fh)
    parent = cap_data["capabilities"][0]
    assert parent["id"] == "fetch-issues"
    # The two pre-existing sub-caps are untouched (bare-id, as written by the
    # fixture); the newly-appended sub-cap is a schema-complete entry.
    assert parent["sub_capabilities"] == [
        {"id": "xsoar-one-fetch-issues"},
        {"id": "xsoar-two-fetch-issues"},
        build_sub_capability_entry(
            "xsoar-my-integration-fetch-issues", "Fetch Issues"
        ),
    ]

    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    assert [c["id"] for c in cfg_data["configurations"]] == [
        "xsoar-one-fetch-issues",
        "xsoar-two-fetch-issues",
        "xsoar-my-integration-fetch-issues",
    ]
    new_entry = cfg_data["configurations"][-1]
    assert new_entry["configurations"] == [{"fields": [{"id": "new_p"}]}]

    # New handler's cap id is the sub-cap id.
    new_handler_yaml = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar-my-integration"
        / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    # Per Batch 4 (Part A.4.3): empty auth_methods → anonymous shape.
    assert new_handler_data["capabilities"] == [
        {
            "id": "xsoar-my-integration-fetch-issues",
            "auth": "none",
            "workloads": ["xsoar-pod"],
            "actions": _expected_action("fetch-issues"),
        },
    ]


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
        [{"id": "xsoar-one-fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}]}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "sub_capabilities": [{"id": "xsoar-one-fetch-issues"}],
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "xsoar-one-fetch-issues",
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


def test_append_handler_case2_promotes_existing_flat_capability(
    tmp_path: Path,
) -> None:
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = _setup_case2_connector(tmp_path, integration_yml_path)

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Jira"},
            "display": "Jira",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={"Fetch Issues": ["new_param1", "new_param2"]},
        auth_methods={"auth_types": [{"name": "api_key"}]},
    )

    # capabilities.yaml — parent now has both sub-caps.
    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()
        cap_data = yaml.safe_load(fh)
    # Both sub-caps (the promoted existing one + the new one) are
    # schema-complete entries.
    assert cap_data["capabilities"] == [
        {
            "id": "fetch-issues",
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-existing-fetch-issues", "Fetch Issues"
                ),
                build_sub_capability_entry(
                    "xsoar-jira-fetch-issues", "Fetch Issues"
                ),
            ],
        }
    ]

    # configurations.yaml — parent's flat entry gone, two sub-cap entries.
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    cfg_ids = [c["id"] for c in cfg_data["configurations"]]
    assert "fetch-issues" not in cfg_ids
    assert cfg_ids == ["xsoar-existing-fetch-issues", "xsoar-jira-fetch-issues"]
    existing_cfg = cfg_data["configurations"][0]
    assert existing_cfg["configurations"] == [
        {"fields": [{"id": "old_param1"}, {"id": "old_param2"}]}
    ]
    new_cfg = cfg_data["configurations"][1]
    assert new_cfg["configurations"] == [
        {"fields": [{"id": "new_param1"}, {"id": "new_param2"}]}
    ]

    # Existing handler.yaml — cap id renamed.
    existing_handler_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-existing" / "handler.yaml"
    )
    with open(existing_handler_yaml) as fh:
        fh.readline()
        existing_handler_data = yaml.safe_load(fh)
    assert existing_handler_data["capabilities"] == [
        {
            "id": "xsoar-existing-fetch-issues",
            "auth_options": [{"id": "oauth2", "scopes": ["api"], "workloads": ["xsoar-pod"]}],
        }
    ]

    # New handler.yaml — cap id is the new sub-cap id.
    new_handler_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-jira" / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    # New handler.yaml is built via build_handler_yaml, so its sub-cap entry
    # carries the family's reset action. The existing handler (renamed in
    # place via rename_handler_capability_id) does NOT gain actions.
    assert new_handler_data["capabilities"] == [
        {
            "id": "xsoar-jira-fetch-issues",
            "auth_options": [
                {
                    "id": "api_key.jira",
                    "view_group": "jira",
                    "scopes": ["api"],
                    "workloads": ["xsoar-pod"],
                }
            ],
            "actions": _expected_action("fetch-issues"),
        }
    ]


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
            "xsoar-existing-fetch-issues", "Fetch Issues"
        ),
        build_sub_capability_entry("xsoar-jira-fetch-issues", "Fetch Issues"),
    ]

    # automation handlers' files are byte-identical.
    assert auto1_yaml.read_bytes() == auto1_bytes_pre
    assert auto2_yaml.read_bytes() == auto2_bytes_pre


# ---------------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------------
def test_append_handler_with_mix_of_3_cases(tmp_path: Path) -> None:
    """Single new handler brings 3 caps, each landing in a different case.

    Updated for Batch 2 (Part A.2.3): ``Automation`` bucket → canonical
    ``automation-and-remediation`` id. The existing connector's capability
    setup uses the canonical id so the append flow finds and extends it.
    """
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])

    # Case 2 source: flat "fetch-issues" referenced by xsoar-flat.
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-flat",
        "xsoar-flat",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    # Case 1 source: split "automation-and-remediation" referenced by xsoar-split.
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar-split",
        "xsoar-split",
        [{"id": "xsoar-split-automation-and-remediation", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {"id": "fetch-issues"},
            {
                "id": "automation-and-remediation",
                "sub_capabilities": [
                    {"id": "xsoar-split-automation-and-remediation"}
                ],
            },
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "configurations": [{"fields": [{"id": "old_fi"}]}],
            },
            {
                "id": "xsoar-split-automation-and-remediation",
                "configurations": [{"fields": [{"id": "old_a"}]}],
            },
        ],
    )

    add_handler_to_existing_connector(
        connector_dir=connector_dir,
        integration_yml={
            "commonfields": {"id": "Jira"},
            "display": "Jira",
        },
        integration_path=integration_yml_path,
        connector_title="My Connector",
        mapped_params={
            "Fetch Issues": ["new_fi"],         # Case 2 (promotion)
            "Automation": ["new_a"],            # Case 1 (sub-caps already there)
            "Log Collection": ["new_lc"],       # Case 3 (brand new)
        },
        auth_methods={},
    )

    # capabilities.yaml
    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()
        cap_data = yaml.safe_load(fh)
    by_id = {c["id"]: c for c in cap_data["capabilities"]}
    # Case 2 (promotion): existing flat cap promoted → both sub-caps are
    # schema-complete entries.
    assert by_id["fetch-issues"]["sub_capabilities"] == [
        build_sub_capability_entry("xsoar-flat-fetch-issues", "Fetch Issues"),
        build_sub_capability_entry("xsoar-jira-fetch-issues", "Fetch Issues"),
    ]
    # Case 1 (already split): existing bare-id sub-cap untouched; new one is a
    # schema-complete entry.
    assert by_id["automation-and-remediation"]["sub_capabilities"] == [
        {"id": "xsoar-split-automation-and-remediation"},
        build_sub_capability_entry(
            "xsoar-jira-automation-and-remediation", "Automation"
        ),
    ]
    # Case 3: brand-new capability — now emitted as parent + one sub-capability
    # (capabilities are ALWAYS modelled as sub-capabilities).
    assert by_id["log-collection"]["id"] == "log-collection"
    assert by_id["log-collection"]["title"] == "Log Collection"
    assert by_id["log-collection"]["default_enabled"] is True
    assert by_id["log-collection"]["required"] is False
    assert by_id["log-collection"]["sub_capabilities"] == [
        build_sub_capability_entry(
            "xsoar-jira-log-collection", "Log Collection"
        )
    ]

    # configurations.yaml
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    cfg_ids = [c["id"] for c in cfg_data["configurations"]]
    assert "fetch-issues" not in cfg_ids  # parent dropped after promotion
    assert "xsoar-flat-fetch-issues" in cfg_ids
    assert "xsoar-jira-fetch-issues" in cfg_ids
    assert "xsoar-split-automation-and-remediation" in cfg_ids
    assert "xsoar-jira-automation-and-remediation" in cfg_ids
    # Case 3 config entry is keyed by the sub-cap id.
    assert "log-collection" not in cfg_ids
    assert "xsoar-jira-log-collection" in cfg_ids

    # Existing flat handler renamed.
    flat_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-flat" / "handler.yaml"
    )
    with open(flat_yaml) as fh:
        fh.readline()
        flat_data = yaml.safe_load(fh)
    assert flat_data["capabilities"] == [
        {"id": "xsoar-flat-fetch-issues", "auth_options": []}
    ]

    # New handler uses sub-cap ids for cases 1+2, bare slug for case 3.
    new_yaml = (
        connector_dir / "components" / "handlers" / "xsoar-jira" / "handler.yaml"
    )
    with open(new_yaml) as fh:
        fh.readline()
        new_data = yaml.safe_load(fh)
    new_ids = [c["id"] for c in new_data["capabilities"]]
    # Capabilities are always sub-capabilities — all three (including the
    # brand-new Case 3 log-collection) use the sub-cap id.
    assert new_ids == [
        "xsoar-jira-fetch-issues",
        "xsoar-jira-automation-and-remediation",
        "xsoar-jira-log-collection",
    ]


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


def test_append_capability_to_files_returns_correct_handler_cap_id_case3(
    tmp_path: Path,
) -> None:
    """Direct unit-test of append_capability_to_files for Case 3."""
    cap_data: dict = {"capabilities": []}
    cfg_data: dict = {"configurations": []}
    result = append_capability_to_files(
        cap_name="Fetch Issues",
        cap_params=["p"],
        new_handler_id="xsoar-new",
        capabilities_data=cap_data,
        configurations_data=cfg_data,
        connector_dir=tmp_path,
    )
    # Case 3 now returns the sub-cap id (capabilities are ALWAYS modelled as
    # sub-capabilities).
    assert result == "xsoar-new-fetch-issues"
    # Case 3 creates the parent capability with a single schema-complete
    # sub-capability.
    assert cap_data["capabilities"] == [
        {
            "id": "fetch-issues",
            "title": "Fetch Issues",
            "default_enabled": True,
            "required": False,
            "sub_capabilities": [
                build_sub_capability_entry(
                    "xsoar-new-fetch-issues", "Fetch Issues"
                )
            ],
        }
    ]
    # Config entry is keyed by the sub-cap id.
    assert cfg_data["configurations"] == [
        {
            "id": "xsoar-new-fetch-issues",
            "configurations": [{"fields": [{"id": "p"}]}],
        }
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
    # Per-handler general_config always writes serializer entries.
    assert serializer_yaml_path.exists()


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


def test_emit_field_for_param_type_17_feed_expiration_policy_hardcoded_values():
    """Per Batch 3 (Part A.11.2) + guide Appendix A: type 17 ('Feed
    Expiration Policy') maps to ``select`` with hardcoded values, NOT
    sourced from the integration yml's ``options:`` list."""
    yml = {
        "type": 17,
        "name": "feedExpirationPolicy",
        "display": "Expiration Method",
        # yml.options would be ignored even if present — hardcoded
        # values from the spec take precedence.
        "options": ["these", "are", "ignored"],
    }
    field = emit_field_for_param("feedExpirationPolicy", {"feedExpirationPolicy": yml})[0]
    assert field["field_type"] == "select"
    keys = [v["key"] for v in field["options"]["values"]]
    # Guide Appendix A type 17 hardcoded labels.
    assert keys == [
        "Indicator Type",
        "Time Interval",
        "Never Expire",
        "When removed from the feed",
    ]


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
    field group with exactly 2 fields: integrationLogLevel (select)
    and defaultIgnore (checkbox). Both field ids are prefixed with
    the handler id for global uniqueness."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    result = build_per_handler_general_config("xsoar-salesforce", handler_dir)

    assert result["view_group"] == "xsoar-salesforce"
    fields = result["fields"]
    assert len(fields) == 2

    log_level = fields[0]
    assert log_level["id"] == "xsoar-salesforce_integrationLogLevel"
    assert log_level["title"] == "Integration Log Level"
    assert log_level["field_type"] == "select"
    assert log_level["metadata"]["xsoar"]["config_type"] == "backend"
    values = log_level["options"]["values"]
    assert [v["key"] for v in values] == ["Off", "Debug", "Verbose"]
    assert log_level["options"]["default_value"] == "Off"

    default_ignore = fields[1]
    assert default_ignore["id"] == "xsoar-salesforce_defaultIgnore"
    assert default_ignore["title"] == "Do not use in CLI by default"
    assert default_ignore["field_type"] == "checkbox"
    assert default_ignore["metadata"]["xsoar"]["config_type"] == "backend"
    assert default_ignore["options"]["default_value"] is False


def test_build_per_handler_general_config_registers_serializer_entries(
    tmp_path: Path,
):
    """build_per_handler_general_config writes 2 serializer field_mappings
    entries bridging the prefixed ids back to the canonical param names."""
    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    build_per_handler_general_config("xsoar-myint", handler_dir)

    serializer_data = _read_serializer_dict(handler_dir)
    mappings = serializer_data.get("field_mappings", [])
    assert len(mappings) == 2
    mapping_by_id = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_by_id["xsoar-myint_integrationLogLevel"] == "integrationLogLevel"
    assert mapping_by_id["xsoar-myint_defaultIgnore"] == "defaultIgnore"


def test_from_scratch_emits_per_handler_general_config_in_configurations_yaml(
    tmp_path: Path,
):
    """End-to-end: create_manifest_from_scratch emits the per-handler
    general_configurations field group + view_groups registry entry
    in configurations.yaml."""
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
    assert "xsoar-myint" in vg_ids

    # general_configurations has a view_group-pinned field group.
    gc_entries = cfg.get("general_configurations", {}).get("configurations", [])
    handler_gc = [e for e in gc_entries if e.get("view_group") == "xsoar-myint"]
    assert len(handler_gc) == 1
    field_ids = [f["id"] for f in handler_gc[0]["fields"]]
    assert "xsoar-myint_integrationLogLevel" in field_ids
    assert "xsoar-myint_defaultIgnore" in field_ids


def test_add_secret_capability_top_level_uses_plain_field_id():
    """
    Given: A mapped_params dict that DOES NOT have a Fetch Secrets bucket
           (or has one with no params). add_secret_capability is called
           with is_sub_capability=False and capability_id='fetch-secrets'.
    When:  add_secret_capability runs.
    Then:  The returned template carries field_id='isFetchCredentials'
           (the plain XSOAR yml name, unrenamed), default_value=True
           (hidden toggles default to True per user decision),
           hidden in both modifier blocks, required=False.
    """
    mapped: dict[str, list[str]] = {
        "general_configurations": [],
        "Automation": ["some_param"],
    }

    template = add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
    )

    assert template["capability_id"] == "fetch-secrets"
    assert len(template["fields"]) == 1
    field = template["fields"][0]
    assert field["id"] == "isFetchCredentials"
    assert field["title"] == "Fetch credentials"
    assert field["field_type"] == "toggle"
    assert field["options"]["default_value"] is True
    assert field["options"]["create_modifiers"] == {
        "required": False,
        "hidden": True,
    }
    assert field["options"]["edit_modifiers"] == {
        "required": False,
        "hidden": True,
    }


def test_add_secret_capability_sub_capability_renames_field_id():
    """
    Given: add_secret_capability is called with is_sub_capability=True
           and a sub-cap id 'fetch-secrets-xsoar-mygraphmail'.
    When:  Inspecting the returned template.
    Then:  field.id is renamed to
           '<capability_id>_isFetchCredentials' so it cannot collide with
           the root fetch-secrets cap's toggle if both exist on the same
           connector.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_secret_capability(
        capability_id="fetch-secrets-xsoar-mygraphmail",
        is_sub_capability=True,
        mapped_params=mapped,
    )

    assert template["capability_id"] == "fetch-secrets-xsoar-mygraphmail"
    assert (
        template["fields"][0]["id"]
        == "fetch-secrets-xsoar-mygraphmail_isFetchCredentials"
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


def test_add_secret_capability_sub_cap_path_writes_serializer_bridge(tmp_path: Path):
    """
    Given: A sub-capability call with handler_dir set so the serializer
           rename bridge fires.
    When:  add_secret_capability runs.
    Then:  serializer.yaml at handler_dir contains a field_mappings entry
           bridging '<sub_cap_id>_isFetchCredentials' (renamed connector
           field id) back to 'isFetchCredentials' (original yml name).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_secret_capability(
        capability_id="fetch-secrets-xsoar-mygraphmail",
        is_sub_capability=True,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    serializer = _read_serializer_dict(tmp_path)
    assert serializer["field_mappings"] == [
        {
            "id": "fetch-secrets-xsoar-mygraphmail_isFetchCredentials",
            "field_name": "isFetchCredentials",
        }
    ]


def test_add_secret_capability_top_level_does_NOT_write_serializer(tmp_path: Path):
    """
    Given: A top-level call (is_sub_capability=False) — even with
           handler_dir supplied, the rename bridge should NOT fire
           because the field id matches the original yml name 1:1 so
           there's nothing to bridge.
    When:  add_secret_capability runs.
    Then:  No serializer.yaml is created at handler_dir.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    assert not (tmp_path / "serializer.yaml").exists()


def test_add_secret_capability_uses_yml_display_for_title_when_present():
    """
    Given: yml_params_by_name has an entry for 'isFetchCredentials' with
           display='Enable credentials sync'.
    When:  add_secret_capability runs.
    Then:  The returned field uses the YAML's display as the title,
           NOT the fallback constant 'Fetch credentials'.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchCredentials": {
            "name": "isFetchCredentials",
            "display": "Enable credentials sync",
            "type": 8,
        }
    }

    template = add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    assert template["fields"][0]["title"] == "Enable credentials sync"


def test_add_secret_capability_falls_back_to_constant_when_display_is_empty():
    """
    Given: yml_params_by_name has an entry for 'isFetchCredentials' but
           with display='' (empty / whitespace-only).
    When:  add_secret_capability runs.
    Then:  The fallback constant 'Fetch credentials' is used. Empty
           display strings don't accidentally produce an empty title.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    yml_lookup = {
        "isFetchCredentials": {
            "name": "isFetchCredentials",
            "display": "   ",  # whitespace-only
            "type": 8,
        }
    }

    template = add_secret_capability(
        capability_id="fetch-secrets",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    assert template["fields"][0]["title"] == "Fetch credentials"


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


def test_log_collection_scenario_A_not_long_running_synthetic_isFetchEvents():
    """
    Given: add_log_collection_capability called with
           is_long_running_capability=False, is_sub_capability=False,
           NO yml param for isFetchEvents.
    When:  Inspecting the returned isFetchEvents field.
    Then:  Synthetic shape — toggle, default False, hidden in both
           modifier blocks, required False, title fallback 'Fetch events'.
           Plain id 'isFetchEvents' (no rename in top-level case).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" in fields_by_id
    ifc = fields_by_id["isFetchEvents"]
    assert ifc["field_type"] == "toggle"
    assert ifc["title"] == "Fetch events"
    assert ifc["options"]["default_value"] is True
    assert ifc["options"]["create_modifiers"] == {"required": False, "hidden": True}
    assert ifc["options"]["edit_modifiers"] == {"required": False, "hidden": True}


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


def test_log_collection_scenario_B_long_running_with_yml_uses_yml_values():
    """
    Given: is_long_running_capability=True AND the yml carries BOTH
           isFetchEvents (defaultvalue 'true') and eventFetchInterval
           (defaultvalue '5', explicit hidden=True).
    When:  add_log_collection_capability runs.
    Then:  Both fields are emitted with values derived from the yml —
           isFetchEvents default_value is True (coerced), and
           eventFetchInterval is a duration field with default
           {minutes: 5} (5-minute count converted) AND hidden=True in
           both modifier blocks (yml override honored).
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
            "hidden": True,
        },
    }

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert fields_by_id["isFetchEvents"]["options"]["default_value"] is True
    assert fields_by_id["eventFetchInterval"]["field_type"] == "duration"
    assert fields_by_id["eventFetchInterval"]["options"]["default_value"] == {
        "minutes": 5
    }
    assert (
        fields_by_id["eventFetchInterval"]["options"]["create_modifiers"]["hidden"]
        is True
    )
    assert (
        fields_by_id["eventFetchInterval"]["options"]["edit_modifiers"]["hidden"]
        is True
    )


def test_log_collection_scenario_C_long_running_no_yml_falls_back_to_synthetic():
    """
    Given: is_long_running_capability=True AND neither isFetchEvents nor
           eventFetchInterval is in the yml (E4 — long-running cap with
           no related yml params).
    When:  add_log_collection_capability runs.
    Then:  Both fields are STILL emitted, using the synthetic shapes:
           isFetchEvents = hidden toggle default False;
           eventFetchInterval = visible numeric input default '1'.
           Same shape as scenario A — only the trigger suppression
           below distinguishes B/C from A.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=True,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchEvents" in fields_by_id
    assert "eventFetchInterval" in fields_by_id
    ifc = fields_by_id["isFetchEvents"]
    assert ifc["options"]["default_value"] is True
    assert ifc["options"]["create_modifiers"]["hidden"] is True
    efi = fields_by_id["eventFetchInterval"]
    assert efi["field_type"] == "duration"
    assert efi["options"]["default_value"] == {"minutes": 1}
    assert efi["options"]["create_modifiers"]["hidden"] is False


def test_log_collection_sub_capability_renames_both_field_ids():
    """
    Given: is_sub_capability=True with a sub-cap id
           'log-collection-xsoar-myhandler'.
    When:  add_log_collection_capability runs.
    Then:  Both field ids are renamed to
           '<capability_id>_<original_name>' so they cannot collide
           with the root log-collection cap's toggles if both exist on
           the same connector.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_log_collection_capability(
        capability_id="log-collection-xsoar-myhandler",
        is_sub_capability=True,
        is_long_running_capability=False,
        mapped_params=mapped,
    )

    field_ids = {f["id"] for f in template["fields"]}
    assert "log-collection-xsoar-myhandler_isFetchEvents" in field_ids
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


def test_log_collection_sub_cap_path_writes_serializer_bridges_for_both(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied. is_long_running=False
           so both fields are renamed (sub-cap rule applies to both
           regardless of scenario A/B/C).
    When:  add_log_collection_capability runs.
    Then:  serializer.yaml at handler_dir contains TWO field_mappings
           entries bridging '<sub_cap_id>_isFetchEvents' →
           'isFetchEvents' AND '<sub_cap_id>_eventFetchInterval' →
           'eventFetchInterval'.
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
    field_mappings = serializer["field_mappings"]
    by_id = {fm["id"]: fm for fm in field_mappings}
    assert (
        by_id["log-collection-xsoar-myhandler_isFetchEvents"]["field_name"]
        == "isFetchEvents"
    )
    assert (
        by_id["log-collection-xsoar-myhandler_eventFetchInterval"]["field_name"]
        == "eventFetchInterval"
    )


def test_log_collection_top_level_does_NOT_write_serializer_bridge(tmp_path: Path):
    """
    Given: top-level call (is_sub_capability=False) even with
           handler_dir supplied. Field ids match the original yml names
           1:1 — nothing to bridge.
    When:  add_log_collection_capability runs.
    Then:  No serializer.yaml is created at handler_dir.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_log_collection_capability(
        capability_id="log-collection",
        is_sub_capability=False,
        is_long_running_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    assert not (tmp_path / "serializer.yaml").exists()


def test_log_collection_uses_yml_display_for_title_when_present():
    """
    Given: yml_params_by_name carries isFetchEvents with display='Enable
           event ingestion' and eventFetchInterval with display='Polling
           interval (minutes)'.
    When:  add_log_collection_capability runs (scenario A — synthetic
           shapes, but title resolution still uses yml.display).
    Then:  Both emitted fields use the vendor-supplied display strings
           as their titles, overriding the fallback constants.
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
    assert fields_by_id["isFetchEvents"]["title"] == "Enable event ingestion"
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


def test_assets_isFetchAssets_is_always_synthetic_hidden_toggle_no_yml():
    """
    Given: add_assets_capability called with NO yml param for
           isFetchAssets.
    When:  Inspecting the returned isFetchAssets field.
    Then:  Synthetic shape — toggle, default False, hidden in both
           modifier blocks, required False, title fallback 'Fetch
           assets and vulnerabilities'. Plain id 'isFetchAssets'
           (no rename in top-level case).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    template = add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    assert "isFetchAssets" in fields_by_id
    ifa = fields_by_id["isFetchAssets"]
    assert ifa["field_type"] == "toggle"
    assert ifa["title"] == "Fetch assets and vulnerabilities"
    assert ifa["options"]["default_value"] is True
    assert ifa["options"]["create_modifiers"] == {"required": False, "hidden": True}
    assert ifa["options"]["edit_modifiers"] == {"required": False, "hidden": True}


def test_assets_isFetchAssets_is_always_synthetic_even_when_yml_carries_it():
    """
    Given: The yml CARRIES isFetchAssets (with defaultvalue: 'true',
           hidden: false in the yml).
    When:  add_assets_capability runs.
    Then:  isFetchAssets is STILL emitted as the synthetic hidden
           toggle (default False, hidden True) — the yml's
           defaultvalue and hidden are IGNORED for isFetchAssets per
           the spec ("default False and hidden True"). Only the title
           is allowed to come from yml.display.
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
    )

    fields_by_id = {f["id"]: f for f in template["fields"]}
    ifa = fields_by_id["isFetchAssets"]
    # Synthetic shape preserved despite yml override attempts.
    assert ifa["options"]["default_value"] is True
    assert ifa["options"]["create_modifiers"]["hidden"] is True
    assert ifa["options"]["edit_modifiers"]["hidden"] is True


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


def test_assets_sub_capability_renames_both_field_ids():
    """
    Given: is_sub_capability=True with a sub-cap id
           'fetch-assets-and-vulnerabilities-xsoar-myhandler'.
    When:  add_assets_capability runs.
    Then:  Both field ids are renamed to
           '<capability_id>_<original_name>' so they cannot collide
           with the root fetch-assets cap's fields if both exist on
           the same connector.
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
        in field_ids
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


def test_assets_sub_cap_path_writes_serializer_bridges_for_both(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied.
    When:  add_assets_capability runs.
    Then:  serializer.yaml at handler_dir contains TWO field_mappings
           entries bridging '<sub_cap_id>_isFetchAssets' →
           'isFetchAssets' AND '<sub_cap_id>_assetsFetchInterval' →
           'assetsFetchInterval'.
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
        by_id["fetch-assets-and-vulnerabilities-xsoar-myhandler_isFetchAssets"][
            "field_name"
        ]
        == "isFetchAssets"
    )
    assert (
        by_id["fetch-assets-and-vulnerabilities-xsoar-myhandler_assetsFetchInterval"][
            "field_name"
        ]
        == "assetsFetchInterval"
    )


def test_assets_top_level_does_NOT_write_serializer_bridge(tmp_path: Path):
    """
    Given: top-level call (is_sub_capability=False) even with
           handler_dir supplied. Field ids match the original yml
           names 1:1 — nothing to bridge.
    When:  add_assets_capability runs.
    Then:  No serializer.yaml is created at handler_dir.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}

    add_assets_capability(
        capability_id="fetch-assets-and-vulnerabilities",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )

    assert not (tmp_path / "serializer.yaml").exists()


def test_assets_uses_yml_display_for_titles_when_present():
    """
    Given: yml_params_by_name carries isFetchAssets with display
           'Enable asset ingestion' and assetsFetchInterval with
           display 'Asset polling interval'.
    When:  add_assets_capability runs.
    Then:  Both emitted fields use the vendor-supplied display
           strings as their titles, overriding the fallback constants.
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
    assert fields_by_id["isFetchAssets"]["title"] == "Enable asset ingestion"
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


def test_add_indicators_capability_top_level_emits_7_fields_with_defaults():
    """
    Given: add_indicators_capability called with is_sub_capability=False,
           no yml params (pure synthetic fallback path).
    When:  add_indicators_capability runs.
    Then:  7 fields are emitted with the correct ids, types, and defaults.
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
    )
    assert template["capability_id"] == "threat-intelligence-and-enrichment"
    fields = template["fields"]
    assert len(fields) == 7

    by_id = {f["id"]: f for f in fields}

    # 1. feed — checkbox, default true, hidden
    feed = by_id["feed"]
    assert feed["field_type"] == "checkbox"
    assert feed["options"]["default_value"] is True
    assert feed["options"]["create_modifiers"]["hidden"] is True
    assert feed["options"]["edit_modifiers"]["hidden"] is True

    # 2. feedFetchInterval — duration, fallback 240 min = 4h
    ffi = by_id["feedFetchInterval"]
    assert ffi["field_type"] == "duration"
    assert ffi["options"]["default_value"] == {"hours": 4}
    assert ffi["options"]["units"] == DURATION_UNITS

    # 3. feedReliability — select, required, default Undetermined
    fr = by_id["feedReliability"]
    assert fr["field_type"] == "select"
    assert fr["options"]["default_value"] == FEED_RELIABILITY_DEFAULT
    assert fr["options"]["create_modifiers"]["required"] is True
    assert fr["options"]["description"] == FEED_RELIABILITY_ADDITIONAL_INFO
    assert len(fr["options"]["values"]) == 6

    # 4. feedExpirationPolicy — select, type 17 values
    fep = by_id["feedExpirationPolicy"]
    assert fep["field_type"] == "select"
    assert fep["options"]["default_value"] == FEED_EXPIRATION_POLICY_DEFAULT
    assert fep["options"]["values"] == FEED_EXPIRATION_POLICY_VALUES

    # 5. feedExpirationInterval — numeric input, hidden, no title
    fei = by_id["feedExpirationInterval"]
    assert fei["field_type"] == "input"
    assert fei["options"]["is_number_input"] is True
    assert fei["options"]["default_value"] == FEED_EXPIRATION_INTERVAL_DEFAULT
    assert fei["options"]["create_modifiers"]["hidden"] is True
    assert fei["options"]["edit_modifiers"]["hidden"] is True
    assert "title" not in fei

    # 6. feedReputation — select, type 18 values
    frep = by_id["feedReputation"]
    assert frep["field_type"] == "select"
    assert frep["options"]["default_value"] == FEED_REPUTATION_DEFAULT
    assert frep["options"]["values"] == INDICATOR_REPUTATION_VALUES
    assert frep["options"]["description"] == FEED_REPUTATION_ADDITIONAL_INFO

    # 7. feedBypassExclusionList — checkbox
    fbe = by_id["feedBypassExclusionList"]
    assert fbe["field_type"] == "checkbox"
    assert fbe["options"]["description"] == FEED_BYPASS_EXCLUSION_ADDITIONAL_INFO


def test_add_indicators_capability_feed_always_true_hidden_ignores_yml():
    """
    Given: yml carries a 'feed' param with hidden=False and defaultvalue='false'.
    When:  add_indicators_capability runs.
    Then:  The feed field is STILL emitted as hidden=True, default=True
           (hardcoded synthetic — yml values are ignored).
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
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    feed = {f["id"]: f for f in template["fields"]}["feed"]
    assert feed["options"]["default_value"] is True
    assert feed["options"]["create_modifiers"]["hidden"] is True
    # Title should use yml display when available.
    assert feed["title"] == "Custom Feed Label"


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
    Then:  All 7 field ids are renamed to f"{capability_id}_{original}".
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "threat-intelligence-and-enrichment-xsoar-myfeed"
    template = add_indicators_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        mapped_params=mapped,
    )
    field_ids = [f["id"] for f in template["fields"]]
    assert f"{cap_id}_feed" in field_ids
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
    Then:  serializer.yaml at handler_dir contains 7 field_mappings entries
           bridging the renamed ids back to the original param names.
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
    assert len(mappings) == 7
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_dict[f"{cap_id}_feed"] == "feed"
    assert mapping_dict[f"{cap_id}_feedFetchInterval"] == "feedFetchInterval"
    assert mapping_dict[f"{cap_id}_feedReliability"] == "feedReliability"
    assert mapping_dict[f"{cap_id}_feedExpirationPolicy"] == "feedExpirationPolicy"
    assert mapping_dict[f"{cap_id}_feedExpirationInterval"] == "feedExpirationInterval"
    assert mapping_dict[f"{cap_id}_feedReputation"] == "feedReputation"
    assert mapping_dict[f"{cap_id}_feedBypassExclusionList"] == "feedBypassExclusionList"


def test_add_indicators_capability_top_level_does_NOT_write_serializer(tmp_path: Path):
    """
    Given: top-level path (is_sub_capability=False) with handler_dir.
    When:  add_indicators_capability runs.
    Then:  No serializer.yaml is created (field names are 1:1).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        handler_dir=tmp_path,
    )
    assert not (tmp_path / "serializer.yaml").exists()


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


def test_add_indicators_capability_feedexpirationinterval_yml_driven():
    """
    Given: yml carries feedExpirationInterval with defaultvalue='1440'.
    When:  add_indicators_capability runs.
    Then:  The field uses the yml default, is still hidden, and has no title.
    """
    yml_lookup = {
        "feedExpirationInterval": {
            "name": "feedExpirationInterval",
            "type": 1,
            "defaultvalue": "1440",
        },
    }
    mapped: dict[str, list[str]] = {"general_configurations": []}
    template = add_indicators_capability(
        capability_id="threat-intelligence-and-enrichment",
        is_sub_capability=False,
        mapped_params=mapped,
        yml_params_by_name=yml_lookup,
    )
    fei = {f["id"]: f for f in template["fields"]}["feedExpirationInterval"]
    assert fei["options"]["default_value"] == "1440"
    assert fei["options"]["create_modifiers"]["hidden"] is True
    assert "title" not in fei


def test_add_indicators_capability_uses_yml_display_for_titles():
    """
    Given: yml carries display strings for feed params.
    When:  add_indicators_capability runs.
    Then:  The emitted fields use the vendor-supplied display strings.
    """
    yml_lookup = {
        "feed": {"name": "feed", "type": 8, "display": "Enable Feed"},
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
    assert by_id["feed"]["title"] == "Enable Feed"
    assert by_id["feedReputation"]["title"] == "Custom Reputation"
    assert by_id["feedBypassExclusionList"]["title"] == "Skip Exclusions"


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
# Fetch Issues capability builder: add_fetch_issues_capability
# ============================================================


def _make_integration_yml(
    integration_id: str = "TestIntegration",
    display: str = "Test Integration",
    default_mapper_in: str = "",
    default_classifier: str = "",
    is_long_running: bool = False,
    configuration: list | None = None,
) -> dict:
    """Helper to build a minimal integration yml dict for fetch-issues tests."""
    yml: dict = {
        "commonfields": {"id": integration_id},
        "display": display,
        "script": {},
    }
    if is_long_running:
        yml["script"]["longRunning"] = True
    if default_mapper_in:
        yml["defaultmapperin"] = default_mapper_in
    if default_classifier:
        yml["defaultclassifier"] = default_classifier
    if configuration is not None:
        yml["configuration"] = configuration
    return yml


def test_add_fetch_issues_capability_top_level_emits_5_fields_standard():
    """
    Given: add_fetch_issues_capability called with is_long_running=False,
           no yml params (pure synthetic fallback path).
    When:  add_fetch_issues_capability runs.
    Then:  5 fields are emitted (no longRunning field).
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
    assert template["capability_id"] == "fetch-issues"
    fields = template["fields"]
    assert len(fields) == 5

    by_id = {f["id"]: f for f in fields}

    # 1. isFetch — checkbox, default true, hidden
    isfetch = by_id["isFetch"]
    assert isfetch["field_type"] == "checkbox"
    assert isfetch["options"]["default_value"] is True
    assert isfetch["options"]["create_modifiers"]["hidden"] is True

    # 2. incidentType — dynamic select
    inctype = by_id["incidentType"]
    assert inctype["field_type"] == "select"
    assert inctype["metadata"]["dynamic_values"]["provider"] == "xsoar"
    assert inctype["metadata"]["dynamic_values"]["params"]["dynamicField"] == "incident-type"
    assert inctype["metadata"]["dynamic_values"]["params"]["integrationID"] == "TestIntegration"
    assert "default_value" not in inctype["options"]  # no default when yml has none

    # 3. incidentFetchInterval — duration, fallback 1 min
    incfi = by_id["incidentFetchInterval"]
    assert incfi["field_type"] == "duration"
    assert incfi["options"]["default_value"] == {"minutes": 1}
    assert incfi["options"]["units"] == DURATION_UNITS

    # 4. mapper_incoming — dynamic select
    mapper = by_id["mapper_incoming"]
    assert mapper["field_type"] == "select"
    assert mapper["metadata"]["dynamic_values"]["params"]["dynamicField"] == "mapper-incoming"

    # 5. classifier — dynamic select
    classifier = by_id["classifier"]
    assert classifier["field_type"] == "select"
    assert classifier["metadata"]["dynamic_values"]["params"]["dynamicField"] == "classifier"

    # No triggers for fetch-issues
    assert template["triggers"] == []


def test_add_fetch_issues_capability_long_running_emits_6_fields():
    """
    Given: add_fetch_issues_capability called with is_long_running=True.
    When:  add_fetch_issues_capability runs.
    Then:  6 fields are emitted (includes longRunning hidden checkbox).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml(is_long_running=True)
    template = add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
    )
    fields = template["fields"]
    assert len(fields) == 6

    by_id = {f["id"]: f for f in fields}
    lr = by_id["longRunning"]
    assert lr["field_type"] == "checkbox"
    assert lr["options"]["default_value"] is True
    assert lr["options"]["create_modifiers"]["hidden"] is True


def test_add_fetch_issues_capability_isfetch_always_true_hidden():
    """
    Given: yml carries an isFetch param with hidden=False and defaultvalue='false'.
    When:  add_fetch_issues_capability runs.
    Then:  The isFetch field is STILL emitted as hidden=True, default=True
           (hardcoded synthetic — yml values are ignored).
    """
    yml_lookup = {
        "isFetch": {
            "name": "isFetch",
            "type": 8,
            "display": "Custom Fetch Label",
            "defaultvalue": "false",
            "hidden": False,
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
    isfetch = {f["id"]: f for f in template["fields"]}["isFetch"]
    assert isfetch["options"]["default_value"] is True
    assert isfetch["options"]["create_modifiers"]["hidden"] is True
    # Title should use yml display when available.
    assert isfetch["title"] == "Custom Fetch Label"


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
    Given: mapped_params has longRunning in a bucket.
    When:  add_fetch_issues_capability runs with is_long_running=True.
    Then:  longRunning is also stripped.
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
    mapper = {f["id"]: f for f in template["fields"]}["mapper_incoming"]
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
    classifier = {f["id"]: f for f in template["fields"]}["classifier"]
    assert classifier["options"]["default_value"] == "QRadar"


def test_add_fetch_issues_capability_no_mapper_classifier_defaults():
    """
    Given: integration yml has NO defaultmapperin or defaultclassifier.
    When:  add_fetch_issues_capability runs.
    Then:  mapper_incoming and classifier fields have no default_value.
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
    assert "default_value" not in by_id["mapper_incoming"]["options"]
    assert "default_value" not in by_id["classifier"]["options"]


def test_add_fetch_issues_capability_incidenttype_default_from_yml():
    """
    Given: yml carries incidentType param with defaultvalue='Phishing'.
    When:  add_fetch_issues_capability runs.
    Then:  The incidentType field has default_value='Phishing'.
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
    inctype = {f["id"]: f for f in template["fields"]}["incidentType"]
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
    incfi = {f["id"]: f for f in template["fields"]}["incidentFetchInterval"]
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
    )
    field_ids = [f["id"] for f in template["fields"]]
    assert f"{cap_id}_isFetch" in field_ids
    assert f"{cap_id}_incidentType" in field_ids
    assert f"{cap_id}_incidentFetchInterval" in field_ids
    assert f"{cap_id}_mapper_incoming" in field_ids
    assert f"{cap_id}_classifier" in field_ids


def test_add_fetch_issues_capability_sub_cap_writes_serializer_bridges(tmp_path: Path):
    """
    Given: sub-cap path AND handler_dir supplied.
    When:  add_fetch_issues_capability runs.
    Then:  serializer.yaml at handler_dir contains field_mappings entries.
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
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    assert serializer_path.exists()
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])  # skip directive
    mappings = data["field_mappings"]
    assert len(mappings) == 5  # 5 fields renamed
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_dict[f"{cap_id}_isFetch"] == "isFetch"
    assert mapping_dict[f"{cap_id}_incidentType"] == "incidentType"
    assert mapping_dict[f"{cap_id}_incidentFetchInterval"] == "incidentFetchInterval"
    assert mapping_dict[f"{cap_id}_mapper_incoming"] == "mapper_incoming"
    assert mapping_dict[f"{cap_id}_classifier"] == "classifier"


def test_add_fetch_issues_capability_long_running_sub_cap_writes_6_bridges(tmp_path: Path):
    """
    Given: sub-cap path with is_long_running=True.
    When:  add_fetch_issues_capability runs.
    Then:  serializer.yaml has 6 field_mappings entries (includes longRunning).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    cap_id = "fetch-issues-xsoar-myhandler"
    integration_yml = _make_integration_yml(is_long_running=True)
    add_fetch_issues_capability(
        capability_id=cap_id,
        is_sub_capability=True,
        is_long_running=True,
        mapped_params=mapped,
        integration_yml=integration_yml,
        handler_dir=tmp_path,
    )
    serializer_path = tmp_path / "serializer.yaml"
    with open(serializer_path) as fh:
        content = fh.read()
    data = yaml.safe_load(content.split("\n", 1)[1])
    mappings = data["field_mappings"]
    assert len(mappings) == 6
    mapping_dict = {m["id"]: m["field_name"] for m in mappings}
    assert mapping_dict[f"{cap_id}_longRunning"] == "longRunning"


def test_add_fetch_issues_capability_top_level_does_NOT_write_serializer(tmp_path: Path):
    """
    Given: top-level path (is_sub_capability=False) with handler_dir.
    When:  add_fetch_issues_capability runs.
    Then:  No serializer.yaml is created (field names are 1:1).
    """
    mapped: dict[str, list[str]] = {"general_configurations": []}
    integration_yml = _make_integration_yml()
    add_fetch_issues_capability(
        capability_id="fetch-issues",
        is_sub_capability=False,
        is_long_running=False,
        mapped_params=mapped,
        integration_yml=integration_yml,
        handler_dir=tmp_path,
    )
    assert not (tmp_path / "serializer.yaml").exists()


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
    )
    by_id = {f["id"]: f for f in template["fields"]}
    for field_id in ["incidentType", "mapper_incoming", "classifier"]:
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


def test_required_license_for_capability_restricts_fetch_caps() -> None:
    from manifest_generator import _required_license_for_capability

    # fetch-issues is license-restricted: intersect with {agentix, xsiam}.
    assert _required_license_for_capability(
        "fetch-issues", ["xsoar", "xsiam", "edr"]
    ) == ["xsiam"]
    # No modules declared -> default to the agentix/xsiam restriction.
    assert _required_license_for_capability("log-collection", []) == [
        "agentix",
        "xsiam",
    ]
    # Non-restricted capability passes the base list through verbatim.
    assert _required_license_for_capability(
        "automation-and-remediation", ["xsoar", "edr"]
    ) == ["xsoar", "edr"]


def test_build_connector_yaml_vendor_drives_id_title_description() -> None:
    """Review point 1: vendor + mapped_params drive id/title via the
    §3.3.1 suffix derivation, and description is templated from vendor."""
    data = build_connector_yaml(
        connector_title="Microsoft Graph",
        pack_tags=[],
        vendor="Microsoft Graph",
        mapped_params={"Fetch Issues": ["p"], "Automation": ["q"]},
        categories=["Analytics & SIEM"],
    )
    meta = data["metadata"]
    # Fetch (collection) + automation -> "automation-and-collection".
    assert data["id"] == "microsoft-graph-automation-and-collection"
    assert meta["title"] == "Microsoft Graph Automation and Collection"
    assert meta["description"] == "integration for Microsoft Graph products."
    assert meta["vendor"] == "Microsoft Graph"
    assert meta["domain"] == ""
    assert meta["categories"] == ["Analytics & SIEM"]


def test_build_connector_yaml_no_vendor_keeps_legacy_stub() -> None:
    """Backward-compat: without vendor, id/title fall back to the title
    slug and description stays empty (legacy behavior)."""
    data = build_connector_yaml("My Connector", pack_tags=[])
    assert data["id"] == "myconnector"
    assert data["metadata"]["title"] == "My Connector"
    assert data["metadata"]["description"] == ""
    assert data["metadata"]["vendor"] == ""


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
