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
    CAPABILITIES_SCHEMA_DIRECTIVE,
    HANDLER_SCHEMA_DIRECTIVE,
    SERIALIZER_PLACEHOLDER,
    add_handler_to_existing_connector,
    append_capability_to_files,
    build_capabilities_yaml,
    build_configurations_yaml,
    build_connector_yaml,
    build_handler_yaml,
    build_summary_yaml,
    bump_minor_version,
    create_manifest_from_scratch,
    deep_merge_dicts,
    derive_handler_id,
    find_existing_handler_for_capability,
    get_pack_tags,
    merge_general_configurations,
    merge_tags_case_insensitive,
    rename_handler_capability_id,
    slugify_capability_name,
    write_capabilities_yaml,
    write_handler_yaml,
    write_serializer_yaml,
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
    assert metadata["category"] == ""
    assert list(metadata["tags"]) == ["forensics"]
    assert metadata["domain"] == ""
    assert metadata["vendor"] == ""
    assert metadata["publisher"] == "Palo Alto Networks"
    assert metadata["author_image"] == "icon-gcp"
    assert metadata["ownership"]["team"] == "xsoar"
    assert list(metadata["ownership"]["maintainers"]) == ["@xsoar-content"]
    assert data["settings"]["allow_skip_verification"] is False


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
            "category": "",
            "tags": list(tags),
            "domain": "",
            "vendor": "",
            "publisher": "Palo Alto Networks",
            "author_image": "icon-gcp",
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "settings": {"allow_skip_verification": False},
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
# derive_handler_id
# ---------------------------------------------------------------------------
def test_derive_handler_id_basic() -> None:
    assert derive_handler_id("Salesforce") == "xsoar_salesforce"
    assert derive_handler_id("My Integration") == "xsoar_myintegration"
    assert derive_handler_id("CrowdStrike Falcon") == "xsoar_crowdstrikefalcon"


def test_derive_handler_id_handles_whitespace() -> None:
    assert derive_handler_id("  Salesforce  ") == "xsoar_salesforce"
    assert derive_handler_id("\tMy Integration\n") == "xsoar_myintegration"


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
    assert data["id"] == "xsoar_salesforce"

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

    # triggering
    triggering = data["triggering"]
    assert triggering["type"] == "PUB_SUB"
    assert triggering["labels"]["xsoar-content-id"] == ""
    assert triggering["args"] == {}

    # capabilities
    assert data["capabilities"] == []

    # test_connection
    tc = data["test_connection"]
    assert tc["type"] == "endpoint"
    assert tc["host"] == "xsoar-api"
    assert tc["endpoint"] == "/test/api/"

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
        connector_dir / "components" / "handlers" / "xsoar_salesforce" / "handler.yaml"
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
        connector_dir / "components" / "handlers" / "xsoar_salesforce" / "handler.yaml"
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
        / "xsoar_myintegration"
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
        / "xsoar_myintegration"
        / "handler.yaml"
    )
    handler_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    handler_yaml_path.write_text("id: xsoar_myintegration\n")

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
    assert data == {
        "metadata": {
            "title": "Summary",
            "description": "Summary for connector Salesforce",
            "link": "",
            "next_steps": "",
        },
    }
    metadata = data["metadata"]
    assert metadata["title"] == "Summary"
    assert metadata["description"] == "Summary for connector Salesforce"
    assert metadata["link"] == ""
    assert metadata["next_steps"] == ""


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

    assert data == {
        "metadata": {
            "title": "Summary",
            "description": "Summary for connector Salesforce",
            "link": "",
            "next_steps": "",
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

    serializer_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar_salesforce"
        / "serializer.yaml"
    )
    assert serializer_yaml_path.is_file()
    assert serializer_yaml_path.read_text() == "# TODO: serializer config\n"


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

    handler_dir = (
        connector_dir / "components" / "handlers" / "xsoar_myintegration"
    )
    handler_yaml_path = handler_dir / "handler.yaml"
    serializer_yaml_path = handler_dir / "serializer.yaml"
    assert handler_yaml_path.is_file()
    assert serializer_yaml_path.is_file()
    assert serializer_yaml_path.read_text() == "# TODO: serializer config\n"


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
        connector_dir / "components" / "handlers" / "xsoar_myintegration"
    )
    handler_dir.mkdir(parents=True, exist_ok=True)
    (handler_dir / "handler.yaml").write_text("id: xsoar_myintegration\n")
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
# slugify_capability_name
# ---------------------------------------------------------------------------
def test_slugify_capability_name_basic() -> None:
    """Cover all 6 standard capability names plus a custom one with '&'."""
    assert slugify_capability_name("Fetch Issues") == "fetch-issues"
    assert slugify_capability_name("Fetch Assets and Vulnerabilities") == (
        "fetch-assets-and-vulnerabilities"
    )
    assert slugify_capability_name("Automation") == "automation"
    assert slugify_capability_name("Fetch Secrets") == "fetch-secrets"
    assert slugify_capability_name("Log Collection") == "log-collection"
    assert slugify_capability_name("Threat Intelligence & Enrichment") == (
        "threat-intelligence-enrichment"
    )


def test_slugify_capability_name_collapses_multiple_dashes() -> None:
    assert slugify_capability_name("Foo  Bar  Baz") == "foo-bar-baz"


def test_slugify_capability_name_strips_leading_trailing_dashes() -> None:
    assert slugify_capability_name("-Foo-") == "foo"


# ---------------------------------------------------------------------------
# build_capabilities_yaml
# ---------------------------------------------------------------------------
def test_build_capabilities_yaml_shape() -> None:
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
    assert data["general_configurations"]["configurations"] == [
        {"fields": [{"id": "url"}, {"id": "verify_ssl"}]}
    ]
    assert data["capabilities"] == [
        {"id": "fetch-issues"},
        {"id": "threat-intelligence-enrichment"},
    ]


def test_build_capabilities_yaml_with_empty_mapped_params() -> None:
    data = build_capabilities_yaml({})
    assert data["capabilities"] == []
    assert data["general_configurations"]["configurations"] == [{"fields": []}]


# ---------------------------------------------------------------------------
# build_configurations_yaml
# ---------------------------------------------------------------------------
def test_build_configurations_yaml_shape() -> None:
    mapped_params = {
        "general_configurations": ["url"],
        "Fetch Issues": ["fetch_limit", "first_fetch"],
        "Automation": ["timeout"],
    }
    data = build_configurations_yaml(mapped_params)

    assert data["metadata"] == {
        "title": "Configuration",
        "description": "Adjust and refine your configurations",
    }
    assert data["configurations"] == [
        {
            "id": "fetch-issues",
            "configurations": [
                {"fields": [{"id": "fetch_limit"}, {"id": "first_fetch"}]}
            ],
        },
        {
            "id": "automation",
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
    assert data["capabilities"] == [
        {"id": "fetch-issues", "auth_options": []},
        {"id": "automation", "auth_options": []},
    ]


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
    assert data["general_configurations"]["configurations"] == [
        {"fields": [{"id": "url"}, {"id": "verify_ssl"}]}
    ]
    assert data["capabilities"] == [
        {"id": "fetch-issues"},
        {"id": "automation"},
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
        "description": "Adjust and refine your configurations",
    }
    assert data["configurations"] == [
        {
            "id": "fetch-issues",
            "configurations": [
                {"fields": [{"id": "fetch_limit"}, {"id": "first_fetch"}]}
            ],
        },
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
        connector_dir / "components" / "handlers" / "xsoar_salesforce" / "handler.yaml"
    )
    with open(handler_yaml_path) as fh:
        # Skip the schema directive line
        fh.readline()
        data = yaml.safe_load(fh)

    expected_auth_options = [
        {"id": "oauth2", "scopes": ["api"]},
        {"id": "api_key", "scopes": ["api"]},
    ]
    assert data["capabilities"] == [
        {"id": "fetch-issues", "auth_options": expected_auth_options},
        {"id": "automation", "auth_options": expected_auth_options},
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
        connector_dir / "components" / "handlers" / "xsoar_salesforce" / "handler.yaml"
    )
    serializer_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_salesforce" / "serializer.yaml"
    )

    assert connector_yaml.is_file()
    assert summary_yaml.is_file()
    assert capabilities_yaml.is_file()
    assert configurations_yaml.is_file()
    assert handler_yaml.is_file()
    assert serializer_yaml.is_file()

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
    assert capabilities_data["capabilities"] == [
        {"id": "fetch-issues"},
        {"id": "automation"},
    ]
    assert capabilities_data["general_configurations"]["configurations"] == [
        {
            "fields": [
                {"id": "url"},
                {"id": "verify_ssl"},
                {"id": "proxy"},
            ]
        }
    ]

    with open(configurations_yaml) as fh:
        configurations_data = yaml.safe_load(fh)
    assert [c["id"] for c in configurations_data["configurations"]] == [
        "fetch-issues",
        "automation",
    ]

    with open(handler_yaml) as fh:
        fh.readline()  # skip schema directive
        handler_data = yaml.safe_load(fh)
    assert handler_data["capabilities"] == [
        {
            "id": "fetch-issues",
            "auth_options": [{"id": "oauth2", "scopes": ["api"]}],
        },
        {
            "id": "automation",
            "auth_options": [{"id": "oauth2", "scopes": ["api"]}],
        },
    ]

    assert serializer_yaml.read_text() == SERIALIZER_PLACEHOLDER


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
            "description": "Adjust and refine your configurations",
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
        handlers_dir / "xsoar_one",
        "xsoar_one",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        handlers_dir / "xsoar_two",
        "xsoar_two",
        [{"id": "automation", "auth_options": []}],
    )

    result = find_existing_handler_for_capability(connector_dir, "fetch-issues")
    assert result == handlers_dir / "xsoar_one" / "handler.yaml"


def test_find_existing_handler_raises_on_no_match(tmp_path: Path) -> None:
    connector_dir = tmp_path / "connectors" / "myconnector"
    handlers_dir = connector_dir / "components" / "handlers"
    _write_existing_handler_yaml(
        handlers_dir / "xsoar_one",
        "xsoar_one",
        [{"id": "automation", "auth_options": []}],
    )

    with pytest.raises(RuntimeError, match="No existing handler found"):
        find_existing_handler_for_capability(connector_dir, "fetch-issues")


def test_find_existing_handler_raises_on_multiple_matches(tmp_path: Path) -> None:
    connector_dir = tmp_path / "connectors" / "myconnector"
    handlers_dir = connector_dir / "components" / "handlers"
    _write_existing_handler_yaml(
        handlers_dir / "xsoar_one",
        "xsoar_one",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        handlers_dir / "xsoar_two",
        "xsoar_two",
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
    handler_dir = tmp_path / "components" / "handlers" / "xsoar_one"
    handler_yaml_path = _write_existing_handler_yaml(
        handler_dir,
        "xsoar_one",
        [
            {"id": "fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"]}]},
            {"id": "automation", "auth_options": []},
        ],
    )

    rename_handler_capability_id(handler_yaml_path, "fetch-issues", "xsoar_one-fetch-issues")

    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
        data = yaml.safe_load(fh)
    assert first_line == HANDLER_SCHEMA_DIRECTIVE
    assert data["id"] == "xsoar_one"
    assert data["capabilities"] == [
        {
            "id": "xsoar_one-fetch-issues",
            "auth_options": [{"id": "oauth2", "scopes": ["api"]}],
        },
        {"id": "automation", "auth_options": []},
    ]


# ---------------------------------------------------------------------------
# Case 3 — new capability
# ---------------------------------------------------------------------------
def test_append_handler_with_new_capability_adds_to_all_files(
    tmp_path: Path,
) -> None:
    """Pre-existing connector has cap A; new handler brings cap B (Case 3)."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    # Pre-existing handler holds "automation".
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_existing",
        "xsoar_existing",
        [{"id": "automation", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(connector_dir, [{"id": "automation"}])
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "automation",
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

    # capabilities.yaml — both caps at top level, no sub-caps.
    with open(connector_dir / "capabilities.yaml") as fh:
        fh.readline()  # skip directive
        cap_data = yaml.safe_load(fh)
    assert cap_data["capabilities"] == [
        {"id": "automation"},
        {"id": "fetch-issues"},
    ]
    for c in cap_data["capabilities"]:
        assert "sub_capabilities" not in c

    # configurations.yaml — both top-level entries.
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    assert [c["id"] for c in cfg_data["configurations"]] == [
        "automation",
        "fetch-issues",
    ]

    # New handler's cap entry id is the bare slug (Case 3).
    new_handler_yaml = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar_myintegration"
        / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    assert new_handler_data["capabilities"] == [
        {"id": "fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"]}]},
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
        connector_dir / "components" / "handlers" / "xsoar_existing",
        "xsoar_existing",
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
        connector_dir / "components" / "handlers" / "xsoar_one",
        "xsoar_one",
        [{"id": "xsoar_one-fetch-issues", "auth_options": []}],
    )
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_two",
        "xsoar_two",
        [{"id": "xsoar_two-fetch-issues", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "sub_capabilities": [
                    {"id": "xsoar_one-fetch-issues"},
                    {"id": "xsoar_two-fetch-issues"},
                ],
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "xsoar_one-fetch-issues",
                "configurations": [{"fields": [{"id": "p1"}]}],
            },
            {
                "id": "xsoar_two-fetch-issues",
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
    assert parent["sub_capabilities"] == [
        {"id": "xsoar_one-fetch-issues"},
        {"id": "xsoar_two-fetch-issues"},
        {"id": "xsoar_myintegration-fetch-issues"},
    ]

    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    assert [c["id"] for c in cfg_data["configurations"]] == [
        "xsoar_one-fetch-issues",
        "xsoar_two-fetch-issues",
        "xsoar_myintegration-fetch-issues",
    ]
    new_entry = cfg_data["configurations"][-1]
    assert new_entry["configurations"] == [{"fields": [{"id": "new_p"}]}]

    # New handler's cap id is the sub-cap id.
    new_handler_yaml = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar_myintegration"
        / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    assert new_handler_data["capabilities"] == [
        {"id": "xsoar_myintegration-fetch-issues", "auth_options": []},
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
        connector_dir / "components" / "handlers" / "xsoar_one",
        "xsoar_one",
        [{"id": "xsoar_one-fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"]}]}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {
                "id": "fetch-issues",
                "sub_capabilities": [{"id": "xsoar_one-fetch-issues"}],
            }
        ],
    )
    _write_existing_configurations_yaml(
        connector_dir,
        [
            {
                "id": "xsoar_one-fetch-issues",
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

    - Single existing handler ``xsoar_existing`` holding flat cap ``fetch-issues``.
    - capabilities.yaml has ``fetch-issues`` (no sub-caps) + any extras.
    - configurations.yaml has ``fetch-issues`` top-level entry + any extras.
    """
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_existing",
        "xsoar_existing",
        [{"id": "fetch-issues", "auth_options": [{"id": "oauth2", "scopes": ["api"]}]}],
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
    assert cap_data["capabilities"] == [
        {
            "id": "fetch-issues",
            "sub_capabilities": [
                {"id": "xsoar_existing-fetch-issues"},
                {"id": "xsoar_jira-fetch-issues"},
            ],
        }
    ]

    # configurations.yaml — parent's flat entry gone, two sub-cap entries.
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    cfg_ids = [c["id"] for c in cfg_data["configurations"]]
    assert "fetch-issues" not in cfg_ids
    assert cfg_ids == ["xsoar_existing-fetch-issues", "xsoar_jira-fetch-issues"]
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
        connector_dir / "components" / "handlers" / "xsoar_existing" / "handler.yaml"
    )
    with open(existing_handler_yaml) as fh:
        fh.readline()
        existing_handler_data = yaml.safe_load(fh)
    assert existing_handler_data["capabilities"] == [
        {
            "id": "xsoar_existing-fetch-issues",
            "auth_options": [{"id": "oauth2", "scopes": ["api"]}],
        }
    ]

    # New handler.yaml — cap id is the new sub-cap id.
    new_handler_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_jira" / "handler.yaml"
    )
    with open(new_handler_yaml) as fh:
        fh.readline()
        new_handler_data = yaml.safe_load(fh)
    assert new_handler_data["capabilities"] == [
        {
            "id": "xsoar_jira-fetch-issues",
            "auth_options": [{"id": "api_key", "scopes": ["api"]}],
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
        connector_dir / "components" / "handlers" / "xsoar_existing" / "handler.yaml"
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
        connector_dir / "components" / "handlers" / "xsoar_existing",
        "xsoar_existing",
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
        {"id": "xsoar_existing-fetch-issues"},
        {"id": "xsoar_jira-fetch-issues"},
    ]

    # automation handlers' files are byte-identical.
    assert auto1_yaml.read_bytes() == auto1_bytes_pre
    assert auto2_yaml.read_bytes() == auto2_bytes_pre


# ---------------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------------
def test_append_handler_with_mix_of_3_cases(tmp_path: Path) -> None:
    """Single new handler brings 3 caps, each landing in a different case."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])

    # Case 2 source: flat "fetch-issues" referenced by xsoar_flat.
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_flat",
        "xsoar_flat",
        [{"id": "fetch-issues", "auth_options": []}],
    )
    # Case 1 source: split "automation" referenced by xsoar_split.
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_split",
        "xsoar_split",
        [{"id": "xsoar_split-automation", "auth_options": []}],
    )
    _write_existing_capabilities_yaml(
        connector_dir,
        [
            {"id": "fetch-issues"},
            {
                "id": "automation",
                "sub_capabilities": [{"id": "xsoar_split-automation"}],
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
                "id": "xsoar_split-automation",
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
    assert by_id["fetch-issues"]["sub_capabilities"] == [
        {"id": "xsoar_flat-fetch-issues"},
        {"id": "xsoar_jira-fetch-issues"},
    ]
    assert by_id["automation"]["sub_capabilities"] == [
        {"id": "xsoar_split-automation"},
        {"id": "xsoar_jira-automation"},
    ]
    assert by_id["log-collection"] == {"id": "log-collection"}
    assert "sub_capabilities" not in by_id["log-collection"]

    # configurations.yaml
    with open(connector_dir / "configurations.yaml") as fh:
        cfg_data = yaml.safe_load(fh)
    cfg_ids = [c["id"] for c in cfg_data["configurations"]]
    assert "fetch-issues" not in cfg_ids  # parent dropped after promotion
    assert "xsoar_flat-fetch-issues" in cfg_ids
    assert "xsoar_jira-fetch-issues" in cfg_ids
    assert "xsoar_split-automation" in cfg_ids
    assert "xsoar_jira-automation" in cfg_ids
    assert "log-collection" in cfg_ids

    # Existing flat handler renamed.
    flat_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_flat" / "handler.yaml"
    )
    with open(flat_yaml) as fh:
        fh.readline()
        flat_data = yaml.safe_load(fh)
    assert flat_data["capabilities"] == [
        {"id": "xsoar_flat-fetch-issues", "auth_options": []}
    ]

    # New handler uses sub-cap ids for cases 1+2, bare slug for case 3.
    new_yaml = (
        connector_dir / "components" / "handlers" / "xsoar_jira" / "handler.yaml"
    )
    with open(new_yaml) as fh:
        fh.readline()
        new_data = yaml.safe_load(fh)
    new_ids = [c["id"] for c in new_data["capabilities"]]
    assert new_ids == [
        "xsoar_jira-fetch-issues",
        "xsoar_jira-automation",
        "log-collection",
    ]


def test_append_handler_does_not_break_existing_summary_yaml(tmp_path: Path) -> None:
    """Regression: append path with capabilities updates still doesn't touch summary.yaml."""
    integration_yml_path = _make_pack_with_integration(
        tmp_path, "MyPack", "MyInt", {"tags": []}
    )
    connector_dir = tmp_path / "connectors" / "myconnector"
    _write_existing_connector_yaml(connector_dir, version="1.0.0", tags=[])
    _write_existing_handler_yaml(
        connector_dir / "components" / "handlers" / "xsoar_existing",
        "xsoar_existing",
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
        new_handler_id="xsoar_new",
        capabilities_data=cap_data,
        configurations_data=cfg_data,
        connector_dir=tmp_path,
    )
    assert result == "fetch-issues"
    assert cap_data["capabilities"] == [{"id": "fetch-issues"}]
    assert cfg_data["configurations"] == [
        {"id": "fetch-issues", "configurations": [{"fields": [{"id": "p"}]}]}
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
        / "xsoar_myint"
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
        / "xsoar_myint"
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


def test_serializer_and_connection_manual_fields_logged_but_not_applied(
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
            auth_methods={},
            manual_serializer_fields={"foo": "bar"},
            manual_connection_fields={"baz": "qux"},
        )

    # INFO log messages emitted
    log_messages = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "manual_serializer_fields received" in log_messages
    assert "serializer.yaml is a string stub" in log_messages
    assert "manual_connection_fields received" in log_messages
    assert "connection.yaml is not yet" in log_messages

    # serializer.yaml content is still the stub (overrides NOT applied)
    serializer_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / "xsoar_myint"
        / "serializer.yaml"
    )
    assert serializer_yaml_path.is_file()
    assert serializer_yaml_path.read_text() == SERIALIZER_PLACEHOLDER
