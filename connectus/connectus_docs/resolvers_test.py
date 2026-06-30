"""Unit tests for the stage-A resolvers (fail-loud contract).

Hermetic: builds a synthetic content + connectus tree under tmp_path and points
the resolvers at it via monkeypatched roots. Run from the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest resolvers_test.py
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import resolvers  # noqa: E402
from resolvers import (  # noqa: E402
    MemberRow,
    ResolutionError,
    resolve,
    resolve_config_params_by_view_group,
    resolve_connector,
    resolve_member_files,
    resolve_members,
    resolve_profiles,
    resolve_profiles_by_view_group,
    resolve_view_groups,
    slugify,
)


# --------------------------------------------------------------------------- #
# Fixture: a synthetic two-repo workspace
# --------------------------------------------------------------------------- #
@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Create content/ + unified-connectors-content/ with one grouped connector.

    Returns the tmp workspace root. Patches the resolver root functions so all
    path resolution targets the fixture.
    """
    content = tmp_path / "content"
    connectus = tmp_path / "unified-connectors-content"
    (content / "Packs").mkdir(parents=True)
    (connectus / "connectors").mkdir(parents=True)
    (content / "connectus").mkdir(parents=True)

    # --- member integration: Foo One (pack FooPack) ---
    integ = content / "Packs" / "FooPack" / "Integrations" / "FooOne"
    integ.mkdir(parents=True)
    (integ / "FooOne.yml").write_text(
        textwrap.dedent(
            """
            commonfields:
              id: Foo One
            name: Foo One
            configuration: []
            script: {commands: []}
            """
        ).strip(),
        encoding="utf-8",
    )
    (integ / "FooOne_description.md").write_text(
        "Generate an API key in the Foo console.", encoding="utf-8"
    )
    (integ / "README.md").write_text("Foo integration readme.", encoding="utf-8")
    pack_dir = content / "Packs" / "FooPack"
    (pack_dir / "README.md").write_text("Foo pack readme.", encoding="utf-8")
    (pack_dir / "pack_metadata.json").write_text(
        json.dumps({"name": "FooPack"}), encoding="utf-8"
    )

    # --- connector folder: foo (grouped) ---
    conn = connectus / "connectors" / "foo"
    conn.mkdir(parents=True)
    (conn / "connector.yaml").write_text(
        "settings:\n  grouped: true\nmetadata:\n  description: x\n", encoding="utf-8"
    )
    (conn / "connection.yaml").write_text(
        textwrap.dedent(
            """
            metadata:
              title: Connection
              description: Enter the credentials to securely authorize the connection
            view_groups:
            - id: foo-one
              label: Foo One
              help_text: placeholder
            profiles:
            - id: plain.foo_one
              type: plain
              view_group: foo-one
              title: API Key
              description: Authentication profile for Foo (passthrough).
              configurations:
              - fields:
                - id: credentials_username
                  title: Username
            """
        ).strip(),
        encoding="utf-8",
    )
    (conn / "configurations.yaml").write_text(
        textwrap.dedent(
            """
            metadata:
              title: Configuration
              description: Adjust and refine your configuration settings
            general_configurations:
            - view_group: foo-one
              configurations:
              - fields:
                - id: max_fetch
                  title: Max fetch
            """
        ).strip(),
        encoding="utf-8",
    )

    # --- pipeline CSV ---
    csv_path = content / "connectus" / "connectus-migration-pipeline.csv"
    csv_path.write_text(
        "Integration ID,Integration File Path,Connector ID,Connector Folder Path\n"
        "Foo One,Packs/FooPack/Integrations/FooOne/FooOne.yml,Foo,connectors/foo\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(resolvers, "content_root", lambda: content)
    monkeypatch.setattr(resolvers, "connectus_repo_root", lambda: connectus)
    monkeypatch.setattr(resolvers, "connectors_root", lambda: connectus / "connectors")
    monkeypatch.setattr(resolvers, "pipeline_csv_path", lambda: csv_path)
    return tmp_path


# --------------------------------------------------------------------------- #
# slugify
# --------------------------------------------------------------------------- #
class TestSlugify:
    def test_spaces_to_dash_lower(self):
        assert slugify("GuardiCore v2") == "guardicore-v2"

    def test_multiword(self):
        assert slugify("Akamai WAF SIEM") == "akamai-waf-siem"

    def test_collapses_runs_and_trims(self):
        assert slugify("  Foo   Bar  ") == "foo-bar"

    def test_keeps_existing_hyphens(self):
        # The migration convention preserves hyphens as separators.
        assert slugify("AWS-EKS") == "aws-eks"
        assert slugify("AWS-SNS-Listener") == "aws-sns-listener"

    def test_strips_parentheses_but_keeps_hyphens(self):
        assert (
            slugify("AWS - IAM (user lifecycle management)")
            == "aws-iam-user-lifecycle-management"
        )
        assert (
            slugify("Microsoft Management Activity API (O365 Azure Events)")
            == "microsoft-management-activity-api-o365-azure-events"
        )

    def test_collapses_mixed_space_and_hyphen_runs(self):
        assert slugify("AWS - SNS") == "aws-sns"

    def test_internal_dot_becomes_separator(self):
        # An internal dot between word chars is a SEPARATOR, matching the
        # migration (on-disk view_group ids are ``tenable-io`` / ``tenable-sc``
        # / ``appsentinels-ai``, never ``tenableio`` / ``appsentinelsai``).
        assert slugify("AppSentinels.ai") == "appsentinels-ai"
        assert slugify("Tenable.io") == "tenable-io"
        assert slugify("Tenable.sc") == "tenable-sc"
        assert slugify("abuse.ch SSL Blacklist Feed") == "abuse-ch-ssl-blacklist-feed"

    def test_internal_slash_becomes_separator(self):
        assert slugify("foo/bar") == "foo-bar"

    def test_trailing_dot_is_dropped_not_separator(self):
        # A dot NOT between word chars (trailing) is still dropped, never a
        # leading/trailing hyphen.
        assert slugify("Acme.") == "acme"


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
class TestHappyPath:
    def test_resolve_connector(self, workspace):
        paths = resolve_connector("foo")
        assert paths.is_grouped is True
        assert paths.connection_yaml is not None
        assert paths.configurations_yaml is not None

    def test_resolve_members(self, workspace):
        members = resolve_members("foo")
        assert [m.integration_id for m in members] == ["Foo One"]

    def test_resolve_view_groups(self, workspace):
        paths = resolve_connector("foo")
        vgs = resolve_view_groups(paths)
        assert [(v.id, v.label) for v in vgs] == [("foo-one", "Foo One")]

    def test_resolve_member_files_required_present(self, workspace):
        member = resolve_members("foo")[0]
        mf = resolve_member_files(member)
        assert mf.description_md.name == "FooOne_description.md"
        assert mf.integration_yml.name == "FooOne.yml"
        assert mf.expected_view_group_id == "foo-one"
        assert mf.commonfields_name == "Foo One"
        assert mf.integration_readme is not None
        assert mf.pack_readme is not None
        assert mf.pack_metadata is not None
        assert mf.warnings == []

    def test_profiles_by_view_group(self, workspace):
        paths = resolve_connector("foo")
        assert resolve_profiles_by_view_group(paths) == {"foo-one": ["plain.foo_one"]}

    def test_config_params_by_view_group(self, workspace):
        paths = resolve_connector("foo")
        result = resolve_config_params_by_view_group(paths)
        assert "foo-one" in result
        assert "credentials_username" in result["foo-one"]
        assert "max_fetch" in result["foo-one"]

    def test_aggregate_resolve(self, workspace):
        res = resolve("foo")
        assert res.paths.slug == "foo"
        assert len(res.members) == 1
        assert len(res.view_groups) == 1


# --------------------------------------------------------------------------- #
# Fail-loud contract
# --------------------------------------------------------------------------- #
class TestFailLoud:
    def test_missing_connector_folder_raises(self, workspace):
        with pytest.raises(ResolutionError, match="Connector folder not found"):
            resolve_connector("does-not-exist")

    def test_no_member_rows_raises(self, workspace):
        with pytest.raises(ResolutionError, match="No member rows found"):
            resolve_members("connector-with-no-csv-rows")

    def test_missing_integration_yml_raises(self, workspace):
        bad = MemberRow(
            integration_id="Ghost",
            integration_yml_relpath="Packs/Ghost/Integrations/Ghost/Ghost.yml",
            connector_id="Foo",
            connector_folder_relpath="connectors/foo",
            csv_row_index=99,
        )
        with pytest.raises(ResolutionError, match="Integration YML not found"):
            resolve_member_files(bad)

    def test_empty_integration_path_raises(self, workspace):
        bad = MemberRow(
            integration_id="NoPath",
            integration_yml_relpath="",
            connector_id="Foo",
            connector_folder_relpath="connectors/foo",
            csv_row_index=5,
        )
        with pytest.raises(ResolutionError, match="empty 'Integration File Path'"):
            resolve_member_files(bad)

    def test_missing_description_md_raises(self, workspace):
        # Remove the PRIMARY description file -> must raise (not swallow).
        desc = (
            workspace
            / "content" / "Packs" / "FooPack" / "Integrations" / "FooOne"
            / "FooOne_description.md"
        )
        desc.unlink()
        member = resolve_members("foo")[0]
        with pytest.raises(ResolutionError, match="PRIMARY description file missing"):
            resolve_member_files(member)

    def test_missing_gapfill_readme_is_warning_not_raise(self, workspace):
        # Removing only the gap-fill README must NOT raise; it warns.
        (
            workspace
            / "content" / "Packs" / "FooPack" / "Integrations" / "FooOne" / "README.md"
        ).unlink()
        member = resolve_members("foo")[0]
        mf = resolve_member_files(member)  # no raise
        assert mf.integration_readme is None
        assert any("integration README" in w for w in mf.warnings)

    def test_no_view_groups_raises(self, workspace):
        conn = workspace / "unified-connectors-content" / "connectors" / "foo" / "connection.yaml"
        conn.write_text("metadata:\n  title: Connection\nprofiles: []\n", encoding="utf-8")
        paths = resolve_connector("foo")
        with pytest.raises(ResolutionError, match="no\\s+view_groups"):
            resolve_view_groups(paths)

    def test_unparseable_yaml_raises(self, workspace):
        conn = workspace / "unified-connectors-content" / "connectors" / "foo" / "connection.yaml"
        conn.write_text("metadata: : : not valid yaml : :\n  - [\n", encoding="utf-8")
        paths = resolve_connector("foo")
        with pytest.raises(ResolutionError, match="Failed to parse YAML"):
            resolve_view_groups(paths)


# --------------------------------------------------------------------------- #
# resolve_profiles (§8.3a.1)
# --------------------------------------------------------------------------- #
class TestResolveProfiles:
    def test_resolve_profiles_surfaces_id_type_view_group_title_description(self, workspace):
        paths = resolve_connector("foo")
        profiles = resolve_profiles(paths)
        assert len(profiles) == 1
        p = profiles[0]
        assert p.id == "plain.foo_one"
        assert p.type == "plain"
        assert p.view_group == "foo-one"
        assert p.title == "API Key"
        assert p.description == "Authentication profile for Foo (passthrough)."

    def test_resolve_profiles_title_description_absent_is_none(self, workspace):
        conn = (
            workspace / "unified-connectors-content" / "connectors" / "foo"
            / "connection.yaml"
        )
        conn.write_text(
            textwrap.dedent(
                """
                metadata:
                  title: Connection
                view_groups:
                - id: foo-one
                  label: Foo One
                  help_text: placeholder
                profiles:
                - id: plain.foo_one
                  type: plain
                  view_group: foo-one
                """
            ).strip(),
            encoding="utf-8",
        )
        paths = resolve_connector("foo")
        p = resolve_profiles(paths)[0]
        assert p.title is None
        assert p.description is None

    def test_resolve_profiles_missing_connection_yaml_raises(self, workspace):
        conn = (
            workspace / "unified-connectors-content" / "connectors" / "foo"
            / "connection.yaml"
        )
        conn.unlink()
        paths = resolve_connector("foo")
        with pytest.raises(ResolutionError, match="connection.yaml not found"):
            resolve_profiles(paths)
