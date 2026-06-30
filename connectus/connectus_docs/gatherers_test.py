"""Unit tests for the stage-B gatherers.

Reuses the hermetic ``workspace`` fixture pattern from resolvers_test. Run from
the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest gatherers_test.py
"""

from __future__ import annotations

import json
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import resolvers  # noqa: E402
import gatherers  # noqa: E402
from gatherers import (  # noqa: E402
    bundle_to_dict,
    gather_connector,
    read_description_md,
    read_readme_for_gapfill,
)
from resolvers import ResolutionError  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixture: synthetic workspace with a 2-member grouped connector
# --------------------------------------------------------------------------- #
def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    content = tmp_path / "content"
    connectus = tmp_path / "unified-connectors-content"
    (content / "Packs").mkdir(parents=True)
    (connectus / "connectors").mkdir(parents=True)
    (content / "connectus").mkdir(parents=True)

    # Member A: clean description with a link + a Commands section to strip.
    a = content / "Packs" / "AlphaPack" / "Integrations" / "Alpha"
    _write(a / "Alpha.yml", "commonfields:\n  id: Alpha\nname: Alpha\nscript: {commands: []}")
    _write(
        a / "Alpha_description.md",
        """
        Alpha overview paragraph.

        Generate an API key in the [Alpha console](https://alpha.example.com).
        <~XSOAR>XSOAR-only note.</~XSOAR>
        <~XSIAM>Keep this XSIAM note.</~XSIAM>

        ## Commands
        ### alpha-do-thing
        does a thing
        """,
    )
    _write(a / "README.md", "Alpha integration readme.\n\n## Commands\n### alpha-do-thing\nx")
    _write(content / "Packs" / "AlphaPack" / "README.md", "Alpha pack readme.")
    (content / "Packs" / "AlphaPack" / "pack_metadata.json").write_text(
        json.dumps({"name": "AlphaPack"}), encoding="utf-8"
    )

    # Member B: label mismatch in the connector view_group (triggers a flag).
    b = content / "Packs" / "BetaPack" / "Integrations" / "Beta"
    _write(b / "Beta.yml", "commonfields:\n  id: Beta\nname: Beta Display\nscript: {commands: []}")
    _write(b / "Beta_description.md", "Beta connection instructions.")

    # Connector folder: view_groups declare alpha (correct) + beta (WRONG label).
    conn = connectus / "connectors" / "multi"
    _write(conn / "connector.yaml", "settings:\n  grouped: true\nmetadata:\n  description: x")
    _write(
        conn / "connection.yaml",
        """
        metadata:
          title: Connection
          description: Enter the credentials to securely authorize the connection
        view_groups:
        - id: alpha
          label: Alpha
          help_text: placeholder
        - id: beta
          label: Wrong Beta Label
          help_text: placeholder
        profiles:
        - id: plain.alpha
          type: plain
          view_group: alpha
          title: API Key
          description: Authentication profile for Alpha (passthrough).
          configurations:
          - fields:
            - id: alpha_user
              title: User
        - id: plain.beta
          type: plain
          view_group: beta
        """,
    )
    # configurations.yaml carries its OWN view_groups[] with help_text — the
    # alpha one is migration boilerplate ("Configurations settings for X.") that
    # the §9.13 audit must be able to read off the bundle.
    _write(
        conn / "configurations.yaml",
        """
        metadata:
          title: Configuration
          description: Adjust and refine your configuration
        view_groups:
        - id: alpha
          label: Alpha
          help_text: Configurations settings for Alpha.
        - id: beta
          label: Wrong Beta Label
          help_text: Set the polling interval and the maximum number of events to fetch.
        """,
    )

    csv_path = content / "connectus" / "connectus-migration-pipeline.csv"
    csv_path.write_text(
        "Integration ID,Integration File Path,Connector ID,Connector Folder Path\n"
        "Alpha,Packs/AlphaPack/Integrations/Alpha/Alpha.yml,Multi,connectors/multi\n"
        "Beta,Packs/BetaPack/Integrations/Beta/Beta.yml,Multi,connectors/multi\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(resolvers, "content_root", lambda: content)
    monkeypatch.setattr(resolvers, "connectus_repo_root", lambda: connectus)
    monkeypatch.setattr(resolvers, "connectors_root", lambda: connectus / "connectors")
    monkeypatch.setattr(resolvers, "pipeline_csv_path", lambda: csv_path)
    return tmp_path


# --------------------------------------------------------------------------- #
# Cleaning helpers
# --------------------------------------------------------------------------- #
class TestReaders:
    def test_read_description_strips_commands_and_xsoar(self, tmp_path):
        p = tmp_path / "d.md"
        p.write_text(
            "Intro.\n<~XSOAR>drop</~XSOAR>\n<~XSIAM>keep</~XSIAM>\n"
            "## Commands\n### cmd\nbody\n",
            encoding="utf-8",
        )
        out = read_description_md(p)
        assert "Intro." in out
        assert "keep" in out
        assert "drop" not in out
        assert "## Commands" not in out
        assert "cmd" not in out

    def test_read_readme_preserves_links(self, tmp_path):
        p = tmp_path / "r.md"
        p.write_text("See [docs](https://x.example.com).\n", encoding="utf-8")
        assert "[docs](https://x.example.com)" in read_readme_for_gapfill(p)


# --------------------------------------------------------------------------- #
# gather_connector
# --------------------------------------------------------------------------- #
class TestGatherConnector:
    def test_members_and_lengths(self, workspace):
        cb = gather_connector("multi")
        ids = [m.integration_id for m in cb.members]
        assert ids == ["Alpha", "Beta"]
        for m in cb.members:
            assert m.description_md_len == len(m.description_md)
            assert m.description_md_len > 0

    def test_commands_and_conditionals_stripped_in_bundle(self, workspace):
        cb = gather_connector("multi")
        alpha = next(m for m in cb.members if m.integration_id == "Alpha")
        assert "## Commands" not in alpha.description_md
        assert "alpha-do-thing" not in alpha.description_md
        assert "XSOAR-only note" not in alpha.description_md
        assert "Keep this XSIAM note." in alpha.description_md

    def test_link_preserved_in_bundle(self, workspace):
        cb = gather_connector("multi")
        alpha = next(m for m in cb.members if m.integration_id == "Alpha")
        assert "[Alpha console](https://alpha.example.com)" in alpha.description_md

    def test_gapfill_present_only_when_files_exist(self, workspace):
        cb = gather_connector("multi")
        alpha = next(m for m in cb.members if m.integration_id == "Alpha")
        beta = next(m for m in cb.members if m.integration_id == "Beta")
        # Alpha has integ + pack readme; Beta has neither.
        assert "integration_readme" in alpha.gapfill
        assert "pack_readme" in alpha.gapfill
        assert beta.gapfill == {}

    def test_gapfill_readme_is_command_stripped(self, workspace):
        cb = gather_connector("multi")
        alpha = next(m for m in cb.members if m.integration_id == "Alpha")
        assert "alpha-do-thing" not in alpha.gapfill["integration_readme"]
        assert "Alpha integration readme." in alpha.gapfill["integration_readme"]

    def test_profiles_and_config_fields_bound(self, workspace):
        cb = gather_connector("multi")
        alpha = next(m for m in cb.members if m.integration_id == "Alpha")
        assert alpha.profile_ids == ["plain.alpha"]
        assert "alpha_user" in alpha.config_field_ids

    def test_bundle_surfaces_on_disk_view_group_help_text(self, workspace):
        # The bundle must carry the on-disk configurations.yaml view_groups[]
        # (id/label/help_text) so the §9.13 audit can read the real on-disk
        # help_text. connection.yaml view_groups are already on bundle.view_groups.
        cb = gather_connector("multi")
        config_by_id = {vg.id: vg for vg in cb.config_view_groups}
        assert "alpha" in config_by_id
        assert config_by_id["alpha"].help_text == "Configurations settings for Alpha."
        assert config_by_id["alpha"].label == "Alpha"
        # connection view_groups still carried on bundle.view_groups.
        conn_by_id = {vg.id: vg for vg in cb.view_groups}
        assert conn_by_id["alpha"].help_text == "placeholder"

    def test_view_group_flag_passes_for_correct_member(self, workspace):
        cb = gather_connector("multi")
        alpha_flag = next(f for f in cb.view_group_flags if f.expected_id == "alpha")
        assert alpha_flag.id_ok is True
        assert alpha_flag.label_ok is True
        assert alpha_flag.is_flag is False

    def test_view_group_flag_raised_for_label_mismatch(self, workspace):
        cb = gather_connector("multi")
        beta_flag = next(f for f in cb.view_group_flags if f.expected_id == "beta")
        assert beta_flag.id_ok is True          # id "beta" exists
        assert beta_flag.label_ok is False      # label "Wrong Beta Label" != "Beta Display"
        assert beta_flag.is_flag is True
        assert beta_flag.expected_label == "Beta Display"

    def test_missing_description_propagates_resolution_error(self, workspace):
        (
            workspace / "content" / "Packs" / "BetaPack" / "Integrations" / "Beta"
            / "Beta_description.md"
        ).unlink()
        with pytest.raises(ResolutionError, match="PRIMARY description file missing"):
            gather_connector("multi")

    def test_bundle_to_dict_includes_profiles_per_member(self, workspace):
        cb = gather_connector("multi")
        data = bundle_to_dict(cb)
        members = {m["integration_id"]: m for m in data["members"]}

        alpha = members["Alpha"]
        # profile_ids retained unchanged.
        assert alpha["profile_ids"] == ["plain.alpha"]
        # new profiles[] array, scoped to alpha's view_group.
        assert len(alpha["profiles"]) == 1
        prof = alpha["profiles"][0]
        assert prof == {
            "id": "plain.alpha",
            "type": "plain",
            "view_group": "alpha",
            "view_group_label": "Alpha",
            "title": "API Key",
            "description": "Authentication profile for Alpha (passthrough).",
            "integration_id": "Alpha",
            "commonfields_name": "Alpha",
        }

        # Beta's profile carries None title/description (absent in connection.yaml).
        beta = members["Beta"]
        assert beta["profile_ids"] == ["plain.beta"]
        assert len(beta["profiles"]) == 1
        beta_prof = beta["profiles"][0]
        assert beta_prof["id"] == "plain.beta"
        assert beta_prof["type"] == "plain"
        assert beta_prof["view_group"] == "beta"
        assert beta_prof["view_group_label"] == "Wrong Beta Label"
        assert beta_prof["title"] is None
        assert beta_prof["description"] is None
        assert beta_prof["commonfields_name"] == "Beta Display"


# --------------------------------------------------------------------------- #
# Partial-description gap-fill (§2.1 always-check, §3.2 pre-trim)
# --------------------------------------------------------------------------- #
@pytest.fixture
def partial_workspace(tmp_path, monkeypatch):
    """A 1-member connector whose description.md is PARTIAL.

    ``Gamma_description.md`` documents the CONNECTION (an API key) but OMITS a
    crucial CONFIGURATION fact (the required ``read:events`` scope). The README
    carries that missing scope PLUS a ``## Commands`` reference that must be
    stripped before it lands in ``gapfill``. This proves the gatherer ALWAYS
    surfaces the README even when description.md exists (§2.1) and that the
    README is command-stripped first (§3.2).
    """
    content = tmp_path / "content"
    connectus = tmp_path / "unified-connectors-content"
    (content / "Packs").mkdir(parents=True)
    (connectus / "connectors").mkdir(parents=True)
    (content / "connectus").mkdir(parents=True)

    g = content / "Packs" / "GammaPack" / "Integrations" / "Gamma"
    _write(g / "Gamma.yml", "commonfields:\n  id: Gamma\nname: Gamma\nscript: {commands: []}")
    # PARTIAL primary: has connection info, MISSING the crucial config scope.
    _write(
        g / "Gamma_description.md",
        """
        Generate an API key in the [Gamma console](https://gamma.example.com).
        """,
    )
    # README carries the crucial missing scope + command noise to be stripped.
    _write(
        g / "README.md",
        """
        ## Setup
        Grant the API key the **read:events** scope before connecting.

        ## Commands
        ### gamma-fetch-events
        Fetches events. Argument: limit. Output: Gamma.Event.
        """,
    )

    conn = connectus / "connectors" / "solo"
    _write(conn / "connector.yaml", "settings:\n  grouped: true\nmetadata:\n  description: x")
    _write(
        conn / "connection.yaml",
        """
        metadata:
          title: Connection
          description: Enter the credentials to securely authorize the connection
        view_groups:
        - id: gamma
          label: Gamma
          help_text: placeholder
        profiles:
        - id: plain.gamma
          type: plain
          view_group: gamma
        """,
    )

    csv_path = content / "connectus" / "connectus-migration-pipeline.csv"
    csv_path.write_text(
        "Integration ID,Integration File Path,Connector ID,Connector Folder Path\n"
        "Gamma,Packs/GammaPack/Integrations/Gamma/Gamma.yml,Solo,connectors/solo\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(resolvers, "content_root", lambda: content)
    monkeypatch.setattr(resolvers, "connectus_repo_root", lambda: connectus)
    monkeypatch.setattr(resolvers, "connectors_root", lambda: connectus / "connectors")
    monkeypatch.setattr(resolvers, "pipeline_csv_path", lambda: csv_path)
    return tmp_path


class TestPartialDescriptionGapfill:
    def test_gapfill_surfaced_when_description_partial(self, partial_workspace):
        """The README is ALWAYS available even though description.md exists (§2.1).

        The partial primary AND the README crucial fact both surface in the
        bundle — the README is not withheld just because description.md is present.
        """
        cb = gather_connector("solo")
        gamma = next(m for m in cb.members if m.integration_id == "Gamma")

        # The PARTIAL primary is present (connection info), but does NOT carry
        # the crucial config scope.
        assert "[Gamma console](https://gamma.example.com)" in gamma.description_md
        assert "read:events" not in gamma.description_md

        # The README gap-fill IS surfaced and carries the crucial missing scope.
        assert "integration_readme" in gamma.gapfill
        assert "read:events" in gamma.gapfill["integration_readme"]

        # Same through the serialized payload the AI authoring stage reads.
        data = bundle_to_dict(cb)
        gamma_dict = next(m for m in data["members"] if m["integration_id"] == "Gamma")
        assert "read:events" not in gamma_dict["description_md"]
        assert "read:events" in gamma_dict["gapfill"]["integration_readme"]

    def test_gapfill_strips_command_noise(self, partial_workspace):
        """Command/reference noise from the README is NOT in gapfill (§3.2)."""
        cb = gather_connector("solo")
        gamma = next(m for m in cb.members if m.integration_id == "Gamma")
        readme = gamma.gapfill["integration_readme"]

        # Crucial setup text survives the pre-trim.
        assert "read:events" in readme
        # Command-section content is stripped before landing in gapfill.
        assert "## Commands" not in readme
        assert "gamma-fetch-events" not in readme
        assert "Gamma.Event" not in readme
