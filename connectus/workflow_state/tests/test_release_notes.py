"""Tests for the new ``Release Notes`` workflow step.

Added 2026-05-31 with the FIXES-TODO combined #4+#6+New_RN execution
plan. Covers:

* :func:`workflow_state.api.find_newest_release_notes_file` — picks the
  highest-version RN .md file in a pack's ``ReleaseNotes/`` dir.
* :func:`workflow_state.api.verify_release_notes_substring` — exact
  case-sensitive substring match for ``"Enabled support for UCP"``.
* :func:`workflow_state.api.evaluate_release_notes_for_integration` —
  the full decision tree (required/path/verified).
* :func:`workflow_state.cli.cmd_set_release_notes` — the CLI command
  rejects on `required=true, verified=false` with the expected hint.

The trigger logic (the git-diff helper) is exercised indirectly through
``evaluate_release_notes_for_integration`` — we monkeypatch the
``_release_notes_trigger_required`` helper to bypass the real git
invocation in unit tests.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from workflow_state import api as ws_api
from workflow_state import cli as ws_cli


# ---------------------------------------------------------------------------
# verify_release_notes_substring
# ---------------------------------------------------------------------------


class TestVerifyReleaseNotesSubstring:

    def test_present_anywhere_returns_true(self, tmp_path: Path) -> None:
        rn = tmp_path / "1_0_0.md"
        rn.write_text(
            "#### Integrations\n\n"
            "##### MyIntegration\n"
            "- Enabled support for UCP.\n",
            encoding="utf-8",
        )
        assert ws_api.verify_release_notes_substring(rn) is True

    def test_present_in_paragraph_returns_true(self, tmp_path: Path) -> None:
        rn = tmp_path / "1_0_0.md"
        rn.write_text(
            "Updated the integration. Enabled support for UCP credentials.\n",
            encoding="utf-8",
        )
        assert ws_api.verify_release_notes_substring(rn) is True

    def test_case_sensitive_mismatch_returns_false(self, tmp_path: Path) -> None:
        rn = tmp_path / "1_0_0.md"
        rn.write_text("enabled support for ucp\n", encoding="utf-8")
        assert ws_api.verify_release_notes_substring(rn) is False

    def test_absent_returns_false(self, tmp_path: Path) -> None:
        rn = tmp_path / "1_0_0.md"
        rn.write_text("Bug fixes and other improvements.\n", encoding="utf-8")
        assert ws_api.verify_release_notes_substring(rn) is False

    def test_missing_file_returns_false(self, tmp_path: Path) -> None:
        rn = tmp_path / "nonexistent.md"
        assert ws_api.verify_release_notes_substring(rn) is False


# ---------------------------------------------------------------------------
# find_newest_release_notes_file
# ---------------------------------------------------------------------------


class TestFindNewestReleaseNotesFile:
    """Picks the highest-version .md file from the pack's ReleaseNotes/ dir.

    Uses a synthetic Packs/<Pack>/Integrations/<Int> layout under
    tmp_path with BASE_DIR patched to point at it. The CSV is also
    patched so ``get_integration_files`` succeeds.
    """

    def _setup_pack(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create the pack layout. Returns (pack_root, integration_dir)."""
        pack = tmp_path / "Packs" / "MyPack"
        integ = pack / "Integrations" / "MyInt"
        integ.mkdir(parents=True)
        (integ / "MyInt.yml").write_text(
            "name: MyInt\ndisplay: MyInt\n"
            "configuration: []\n"
            "script:\n  type: python\n  script: ''\n  commands: []\n",
            encoding="utf-8",
        )
        (integ / "MyInt.py").write_text("def main(): pass\n", encoding="utf-8")
        return pack, integ

    def _patch_for_pack(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Patch BASE_DIR + a single-row CSV pointing at MyInt."""
        rows = [{
            "Integration ID": "MyInt",
            "Integration File Path": "Packs/MyPack/Integrations/MyInt/MyInt.yml",
            "Connector ID": "TestConnector",
            "assignee": "tester",
        }]
        monkeypatch.setattr(ws_api, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(ws_api, "load_csv", lambda: rows)

    def test_picks_highest_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pack, _ = self._setup_pack(tmp_path)
        rn_dir = pack / "ReleaseNotes"
        rn_dir.mkdir()
        (rn_dir / "1_0_0.md").write_text("old", encoding="utf-8")
        (rn_dir / "1_2_3.md").write_text("middle", encoding="utf-8")
        (rn_dir / "2_0_0.md").write_text("newest", encoding="utf-8")
        self._patch_for_pack(monkeypatch, tmp_path)
        newest = ws_api.find_newest_release_notes_file("MyInt")
        assert newest is not None
        assert newest.name == "2_0_0.md"

    def test_ignores_non_version_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pack, _ = self._setup_pack(tmp_path)
        rn_dir = pack / "ReleaseNotes"
        rn_dir.mkdir()
        (rn_dir / "1_0_0.md").write_text("valid", encoding="utf-8")
        (rn_dir / "README.md").write_text("not a version file", encoding="utf-8")
        (rn_dir / "draft.md").write_text("not a version file", encoding="utf-8")
        self._patch_for_pack(monkeypatch, tmp_path)
        newest = ws_api.find_newest_release_notes_file("MyInt")
        assert newest is not None
        assert newest.name == "1_0_0.md"

    def test_returns_none_when_no_rn_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._setup_pack(tmp_path)  # no ReleaseNotes/ dir
        self._patch_for_pack(monkeypatch, tmp_path)
        assert ws_api.find_newest_release_notes_file("MyInt") is None

    def test_returns_none_when_no_versioned_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pack, _ = self._setup_pack(tmp_path)
        rn_dir = pack / "ReleaseNotes"
        rn_dir.mkdir()
        (rn_dir / "README.md").write_text("not a version file", encoding="utf-8")
        self._patch_for_pack(monkeypatch, tmp_path)
        assert ws_api.find_newest_release_notes_file("MyInt") is None


# ---------------------------------------------------------------------------
# evaluate_release_notes_for_integration — full decision tree
# ---------------------------------------------------------------------------


class TestEvaluateReleaseNotesForIntegration:
    """The setter consumes this helper to compute the canonical cell shape."""

    def _setup_full(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Path:
        pack = tmp_path / "Packs" / "MyPack"
        integ = pack / "Integrations" / "MyInt"
        integ.mkdir(parents=True)
        (integ / "MyInt.yml").write_text(
            "name: MyInt\ndisplay: MyInt\nconfiguration: []\n"
            "script:\n  type: python\n  script: ''\n  commands: []\n",
            encoding="utf-8",
        )
        (integ / "MyInt.py").write_text("def main(): pass\n", encoding="utf-8")
        rows = [{
            "Integration ID": "MyInt",
            "Integration File Path": "Packs/MyPack/Integrations/MyInt/MyInt.yml",
            "Connector ID": "TestConnector",
            "assignee": "tester",
        }]
        monkeypatch.setattr(ws_api, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
        return pack

    def test_not_required_when_no_diff(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._setup_full(tmp_path, monkeypatch)
        monkeypatch.setattr(
            ws_api, "_release_notes_trigger_required", lambda _id: False
        )
        cell = ws_api.evaluate_release_notes_for_integration("MyInt")
        assert cell == {"required": False, "path": None, "verified": False}

    def test_required_and_verified_when_substring_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pack = self._setup_full(tmp_path, monkeypatch)
        rn_dir = pack / "ReleaseNotes"
        rn_dir.mkdir()
        (rn_dir / "1_0_0.md").write_text(
            "- Enabled support for UCP\n", encoding="utf-8"
        )
        monkeypatch.setattr(
            ws_api, "_release_notes_trigger_required", lambda _id: True
        )
        cell = ws_api.evaluate_release_notes_for_integration("MyInt")
        assert cell["required"] is True
        assert cell["verified"] is True
        assert "1_0_0.md" in (cell["path"] or "")

    def test_required_but_substring_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pack = self._setup_full(tmp_path, monkeypatch)
        rn_dir = pack / "ReleaseNotes"
        rn_dir.mkdir()
        (rn_dir / "1_0_0.md").write_text("Bug fixes.\n", encoding="utf-8")
        monkeypatch.setattr(
            ws_api, "_release_notes_trigger_required", lambda _id: True
        )
        cell = ws_api.evaluate_release_notes_for_integration("MyInt")
        assert cell["required"] is True
        assert cell["verified"] is False
        assert "1_0_0.md" in (cell["path"] or "")

    def test_required_but_no_rn_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._setup_full(tmp_path, monkeypatch)  # no ReleaseNotes/ dir
        monkeypatch.setattr(
            ws_api, "_release_notes_trigger_required", lambda _id: True
        )
        cell = ws_api.evaluate_release_notes_for_integration("MyInt")
        assert cell["required"] is True
        assert cell["path"] is None
        assert cell["verified"] is False


# ---------------------------------------------------------------------------
# cmd_set_release_notes — surface behavior
# ---------------------------------------------------------------------------


class TestCmdSetReleaseNotes:

    def test_rejects_with_hint_when_required_but_not_verified(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the helper computes required=true + verified=false, the
        CLI must exit nonzero and print the operator hint."""
        monkeypatch.setattr(
            ws_api, "evaluate_release_notes_for_integration",
            lambda _id: {
                "required": True,
                "path": "Packs/MyPack/ReleaseNotes/1_0_0.md",
                "verified": False,
            },
        )
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_release_notes(["MyInt"])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Release Notes step rejected" in out
        assert "HINT" in out
        assert "demisto-sdk update-release-notes" in out
        assert "Enabled support for UCP" in out

    def test_rejects_with_hint_when_no_rn_file(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ws_api, "evaluate_release_notes_for_integration",
            lambda _id: {
                "required": True, "path": None, "verified": False,
            },
        )
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_release_notes(["MyInt"])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Release Notes step rejected" in out
        assert "NO release-notes file was found" in out

    def test_rejects_extra_args(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """The setter is positional-only (just the integration ID).
        Reject extra JSON-payload-style usage."""
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_release_notes(["MyInt", '{"required": true}'])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "auto-computed" in out

    def test_rejects_no_args(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_release_notes([])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Usage" in out
