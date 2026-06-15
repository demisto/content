"""Tests for the YML-aware Auth Details cross-check added to ``set-auth``.

Covers :func:`workflow_state.api._credential_param_names_from_yml` and
:func:`workflow_state.api._check_other_connection_no_yml_credentials`,
which reject any ``other_connection`` entry that names a type-9
(Credentials) / type-14 (Authentication Certificate) param declared in
the integration's own YML — such a param is an auth SECRET misclassified
as connection metadata and belongs in an ``auth_types[]`` profile's
``xsoar_param_map``.

The check consults the integration's YML on disk. These tests mock
:func:`workflow_state.api.get_integration_files` and write a temp YML so
no real CSV / pack files are needed.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest import mock

import pytest

from workflow_state import api as ws_api


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yml(tmp_path: Path, configuration: list[dict]) -> Path:
    """Write a minimal integration YML with the given configuration list."""
    import yaml

    doc = {"commonfields": {"id": "Dummy"}, "configuration": configuration}
    yml = tmp_path / "Dummy.yml"
    yml.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return yml


def _patch_files_to(yml_abs: Path):
    """Patch get_integration_files + BASE_DIR so the helper resolves to
    the temp YML. The helper joins BASE_DIR + the returned relative
    'yml'; we set BASE_DIR to the temp dir and return the basename."""
    return (
        mock.patch.object(
            ws_api,
            "get_integration_files",
            return_value={"yml": yml_abs.name},
        ),
        mock.patch.object(ws_api, "BASE_DIR", str(yml_abs.parent)),
    )


# ---------------------------------------------------------------------------
# _credential_param_names_from_yml
# ---------------------------------------------------------------------------


class TestCredentialParamNamesFromYml:
    def test_collects_type9_credentials(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "server", "type": 0},
            {"name": "credentials", "type": 9},
            {"name": "insecure", "type": 8},
        ])
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert err is None
        assert names == {"credentials"}

    def test_collects_type4_encrypted(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "apikey", "type": 4},
            {"name": "url", "type": 0},
        ])
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert err is None
        assert names == {"apikey"}

    def test_collects_all_secret_types_together(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "apikey", "type": 4},
            {"name": "credentials", "type": 9},
            {"name": "cert", "type": 14},
            {"name": "url", "type": 0},
        ])
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert err is None
        assert names == {"apikey", "credentials", "cert"}

    def test_collects_type14_certificate(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "cert", "type": 14},
            {"name": "url", "type": 0},
        ])
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert err is None
        assert names == {"cert"}

    def test_no_credential_params(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "url", "type": 0},
            {"name": "insecure", "type": 8},
            {"name": "incidentType", "type": 13},
        ])
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert err is None
        assert names == set()

    def test_missing_yml_is_nonfatal(self) -> None:
        with mock.patch.object(
            ws_api, "get_integration_files",
            return_value={"error": "not found"},
        ):
            names, err = ws_api._credential_param_names_from_yml("Dummy")
        assert names == set()
        assert err is not None


# ---------------------------------------------------------------------------
# _check_other_connection_no_yml_credentials
# ---------------------------------------------------------------------------


class TestCheckOtherConnectionNoYmlCredentials:
    def _yml_with_creds(self, tmp_path: Path) -> Path:
        return _write_yml(tmp_path, [
            {"name": "server", "type": 0},
            {"name": "credentials", "type": 9},
            {"name": "insecure", "type": 8},
            {"name": "proxy", "type": 8},
        ])

    def test_bare_credential_name_in_other_connection_rejected(
        self, tmp_path: Path
    ) -> None:
        yml = self._yml_with_creds(tmp_path)
        payload = json.dumps({
            "auth_types": [],
            "other_connection": ["credentials", "server"],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors, "expected the bare 'credentials' entry to be rejected"
        assert "credentials" in errors[0]
        assert "type-9" in errors[0]

    def test_type4_encrypted_secret_in_other_connection_rejected(
        self, tmp_path: Path
    ) -> None:
        """A flat type-4 (Encrypted text) secret name is rejected just
        like a type-9/type-14 param."""
        yml = _write_yml(tmp_path, [
            {"name": "apikey", "type": 4},
            {"name": "url", "type": 0},
        ])
        payload = json.dumps({
            "auth_types": [],
            "other_connection": ["apikey", "url"],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors, "expected the type-4 'apikey' entry to be rejected"
        assert "apikey" in errors[0]
        assert "type-4" in errors[0]

    def test_type14_certificate_in_other_connection_rejected(
        self, tmp_path: Path
    ) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "cert", "type": 14},
            {"name": "url", "type": 0},
        ])
        payload = json.dumps({
            "auth_types": [],
            "other_connection": ["cert", "url"],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors
        assert "cert" in errors[0]

    def test_dotted_leaf_parent_resolves_to_credential(
        self, tmp_path: Path
    ) -> None:
        """credentials.password collapses to 'credentials' which is type-9."""
        yml = self._yml_with_creds(tmp_path)
        payload = json.dumps({
            "auth_types": [],
            "other_connection": ["credentials.password", "server"],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors
        assert "credentials.password" in errors[0]

    def test_clean_other_connection_passes(self, tmp_path: Path) -> None:
        yml = self._yml_with_creds(tmp_path)
        payload = json.dumps({
            "auth_types": [{
                "name": "credentials", "type": "Plain", "interpolated": True,
                "xsoar_param_map": {
                    "credentials.identifier": "username",
                    "credentials.password": "password",
                },
            }],
            "other_connection": ["insecure", "proxy", "server"],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors == []

    def test_missing_yml_skips_check(self) -> None:
        """When the YML can't be resolved the check is skipped (non-fatal)."""
        payload = json.dumps({
            "auth_types": [],
            "other_connection": ["credentials"],
        })
        with mock.patch.object(
            ws_api, "get_integration_files",
            return_value={"error": "not found"},
        ):
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors == []

    def test_empty_other_connection_passes(self, tmp_path: Path) -> None:
        yml = self._yml_with_creds(tmp_path)
        payload = json.dumps({"auth_types": [], "other_connection": []})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_other_connection_no_yml_credentials(
                "Dummy", payload
            )
        assert errors == []

    def test_invalid_json_skips_check(self) -> None:
        assert ws_api._check_other_connection_no_yml_credentials(
            "Dummy", "not json"
        ) == []


# ---------------------------------------------------------------------------
# _check_type9_companions_present
# ---------------------------------------------------------------------------


def _auth_json(xsoar_param_map: dict) -> str:
    """Build an auth payload with one auth_types[] entry carrying the given
    xsoar_param_map (other keys are immaterial to the companion check)."""
    return json.dumps({
        "auth_types": [{
            "name": "credentials",
            "type": "Plain",
            "interpolated": True,
            "xsoar_param_map": xsoar_param_map,
        }],
        "other_connection": [],
    })


class TestCheckType9CompanionsPresent:
    def test_pass_both_companions_present(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({
            "credentials.identifier": "username",
            "credentials.password": "password",
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_fail_missing_password(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({"credentials.identifier": "username"})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert len(errors) == 1
        assert "credentials.password" in errors[0]
        assert "credentials.identifier" not in errors[0].split("Missing:")[1]

    def test_fail_missing_identifier(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({"credentials.password": "password"})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert len(errors) == 1
        assert "credentials.identifier" in errors[0].split("Missing:")[1]
        assert "credentials.password" not in errors[0].split("Missing:")[1]

    def test_fail_missing_both(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({"unrelated.key": "x"})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert len(errors) == 1
        missing = errors[0].split("Missing:")[1]
        assert "credentials.identifier" in missing
        assert "credentials.password" in missing

    def test_pass_hiddenpassword_exemption(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "credentials", "type": 9, "hiddenpassword": True},
        ])
        payload = _auth_json({"credentials.identifier": "username"})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_pass_hiddenusername_exemption(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "credentials", "type": 9, "hiddenusername": True},
        ])
        payload = _auth_json({"credentials.password": "password"})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_skip_fully_hidden_param(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "credentials", "type": 9, "hidden": True},
        ])
        payload = _auth_json({})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_missing_yml_is_nonfatal(self) -> None:
        payload = _auth_json({})
        with mock.patch.object(
            ws_api, "get_integration_files",
            return_value={"error": "boom"},
        ):
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_type4_and_type14_are_ignored(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "apikey", "type": 4},
            {"name": "cert", "type": 14},
        ])
        payload = _auth_json({})
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert errors == []

    def test_multiple_type9_one_incomplete(self, tmp_path: Path) -> None:
        yml = _write_yml(tmp_path, [
            {"name": "creds_a", "type": 9},
            {"name": "creds_b", "type": 9},
        ])
        payload = json.dumps({
            "auth_types": [{
                "name": "p",
                "type": "Plain",
                "interpolated": True,
                "xsoar_param_map": {
                    "creds_a.identifier": "username",
                    "creds_a.password": "password",
                    "creds_b.identifier": "username",
                    # creds_b.password missing
                },
            }],
            "other_connection": [],
        })
        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            errors = ws_api._check_type9_companions_present("Dummy", payload)
        assert len(errors) == 1
        assert "creds_b" in errors[0]
        assert "creds_b.password" in errors[0]
        assert "creds_a" not in errors[0]


# ---------------------------------------------------------------------------
# Dry-run path surfaces the type-9 companion failure
# ---------------------------------------------------------------------------


class TestDryRunSurfacesType9CompanionFailure:
    def test_dry_run_real_path_reports_yml_cross_check_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A type-9 param missing its password companion makes the dry-run
        envelope report yml_cross_check.passed == False and would_commit
        == False — exercising the real wiring end-to-end."""
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({"credentials.identifier": "username"})

        rows = [{
            "Integration ID": "Dummy",
            "Integration File Path": yml.name,
            "Connector ID": "dummy",
            "Auth Details": "",
        }]
        monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
        monkeypatch.setattr(
            ws_api, "save_csv",
            lambda _r: (_ for _ in ()).throw(
                AssertionError("dry-run must not write")
            ),
        )

        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            env = ws_api.dry_run_auth("Dummy", payload)

        assert env["yml_cross_check"]["passed"] is False
        assert any(
            "credentials.password" in e
            for e in env["yml_cross_check"]["errors"]
        )
        assert env["verdict"]["would_commit"] is False
        assert env["verdict"]["reason"] == "YML cross-check failed"
        assert "skipped" in env["seed_overlap"]
        assert "skipped" in env["parity"]
        assert env["pass"] is False

    def test_dry_run_patched_helper_surfaces_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Belt-and-suspenders: patch _check_type9_companions_present to a
        fake error and assert it flows into the dry-run envelope."""
        yml = _write_yml(tmp_path, [{"name": "credentials", "type": 9}])
        payload = _auth_json({
            "credentials.identifier": "username",
            "credentials.password": "password",
        })
        rows = [{
            "Integration ID": "Dummy",
            "Integration File Path": yml.name,
            "Connector ID": "dummy",
            "Auth Details": "",
        }]
        monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
        monkeypatch.setattr(
            ws_api, "_check_type9_companions_present",
            lambda _i, _j: ["FAKE companion error"],
        )

        p_files, p_base = _patch_files_to(yml)
        with p_files, p_base:
            env = ws_api.dry_run_auth("Dummy", payload)

        assert env["yml_cross_check"]["passed"] is False
        assert "FAKE companion error" in env["yml_cross_check"]["errors"]
        assert env["verdict"]["would_commit"] is False
