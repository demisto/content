"""Tests for ``check_type9_in_profile`` — the type-9 auth-placement validator.

In XSOAR a ``type: 9`` (Credentials) param is a compound secret. Under
ConnectUs that secret MUST be consumed via an auth profile's
``xsoar_param_map`` (``<name>.identifier`` / ``<name>.password``) and MUST
NOT be parked in ``other_connection`` (shared connection config). If it is
needed by more than one profile it must be manually duplicated into each
profile — never hoisted into ``other_connection``.

These tests assert the pure-function classifier
(:func:`check_type9_placement`), the type-9 YML collector, the JSON-verdict
shape, the exit-code contract, and the standalone CLI plumbing.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import check_type9_in_profile as c9

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _yml(*params: dict) -> dict:
    """Build a minimal integration-YML dict from configuration params."""
    return {"name": "TestInt", "configuration": list(params)}


def _cred(name: str, *, hidden=None) -> dict:
    p = {"name": name, "type": 9, "display": name}
    if hidden is not None:
        p["hidden"] = hidden
    return p


def _profile(name: str, xpm: dict, type_: str = "Plain") -> dict:
    return {"type": type_, "name": name, "xsoar_param_map": xpm, "interpolated": True}


# --------------------------------------------------------------------------
# collect_type9_params
# --------------------------------------------------------------------------


def test_collects_non_hidden_type9_params():
    yml = _yml(
        _cred("credentials"),
        {"name": "url", "type": 0},
        {"name": "api_key", "type": 4},
        _cred("hunting_creds"),
    )
    assert c9.collect_type9_params(yml) == {"credentials", "hunting_creds"}


def test_skips_hidden_type9_params():
    yml = _yml(
        _cred("credentials"),
        _cred("legacy_creds", hidden=True),
        _cred("platform_creds", hidden="platform"),
        _cred("mp_creds", hidden=["platform"]),
    )
    assert c9.collect_type9_params(yml) == {"credentials"}


def test_no_type9_params_returns_empty():
    yml = _yml({"name": "url", "type": 0}, {"name": "api_key", "type": 4})
    assert c9.collect_type9_params(yml) == set()


# --------------------------------------------------------------------------
# check_type9_placement — OK path
# --------------------------------------------------------------------------


def test_pass_when_type9_in_profile():
    yml = _yml(_cred("credentials"), {"name": "url", "type": 0})
    auth = {
        "auth_types": [
            _profile(
                "creds",
                {
                    "credentials.identifier": "username",
                    "credentials.password": "password",
                },
            )
        ],
        "other_connection": ["url"],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is True
    assert verdict["ok"] == ["credentials"]
    assert verdict["misplaced"] == []
    assert verdict["missing"] == []


def test_pass_with_hiddenusername_password_only_leaf():
    # APIKey-style type-9 where only the password leaf is mapped.
    yml = _yml(_cred("api_key"))
    auth = {
        "auth_types": [_profile("api_key", {"api_key.password": "key"}, "APIKey")],
        "other_connection": [],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is True
    assert verdict["ok"] == ["api_key"]


def test_no_type9_params_passes_with_note():
    yml = _yml({"name": "url", "type": 0}, {"name": "api_key", "type": 4})
    auth = {
        "auth_types": [_profile("api_key", {"api_key": "key"}, "APIKey")],
        "other_connection": ["url"],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is True
    assert "note" in verdict


# --------------------------------------------------------------------------
# check_type9_placement — MISPLACED path
# --------------------------------------------------------------------------


def test_fail_when_type9_in_other_connection():
    yml = _yml(_cred("credentials"), {"name": "url", "type": 0})
    auth = {
        "auth_types": [],
        "other_connection": ["credentials", "url"],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is False
    assert [e["param"] for e in verdict["misplaced"]] == ["credentials"]
    assert verdict["ok"] == []


def test_misplaced_even_if_also_in_a_profile():
    # Present in both a profile AND other_connection: still misplaced,
    # because the secret must never appear in shared connection config.
    yml = _yml(_cred("credentials"))
    auth = {
        "auth_types": [
            _profile("creds", {"credentials.password": "password"})
        ],
        "other_connection": ["credentials"],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is False
    assert [e["param"] for e in verdict["misplaced"]] == ["credentials"]


def test_misplaced_reason_mentions_param_and_other_connection():
    yml = _yml(_cred("credentials"))
    auth = {"auth_types": [], "other_connection": ["credentials"]}
    verdict = c9.check_type9_placement(yml, auth)
    reason = verdict["misplaced"][0]["reason"]
    assert "credentials" in reason
    assert "other_connection" in reason


# --------------------------------------------------------------------------
# check_type9_placement — MISSING path
# --------------------------------------------------------------------------


def test_fail_when_type9_absent_everywhere():
    yml = _yml(_cred("credentials"))
    auth = {
        "auth_types": [_profile("api_key", {"api_key": "key"}, "APIKey")],
        "other_connection": ["url"],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is False
    assert [e["param"] for e in verdict["missing"]] == ["credentials"]
    assert verdict["misplaced"] == []


# --------------------------------------------------------------------------
# Multi-profile
# --------------------------------------------------------------------------


def test_multi_profile_cred_in_one_profile_passes():
    # The skill does NOT require presence in every profile — only that it's
    # in at least one and not in other_connection.
    yml = _yml(_cred("credentials"))
    auth = {
        "auth_types": [
            _profile(
                "Basic",
                {
                    "credentials.identifier": "username",
                    "credentials.password": "password",
                },
            ),
            _profile(
                "Cert",
                {"client_cert": "client_certificate"},
                "Passthrough",
            ),
        ],
        "other_connection": [],
    }
    verdict = c9.check_type9_placement(yml, auth)
    assert verdict["pass"] is True
    assert verdict["ok"] == ["credentials"]


# --------------------------------------------------------------------------
# CLI — standalone mode
# --------------------------------------------------------------------------

SCRIPT = Path(__file__).resolve().parent / "check_type9_in_profile.py"


def _write_yml(tmp_path: Path, doc: dict) -> Path:
    import yaml

    p = tmp_path / "Int.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def _run(args: list[str]):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def test_cli_pass_exit_zero(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    auth = json.dumps(
        {
            "auth_types": [
                _profile(
                    "creds",
                    {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                )
            ],
            "other_connection": [],
        }
    )
    res = _run(["--integration-yml", str(yml), "--auth-details", auth])
    assert res.returncode == c9.EXIT_PASS, res.stderr
    out = json.loads(res.stdout)
    assert out["pass"] is True
    assert out["ok"] == ["credentials"]


def test_cli_fail_exit_one(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    auth = json.dumps({"auth_types": [], "other_connection": ["credentials"]})
    res = _run(["--integration-yml", str(yml), "--auth-details", auth])
    assert res.returncode == c9.EXIT_FAIL
    out = json.loads(res.stdout)
    assert out["pass"] is False
    assert out["misplaced"][0]["param"] == "credentials"


def test_cli_human_summary_to_stderr(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    auth = json.dumps({"auth_types": [], "other_connection": ["credentials"]})
    res = _run(["--integration-yml", str(yml), "--auth-details", auth, "--human"])
    assert "MISPLACED" in res.stderr
    assert "PASS: False" in res.stderr


def test_cli_usage_error_no_inputs():
    res = _run([])
    assert res.returncode == c9.EXIT_USAGE
    assert "error:" in res.stderr


def test_cli_usage_error_invalid_json(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    res = _run(["--integration-yml", str(yml), "--auth-details", "{not json"])
    assert res.returncode == c9.EXIT_USAGE
    assert "not valid JSON" in res.stderr


def test_cli_auth_details_file(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    ad = tmp_path / "auth.json"
    ad.write_text(
        json.dumps(
            {
                "auth_types": [
                    _profile("creds", {"credentials.password": "password"})
                ],
                "other_connection": [],
            }
        ),
        encoding="utf-8",
    )
    res = _run(["--integration-yml", str(yml), "--auth-details-file", str(ad)])
    assert res.returncode == c9.EXIT_PASS, res.stderr


def test_cli_mutually_exclusive_id_and_path(tmp_path):
    yml = _write_yml(tmp_path, _yml(_cred("credentials")))
    res = _run(
        ["--integration-id", "Foo", "--integration-yml", str(yml)]
    )
    assert res.returncode == c9.EXIT_USAGE
    assert "mutually exclusive" in res.stderr


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
