"""Tests that ``check_param_parity.main()`` attaches the instance-creation
payloads to the results envelope under ``creation_payloads``.

The persisted JSON (and the stdout envelope) must include the XSOAR-side and
UCP-side instance-creation payloads so a failing run is reproducible/debuggable
straight from the artifact.

To stay hermetic (NO network / tenant / docker) we monkeypatch every upstream
dependency main() touches: the resolver, YML parsing, the two captures (now
returning the new ``(captured, creation_payload)`` tuple), the normalizer, the
differ, and the results-ledger persistence (which we intercept to grab the
envelope actually written).
"""
from __future__ import annotations

import json
import types

import check_param_parity


def _fake_variant() -> types.SimpleNamespace:
    """A single legal variant (no fetch caps → all fetch flags False)."""
    return types.SimpleNamespace(
        id="automation-and-remediation",
        capabilities=[],
        enabled_capability_ids=["automation-and-remediation"],
        # Per-variant field SCOPING (Bucket C): empty scoping → behaviour unchanged.
        in_scope_fields=frozenset(),
        enabled_ownership_units=set(),
        fetch_flags={
            "isFetch": False, "isFetchEvents": False, "isFetchAssets": False,
            "isFetchSamples": False, "isFetchCredentials": False, "feed": False,
        },
    )


def _fake_parity_inputs(integration_yml_path: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        integration_yml_path=integration_yml_path,
        integration_brand="AWS - ACM",
        connector_id="aws-acm",
        connector_dir="/tmp/fake-connector",
        compare_params=set(),
        ignored_params={},
        capabilities=[],
        variants=[_fake_variant()],
        profiles=[],
        param_to_connector_field={},
        field_owning_subcapabilities={},
    )


def _drive_main(monkeypatch, tmp_path, *, integration_payload, connector_payload):
    """Run main() with all deps stubbed; return the persisted envelope dict."""
    yml = tmp_path / "integration.yml"
    yml.write_text("name: X\nconfiguration: []\n")

    monkeypatch.setattr(
        check_param_parity.resolver_mod,
        "resolve",
        lambda integration_id: _fake_parity_inputs(str(yml)),
    )
    monkeypatch.setattr(
        check_param_parity,
        "parse_integration_yml",
        lambda path: {"name": "X", "configuration": []},
    )
    monkeypatch.setattr(
        check_param_parity, "fill_params_from_yml", lambda config, overrides: {}
    )
    monkeypatch.setattr(check_param_parity, "create_client", lambda: object())

    # Captures return the new tuple contract: (captured_params, creation_payload).
    monkeypatch.setattr(
        check_param_parity,
        "capture_xsoar_params",
        lambda **kwargs: ({"p": "v"}, integration_payload),
    )
    monkeypatch.setattr(
        check_param_parity,
        "capture_ucp_params",
        lambda **kwargs: ({"p": "v"}, connector_payload),
    )

    # Normalizer + differ stubbed to deterministic, passing output.
    monkeypatch.setattr(
        check_param_parity,
        "normalize_for_diff",
        lambda raw, config, **kwargs: (dict(raw), {}),
    )
    monkeypatch.setattr(
        check_param_parity,
        "diff_params",
        lambda **kwargs: {
            "status": "pass",
            "summary": {"n_ok": 1, "n_total": 1, "n_fail": 0, "n_warn": 0},
        },
    )

    # Intercept the persisted envelope.
    written = {}

    def _fake_write_result(envelope, *, connector_id, integration_id):
        written["envelope"] = envelope
        return tmp_path / "result.json"

    monkeypatch.setattr(check_param_parity.results_ledger, "write_result", _fake_write_result)
    monkeypatch.setattr(
        check_param_parity.results_ledger, "append_ledger", lambda *a, **k: None
    )

    rc = check_param_parity.main(["--integration-id", "AWS - ACM"])
    return rc, written["envelope"]


def test_envelope_has_creation_payloads(monkeypatch, tmp_path):
    integration_payload = {"url": "https://x", "__params_parity_dump__": "1"}
    connector_payload = {"configuration": [], "connection": {"profiles": []}}

    rc, envelope = _drive_main(
        monkeypatch,
        tmp_path,
        integration_payload=integration_payload,
        connector_payload=connector_payload,
    )

    assert rc == 0
    # creation_payloads now live INSIDE each variant entry of the aggregate.
    assert envelope["variants"], "aggregate must carry at least one variant"
    variant = envelope["variants"][0]
    assert "creation_payloads" in variant
    assert set(variant["creation_payloads"].keys()) == {"integration", "connector"}
    assert variant["creation_payloads"]["integration"] == integration_payload
    assert variant["creation_payloads"]["connector"] == connector_payload
    # Must survive JSON round-trip (the envelope is dumped to stdout + disk).
    json.dumps(envelope, default=str)


def test_envelope_creation_payloads_none_when_loading_from_file(monkeypatch, tmp_path):
    """The --skip-* file-load branches have no payload → None is recorded."""
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps({"p": "v"}))

    yml = tmp_path / "integration.yml"
    yml.write_text("name: X\nconfiguration: []\n")

    monkeypatch.setattr(
        check_param_parity.resolver_mod,
        "resolve",
        lambda integration_id: _fake_parity_inputs(str(yml)),
    )
    monkeypatch.setattr(
        check_param_parity,
        "parse_integration_yml",
        lambda path: {"name": "X", "configuration": []},
    )
    monkeypatch.setattr(
        check_param_parity, "fill_params_from_yml", lambda config, overrides: {}
    )
    monkeypatch.setattr(check_param_parity, "create_client", lambda: object())
    monkeypatch.setattr(
        check_param_parity,
        "normalize_for_diff",
        lambda raw, config, **kwargs: (dict(raw), {}),
    )
    monkeypatch.setattr(
        check_param_parity,
        "diff_params",
        lambda **kwargs: {
            "status": "pass",
            "summary": {"n_ok": 1, "n_total": 1, "n_fail": 0, "n_warn": 0},
        },
    )
    written = {}
    monkeypatch.setattr(
        check_param_parity.results_ledger,
        "write_result",
        lambda envelope, **k: (written.__setitem__("envelope", envelope), tmp_path / "r.json")[1],
    )
    monkeypatch.setattr(
        check_param_parity.results_ledger, "append_ledger", lambda *a, **k: None
    )

    rc = check_param_parity.main(
        [
            "--integration-id", "AWS - ACM",
            "--skip-xsoar", "--integration-capture-file", str(cap),
            "--skip-ucp", "--connector-capture-file", str(cap),
        ]
    )

    assert rc == 0
    envelope = written["envelope"]
    variant = envelope["variants"][0]
    assert variant["creation_payloads"] == {"integration": None, "connector": None}
