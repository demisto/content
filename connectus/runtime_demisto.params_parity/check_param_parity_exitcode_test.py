"""Exit-code robustness tests for the param-parity orchestrator.

Focused, hermetic tests (NO network / tenant / docker) that pin down the
exit-code contract for a CAPTURE CRASH:

  A live-capture call that RAISES an exception (proxy 403, tenant unreachable,
  connection error, etc.) is a SETUP failure, NOT a parameter diff. It must be
  converted to a clean ``return 2`` (which the deploy_and_test wrapper maps to
  exit 11 = SETUP_BLOCK), and must NEVER:

    * propagate the exception out of main() (Python would exit 1, which the
      wrapper maps to exit 10 = PARITY_FAIL — a misleading "real diff"), or
    * produce a fake parity result.

Background — the bug:
  ``check_param_parity.main()`` originally only handled the EXPLICIT-None path
  for each capture (``if integration_raw is None: return 2``). If the capture
  RAISED instead of returning None, the exception escaped main() → exit 1 →
  wrapper PARITY_FAIL. The fix wraps BOTH capture calls in try/except so any
  exception becomes a setup-blocked ``return 2``.

To stay hermetic these tests drive the real ``check_param_parity.main()`` with
every upstream piece main() touches BEFORE the capture monkeypatched out, and
the capture(s) monkeypatched to RAISE. We then assert main() returns 2.
"""
from __future__ import annotations

import types

import check_param_parity


def _fake_variant() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id="automation-and-remediation",
        capabilities=[],
        enabled_capability_ids=["automation-and-remediation"],
        fetch_flags={
            "isFetch": False, "isFetchEvents": False, "isFetchAssets": False,
            "isFetchSamples": False, "isFetchCredentials": False, "feed": False,
        },
    )


def _fake_parity_inputs(integration_yml_path: str) -> types.SimpleNamespace:
    """A minimal ParityInputs-like stub with the attrs main() reads pre-capture."""
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
    )


def _stub_upstream(monkeypatch, tmp_path):
    """Monkeypatch every main() dependency BEFORE the capture so we reach it.

    Returns the path to a real (small) integration YML on disk so main()'s
    ``os.path.exists`` guard passes.
    """
    yml = tmp_path / "integration.yml"
    yml.write_text("name: X\nconfiguration: []\n")

    monkeypatch.setattr(
        check_param_parity.resolver_mod,
        "resolve",
        lambda integration_id: _fake_parity_inputs(str(yml)),
    )
    # Avoid needing real YML parsing / dummy generation.
    monkeypatch.setattr(
        check_param_parity,
        "parse_integration_yml",
        lambda path: {"name": "X", "configuration": []},
    )
    monkeypatch.setattr(
        check_param_parity, "fill_params_from_yml", lambda config, overrides: {}
    )
    # A dummy XSOAR client object is enough — the captures are stubbed.
    monkeypatch.setattr(check_param_parity, "create_client", lambda: object())
    return yml


def test_integration_capture_exception_returns_2(monkeypatch, tmp_path):
    """INTEGRATION-side capture RAISING → setup-blocked return 2 (NOT crash/1)."""
    _stub_upstream(monkeypatch, tmp_path)

    def _boom(**kwargs):
        raise RuntimeError("proxy 403")

    monkeypatch.setattr(check_param_parity, "capture_xsoar_params", _boom)

    rc = check_param_parity.main(["--integration-id", "AWS - ACM"])

    assert rc == 2


def test_connector_capture_exception_returns_2(monkeypatch, tmp_path):
    """CONNECTOR-side capture RAISING (after a good integration capture) → 2."""
    _stub_upstream(monkeypatch, tmp_path)

    # INTEGRATION side succeeds with a real dict (returns the new tuple contract
    # (captured, creation_payload)) ...
    monkeypatch.setattr(
        check_param_parity,
        "capture_xsoar_params",
        lambda **kwargs: ({"some_param": "value"}, {"some_param": "value"}),
    )

    # ... but the CONNECTOR side blows up.
    def _boom(**kwargs):
        raise ConnectionError("tenant unreachable")

    monkeypatch.setattr(check_param_parity, "capture_ucp_params", _boom)

    rc = check_param_parity.main(["--integration-id", "AWS - ACM"])

    assert rc == 2
