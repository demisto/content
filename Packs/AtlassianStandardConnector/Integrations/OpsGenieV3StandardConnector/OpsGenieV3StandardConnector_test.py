"""
Sanity tests for the OpsGenieV3StandardConnector shim integration.

Full behavioural coverage lives in the OpsGenieV3ApiModule tests; this file only confirms the shim wires
through to the ApiModule.
"""

import OpsGenieV3StandardConnector as integration_module
import pytest


class TestMain:
    def test_delegates_to_api_module(self, monkeypatch):
        calls = []
        monkeypatch.setattr(integration_module, "run_opsgenie_v3_integration", lambda: calls.append(1))
        integration_module.main()
        assert calls == [1]

    def test_propagates_exceptions(self, monkeypatch):
        def boom():
            raise RuntimeError("boom")

        monkeypatch.setattr(integration_module, "run_opsgenie_v3_integration", boom)
        with pytest.raises(RuntimeError, match="boom"):
            integration_module.main()
