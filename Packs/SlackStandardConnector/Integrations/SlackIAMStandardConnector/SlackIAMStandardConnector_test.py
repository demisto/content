"""
Sanity tests for the SlackIAMStandardConnector shim integration.

Full behavioural coverage lives in the SlackIAMApiModule tests; this
file only confirms the shim wires through to the ApiModule.
"""

import pytest
import SlackIAMStandardConnector as integration_module


class TestMain:
    def test_delegates_to_api_module(self, mocker):
        run = mocker.patch.object(integration_module, "run_slack_iam_integration")
        integration_module.main()
        assert run.call_count == 1

    def test_propagates_exceptions(self, mocker):
        mocker.patch.object(integration_module, "run_slack_iam_integration", side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError, match="boom"):
            integration_module.main()
