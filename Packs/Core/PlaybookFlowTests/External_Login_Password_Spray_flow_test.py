"""
{
    "marketplaces": ["XSIAM"],
    "additional_needed_packs": {
        "PackOne": "instance_name1",
        "PackTwo": ""
    }
}
"""
import json
import pytest
from demisto_sdk.commands.common.clients import XsiamClient, XsoarClient, get_client_from_server_type

# Any additional imports your tests require


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def api_client(client_obj: XsoarClient | None = None):
    if client_obj:
        yield client_obj
    else:
        client_obj = get_client_from_server_type()
        yield client_obj


class TestExample:
    @classmethod
    def setup_class(self):
        """Run once for the class before *all* tests"""
        print("Testing out running in setup!")
        self.data = "test"
        print("jasmine")

    def setup_method(self, method):
        pass

    def some_helper_function(self, method):
        pass

    def teardown_method(self, method):
        print("tearing down")

    @classmethod
    def teardown_class(self):
        """Run once for the class after all tests"""

    # PLAYBOOK X CHECKING VALID alert
    def test_feature_one_manual_true(self, api_client: XsiamClient):
        """Test feature one"""
        assert True

    def test_feature_two(self, api_client: XsiamClient):
        """Test feature two"""
        # Test another aspect of your application
        api_client.list_indicators()
        api_client.run_cli_command(
            investigation_id="INCIDENT-1", command='!Set key=test value=A')
        # c = api_client.create_alert_from_json(myjson)
        raise AssertionError  # replace with actual assertions for your application


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    pytest.main()
