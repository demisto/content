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
        alert_example = {
            "vendor": "string",
            "product": "string",
            "severity": "medium",
            "category": "string",
            "alert_name": "jasmineTest2",
            # "attached_playbook_id":"2b1491ae-4a86-4227-8311-84039f42d907"
            # "action_status": "Reported",
        }

        name = "IDO TEST"

        external_alert_id = api_client.create_alert_from_json(json_content=alert_example)

        api_client.search_alerts(external_alert_id=external_alert_id)
        api_client.get_internal_alert_id(external_alert_id)
        # api_client._xdr_client.
        # inc_data = api_client.create_incident(name=name, additional_data=incident_example,
        #                                       attached_playbook_id="2b1491ae-4a86-4227-8311-84039f42d907")
        inc_data = api_client.create_incident(name=name, attached_playbook_id="2b1491ae-4a86-4227-8311-84039f42d907")
        inv_status = api_client.get_investigation_status(inc_data.inc_id)
        inv_status['invContext']
        api_client.get_investigation_context("INCIDENT-1")
        api_client.get_playbook_state("INC-19")
        pb_exmaple = api_client.get_playbook_data("2b1491ae-4a86-4227-8311-84039f42d907")
        new_inputs = pb_exmaple['inputs'][0]['value']['simple']
        api_client.update_playbook_input("2b1491ae-4a86-4227-8311-84039f42d907", new_inputs)
        assert new_inputs is not None

    def test_feature_two(self, api_client: XsiamClient):
        """Test feature two"""
        # Test another aspect of your application
        api_client.list_indicators()
        api_client.run_cli_command(
            investigation_id="INCIDENT-1", command='!Set key=test value=A')
        raise AssertionError  # replace with actual assertions for your application


if __name__ == "__main__":
    pytest.main()
