import json
import pytest
from Akamai_WAF import Client
from CommonServerPython import *  # noqa: F401


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def akamai_waf_client():
    return Client(base_url="https://hostname/",
                  verify=False,
                  proxy=False)


def test_get_cps_enrollment_deployment_command_production(mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_id and environment = 'production'
    When:
        - running the command get-cps-enrollment-deployment
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import get_cps_enrollment_deployment_command

    enrollment_id = 11111  # TODO check if it is correct
    environment = 'production'
    expected_response = util_load_json('test_data/get_cps_enrollmant_deployment_test.json').get(environment)
    mocker.patch.object(akamai_waf_client, 'get_cps_enrollment_deployment', return_value=expected_response)

    human_readable, context_entry, raw_response = get_cps_enrollment_deployment_command(akamai_waf_client,
                                                                                        enrollment_id,
                                                                                        environment)
    assert expected_response == raw_response
