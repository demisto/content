import json
import pytest
from Akamai_WAF import Client
from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(scope='module')
def akamai_waf_client():
    return Client(base_url="https://hostname/",
                  verify=False,
                  proxy=False)


environments = ['production', 'staging']


@pytest.mark.parametrize('environment', environments)
def test_get_cps_enrollment_deployment_command(environment, mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_id and environment
    When:
        - running the command get-cps-enrollment-deployment
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import get_cps_enrollment_deployment_command

    enrollment_id = 111111

    test_data = util_load_json('test_data/get_cps_enrollment_deployment_test.json')
    expected_response = test_data.get(environment)
    expected_human_readable = test_data.get(f'{environment}_human_readable')
    expected_context_entry = test_data.get(f'{environment}_context_entry')

    mocker.patch.object(akamai_waf_client, 'get_cps_enrollment_deployment', return_value=expected_response)

    human_readable, context_entry, raw_response = get_cps_enrollment_deployment_command(akamai_waf_client,
                                                                                        enrollment_id,
                                                                                        environment)
    assert expected_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_cidr_blocks_command(mocker, akamai_waf_client):
    """
    Given:
        - A last_action and an effective_date_gt
    When:
        - running the command list-cidr-blocks
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import list_cidr_blocks_command

    last_action = 'add'
    effective_date_gt = '2021-02-21'

    test_data = util_load_json('test_data/list_cidr_blocks_test.json')
    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'list_cidr_blocks', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = list_cidr_blocks_command(akamai_waf_client, last_action, effective_date_gt)

    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry
