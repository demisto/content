import pytest
import requests_mock
from AnsibleTower import Client, delete_host, job_template_launch, create_ad_hoc_command
from test_data.test_responses import JOB_TEMPLATE_LAUNCH_RES, ADHOC_COMMAND_LAUNCH_RES, JOB_TEMPLATE_EXPECTED, \
    ADHOC_COMMAND_LAUNCH_EXPECTED

API_URL = "https://test"

test_data = [
    (
        delete_host,
        {"host_id": "1"},
        {},
        {"id": "1", "Deleted": True},
        'AnsibleAWX.Host(val.id == obj.id)'
    ),
    (
        job_template_launch,
        {"job_template_id": "1"},
        JOB_TEMPLATE_LAUNCH_RES,
        JOB_TEMPLATE_EXPECTED,
        'AnsibleAWX.Job(val.id == obj.id)'
    ),

    (
        create_ad_hoc_command,
        {"inventory_id": "1", "credential_id": "1", "module_name": "ping"},
        ADHOC_COMMAND_LAUNCH_RES,
        ADHOC_COMMAND_LAUNCH_EXPECTED,
        'AnsibleAWX.AdhocCommand(val.id == obj.id)'
    )
]


remove_fields_test_responses = [
    (
        {"results": [
            {"related": {"all_groups": "/api/v2/hosts/4/all_groups/"},
             "summary_fields": {},
             "name": "inventory",
             "id": 1}]}
    ),
    (
        {"related": {"all_groups": "/api/v2/hosts/4/all_groups/"},
         "summary_fields": {"groups": {"count": 0, "results": []}},
         "name": "new name",
         "id": 1
         }
    ),
    (
        {"name": "new name", "id": 1}
    )
]


def test_api_request_remove_fields():
    """
     Given:
         - an api endpoint

     When:
         - call api_request

     Then:
         - validating that irrelevant fields - related and summary_fields - removed

     """
    client = Client(API_URL, 'username', 'password', True, False)
    url = "https://test/api/v2/inventories/"
    for response_mock in remove_fields_test_responses:
        with requests_mock.Mocker() as m:
            m.get(url, status_code=200, json=response_mock)
            response = client.api_request(method='GET', url_suffix='inventories/', params={})
            assert response.get('related', None) is None
            assert response.get('summary_fields', None) is None


@pytest.mark.parametrize('command, args, response, expected_result, output_prefix', test_data)
def test_create_host(command, args, response, expected_result, output_prefix, mocker):
    """
    Given:
        - parameters to launch

    When:
        - call api_request and use the response for command results

    Then:
        - validating that irrelevant fields removed and that the added fields was added correctly

    """

    client = Client(API_URL, 'username', 'password', True, False)
    mocker.patch.object(client, 'api_request', return_value=response)
    results = command(client, args)
    if isinstance(results, list):
        output = results[0].to_context().get('EntryContext', {})
    else:
        output = results.to_context().get('EntryContext', {})
    assert output.get(output_prefix, '') == expected_result
