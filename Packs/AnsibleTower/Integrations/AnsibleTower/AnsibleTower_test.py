import pytest
from AnsibleTower import Client, create_host, delete_host, inventories_list, job_template_launch, create_ad_hoc_command
from test_data.test_responses import JOB_TEMPLATE_LAUNCH_RES, ADHOC_COMMAND_LAUNCH_RES, JOB_TEMPLATE_EXPECTED, \
    ADHOC_COMMAND_LAUNCH_EXPECTED

API_URL = "https://ansilble"

test_data = [
    (
        create_host,
        {'name': "new name", 'description': "desc", "inventory_id": "1"},
        {"related": {"all_groups": "/api/v2/hosts/4/all_groups/"},
         "summary_fields": {"groups": {"count": 0, "results": []}},
         "name": "new name",
         "id": 1
         },
        {"name": "new name", "id": 1},
        'AnsibleAWX.Host(val.id == obj.id)'
    ),
    (
        delete_host,
        {"host_id": "1"},
        {},
        {"id": "1", "Deleted": True},
        'AnsibleAWX.Host(val.id == obj.id)'
    ),
    (
        inventories_list,
        {},
        {"results": [
            {"related": {"all_groups": "/api/v2/hosts/4/all_groups/"},
             "summary_fields": {},
             "name": "inventory",
             "id": 1
             }]
         },
        {"name": "inventory", "id": 1},
        'AnsibleAWX.Inventory(val.id == obj.id)'
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


@pytest.mark.parametrize('command, args, response, expected_result, output_prefix', test_data)
def test_create_host(command, args, response, expected_result, output_prefix, mocker):

    # check host creation- checks the response, and the request body

    client = Client(API_URL, 'username', 'password', True, False)
    mocker.patch.object(client, 'api_request', return_value=response)
    results = command(client, args)
    if isinstance(results, list):
        output = results[0].to_context().get('EntryContext', {})
    else:
        output = results.to_context().get('EntryContext', {})
    assert output.get(output_prefix, '') == expected_result
