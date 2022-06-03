"""Cisco Umbrella Reporting v2 Integration for Cortex XSOAR - Unit Tests file
To run tests you need the following configured in as environment variables

Envvars:
    API_KEY: API Key for Cisco Umbrella Reporting v2
    API_SECRET: API Secret for Cisco Umbrella Reporting v2
    ORG_ID: Cisco Umbrella Organization ID

"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_summary_mock_response(*args, **kwargs):
    return {
        "applications": 161,
        "domains": 26910,
        "requestsblocked": 5566,
        "filetypes": 0,
        "requests": 141065,
        "policycategories": 15,
        "requestsallowed": 135380,
        "categories": 160,
        "identitytypes": 3,
        "applicationsblocked": 0,
        "files": 1653,
        "identities": 4,
        "policyrequests": 4664,
        "applicationsallowed": 0
    }


def test_get_summary(mocker):
    """Tests get_summary command function.

    Checks the output of the command function with the expected output.
    """
    from UmbrellaReporting import Client, get_summary_command

    mocker.patch(
        "UmbrellaReporting.Client.get_summary",
        get_summary_mock_response)

    headers = {
        "Authorization": "Bearer access-token"
    }
    client = Client(base_url='mock://reports.api.umbrella.com/v2', verify=False, headers=headers, proxy=None, org_id=123456)
    args = {
        'start': '-30days',
        'end': 'now'
    }
    output = get_summary_command(client, args)

    assert output.outputs_prefix == 'UmbrellaReporting.Summary'
    assert len(output.outputs) == len(get_summary_mock_response())


def list_top_threats_mock_response(*args, **kwargs):
    return [
        {
            "threat": "",
            "threattype": "Adware",
            "count": 14
        },
        {
            "threat": "MageCart MirrorThief",
            "threattype": "Information Stealer",
            "count": 2
        },
        {
            "threat": "",
            "threattype": "Ransomware",
            "count": 1
        },
        {
            "threat": "",
            "threattype": "Malvertising",
            "count": 1
        }
    ]


def test_list_top_threats(mocker):
    """Tests list_top_threats command function.

    Checks the output of the command function with the expected output.
    """
    from UmbrellaReporting import Client, list_top_threats_command

    mocker.patch(
        "UmbrellaReporting.Client.list_top_threats",
        list_top_threats_mock_response)

    headers = {
        "Authorization": "Bearer access-token"
    }
    client = Client(base_url='mock://reports.api.umbrella.com/v2', verify=False, headers=headers, proxy=None, org_id=123456)
    args = {
        'start': '-30days',
        'end': 'now'
    }
    output = list_top_threats_command(client, args)

    assert output.outputs_prefix == 'UmbrellaReporting.TopThreats'
    assert len(output.outputs) == len(list_top_threats_mock_response())
