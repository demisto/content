"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from CommonServerPython import CommandResults


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_parse_raw():
    from RunZero import parse_raw_response
    raw_asset = util_load_json('test_data/asset.json')
    actual_response = parse_raw_response(raw=raw_asset)
    assert actual_response == {
        'Addresses': ['192.168.1.91', 'fe80::250:56ff:fe89:b0e1'],
        'Asset Status': True,
        'Hostname': ["RHEL85", "RHEL85.LOCALDOMAIN"],
        'OS': 'Red Hat Enterprise Linux 8.5',
        'Type': 'Server',
        'Hardware': 'VMware VM',
        'Outlier': 0,
        'MAC vendor': ['VMware, Inc.'],
        'MAC age': '',
        'MAC': ['00:50:56:89:b0:e1'],
        'OS EOL': 0,
        'Sources': ['runZero'],
        'Comments': 'My comment2',
        'Tags': {'ThisTag': '', 'ThisTag22': '', 'tag1': '', 'tag2': ''},
        'Svcs': 11,
        'TCP': 3,
        'UDP': 4,
        'ICMP': 1,
    }


def test_assets_search(requests_mock):
    """
    Tests the assets command function.
        Given:
        When:
        Then:
    """
    from RunZero import Client, asset_search
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/org/assets',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = asset_search(
        client=client,
        args={}
    )

    readable_output = '### runzero-asset-search\n|Addresses|Asset Status|Comments|Hardware|Hostname|ICMP|MAC|MAC vendor|OS|OS EOL|Outlier|Sources|Svcs|TCP|Tags|Type|UDP|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | VMware VM | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | runZero | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | Server | 4 |\n'
    outputs = [{'Addresses': ['192.168.1.91', 'fe80::250:56ff:fe89:b0e1'], 'Asset Status': True, 'Hostname': ['RHEL85', 'RHEL85.LOCALDOMAIN'], 'OS': 'Red Hat Enterprise Linux 8.5', 'Type': 'Server', 'Hardware': 'VMware VM', 'Outlier': 0, 'MAC vendor': ['VMware, Inc.'], 'MAC age': '', 'MAC': ['00:50:56:89:b0:e1'], 'OS EOL': 0, 'Sources': ['runZero'], 'Comments': 'My comment2', 'Tags': {'ThisTag': '', 'ThisTag22': '', 'tag1': '', 'tag2': ''}, 'Svcs': 11, 'TCP': 3, 'UDP': 4, 'ICMP': 1}]
    expectedCommandResult = CommandResults(outputs_prefix='RunZero',
                                           outputs_key_field='Asset',
                                           raw_response=mock_response,
                                           outputs=outputs,
                                           readable_output=readable_output,
                                           )

    assert actual_commandResult.readable_output == expectedCommandResult.readable_output
    assert actual_commandResult.raw_response == expectedCommandResult.raw_response
    assert actual_commandResult.outputs_key_field == expectedCommandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expectedCommandResult.outputs_prefix
    assert actual_commandResult.outputs == expectedCommandResult.outputs


def test_asset_search(requests_mock):
    """
    Tests the assets command function.
        Given:
        When:
        Then:
    """
    from RunZero import Client, asset_search
    mock_response = util_load_json('test_data/asset.json')
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/org/assets?search=address:192.168.1.91',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = asset_search(
        client=client,
        args={'ips': '192.168.1.91'}
    )
    readable_output = '### runzero-asset-search\n|Addresses|Asset Status|Comments|Hardware|Hostname|ICMP|MAC|MAC vendor|OS|OS EOL|Outlier|Sources|Svcs|TCP|Tags|Type|UDP|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | VMware VM | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | runZero | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | Server | 4 |\n'
    outputs = [{'Addresses': ['192.168.1.91', 'fe80::250:56ff:fe89:b0e1'], 'Asset Status': True, 'Hostname': ['RHEL85', 'RHEL85.LOCALDOMAIN'], 'OS': 'Red Hat Enterprise Linux 8.5', 'Type': 'Server', 'Hardware': 'VMware VM', 'Outlier': 0, 'MAC vendor': ['VMware, Inc.'], 'MAC age': '', 'MAC': ['00:50:56:89:b0:e1'], 'OS EOL': 0, 'Sources': ['runZero'], 'Comments': 'My comment2', 'Tags': {'ThisTag': '', 'ThisTag22': '', 'tag1': '', 'tag2': ''}, 'Svcs': 11, 'TCP': 3, 'UDP': 4, 'ICMP': 1}]
    expectedCommandResult = CommandResults(outputs_prefix='RunZero',
                                           outputs_key_field='Asset',
                                           raw_response=mock_response,
                                           outputs=outputs,
                                           readable_output=readable_output,
                                           )
    
    assert actual_commandResult.readable_output == expectedCommandResult.readable_output
    assert actual_commandResult.raw_response == expectedCommandResult.raw_response
    assert actual_commandResult.outputs_key_field == expectedCommandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expectedCommandResult.outputs_prefix
    assert actual_commandResult.outputs == expectedCommandResult.outputs
