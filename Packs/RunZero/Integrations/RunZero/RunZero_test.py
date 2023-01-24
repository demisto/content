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

ASSET_ID = 'bf707048-7ce9-4249-a58c-0aaa257d69f0'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_parse_rtt():
    from RunZero import normalize_rtt
    actual_rtt = 837561
    expected_rtt = 0.84
    normalized_rtt = normalize_rtt(actual_rtt)
    assert normalized_rtt == expected_rtt


def test_parse_raw_asset():
    from RunZero import parse_raw_asset
    raw_asset = util_load_json('test_data/assets.json')[0]
    actual_response = parse_raw_asset(raw=raw_asset)
    assert actual_response[0] == {
        'ID': 'bf707048-7ce9-4249-a58c-0aaa257d69f0',
        'Addresses': ['192.168.1.91', 'fe80::250:56ff:fe89:b0e1'],
        'Asset_Status': True,
        'Hostname': ["RHEL85", "RHEL85.LOCALDOMAIN"],
        'OS': 'Red Hat Enterprise Linux 8.5',
        'Type': 'Server',
        'Hardware': 'VMware VM',
        'Outlier': 0,
        'MAC_Vendor': ['VMware, Inc.'],
        'MAC_Age': '',
        'MAC': ['00:50:56:89:b0:e1'],
        'OS_EOL': 0,
        'Sources': ['runZero'],
        'Comments': 'My comment2',
        'Tags': {'tag1': '', 'tag2': ''},
        'Svcs': 11,
        'TCP': 3,
        'UDP': 4,
        'ICMP': 1,
        'ARP': 1,
        'SW': 2,
        'Vulns': 0,
        'RTT/ms': 0.84,
        'Hops': 0,
        'Detected': 'arp',
        'First_Seen': '2022-12-25T22:28:29.000Z',
        'Last_Seen': '2022-12-25T22:41:58.000Z',
        'Explorer': 'RHEL85.LOCALDOMAIN',
        'Hosted_Zone': None,
        'Site': 'Primary',
    }


def test_parse_raw_service():
    from RunZero import parse_raw_service
    raw_service = util_load_json('test_data/services.json')[0]
    actual_response = parse_raw_service(raw=raw_service)
    assert actual_response[0] == {
        'ID': '04d60ddf-8d28-494c-8186-8cd514e5b9cb',
        'Asset_Status': True,
        'Address': 'fe80::250:56ff:fe89:b0e1',
        'Transport': 'udp',
        'Port': 111,
        'Protocol': ['rpcbind', 'sunrpc'],
        'VHost': '',
        'Summary': '',
        'Hostname': ['RHEL85', 'RHEL85.LOCALDOMAIN'],
        'OS': 'Red Hat Enterprise Linux 8.5',
        'Type': 'Server',
        'Hardware': 'VMware VM',
        'Outlier': 0,
        'MAC_Vendor': ['VMware, Inc.'],
        'MAC_Age': None,
        'MAC': ['00:50:56:89:b0:e1'],
        'OS_EOL': 0,
        'Comments': 'integration comment',
        'Tags': {'ThisTag': '', 'ThisTag22': '', 'tag1': '', 'tag2': ''},
        'Svcs': 11,
        'TCP': 3,
        'UDP': 4,
        'ICMP': 1,
        'ARP': 1,
        'SW': 2,
        'Vulns': 0,
        'RTT/ms': 0.84,
        'Hops': 0,
        'Detected': 'arp',
        'First_Seen': '2022-12-25T22:28:29.000Z',
        'Last_Seen': '2022-12-25T22:41:58.000Z',
        'Explorer': 'RHEL85.LOCALDOMAIN',
        'Hosted_Zone': None,
        'Site': 'Primary',
    }


def test_assets_search(requests_mock):
    """
    Tests the assets-search command function.
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
    del mock_response[0]['attributes']  # display attributes is defaulted to false
    del mock_response[0]['services']  # display services is defaulted to false

    readable_output = '### Asset\n|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | tag1: <br>tag2:  | Server | 4 | 0 |\n'
    expectedCommandResult = CommandResults(outputs_prefix='RunZero.Asset',
                                           outputs_key_field='id',
                                           raw_response=mock_response,
                                           outputs=mock_response,
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
    mock_response = util_load_json('test_data/assets.json')
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
        args={'ips': '192.168.1.91', 'display_attributes': 'True', 'display_services': 'True'}
    )
    readable_output = '### Asset\n|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | tag1: <br>tag2:  | Server | 4 | 0 |\n'
    expectedCommandResult = CommandResults(outputs_prefix='RunZero.Asset',
                                           outputs_key_field='id',
                                           raw_response=mock_response,
                                           outputs=mock_response,
                                           readable_output=readable_output,
                                           )

    assert actual_commandResult.readable_output == expectedCommandResult.readable_output
    assert actual_commandResult.raw_response == expectedCommandResult.raw_response
    assert actual_commandResult.outputs_key_field == expectedCommandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expectedCommandResult.outputs_prefix
    assert actual_commandResult.outputs == expectedCommandResult.outputs


def test_comment_add(requests_mock):
    """
    Tests the comment-add command function.
        Given: An asset
        When: Posting publishing new comment asset
        Then: New comment is attached to asset.
    """
    from RunZero import Client, comment_add
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.patch(
        f'https://console.runzero.com/api/v1.0/org/assets/{ASSET_ID}/comments',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = comment_add(
        client=client,
        args={'asset_id': ASSET_ID,
              'comment': 'My comment2'}
    )

    assert 'My comment2' == actual_commandResult.raw_response[0]['comments']
    assert f'Comment added to {ASSET_ID} successfully.' == actual_commandResult.readable_output


def test_tag_add(requests_mock):
    """
    Tests the tag-add command function.
        Given: An asset
        When: Posting publishing new tags for asset
        Then: New tags are attached to asset.
    """
    from RunZero import Client, tags_add    
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.patch(
        f'https://console.runzero.com/api/v1.0/org/assets/{ASSET_ID}/tags',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = tags_add(
        client=client,
        args={'asset_id': ASSET_ID,
              'tags': 'tag1 tag2'}
    )
    tags = actual_commandResult.raw_response[0]['tags']
    assert 'tag1' in tags
    assert 'tag2' in tags
    assert f'Tags added to {ASSET_ID} successfully.' == actual_commandResult.readable_output


def test_service_search(requests_mock):
    """
    Tests the service-search command function.
        Given: Services in RunZero
        When: Calling RunService service search command
        Then: Returning the expected services
    """
    from RunZero import Client, service_search
    mock_response = util_load_json('test_data/services.json')
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/org/services',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = service_search(
        client=client,
        args={'display_attributes': 'True'}
    )

    readable_output = '### Service\n|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 04d60ddf-8d28-494c-8186-8cd514e5b9cb | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 10f9e421-d80a-47d6-9643-d3e0c423a0f7 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | a0dafbdd-e56d-4d01-be51-99dbbaaa8322 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | b3760c57-934f-4e45-ad9b-3aef27a9825a | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | c807c93b-3b63-4937-89f5-c3d89eb36003 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | e9e37c0a-a952-40b2-880d-077df0434794 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 9090 | http,<br>tls | 0.84 | 2 | Primary | HTTP/1.1 301 Moved Permanently<br>Content-Type: text/html<br>Location: https://192.168.1.91:9090/<br>Content-Length: 73<br>X-DNS-Prefetch-Control: off<br>Referrer-Policy: no-referrer<br>X-Content-Type-Options: nosniff<br>Cross-Origin-Resource-Policy: same-origin<br><br><html><head><title>Moved</title></head><body>Please use TLS</body></html> | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | f9917aca-cc6b-4c49-96fa-4cd00e748719 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n'
    expectedCommandResult = CommandResults(outputs_prefix='RunZero.Service',
                                           outputs_key_field='service_id',
                                           raw_response=mock_response,
                                           outputs=mock_response,
                                           readable_output=readable_output,
                                           )

    assert actual_commandResult.readable_output == expectedCommandResult.readable_output
    assert actual_commandResult.raw_response == expectedCommandResult.raw_response
    assert actual_commandResult.outputs_key_field == expectedCommandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expectedCommandResult.outputs_prefix
    assert actual_commandResult.outputs == expectedCommandResult.outputs


def test_service_search_using_search_string(requests_mock):
    """
    Tests the service-search command function.
        Given: A service in RunZero
        When: Calling service-search command with specific search query 
        Then: Returning the desired service.
    """
    from RunZero import Client, service_search
    mock_response = util_load_json('test_data/services.json')
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/org/services',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False
    )

    actual_commandResult = service_search(
        client=client,
        args={'search': 'service_address:192.168.1.91',
              'display_attributes': 'False'}
    )

    for mock_res_item in mock_response:        
        del mock_res_item['attributes']

    readable_output = '### Service\n|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 04d60ddf-8d28-494c-8186-8cd514e5b9cb | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 10f9e421-d80a-47d6-9643-d3e0c423a0f7 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | a0dafbdd-e56d-4d01-be51-99dbbaaa8322 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | b3760c57-934f-4e45-ad9b-3aef27a9825a | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | c807c93b-3b63-4937-89f5-c3d89eb36003 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | e9e37c0a-a952-40b2-880d-077df0434794 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 9090 | http,<br>tls | 0.84 | 2 | Primary | HTTP/1.1 301 Moved Permanently<br>Content-Type: text/html<br>Location: https://192.168.1.91:9090/<br>Content-Length: 73<br>X-DNS-Prefetch-Control: off<br>Referrer-Policy: no-referrer<br>X-Content-Type-Options: nosniff<br>Cross-Origin-Resource-Policy: same-origin<br><br><html><head><title>Moved</title></head><body>Please use TLS</body></html> | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | f9917aca-cc6b-4c49-96fa-4cd00e748719 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n'
    expectedCommandResult = CommandResults(outputs_prefix='RunZero.Service',
                                           outputs_key_field='service_id',
                                           raw_response=mock_response,
                                           outputs=mock_response,
                                           readable_output=readable_output,
                                           )

    assert actual_commandResult.readable_output == expectedCommandResult.readable_output
    assert actual_commandResult.raw_response == expectedCommandResult.raw_response
    assert actual_commandResult.outputs_key_field == expectedCommandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expectedCommandResult.outputs_prefix
    assert actual_commandResult.outputs == expectedCommandResult.outputs
    