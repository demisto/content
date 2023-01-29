import json
import io
import pytest
from CommonServerPython import CommandResults

ASSET_ID = 'bf707048-7ce9-4249-a58c-0aaa257d69f0'
BASE_URL = 'https://console.runzero.com/api/v1.0'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_client():
    from RunZero import Client
    return Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False
    )


def assertCommandResults(actual_commandResult, expected_commandResult):
    assert actual_commandResult.readable_output == expected_commandResult.readable_output
    assert actual_commandResult.raw_response == expected_commandResult.raw_response
    assert actual_commandResult.outputs_key_field == expected_commandResult.outputs_key_field
    assert actual_commandResult.outputs_prefix == expected_commandResult.outputs_prefix
    assert actual_commandResult.outputs == expected_commandResult.outputs


def test_normalize_rtt():
    """
    Tests the normalize_rtt function.
        Given: a raw response of RTT from server
        When: Calling normalize_rtt
        Then: Returns normalized value of RTT where  0 <= RTT <= 1
              Same as in RunZero Web client
    """
    from RunZero import normalize_rtt
    actual_rtt = 837561
    expected_rtt = 0.84
    normalized_rtt = normalize_rtt(actual_rtt)
    assert normalized_rtt == expected_rtt


def test_parse_raw_asset():
    """
    Tests the parse_raw_asset function.
        Given: raw response of asset_search
        When: Calling parse_raw_asset
        Then: Returns the expected parsed response
    """
    from RunZero import parse_raw_asset
    raw_asset = util_load_json('test_data/assets.json')[0]
    expected_asset_res = util_load_json('test_data/parsed_asset_result.json')
    actual_response = parse_raw_asset(raw=raw_asset)
    assert actual_response[0] == expected_asset_res


def test_parse_raw_service():
    """
    Tests the parse_raw_service function.
        Given: raw response of service_search
        When: Calling parse_raw_service
        Then: Returns the expected parsed response
    """
    from RunZero import parse_raw_service
    raw_service = util_load_json('test_data/services.json')[0]
    expected_service_res = util_load_json('test_data/parsed_service_result.json')
    actual_response = parse_raw_service(raw=raw_service)
    assert actual_response[0] == expected_service_res


def test_parse_raw_wireless():
    """
    Tests the parse_raw_wireless function.
        Given: raw response of wireless
        When: Calling parse_raw_wireless
        Then: Returns the expected parsed response
    """
    from RunZero import parse_raw_wireless
    raw_service = util_load_json('test_data/wireless.json')[0]
    expected_wireless_res = util_load_json('test_data/parsed_wireless_result.json')
    actual_response = parse_raw_wireless(raw=raw_service)
    assert actual_response[0] == expected_wireless_res


def test_assets_search(requests_mock):
    """
    Tests the assets-search command function.
        Given: Assets in RunZero
        When: Searching for all assets
        Then: Returns the assets
    """
    from RunZero import asset_search_command
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.get(
        f'{BASE_URL}/org/assets',
        json=mock_response)

    client = get_client()

    actual_commandResult = asset_search_command(
        client=client,
        args={}
    )
    del mock_response[0]['attributes']  # display attributes is defaulted to false
    del mock_response[0]['services']  # display services is defaulted to false

    readable_output = '### Asset\n|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | tag1: <br>tag2:  | Server | 4 | 0 |\n'
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Asset',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
                                            )

    assertCommandResults(actual_commandResult, expected_commandResult)


def test_assets_search_exits_if_invalid_args(requests_mock):
    """
    Tests the assets-search command function.
        Given: Assets in RunZero
        When: Searching for all assets with more than one valid arg.
        Then: The command exits with SystemExit(0)
    """
    from RunZero import asset_search_command
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.get(
        f'{BASE_URL}/org/assets',
        json=mock_response)

    client = get_client()
    with pytest.raises(SystemExit) as excinfo:
        asset_search_command(
            client=client,
            args={'ips': '192.168.1.1', 'hostnames': 'localhost'}
        )
    assert excinfo.value.code == 0


def test_service_search_exits_if_invalid_args(requests_mock):
    """
    Tests the service-search command function.
        Given: Services in RunZero.
        When: Searching for all services providing more than one valid arg.
        Then: The command exits with SystemExit(0).
    """
    from RunZero import service_search_command
    mock_response = util_load_json('test_data/services.json')
    requests_mock.get(
        f'{BASE_URL}/org/services',
        json=mock_response)

    client = get_client()
    with pytest.raises(SystemExit) as excinfo:
        service_search_command(
            client=client,
            args={'service_id': '04d60ddf-8d28-494c-8186-8cd514e5b9cb', 'search': 'ips:191.168.1.1'}
        )
    assert excinfo.value.code == 0


def test_wireless_search_exits_if_invalid_args(requests_mock):
    """
    Tests the wirelessLAN-search command function.
        Given: Wireless LAN in RunZero.
        When: Searching for all wirelessLAN providing more than one valid arg.
        Then: The command exits with SystemExit(0).
    """
    from RunZero import wireless_lan_search_command
    mock_response = util_load_json('test_data/wireless.json')
    requests_mock.get(
        f'{BASE_URL}/org/wireless',
        json=mock_response)

    client = get_client()
    with pytest.raises(SystemExit) as excinfo:
        wireless_lan_search_command(
            client=client,
            args={'wireless_id': '04d60ddf-8d28-494c-8186-8cd514e5b9cb', 'search': 'interface:wlan0'}
        )
    assert excinfo.value.code == 0



def test_asset_search(requests_mock):
    """
    Tests the assets command function.
        Given:
        When:
        Then:
    """
    from RunZero import asset_search_command
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.get(
        f'{BASE_URL}/org/assets?search=address:192.168.1.91',
        json=mock_response)

    client = client = get_client()

    actual_commandResult = asset_search_command(
        client=client,
        args={'ips': '192.168.1.91', 'display_attributes': 'True', 'display_services': 'True'}
    )
    readable_output = '### Asset\n|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | 192.168.1.91,<br>fe80::250:56ff:fe89:b0e1 | true | My comment2 | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | tag1: <br>tag2:  | Server | 4 | 0 |\n'
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Asset',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test_comment_add(requests_mock):
    """
    Tests the comment-add command function.
        Given: An asset
        When: Posting publishing new comment asset
        Then: New comment is attached to asset.
    """
    from RunZero import comment_add_command
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.patch(
        f'{BASE_URL}/org/assets/{ASSET_ID}/comments',
        json=mock_response)

    client = get_client()

    actual_commandResult = comment_add_command(
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
    from RunZero import tags_add_command    
    mock_response = util_load_json('test_data/assets.json')
    requests_mock.patch(
        f'{BASE_URL}/org/assets/{ASSET_ID}/tags',
        json=mock_response)

    client = get_client()

    actual_commandResult = tags_add_command(
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
    from RunZero import service_search_command
    mock_response = util_load_json('test_data/services.json')
    requests_mock.get(
        f'{BASE_URL}/org/services',
        json=mock_response)

    client = get_client()

    actual_commandResult = service_search_command(
        client=client,
        args={'display_attributes': 'True'}
    )

    readable_output = '### Service\n|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 04d60ddf-8d28-494c-8186-8cd514e5b9cb | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 10f9e421-d80a-47d6-9643-d3e0c423a0f7 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | a0dafbdd-e56d-4d01-be51-99dbbaaa8322 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | b3760c57-934f-4e45-ad9b-3aef27a9825a | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | c807c93b-3b63-4937-89f5-c3d89eb36003 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | e9e37c0a-a952-40b2-880d-077df0434794 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 9090 | http,<br>tls | 0.84 | 2 | Primary | HTTP/1.1 301 Moved Permanently<br>Content-Type: text/html<br>Location: https://192.168.1.91:9090/<br>Content-Length: 73<br>X-DNS-Prefetch-Control: off<br>Referrer-Policy: no-referrer<br>X-Content-Type-Options: nosniff<br>Cross-Origin-Resource-Policy: same-origin<br><br><html><head><title>Moved</title></head><body>Please use TLS</body></html> | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | f9917aca-cc6b-4c49-96fa-4cd00e748719 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n'
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Service',
                                            outputs_key_field='service_id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
                                            )

    assertCommandResults(actual_commandResult, expected_commandResult)


def test_service_search_using_search_string(requests_mock):
    """
    Tests the service-search command function.
        Given: A service in RunZero
        When: Calling service-search command with specific search query
        Then: Returning the desired service.
    """
    from RunZero import service_search_command
    mock_response = util_load_json('test_data/services.json')
    requests_mock.get(
        f'{BASE_URL}/org/services',
        json=mock_response)

    client = get_client()

    actual_commandResult = service_search_command(
        client=client,
        args={'search': 'service_address:192.168.1.91',
              'display_attributes': 'False'}
    )

    for mock_res_item in mock_response:        
        del mock_res_item['attributes']

    readable_output = '### Service\n|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 04d60ddf-8d28-494c-8186-8cd514e5b9cb | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: <br>ThisTag22: <br>tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 10f9e421-d80a-47d6-9643-d3e0c423a0f7 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | a0dafbdd-e56d-4d01-be51-99dbbaaa8322 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | b3760c57-934f-4e45-ad9b-3aef27a9825a | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | icmp | Server | 4 | 0 |\n| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | c807c93b-3b63-4937-89f5-c3d89eb36003 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | udp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | arp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | e9e37c0a-a952-40b2-880d-077df0434794 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 9090 | http,<br>tls | 0.84 | 2 | Primary | HTTP/1.1 301 Moved Permanently<br>Content-Type: text/html<br>Location: https://192.168.1.91:9090/<br>Content-Length: 73<br>X-DNS-Prefetch-Control: off<br>Referrer-Policy: no-referrer<br>X-Content-Type-Options: nosniff<br>Cross-Origin-Resource-Policy: same-origin<br><br><html><head><title>Moved</title></head><body>Please use TLS</body></html> | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br>RHEL85.LOCALDOMAIN | 1 | f9917aca-cc6b-4c49-96fa-4cd00e748719 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | tag1: <br>tag2:  | tcp | Server | 4 | 0 |\n'
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Service',
                                            outputs_key_field='service_id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
                                            )

    assertCommandResults(actual_commandResult, expected_commandResult)


def test_quota_get(requests_mock):
    """
    Tests the quota-get command function.
        Given: An API key in RunZero
        When: Calling quota-get command
        Then: Returns information about api key (limit, usage, type ..)
    """
    from RunZero import quota_get_command
    mock_response = util_load_json('test_data/quota.json')
    requests_mock.get(
        f'{BASE_URL}/org/key',
        json=mock_response)

    client = get_client()

    actual_commandResult = quota_get_command(client=client)

    expected_commandResult = CommandResults(outputs_prefix='RunZero.Quota',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output='### Quota\n|counter|usage_limit|usage_today|\n|---|---|---|\n| 1 | 1576300370 | 100 |\n',
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test__wireless_lan_search(requests_mock):
    """
    Tests the wireless_lan_search command function.
        Given: A wireless LAN asset in RunZero
        When: Calling wireless_lan_search command
        Then: Returns the wireless_lan asset
    """
    from RunZero import wireless_lan_search_command
    mock_response = util_load_json('test_data/wireless.json')
    requests_mock.get(
        f'{BASE_URL}/org/wireless',
        json=mock_response)

    client = get_client()

    actual_commandResult = wireless_lan_search_command(client=client, args={})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.WirelessLAN',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output='### Wireless\n|Additional|Auth|BSSID|ESSID|Enc|Family|First_seen|ID|Int|Last_seen|Sig|Site|Type|Vendor|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| additionalProp1: string<br>additionalProp2: string<br>additionalProp3: string | wpa2-psk | 11:22:33:44:55:66 | Free WiFi | aes | 223344 | 1970-01-19T05:51:40.000Z | e77602e0-3fb8-4734-aef9-fbc6fdcb0fa8 | wlan0 | 1970-01-19T05:51:40.000Z | 99 | Primary | infrastructure | Ubiquiti Networks |\n'
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test_asset_delete(requests_mock):
    """
    Tests the asset_delete command function.
        Given: An asset in RunZero
        When: Calling asset delete command with the corresponding asset id.
        Then: Returns the asset deleted successfully.
    """
    from RunZero import asset_delete_command
    requests_mock.delete(
        f"{BASE_URL}/org/assets/bulk/delete?asset_ids=[{ASSET_ID}]",
        json={})

    client = get_client()

    actual_commandResult = asset_delete_command(client, {'asset_ids': [ASSET_ID]})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Asset',
                                            outputs_key_field=None,
                                            raw_response={},
                                            outputs=None,
                                            readable_output=f"Assets ['{ASSET_ID}'] deleted successfully."
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test_service_delete(requests_mock):
    """
    Tests the service_delete command function.
        Given: A service in RunZero
        When: Calling service delete command with the corresponding service id.
        Then: Returns the service deleted successfully.
    """
    from RunZero import service_delete_command
    requests_mock.delete(
        f"{BASE_URL}/org/services/{ASSET_ID}",
        json={})

    client = get_client()
    actual_commandResult = service_delete_command(client, {'service_id': ASSET_ID})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Service',
                                            outputs_key_field=None,
                                            raw_response={},
                                            outputs=None,
                                            readable_output=f"Service {ASSET_ID} deleted successfully."
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test_wireless_lan_delete(requests_mock):
    """
    Tests the wireless_lan command function.
        Given: A wirelessLAN in RunZero
        When: Calling wireless LAN delete command with the corresponding wireless id.
        Then: Returns the wireless deleted successfully.
    """
    from RunZero import wireless_lan_delete_command
    requests_mock.delete(
        f'{BASE_URL}/org/wireless/{ASSET_ID}',
        json={})

    client = get_client()
    actual_commandResult = wireless_lan_delete_command(client, {'wireless_id': ASSET_ID})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.WirelessLAN',
                                            outputs_key_field=None,
                                            raw_response={},
                                            outputs=None,
                                            readable_output=f'Wireless LAN {ASSET_ID} deleted successfully.'
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)


def test_tag_delete(requests_mock):
    """
    Tests the tags_delete command function.
        Given: An asset with tags in RunZero
        When: Calling tag delete command with asset id and tags to delete.
        Then: Returns the tags deleted successfully.
    """
    from RunZero import tag_delete_command
    requests_mock.patch(
        f'{BASE_URL}/org/assets/{ASSET_ID}/tags',
        json={})
    client = get_client()
    tagsList = ['tag1', 'tag2']
    actual_commandResult = tag_delete_command(client, {'asset_id': ASSET_ID, 'tags': tagsList})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Tag',
                                            outputs_key_field=None,
                                            raw_response={},
                                            outputs=None,
                                            readable_output=f'Tags {tagsList} from asset: {ASSET_ID} deleted successfully.'
                                            )
    assertCommandResults(actual_commandResult, expected_commandResult)
