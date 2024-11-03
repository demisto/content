import json
import pytest
from CommonServerPython import CommandResults

ASSET_ID = 'bf707048-7ce9-4249-a58c-0aaa257d69f0'
BASE_URL = 'https://console.runzero.com/api/v1.0'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_file(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


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
    readable_output = util_load_file('test_data/asset_hr.txt')
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
            args={'service_id': '04d60ddf-8d28-494c-8186-8cd514e5b9cb', 'search': 'ips:192.168.1.1'}
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
    readable_output = util_load_file('test_data/asset_hr.txt')
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

    assert actual_commandResult.raw_response[0]['comments'] == 'My comment2'
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

    readable_output = util_load_file('test_data/service_hr.txt')
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

    readable_output = util_load_file('test_data/service_hr.txt')
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
    readable_output = util_load_file('test_data/quota_hr.txt')
    expected_commandResult = CommandResults(outputs_prefix='RunZero.Quota',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
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
    readable_output = util_load_file('test_data/wireless_hr.txt')

    actual_commandResult = wireless_lan_search_command(client=client, args={})
    expected_commandResult = CommandResults(outputs_prefix='RunZero.WirelessLAN',
                                            outputs_key_field='id',
                                            raw_response=mock_response,
                                            outputs=mock_response,
                                            readable_output=readable_output,
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


def test_parse_tags_from_list():
    from RunZero import parse_tags_from_list
    tag_list = ['tag1', 'tag2']
    actual_string = parse_tags_from_list(tag_list)
    assert actual_string == ' -tag1 -tag2'
