import dateparser
from ThreatConnectV3 import *
from freezegun import freeze_time
import pytest
import demistomock as demisto

client = Client('test', 'test', 'test', False)


def load_mock_response(file_name: str) -> str:
    with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
        return mock_file.read()


@freeze_time('2020-04-20')
def test_create_header():
    assert client.create_header('test', Method.GET) == {
        'Authorization': 'TC test:p5a/YiTRs7sNMp/PEDgZxky8lJDRLbza1pi8erjURrU=',
        'Content-Type': 'application/json',
        'Timestamp': '1587340800'}


def test_create_or_query():
    assert create_or_query('1,2,3,4,5', 'test') == 'test="1" OR test="2" OR test="3" OR test="4" OR test="5" '
    assert create_or_query('1,2,3,4,5', 'test', '') == 'test=1 OR test=2 OR test=3 OR test=4 OR test=5 '
    assert create_or_query([1, 2, 3, 4, 5], 'test') == 'test="1" OR test="2" OR test="3" OR test="4" OR test="5" '


@pytest.fixture
def groups_fixture() -> list:
    return [{'dateAdded': '2022-08-04T12:35:33Z', 'id': 1}, {'dateAdded': '2022-09-06T12:35:33Z', 'id': 2},
            {'dateAdded': '2022-03-06T12:35:33Z', 'id': 3}, {'dateAdded': '2022-09-06T12:36:33Z', 'id': 3},
            {'dateAdded': '2022-08-06T11:35:33Z', 'id': 4}]


@pytest.mark.parametrize('last_run, expected_result', [('2022-07-04T12:35:33', '2022-09-06T12:36:33'),
                                                       ('2023-07-04T12:35:33', '2023-07-04T12:35:33')])
def test_get_last_run_time(last_run, expected_result, groups_fixture):
    """
    Given:
        - a response containing groups with last_run time and the previos last run_time.
    When:
        - Checking for the next last_run.
    Then:
        - Validate that the correct last run is set.
    """
    assert get_last_run_time(groups_fixture, last_run) == expected_result


def test_get_last_run_no_groups():
    """
    Given:
        - no grops were found.
    When:
        - checking for the next last_run.
    Then:
        - validate that the last run remains as it was before in the previos round.
    """
    assert get_last_run_time([], '2022-07-04T12:35:33') == '2022-07-04T12:35:33'


def test_fetch_incidents_first_run(mocker):
    """
    Given:
        - getLastRun is empty (first run)
    When:
        - calling fetch_events
    Then:
        - Validate that the last run is set properly
    """
    import ThreatConnectV3
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(dateparser, 'parse', return_value=dateparser.parse('2022-08-04T12:35:33'))
    mocker.patch.object(ThreatConnectV3, 'list_groups', return_value=[])
    assert fetch_incidents(client) == '2022-08-04T12:35:33'


def test_fetch_incidents_not_first_run(mocker, groups_fixture):
    import ThreatConnectV3
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_time': '2021-08-04T12:35:33', 'last_id': 1})
    mocker.patch.object(ThreatConnectV3, 'list_groups', return_value=groups_fixture)
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    fetch_incidents(client, {})
    incidents = demisto.incidents.call_args[0][0]

    assert len(incidents) == 3
    demisto.setLastRun.assert_called_with({'last_time': '2022-09-06T12:36:33', 'last_id': 4})


def test_create_context():  # type: ignore # noqa
    indicators = [{
        "id": 40435508,
        "ownerName": "Technical Blogs and Reports",
        "dateAdded": "2021-12-09T12:57:18Z",
        "webLink": "https://partnerstage.threatconnect.com/auth/indicators/details/url.xhtml?orgid=40435508",
        "type": "URL",
        "lastModified": "2022-07-26T13:51:49Z",
        "rating": 3.00,
        "confidence": 32,
        "source": "https://blog.sucuri.net/2021/12/php-re-infectors-the-malware-that-keeps-on-giving.html",
        "summary": "http://yourwebsite.com/opcache.php",
    }]
    res = ({'TC.Indicator(val.ID && val.ID === obj.ID)': [{'Confidence': 32,
                                                           'CreateDate': '2021-12-09T12:57:18Z',
                                                           'Description': None,
                                                           'ID': 40435508,
                                                           'LastModified': '2022-07-26T13:51:49Z',
                                                           'Name': 'http://yourwebsite.com/opcache.php',
                                                           'Owner': 'Technical Blogs and '
                                                                    'Reports',
                                                           'Rating': 3,
                                                           'Type': 'URL',
                                                           'WebLink': 'https://partnerstage.threatconnect.com/auth'
                                                                      '/indicators/details/url.xhtml?orgid=40435508'}],
            'URL(val.Data && val.Data == obj.Data)': [{'Data': 'http://yourwebsite.com/opcache.php',
                                                       'Malicious': {'Description': '',
                                                                     'Vendor': 'ThreatConnect'}}]},
           [{'Confidence': 32,
             'CreateDate': '2021-12-09T12:57:18Z',
             'Description': None,
             'ID': 40435508,
             'LastModified': '2022-07-26T13:51:49Z',
             'Name': 'http://yourwebsite.com/opcache.php',
             'Owner': 'Technical Blogs and Reports',
             'Rating': 3,
             'Type': 'URL',
             'WebLink': 'https://partnerstage.threatconnect.com/auth/indicators/details/url.xhtml?orgid=40435508'}])
    assert create_context(indicators) == res


def test_list_groups(mocker):
    mock = mocker.patch.object(Client, 'make_request', return_value={})
    client = Client(api_id='test', api_secret='test', base_url='https://test.com')
    list_groups(client, {}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=0&resultLimit=100'
    list_groups(client, {'tag': 'a,b'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=a%2Cbtag%20like%20%22%25a%25%22%20AND%20tag%20like%' \
                                     '20%22%25b%25%22&fields=tags&resultStart=0&resultLimit=100'
    list_groups(client, {'id': 'test'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=%28id%3Dtest%20%29&resultStart=0&resultLimit=100'
    list_groups(client, {'fromDate': '2022.08.08'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=dateAdded%20%3E%20%222022.08.08%22%20&resultStart=' \
                                     '0&resultLimit=100'
    list_groups(client, {'security_label': 'TLP:AMBER'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=securityLabel%20like%20%22%25TLP%3AAMBER%25%22&fields=' \
                                     'securityLabels&resultStart=0&resultLimit=100'
    list_groups(client, {'group_type': 'Incident'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=typeName%20EQ%20%22Incident%22&resultStart=' \
                                     '0&resultLimit=100'
    list_groups(client, {'filter': 'dateAdded > 2022-03-03'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=dateAdded%20%3E%202022-03-03&resultStart=0&resultLimit=100'
    list_groups(client, {'limit': '666'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=0&resultLimit=666'
    list_groups(client, {'page': '777'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?resultStart=777&resultLimit=100'
    list_groups(client, {'page': '777', 'limit': '666', 'group_type': 'Incident'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=typeName%20EQ%20%22Incident%22&resultStart=777&resultLimit=666'
    list_groups(client, {'security_label': 'TLP:AMBER', 'tag': 'a,b', 'id': 'test'}, return_raw=True)
    assert mock.call_args.args[1] == '/api/v3/groups?tql=%28id%3Dtest%20%29a%2Cb%20AND%20tag%20like%20%22%25a%25' \
                                     '%22%20AND%20tag%20like%20%22%25b%25%22%20AND%20securityLabel%20like%20%22%25TLP' \
                                     '%3AAMBER%25%22&fields=tags&fields=securityLabels&resultStart=0&resultLimit=100'


def test_set_additional_data_with_mode():
    """
    Given:
        - Labels with a mode
    When:
        - Setting additional data with a mode
    Then:
        - The output should include the provided mode
    """
    labels = ['label1', 'label2']
    mode = 'test_mode'
    expected_output = {
        'data': [{'name': 'label1'}, {'name': 'label2'}],
        'mode': mode
    }
    assert set_additional_data(labels, mode) == expected_output


@pytest.mark.parametrize(
    "is_update, asset_type, asset_value, address_type, network_type, social_network, expected_output",
    [
        (False, AssetType.EMAIL_ADDRESS, 'test@example.com', 'personal', None, 'Twitter',
         {
             'address': 'test@example.com',
             'type': AssetType.EMAIL_ADDRESS,
             'addressType': 'personal',
             'socialNetwork': 'Twitter'
         }),
        (True, AssetType.EMAIL_ADDRESS, 'test@example.com', None, 'internet', None,
         {
             'address': 'test@example.com',
             'networkType': 'internet'
         })
    ],
)
def test_set_victim_asset(is_update, asset_type, asset_value, address_type, network_type, social_network, expected_output):
    """
    Given:
        - Victim asset parameters
    When:
        - Setting victim asset
    Then:
        - The output is in the correct structure
    """
    result = set_victim_asset(is_update, asset_type, asset_value, address_type, network_type, social_network)
    assert result == expected_output


def test_create_victim_command(mocker):
    """
    Given:
        - Victim parameters
    When:
        - Creating victim
    Then:
        - The request is in the correct structure
    """
    args = {
        'name': 'Test Victim',
        'nationality': 'Test Nationality',
        'org': 'Test Org',
        'attribute_type': 'Test Attribute Type',
        'attribute_value': 'Test Attribute Value',
        'asset_type': AssetType.PHONE,
        'security_labels': "TLP:RED",
        'asset_value': 'Test Asset Value'
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_create_victim_command(client, args)
    payload = res.call_args[1]['payload']
    payload_data = json.loads(payload)
    assert payload_data['name'] == 'Test Victim'
    assert payload_data['nationality'] == 'Test Nationality'
    assert payload_data['org'] == 'Test Org'
    assert 'attributes' in payload_data
    assert 'assets' in payload_data
    assert 'securityLabels' in payload_data


def test_create_victim_asset_command(mocker):
    """
    Given:
        - Victim asset parameters
    When:
        - Creating victim asset
    Then:
        - The request is in the correct structure
    """
    args = {
        'victim_id': 'test_victim_id',
        'asset_type': AssetType.PHONE,
        'asset_value': 'Test Asset Value',
        'asset_address_type': 'Test Address Type'
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_create_victim_asset_command(client, args)
    payload = res.call_args[1]['payload']
    payload_data = json.loads(payload)
    assert payload_data['victimId'] == 'test_victim_id'
    assert payload_data['type'] == AssetType.PHONE.value
    assert payload_data['addressType'] == 'Test Address Type'


def test_create_victim_attributes_command(mocker):
    """
    Given:
        - Victim attribute parameters
    When:
        - Creating victim attriburte
    Then:
        - The request is in the correct structure
    """
    args = {
        'victim_id': 'test_victim_id',
        'attribute_type': 'Test Attribute Type',
        'attribute_value': 'Test Attribute Value',
        'source': 'Test Source',
        'security_labels': ['TLP:GREEN', 'TLP:RED']
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_create_victim_attributes_command(client, args)
    payload = res.call_args[1]['payload']
    payload_data = json.loads(payload)
    assert payload_data['victimId'] == 'test_victim_id'
    assert payload_data['type'] == 'Test Attribute Type'
    assert payload_data['value'] == 'Test Attribute Value'
    assert payload_data['source'] == 'Test Source'
    assert 'securityLabels' in payload_data


def test_update_victim_command(mocker):
    """
    Given:
        - Victim parameters
    When:
        - Updating victim
    Then:
        - The request is in the correct structure
    """
    args = {
        'mode': 'delete',
        'victim_id': 'test_victim_id',
        'name': 'Updated Victim Name',
        'nationality': 'Updated Nationality',
        'org': 'Updated Org',
        'sub_org': 'Updated Sub Org',
        'security_labels': ['TLP:GREEN', 'TLP:RED'],
        'tags': ['Tag1', 'Tag2'],
        'work_location': 'Updated Work Location',
        'asset_type': AssetType.EMAIL_ADDRESS,
        'asset_value': 'Updated@example.com',
        'asset_address_type': 'Updated Address Type',
        'asset_network_type': 'Updated Network Type',
        'asset_social_network': 'Updated Social Network',
        'attribute_type': 'Updated Attribute Type',
        'attribute_value': 'Updated Attribute Value',
        'associated_groups_ids': ['group_id_1', 'group_id_2']
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_update_victim_command(client, args)
    payload = res.call_args[1]['payload']
    payload_data = json.loads(payload)

    assert payload_data['name'] == 'Updated Victim Name'
    assert payload_data['nationality'] == 'Updated Nationality'
    assert payload_data['org'] == 'Updated Org'
    assert payload_data['suborg'] == 'Updated Sub Org'
    assert 'securityLabels' in payload_data
    assert 'tags' in payload_data
    assert payload_data['workLocation'] == 'Updated Work Location'
    assert 'assets' in payload_data
    assert 'attributes' in payload_data
    assert 'associatedGroups' in payload_data
    assert payload_data['associatedGroups']['mode'] == 'delete'


def test_update_victim_asset_command(mocker):
    """
    Given:
        - Victim asset parameters
    When:
        - Updating victim asset
    Then:
        - The request is in the correct structure
    """
    args = {
        'victim_asset_id': 'test_victim_asset_id',
        'asset_value': 'Updated Asset Value',
        'asset_address_type': 'Updated Address Type'
    }

    # Mocking the GET request to fetch the victim asset data
    victim_asset_data = {
        'data': {
            'type': AssetType.EMAIL_ADDRESS.value  # Assuming the type is EMAIL for testing purposes
            # Include other necessary fields here for a comprehensive test
        }
    }
    res = mocker.patch.object(Client, 'make_request', side_effect=[victim_asset_data, {}])
    tc_update_victim_asset_command(client, args)
    payload = res.call_args[1]['payload']
    url = res.call_args[1]['url_suffix']
    payload_data = json.loads(payload)
    assert 'test_victim_asset_id' in url
    assert payload_data['addressType'] == 'Updated Address Type'
    assert 'type' not in payload_data


def test_update_victim_attributes_command(mocker):
    """
    Given:
        - Victim attribute parameters
    When:
        - Updating victim attribute
    Then:
        - The request is in the correct structure
    """
    args = {
        'victim_attribute_id': 'test_victim_attribute_id',
        'attribute_value': 'Updated Attribute Value',
        'source': 'Updated Source',
        'security_labels': ['TLP:GREEN', 'TLP:RED']
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_update_victim_attributes_command(client, args)
    payload = res.call_args[1]['payload']
    payload_data = json.loads(payload)
    url = res.call_args[1]['url_suffix']
    assert 'test_victim_attribute_id' in url
    assert payload_data['value'] == 'Updated Attribute Value'
    assert payload_data['source'] == 'Updated Source'
    assert 'securityLabels' in payload_data


ARGS_INCLUDE_ASSETS_ATTRIBUTES = {
    'include_assets': True,
    'include_associated_groups': False,
    'include_attributes': True,
    'include_security_labels': False,
    'filter': 'Test Filter',
    'victim_id': 'test_victim_id',
    'limit': 20,
    'page': 1
}

EXPECTED_URL_ASSETS_ATTRIBUTES = f'{VICTIM_API_PREFIX}/test_victim_id?'\
                                 f'&resultStart=20&resultLimit=20&fields=attributes&fields=assets&tql=Test%20Filter'


ARGS_INCLUDE_ALL = {
    'include_all_metaData': True,
    'filter': 'Test Filter',
    'victim_id': 'test_victim_id',
    'limit': 20,
    'page': 1
}

EXPECTED_URL_INCLUDE_ALL = (f'{VICTIM_API_PREFIX}/test_victim_id?'
                            f'&resultStart=20&resultLimit=20&'
                            f'fields=tags&fields=securityLabels&fields=attributes&fields=associatedGroups&fields=assets'
                            f'&tql=Test%20Filter')


@pytest.mark.parametrize('args, expected_url', [(ARGS_INCLUDE_ASSETS_ATTRIBUTES, EXPECTED_URL_ASSETS_ATTRIBUTES),
                                                (ARGS_INCLUDE_ALL, EXPECTED_URL_INCLUDE_ALL)])
def test_list_victims_command(mocker, args, expected_url):
    """
    Given:
        - List victim parameters
    When:
        - Retrieving all victims
    Then:
        - The url request contains all given fields
    """

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_list_victims_command(client, args)

    # Verifying if the client.make_request method was called with the expected arguments
    actual_url = res.call_args[1]['url_suffix']
    assert expected_url == actual_url


def test_list_victim_assets_command(mocker):
    """
    Given:
        - List victim assets parameters
    When:
        - Retrieving all victim assets
    Then:
        - The url request contains all given fields
    """
    args = {
        'filter': 'Test Filter',
        'victim_asset_id': 'test_victim_asset_id',
        'limit': 20,
        'page': 1
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_list_victim_assets_command(client, args)
    expected_url = f'{VICTIM_ASSET_API_PREFIX}/test_victim_asset_id?&resultStart=20&resultLimit=20&tql=Test%20Filter'
    actual_url = res.call_args[1]['url_suffix']
    assert expected_url == actual_url


def test_list_victim_attributes_command(mocker):
    """
    Given:
        - List victim attributes parameters
    When:
        - Retrieving all victim attributes
    Then:
        - The url request contains all given fields
    """
    args = {
        'filter': 'Test Filter',
        'victim_attribute_id': 'test_victim_attribute_id',
        'limit': 20,
        'page': 1
    }

    res = mocker.patch.object(Client, 'make_request', return_value={})
    tc_list_victim_attributes_command(client, args)
    expected_url = f'{VICTIM_ATTRIBUTE_API_PREFIX}/test_victim_attribute_id?&resultStart=20&resultLimit=20&tql=Test%20Filter'
    actual_url = res.call_args[1]['url_suffix']
    assert expected_url == actual_url


def test_to_readable():
    """
    Given:
        - Response victim assets
    When:
        - Converting the response data to readable outputs
    Then:
        - The readable outputs does not contain the asset value key in the readable data
    """
    response_outputs = json.loads(load_mock_response('assets.json'))
    readable_outputs = to_readable(response_outputs)
    assert 'phone' not in readable_outputs[0]
    assert 'asset' in readable_outputs[0]
    assert 'EmailAddress' not in readable_outputs[1]
    assert 'asset' in readable_outputs[1]
    assert 'SocialNetwork' not in readable_outputs[2]
    assert 'asset' in readable_outputs[2]
    assert 'NetworkAccount' not in readable_outputs[3]
    assert 'asset' in readable_outputs[3]


def test_tc_add_indicator_command_with_description(mocker):
    """
    Given:
        - arguments fot the tc-add-indicator command
    When:
        - Adding an indicator
    Then:
        - The request contains the description attribute
    """
    import ThreatConnectV3
    res = mocker.patch.object(Client, 'make_request', return_value={})
    mocker.patch.object(ThreatConnectV3, 'create_context', return_value=([], []))
    tc_add_indicator_command(client, {'tags': [], 'indicator': '1.1.1.1',
                                      'indicatorType': 'Address',
                                      'description': 'description'})
    # Verifying if the client.make_request method was called with the expected arguments
    call_args = json.loads(res.call_args[1]["payload"])
    assert {"type": "Description", "value": "description", "default": True} in call_args["attributes"]["data"]
