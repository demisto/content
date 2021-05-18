import pytest
import demistomock as demisto
import copy
from random import randrange


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'www.qradar.com', 'token': 'token', 'proxy': True})


def test_enrich_offense_res_with_source_and_destination_address_normal(mocker):
    """
    Given:
        - Offense raw response was fetched successfully with source and destination addresses IDs
    When
        - I enrich the offense with source and destination addresses
    Then
        - The offense result will have the source and destination addresses
    """
    import QRadar as qradar
    # Given:
    #     - Offense raw response was fetched successfully with source and destination addresses IDs
    mocker.patch.object(qradar, 'extract_source_and_destination_addresses_ids',
                        return_value=(SOURCE_ADDR_IDS_DICT, DEST_ADDR_IDS_DICT))
    mocker.patch.object(qradar, 'enrich_source_addresses_dict')
    mocker.patch.object(qradar, 'enrich_destination_addresses_dict')
    # When
    #     - I enrich the offense with source and destination addresses
    enriched_offense = qradar.enrich_offense_res_with_source_and_destination_address(OFFENSE_RAW_RESULT)
    # Then
    #     - The offense result will have the source and destination addresses
    assert enriched_offense[0]['source_address_ids'] == ENRICH_OFFENSES_ADDR_EXPECTED[0]['source_address_ids']
    assert enriched_offense[0]['local_destination_address_ids'] == ENRICH_OFFENSES_ADDR_EXPECTED[0][
        'local_destination_address_ids']


def test_enrich_offense_res_with_source_and_destination_address_exception(mocker):
    """
    Given:
        - Offense raw response was fetched successfully with source and destination addresses IDs
    When
        - I enrich the offense with source and destination addresses, but encounter an exception in the middle
    Then
        - The offense result will be the same as the raw offense response
    """
    import QRadar as qradar
    # Given:
    #     - Offense raw response was fetched successfully with source and destination addresses IDs
    mocker.patch.object(qradar, 'extract_source_and_destination_addresses_ids',
                        return_value=(SOURCE_ADDR_IDS_DICT, DEST_ADDR_IDS_DICT))
    # When
    #     - I enrich the offense with source and destination addresses, but encounter an exception in the middle
    mocker.patch.object(qradar, 'enrich_source_addresses_dict', side_effect=Exception('Raised exception'))
    # Then
    #     - The offense result will be the same as the raw offense response
    assert qradar.enrich_offense_res_with_source_and_destination_address(OFFENSE_RAW_RESULT) == OFFENSE_RAW_RESULT


def test_get_reference_by_name(mocker):
    """
    Given:
        - There's a reference set with non-url safe chars
    When
        - I fetch reference by name
    Then
        - The rest API endpoint will be called with URL safe chars
    """
    import QRadar as qradar
    mocker.patch.object(qradar, 'send_request')
    # Given:
    #     - There's a reference set with non-url safe chars
    # When
    #     - I fetch reference by name
    qradar.get_ref_set(NON_URL_SAFE_MSG)
    # Then
    #     - The rest API endpoint will be called with URL safe chars
    qradar.send_request.assert_called_with('GET', 'www.qradar.com/api/reference_data/sets/{}'.format(
        NON_URL_SAFE_MSG_URL_ENCODED), REQUEST_HEADERS, params={})


def test_delete_reference_set(mocker):
    """
    Given:
        - There's a reference set with non-url safe chars
    When
        - I delete a reference by name
    Then
        - The rest API endpoint will be called with URL safe chars
    """
    import QRadar as qradar
    mocker.patch.object(qradar, 'send_request')
    # Given:
    #     - There's a reference set with non-url safe chars
    # When
    #     - I delete a reference by name
    qradar.delete_reference_set(NON_URL_SAFE_MSG)
    # Then
    #     - The rest API endpoint will be called with URL safe chars
    qradar.send_request.assert_called_with('DELETE', 'www.qradar.com/api/reference_data/sets/{}'.format(
        NON_URL_SAFE_MSG_URL_ENCODED))


def test_update_reference_set_value(mocker):
    """
    Given:
        - There's a reference set with non-url safe chars
    When
        - I fetch reference value by name
    Then
        - The rest API endpoint will be called with URL safe chars
    """
    import QRadar as qradar
    mocker.patch.object(qradar, 'send_request')
    # Given:
    #     - There's a reference set with non-url safe chars
    # When
    #     - I fetch reference value by name
    qradar.update_reference_set_value(NON_URL_SAFE_MSG, 'value')
    # Then
    #     - The rest API endpoint will be called with URL safe chars
    qradar.send_request.assert_called_with('POST', 'www.qradar.com/api/reference_data/sets/{}'.format(
        NON_URL_SAFE_MSG_URL_ENCODED), params={'name': NON_URL_SAFE_MSG, 'value': 'value'})


def test_delete_reference_set_value(mocker):
    """
    Given:
        - There's a reference set with non-url safe chars
    When
        - I delete a reference value by name
    Then
        - The rest API endpoint will be called with URL safe chars
    """
    import QRadar as qradar
    mocker.patch.object(qradar, 'send_request')
    # Given:
    #     - There's a reference set with non-url safe chars
    # When
    #     - I delete a reference value by name
    qradar.delete_reference_set_value(NON_URL_SAFE_MSG, 'value')
    # Then
    #     - The rest API endpoint will be called with URL safe chars
    qradar.send_request.assert_called_with('DELETE', 'www.qradar.com/api/reference_data/sets/{}/value'.format(
        NON_URL_SAFE_MSG_URL_ENCODED), params={'name': NON_URL_SAFE_MSG, 'value': 'value'})


def test_create_incident_from_offense():
    """
    Given:
        - There's an offense
    When:
        - I fetch incidents
    Then:
        - The function will create an incident from the offense
    """
    import QRadar as qradar
    incident = qradar.create_incident_from_offense(OFFENSE_RAW_RESULT[0])
    assert incident['name'] == INCIDENT_RESULT['name']


def test_create_incident_from_offense_no_description():
    """
    Given:
        - There's an offense
    When:
        - I fetch incidents
    Then:
        - The function will create an incident from the offense
    """
    import QRadar as qradar
    expected_incident_name = '49473 '

    raw_offense = copy.deepcopy(OFFENSE_RAW_RESULT[0])
    raw_offense['description'] = ''
    incident = qradar.create_incident_from_offense(raw_offense)
    assert incident['name'] == expected_incident_name

    raw_offense['description'] = None
    incident = qradar.create_incident_from_offense(raw_offense)
    assert incident['name'] == expected_incident_name


def test_create_incident_from_offense_new_line_description():
    """
    Given:
        - There's an offense with \n in its description
    When:
        - I fetch incidents
    Then:
        - The function will create an incident from the offense without \n in the incident name
    """
    import QRadar as qradar
    raw_offense = copy.deepcopy(OFFENSE_RAW_RESULT[0])
    raw_offense['description'] = '\n{}\n'.format(raw_offense['description'])
    incident = qradar.create_incident_from_offense(raw_offense)

    # assert incident['name'] was altered correctly
    assert incident['name'] == '49473  Activacion '

    # assert offense['description'] wasn't altered
    description_asserted = False
    for label in incident['labels']:
        if label.get('type') == 'description':
            assert label.get('value') == '\nActivacion\n'
            description_asserted = True
    assert description_asserted


def test_get_entry_for_object():
    """
    Given:
        There's a title, obj, contents, and headers
    When:
        I call get_entry_for_object
    Then:
        get_entry_for_object will return a an entry with the given headers
    """
    import QRadar as qradar
    title = "Title"
    obj = {'id': 1, 'name': 'test', 'field_to_drop': 'sensitive data'}
    contents = {'test': 'test'}
    headers = u'name'
    # single header
    entry = qradar.get_entry_for_object(title, obj, contents, headers)
    assert entry['HumanReadable'] == '### Title\n|name|\n|---|\n| test |\n'
    entry = qradar.get_entry_for_object(title, obj, contents, str(headers))
    assert entry['HumanReadable'] == '### Title\n|name|\n|---|\n| test |\n'
    assert entry['EntryContext'] == obj
    assert entry['Contents'] == contents

    # multiple headers
    headers = ['name', 'id']
    entry = qradar.get_entry_for_object(title, obj, contents, headers)
    assert 'sensitive data' not in entry['HumanReadable']
    assert 'id' in entry['HumanReadable']
    assert 'name' in entry['HumanReadable']
    assert entry['EntryContext'] == obj
    assert entry['Contents'] == contents


def test_upload_indicators_command_indicators_found(mocker):
    """
    Given:
        - There are indicators in Demisto
    When:
        - Need to upload indicators to QRadar reference set
    Then:
        - The function will upload indicators to QRadar reference set
    """

    import QRadar as qradar
    mocker.patch.object(demisto, 'args', return_value={'ref_name': 'test_ref_set', 'limit': '20', 'page': '0'})
    mocker.patch.object(qradar, 'check_ref_set_exist', return_value=REF_SET_DATA)
    mocker.patch.object(qradar, 'get_indicators_list', return_value=INDICATORS_LIST)
    mocker.patch.object(qradar, 'get_ref_set', return_value=RAW_RESPONSE)
    mocker.patch.object(qradar, 'upload_indicators_list_request', return_value=RAW_RESPONSE)
    mocker.patch.object(qradar, 'enrich_reference_set_result', return_value=REF_SET_DATA)
    res = qradar.upload_indicators_command()
    assert res[2]['name'] == 'test_ref_set'
    assert res[2]['number_of_elements'] == 42
    assert res[2]['element_type'] == 'ALN'


def test_upload_indicators_command_no_indicators_found(mocker):
    """
    Given:
        - There are no indicators in Demisto
    When:
        - Need to upload indicators to QRadar reference set
    Then:
        - The function will not upload indicators to QRadar reference set
    """

    import QRadar as qradar
    mocker.patch.object(demisto, 'args', return_value={'ref_name': 'test_ref_set', 'limit': '20', 'page': '0'})
    mocker.patch.object(qradar, 'check_ref_set_exist', return_value=REF_SET_DATA_NO_INDICATORS)
    mocker.patch.object(qradar, 'get_indicators_list', return_value=([], []))
    res, _, _ = qradar.upload_indicators_command()
    assert res == "No indicators found, Reference set test_ref_set didn't change"


def test_fetch_incidents(mocker):
    """
    Given:
        - There are 3 fetchable offenses in the system with random gaps between them
        - Last run is empty
        - The first fetch is unsuccessful
    When:
        - fetch-incidents is called

    Then:
        - The integration will try to fetch until it fetches the first available offense
        - The integration will set the last run to be GTE to the last fetched offense
    """
    import QRadar as qradar
    # init
    offenses_num = 3
    gap_between_offenses = randrange(5)
    get_offenses_results = []
    first_offense_id = None
    # set offenses_per_call for fetch
    qradar.OFFENSES_PER_CALL = 1

    # prepare offenses with gaps between them
    for i in range(offenses_num - 1):
        for j in range(gap_between_offenses):
            get_offenses_results.append([])
        offense = copy.deepcopy(OFFENSE_RAW_RESULT[0])
        offense['id'] = len(get_offenses_results)
        if first_offense_id is None:
            first_offense_id = offense['id']
        get_offenses_results.append([offense])

    # empty result should be fetched first - triggers look for limit
    get_offenses_results.insert(0, [])
    # last offense should be fetched 2nd - sets limit
    get_offenses_results.insert(1, get_offenses_results[-1])

    mocker.patch.object(demisto, 'params', return_value={'full_enrich': False})
    mocker.patch.object(qradar, 'get_offenses', side_effect=get_offenses_results)
    set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')

    qradar.fetch_incidents()
    assert first_offense_id <= set_last_run_mock.call_args[0][0]['id']


""" CONSTANTS """
REQUEST_HEADERS = {'Content-Type': 'application/json', 'SEC': 'token'}
NON_URL_SAFE_MSG = 'non-safe/;/?:@=&"<>#%{}|\\^~[] `'
NON_URL_SAFE_MSG_URL_ENCODED = 'non-safe%2F%3B%2F%3F%3A%40%3D%26%22%3C%3E%23%25%7B%7D%7C%5C%5E%7E%5B%5D%20%60'

""" API RAW RESULTS """

OFFENSE_RAW_RESULT = [{
    "assigned_to": "mocker",
    "categories": [
        "Unknown Potential Exploit Attack",
        "Potential Web Exploit"
    ],
    "category_count": 2,
    "close_time": None,
    "closing_reason_id": None,
    "closing_user": None,
    "credibility": 2,
    "description": "Activacion",
    "destination_networks": [
        "mock_net"
    ],
    "device_count": 2,
    "domain_id": 27,
    "event_count": 2,
    "flow_count": 0,
    "follow_up": False,
    "id": 49473,
    "inactive": False,
    "last_updated_time": 1563433313767,
    "local_destination_address_ids": [
        1234412
    ],
    "local_destination_count": 1,
    "log_sources": [
        {
            "id": 115,
            "name": "Custom Rule Engine",
            "type_id": 18,
            "type_name": "EventCRE"
        },
        {
            "id": 2439,
            "name": "FortiGate 02",
            "type_id": 73,
            "type_name": "FortiGate"
        }
    ],
    "magnitude": 4,
    "offense_source": "192.168.0.1",
    "offense_type": 0,
    "policy_category_count": 0,
    "protected": False,
    "relevance": 4,
    "remote_destination_count": 0,
    "rules": [
        {
            "id": 166,
            "type": "CRE_RULE"
        }
    ],
    "security_category_count": 2,
    "severity": 6,
    "source_address_ids": [
        294626
    ],
    "source_count": 1,
    "source_network": "other",
    "start_time": 1563433305606,
    "status": "OPEN",
    "username_count": 0
}]

""" FUNCTION MOCK RESULTS """

SOURCE_ADDR_IDS_DICT = {
    294626: '192.168.0.1'
}
DEST_ADDR_IDS_DICT = {
    1234412: '192.168.0.2'
}

ENRICH_OFFENSES_ADDR_EXPECTED = [
    {'offense_source': '192.168.0.1', 'status': 'OPEN', 'remote_destination_count': 0, 'source_count': 1,
     'description': 'Activacion', 'rules': [{'type': 'CRE_RULE', 'id': 166}], 'destination_networks': ['mock_net'],
     'source_address_ids': ['192.168.0.1'], 'policy_category_count': 0, 'last_updated_time': 1563433313767,
     'offense_type': 0, 'category_count': 2, 'inactive': False, 'security_category_count': 2, 'flow_count': 0,
     'protected': False, 'domain_id': 27, 'categories': ['Unknown Potential Exploit Attack', 'Potential Web Exploit'],
     'follow_up': False, 'close_time': None, 'start_time': 1563433305606, 'severity': 6, 'event_count': 2,
     'credibility': 2, 'local_destination_count': 1, 'closing_reason_id': None, 'device_count': 2, 'id': 49473,
     'username_count': 0, 'magnitude': 4, 'closing_user': None, 'source_network': 'other', 'assigned_to': 'mocker',
     'relevance': 4, 'local_destination_address_ids': ['192.168.0.2'],
     'log_sources': [{'type_name': 'EventCRE', 'type_id': 18, 'id': 115, 'name': 'Custom Rule Engine'},
                     {'type_name': 'FortiGate', 'type_id': 73, 'id': 2439, 'name': 'FortiGate 02'}]}]

INCIDENT_RESULT = {
    "labels": [
        {
            "type": "offense_source",
            "value": "192.168.0.1"
        },
        {
            "type": "status",
            "value": "OPEN"
        },
        {
            "type": "remote_destination_count",
            "value": "0"
        },
        {
            "type": "source_count",
            "value": "1"
        },
        {
            "type": "description",
            "value": "Activacion"
        },
        {
            "type": "rules",
            "value": "[{'type': 'CRE_RULE', 'id': 166}]"
        },
        {
            "type": "destination_networks",
            "value": "['mock_net']"
        },
        {
            "type": "source_address_ids",
            "value": "[294626]"
        },
        {
            "type": "policy_category_count",
            "value": "0"
        },
        {
            "type": "last_updated_time",
            "value": "1563433313767"
        },
        {
            "type": "offense_type",
            "value": "0"
        },
        {
            "type": "category_count",
            "value": "2"
        },
        {
            "type": "inactive",
            "value": "False"
        },
        {
            "type": "security_category_count",
            "value": "2"
        },
        {
            "type": "flow_count",
            "value": "0"
        },
        {
            "type": "protected",
            "value": "False"
        },
        {
            "type": "domain_id",
            "value": "27"
        },
        {
            "type": "categories",
            "value": "['Unknown Potential Exploit Attack', 'Potential Web Exploit']"
        },
        {
            "type": "follow_up",
            "value": "False"
        },
        {
            "type": "close_time",
            "value": "None"
        },
        {
            "type": "start_time",
            "value": "1563433305606"
        },
        {
            "type": "severity",
            "value": "6"
        },
        {
            "type": "event_count",
            "value": "2"
        },
        {
            "type": "credibility",
            "value": "2"
        },
        {
            "type": "local_destination_count",
            "value": "1"
        },
        {
            "type": "closing_reason_id",
            "value": "None"
        },
        {
            "type": "device_count",
            "value": "2"
        },
        {
            "type": "id",
            "value": "49473"
        },
        {
            "type": "username_count",
            "value": "0"
        },
        {
            "type": "magnitude",
            "value": "4"
        },
        {
            "type": "closing_user",
            "value": "None"
        },
        {
            "type": "source_network",
            "value": "other"
        },
        {
            "type": "assigned_to",
            "value": "mocker"
        },
        {
            "type": "relevance",
            "value": "4"
        },
        {
            "type": "local_destination_address_ids",
            "value": "[1234412]"
        },
        {
            "type": "log_sources",
            "value": "[{'type_name': 'EventCRE', 'type_id': 18, 'id': 115, 'name': 'Custom Rule Engine'}, {'type_name':"
                     " 'FortiGate', 'type_id': 73, 'id': 2439, 'name': 'FortiGate 02'}]"
        }
    ],
    "name": "49473 Activacion",
    "occurred": "2019-07-18T07:01:45.606000Z",
    "rawJSON": "{\"offense_source\": \"192.168.0.1\", \"status\": \"OPEN\", \"remote_destination_count\": 0, \"source_"
               "count\": 1, \"description\": \"Activacion\", \"rules\": [{\"type\": \"CRE_RULE\", \"id\": 166}], \"de"
               "stination_networks\": [\"mock_net\"], \"source_address_ids\": [294626], \"policy_category_count\": 0, "
               "\"last_updated_time\": 1563433313767, \"offense_type\": 0, \"category_count\": 2, \"inactive\": false, "
               "\"security_category_count\": 2, \"flow_count\": 0, \"protected\": false, \"domain_id\": 27, \"cate"
               "gories\": [\"Unknown Potential Exploit Attack\", \"Potential Web Exploit\"], \"follow_up\": false, \"c"
               "lose_time\": null, \"start_time\": 1563433305606, \"severity\": 6, \"event_count\": 2, \"credibility\":"
               " 2, \"local_destination_count\": 1, \"closing_reason_id\": null, \"device_count\": 2, \"id\": 4947"
               "3, \"username_count\": 0, \"magnitude\": 4, \"closing_user\": null, \"source_network\": \"other\", \"as"
               "signed_to\": \"mocker\", \"relevance\": 4, \"local_destination_address_ids\": [1234412], \"log_sour"
               "ces\": [{\"type_name\": \"EventCRE\", \"type_id\": 18, \"id\": 115, \"name\": \"Custom Rule Engine\"}, "
               "{\"type_name\": \"FortiGate\", \"type_id\": 73, \"id\": 2439, \"name\": \"FortiGate 02\"}]}"
}

INDICATORS_LIST = [{'indicator_type': 'File', 'value': 'file_test'},
                   {'indicator_type': 'Domain', 'value': 'domain.com'}]

RAW_RESPONSE = {
    'timeout_type': 'UNKNOWN',
    'element_type': 'ALN',
    'creation_time': '00000',
    'number_of_elements': 42,
    'name': 'test_ref_set'
}
REF_SET_DATA = {
    'TimeoutType': 'UNKNOWN',
    'ElementType': 'ALN',
    'CreationTime': '00000',
    'NumberOfElements': 42,
    'Name': 'test_ref_set'
}


REF_SET_DATA_NO_INDICATORS = {
    'Name': 'test_ref_set',
    'NumberOfElements': 0,
    'ElementType': 'ALN',
    'TimeoutType': 'UNKNOWN',
}


RAW_RESPONSE_NO_INDICATORS = {
    'TimeoutType': 'UNKNOWN',
    'ElementType': 'ALN',
    'CreationTime': '00000',
    'NumberOfElements': 0,
    'Name': 'test_ref_set'
}
