import pytest
import demistomock as demisto


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
    qradar.get_reference_by_name(NON_URL_SAFE_MSG)
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
