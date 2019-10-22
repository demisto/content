import pytest
import demistomock as demisto


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'www.qradar.com', 'token': 'token', 'proxy': True})


def test_enrich_offense_res_with_source_and_destination_address_normal(mocker):
    import QRadar as qradar
    mocker.patch.object(qradar, 'extract_source_and_destination_addresses_ids',
                        return_value=(SOURCE_ADDR_IDS_DICT, DEST_ADDR_IDS_DICT))
    mocker.patch.object(qradar, 'enrich_source_addresses_dict')
    mocker.patch.object(qradar, 'enrich_destination_addresses_dict')
    # Assert function enriched offense with destination and source addresses
    assert qradar.enrich_offense_res_with_source_and_destination_address(
        OFFENSE_RAW_RESULT) == ENRICH_OFFENSES_ADDR_EXPECTED


def test_enrich_offense_res_with_source_and_destination_address_exception(mocker):
    import QRadar as qradar
    mocker.patch.object(qradar, 'extract_source_and_destination_addresses_ids',
                        return_value=(SOURCE_ADDR_IDS_DICT, DEST_ADDR_IDS_DICT))
    mocker.patch.object(qradar, 'enrich_source_addresses_dict', side_effect=Exception('Raised exception'))
    # Assert function returns the raw result in case of raised exception
    assert qradar.enrich_offense_res_with_source_and_destination_address(OFFENSE_RAW_RESULT) == OFFENSE_RAW_RESULT


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
