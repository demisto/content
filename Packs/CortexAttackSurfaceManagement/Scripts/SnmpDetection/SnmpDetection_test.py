from SnmpDetection import snmp_detect
import json
import SnmpDetection


def load_test_data(json_path):
    """Load test data from json file."""
    with open(json_path) as f:
        return json.load(f)


def test_snmp_v1(mocker):
    """Unit tests for SNMP Version 1."""
    snmp_v1_response = load_test_data('./test_data/snmp_output.json')
    mocker.patch.object(SnmpDetection, 'snmp_v1', return_value=snmp_v1_response)
    result = snmp_detect("1.1.1.1", 3)
    assert isinstance(result, dict)
    assert result == {'enabled': 'True', 'versions': ['v1']}


def test_snmp_v2(mocker):
    """Unit tests for SNMP Version 2."""
    snmp_v2_response = load_test_data('./test_data/snmp_output.json')
    mocker.patch.object(SnmpDetection, 'snmp_v2', return_value=snmp_v2_response)
    result = snmp_detect("1.1.1.1", 3)
    assert isinstance(result, dict)
    assert result == {'enabled': 'True', 'versions': ['v2']}


def test_snmp_v3(mocker):
    """Unit tests for SNMP Version 3."""
    snmp_v3_response = load_test_data('./test_data/snmp_output.json')
    mocker.patch.object(SnmpDetection, 'snmp_v3', return_value=snmp_v3_response)
    result = snmp_detect("1.1.1.1", 3)
    assert isinstance(result, dict)
    assert result == {'enabled': 'True', 'versions': ['v3']}


def test_snmp_multiple_versions(mocker):
    """Unit tests for multiple SNMP Versions."""
    snmp__multiple_response = load_test_data('./test_data/snmp_output.json')
    mocker.patch.object(SnmpDetection, 'snmp_v1', return_value=snmp__multiple_response)
    mocker.patch.object(SnmpDetection, 'snmp_v2', return_value=snmp__multiple_response)
    mocker.patch.object(SnmpDetection, 'snmp_v3', return_value=snmp__multiple_response)
    result = snmp_detect("1.1.1.1", 3)
    assert isinstance(result, dict)
    assert result == {'enabled': 'True', 'versions': ['v1', 'v2', 'v3']}


def test_snmp_no_versions(mocker):
    """Unit tests for disabled SNMP."""
    result = snmp_detect("1.1.1.1", 3)
    assert result == {'enabled': 'False', 'versions': []}
