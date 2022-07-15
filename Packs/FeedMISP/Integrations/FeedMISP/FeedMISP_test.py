import json
import pytest
import demistomock as demisto

from CommonServerPython import DemistoException, ThreatIntel
from FeedMISP import clean_user_query, build_indicators_iterator, \
    handle_file_type_fields, get_galaxy_indicator_type, build_indicators_from_galaxies, update_indicators_iterator


def test_build_indicators_iterator_success():
    """
     Given
         - A list of attributes returned from MISP
     When
         - Attributes are well formed
     Then
         - Create an iterator of indicators
     """
    attributes = {
        'response': {
            'Attribute': [
                {
                    'id': '123',
                    'type': 'sha256',
                    'value': '123456789',
                },
            ]
        }
    }
    attributes_iterator = build_indicators_iterator(attributes, "some_url")
    assert len(attributes_iterator) == 1
    assert attributes_iterator[0]['value'] == attributes['response']['Attribute'][0]


def test_build_indicators_iterator_fail():
    """
     Given
         - A list of attributes returned from MISP
     When
         - Attributes are not well formed
     Then
         - Raise a KeyError
     """
    with pytest.raises(KeyError):
        attributes = {"wrong_key": "some_value"}
        build_indicators_iterator(attributes, "some_url")


def test_handle_file_type_fields_simple_hash():
    """
    Given
        - Indicator created from an attribute of a hash
    When
        - Indicator contains only hash value
    Then
        - Set the hash value as a field of a matching hash name
    """
    raw_type = 'sha256'
    indicator_obj = {
        'value': 'somehashvalue',
        'type': 'File',
        'service': 'MISP',
        'fields': {}
    }
    handle_file_type_fields(raw_type, indicator_obj)
    assert indicator_obj['fields']['SHA256'] == 'somehashvalue'


def test_handle_file_type_fields_hash_and_filename():
    """
    Given
        - Indicator created from an attribute of a hash and filename
    When
        - Indicator contains both hash value and a filename
    Then
        - Set the hash value as a field of a matching hash name, update the value of the indicator
          to the hash value and add 'Associated File Names' field with the filename
    """
    raw_type = 'filename|sha256'
    indicator_obj = {
        'value': 'file.exe|somehashvalue',
        'type': 'File',
        'service': 'MISP',
        'fields': {}
    }
    handle_file_type_fields(raw_type, indicator_obj)
    assert indicator_obj['fields']['SHA256'] == 'somehashvalue'
    assert indicator_obj['fields']['Associated File Names'] == 'file.exe'
    assert indicator_obj['value'] == 'somehashvalue'


def test_clean_user_query_success():
    """
    Given
        - A json string query
    When
        - query is good
    Then
        - create a dict from json string
    """
    querystr = '{"returnFormat": "json", "type": {"OR": ["ip-src"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert len(params) == 3


def test_clean_user_query_bad_query():
    """
    Given
        - A json string query
    When
        - json syntax is incorrect
    Then
        - raise a DemistoException
    """
    with pytest.raises(DemistoException):
        querystr = '{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]'
        clean_user_query(querystr)


def test_clean_user_query_change_format():
    """
    Given
        - A json parsed result from qualys
    When
        - query has a unsupported return format
    Then
        - change return format to json
    """
    querystr = '{"returnFormat": "xml", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert params["returnFormat"] == "json"


def test_clean_user_query_remove_timestamp():
    """
    Given
        - A json parsed result from qualys
    When
        - query has timestamp parameter
    Then
        - Return query without the timestamp parameter
    """
    good_query = '{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    querystr = '{"returnFormat": "json", "timestamp": "1617875568", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert good_query == json.dumps(params)


def test_get_galaxy_indicator_type_success():
    """
    Given
        - Galaxy name
    When
        - Galaxy name is of a supported type
    Then
        - Return the matching indicator type
    """
    galaxy_name = 'misp-galaxy:mitre-attack-pattern="Testing - R123"'
    assert get_galaxy_indicator_type(galaxy_name) == ThreatIntel.ObjectsNames.ATTACK_PATTERN


def test_get_galaxy_indicator_type_doesnt_exist():
    """
    Given
        - Galaxy name
    When
        - Galaxy name is not supported
    Then
        - Return None
    """
    galaxy_name = 'misp-galaxy:doesnt-exist="Testing - R123"'
    assert get_galaxy_indicator_type(galaxy_name) is None


def test_build_indicators_from_galaxies():
    """
    Given
        - Indicator with galaxy tags
    When
        - Only one of the two galaxies is supported
    Then
        - Return List with an indicator created from the supported galaxy
    """
    indicator_obj = {
        'value': 'some_value',
        'type': 'IP',
        'service': 'MISP',
        'fields': {},
        'rawJSON': {
            'value': {
                'Tag': [
                    {
                        'name': 'misp-galaxy:mitre-attack-pattern="Some Value - R1234"',
                    },
                    {
                        'name': 'misp-galaxy:amitt-misinformation-pattern="fake galaxy"'
                    },
                ]
            }
        }
    }
    galaxy_indicators = build_indicators_from_galaxies(indicator_obj, 'Suspicious')
    assert len(galaxy_indicators) == 1
    assert galaxy_indicators[0]['value'] == "Some Value"
    assert galaxy_indicators[0]['type'] == ThreatIntel.ObjectsNames.ATTACK_PATTERN


def test_update_indicators_iterator_first_fetch(mocker):
    """
    Given
        - Indicators received
    When
        - First fetch, no last run parameters
    Then
        - return all indicators
    """
    indicators_iterator = [
        {
            'value': {'timestamp': '5'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '1'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '3'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
    ]
    query = {'key': 'val'}
    mocker.patch.object(demisto, 'getLastRun', return_value=None)
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert added_indicators_iterator == indicators_iterator


def test_update_indicators_iterator_timestamp_exists_all_new_indicators_same_query(mocker):
    """
     Given
         - Indicators received, lastrun has timestamp and query
     When
         - indicators updated after timestamp and same query as before
     Then
         - return all indicators
     """
    indicators_iterator = [
        {
            'value': {'timestamp': '5'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '1'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '3'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
    ]
    query = {'key': 'val'}
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '0', 'params': query})
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert added_indicators_iterator == indicators_iterator


def test_update_indicators_iterator_timestamp_exists_no_new_indicators_same_query(mocker):
    """
     Given
         - Indicators received, lastrun has the timestamp and query
     When
         - last run timestamp is bigger then the indicators timestamp and query is the same
     Then
         - return no indicators
     """
    indicators_iterator = [
        {
            'value': {'timestamp': '1'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '3'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
    ]
    query = {'key': 'val'}
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '4', 'params': query})
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert not added_indicators_iterator


def test_update_indicators_iterator_timestamp_exists_some_new_indicators_same_query(mocker):
    """
     Given
         - Indicators received, lastrun has the timestamp and query
     When
         - some indicators has timestamp bigger then the lastrun timestamp
     Then
         - return indicators which have timestamp bigger then lastrun timestamp
     """
    indicators_iterator = [
        {
            'value': {'timestamp': '5'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '1'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '3'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
    ]
    query = {'key': 'val'}
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '4', 'params': query})
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert added_indicators_iterator[0]['value']['timestamp'] == '5'


def test_update_indicators_iterator_timestamp_exists_no_indicators_same_query(mocker):
    """
     Given
         - No indicators received
     When
         - lastrun has timestamp and query
     Then
         - return no indicators
     """
    indicators_iterator = []
    query = {'key': 'val'}
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '4', 'params': query})
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert not added_indicators_iterator


def test_update_indicators_iterator_indicators_before_timestamp_different_query(mocker):
    """
     Given
         - Indicators received, lastrun has the timestamp and query
     When
         - all indicators have smaller timestamp then lastrun but query has changed
     Then
         - reset lastrun and return all indicators
     """
    indicators_iterator = [
        {
            'value': {'timestamp': '1'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
        {
            'value': {'timestamp': '3'},
            'type': 'IP',
            'raw_type': 'ip-src',
        },
    ]
    query = {'key': 'val'}
    old_query = {'key': 'old'}
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '4', 'params': old_query})
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, query, True)
    assert added_indicators_iterator == indicators_iterator
