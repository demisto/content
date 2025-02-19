import json
import pytest
import demistomock as demisto

from CommonServerPython import DemistoException, ThreatIntel, FeedIndicatorType
from FeedMISP import parsing_user_query, build_indicators_iterator, \
    handle_file_type_fields, get_galaxy_indicator_type, build_indicators_from_galaxies, \
    update_indicator_fields, get_ip_type, Client, fetch_attributes_command


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


def test_parsing_user_query_success():
    """
    Given
        - A json string query
    When
        - query is good
    Then
        - create a dict from json string
    """
    querystr = '{"returnFormat": "json","limit": "3", "type": {"OR": ["ip-src"]}, "tags": {"OR": ["tlp:%"]}}'
    params = parsing_user_query(querystr, limit=40000)
    assert len(params) == 5


def test_parsing_user_query_bad_query():
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
        parsing_user_query(querystr, limit=4)


def test_parsing_user_query_change_format():
    """
    Given
        - A json parsed result from qualys
    When
        - query has a unsupported return format
    Then
        - change return format to json
    """
    querystr = '{"returnFormat": "xml", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = parsing_user_query(querystr, limit=4)
    assert params["returnFormat"] == "json"


def test_parsing_user_query_remove_timestamp():
    """
    Given
        - A json parsed result from qualys
    When
        - query has timestamp parameter
    Then
        - Return query without the timestamp parameter
    """
    good_query = ('{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}, "page": 1, "limit": 2000,'
                  ' "attribute_timestamp": "1617875568"}')
    querystr = '{"returnFormat": "json", "timestamp": "1617875568", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = parsing_user_query(querystr, limit=2)
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


@pytest.mark.parametrize(
    "indicator, feed_tags, expected_calls",
    [
        (
            {
                "value": "some_value",
                "type": "IP",
                "service": "MISP",
                "fields": {},
                "rawJSON": {
                    "value": {
                        "Tag": [
                            {
                                "name": 'misp-galaxy:mitre-attack-pattern="Some Value - R1234"',
                            }
                        ]
                    }
                },
            },
            None,
            1,
        ),
        (
            {
                "value": "some_value",
                "type": "IP",
                "service": "MISP",
                "fields": {},
                "rawJSON": {"value": {}},
            },
            ["test", "test2"],
            1,
        ),
        (
            {
                "value": "some_value",
                "type": "IP",
                "service": "MISP",
                "fields": {},
                "rawJSON": {"value": {}},
            },
            None,
            0,
        ),
    ],
)
def test_update_indicator_fields(
    mocker, indicator: dict, feed_tags: list | None, expected_calls: int
):
    """
    Given:
        - indicator and feed_tags argument
    When:
        - the update_indicator_fields function runs
    Then:
        - Ensure the update_indicator_fields function is called
          if the feed_tags argument is passed even though the indicator has no tag.
        - Ensure the update_indicator_fields function is called when the indicator has tag.
        - Ensure the update_indicator_fields function is not called
          when the indicator has no tag and no feed_tags argument is sent.
    """
    handle_tags_fields_mock = mocker.patch("FeedMISP.handle_tags_fields")

    update_indicator_fields(indicator, None, "test", feed_tags)
    assert handle_tags_fields_mock.call_count == expected_calls


@pytest.mark.parametrize('indicator, indicator_type', [
    ({'value': '1.1.1.1'}, FeedIndicatorType.IP),
    ({'value': '1.1.1.1/24'}, FeedIndicatorType.CIDR),
    ({'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'}, FeedIndicatorType.IPv6),
    ({'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334/64'}, FeedIndicatorType.IPv6CIDR),
])
def test_get_ip_type(indicator, indicator_type):
    assert get_ip_type(indicator) == indicator_type


def test_search_query_indicators_pagination(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - the fetch_attributes_command function runs
    Then:
        - Ensure the pagination mechanism return the expected result (good http response is returned)
    """
    client = Client(base_url="example",
                    authorization="auth",
                    verify=False,
                    proxy=False,
                    timeout=60,
                    performance=False,
                    max_indicator_to_fetch=2000
                    )
    returned_result_1 = {'response':
                         {'Attribute': [{'id': '1', 'event_id': '1', 'object_id': '0',
                                         'object_relation': None, 'category': 'Payload delivery',
                                         'type': 'sha256', 'to_ids': True, 'uuid': '5fd0c620',
                                         'timestamp': '1607517728', 'distribution': '5', 'sharing_group_id': '0',
                                         'comment': 'malspam', 'deleted': False, 'disable_correlation': False,
                                         'first_seen': None, 'last_seen': None,
                                         'value': 'val1', 'Event': {}},
                                        {'id': '2', 'event_id': '2', 'object_id': '0',
                                         'object_relation': None, 'category': 'Payload delivery',
                                         'type': 'sha256', 'to_ids': True, 'uuid': '5fd0c620',
                                         'timestamp': '1607517728', 'distribution': '5', 'sharing_group_id': '0',
                                         'comment': 'malspam', 'deleted': False, 'disable_correlation': False,
                                         'first_seen': None,
                                         'last_seen': None, 'value': 'val2', 'Event': {}}]}}
    returned_result_2 = {'response': {'Attribute': []}}
    mocker.patch.object(Client, '_http_request', side_effect=[returned_result_1, returned_result_2])
    params_dict = {
        'type': 'attribute',
        'filters': {'category': ['Payload delivery']},
    }
    mocker.patch("FeedMISP.LIMIT", new=2000)
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'createIndicators')
    fetch_attributes_command(client, params_dict)
    indicators = demisto.createIndicators.call_args[0][0]
    assert len(indicators) == 2


def test_search_query_indicators_pagination_bad_case(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - the fetch_attributes_command function runs
    Then:
        - Ensure the pagination mechanism raises an error (bad http response is returned)
    """
    from CommonServerPython import DemistoException
    client = Client(base_url="example",
                    authorization="auth",
                    verify=False,
                    proxy=False,
                    timeout=60,
                    performance=False,
                    max_indicator_to_fetch=2000
                    )
    returned_result = {'Error': 'failed api call'}
    expected_result = "Error in API call - check the input parameters and the API Key. Error: failed api call"
    mocker.patch.object(Client, '_http_request', return_value=returned_result)
    params_dict = {
        'type': 'attribute',
        'filters': {'category': ['Payload delivery']}
    }
    with pytest.raises(DemistoException) as e:
        fetch_attributes_command(client, params_dict)
    assert str(e.value) == expected_result


def test_parsing_user_query_timestamp_deprecated():
    """
        Given:
            - No input
        When:
            - The parsing_user_query function runs
        Then:
            - Ensure the parsing_user_query function correctly parses the user query JSON string,
              replacing the 'timestamp' key with 'attribute_timestamp' since timestamp deprecated.
        """
    good_query = ('{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}, "page": 1,'
                  ' "limit": 2000, "attribute_timestamp": "1617875568"}')
    query_str = ('{"returnFormat": "json", "timestamp": "1617875568", "type": {"OR": ["md5"]},'
                 ' "tags": {"OR": ["tlp:%"]}}')
    params = parsing_user_query(query_str, limit=2)
    assert good_query == json.dumps(params)


def test_ignore_last_fetched_indicator(mocker):
    """
    Given:
        - The fetch_attributes_command function is called with a client object and a params_dict.
    When:
        - The last fetched indicator is returned when already fetched.
    Then:
        - The fetch_attributes_command function should ignore the last fetched indicator and continue fetching new indicators.
    """
    client = Client(base_url="example",
                    authorization="auth",
                    verify=False,
                    proxy=False,
                    timeout=60,
                    performance=False,
                    max_indicator_to_fetch=2000
                    )
    mocked_result = {'response':
                     {'Attribute': [{'id': '1', 'event_id': '1', 'object_id': '0',
                                     'object_relation': None, 'category': 'Payload delivery',
                                     'type': 'sha256', 'to_ids': True, 'uuid': '5fd0c620',
                                     'timestamp': '1607517728', 'distribution': '5', 'sharing_group_id': '0',
                                     'comment': 'malspam', 'deleted': False, 'disable_correlation': False,
                                     'first_seen': None, 'last_seen': None,
                                     'value': 'test', 'Event': {}}]}}
    mocker.patch.object(Client, '_http_request', side_effect=[mocked_result])
    params_dict = {
        'type': 'attribute',
        'filters': {'category': ['Payload delivery']},
    }
    mocked_last_run = {"last_indicator_timestamp": "1607517728", "last_indicator_value": "test"}
    mocker.patch.object(demisto, 'getLastRun', return_value=mocked_last_run)
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'createIndicators')
    fetch_attributes_command(client, params_dict)
    indicators = demisto.createIndicators.call_args
    assert not indicators  # No indicators should be created since the latest indicator was already fetched


def test_fetch_new_indicator_after_last_indicator_been_ignored(mocker):
    """
    Given:
        - The fetch_attributes_command function is called with a client object and a params_dict.
    When:
        - The latest retrieved indicators been ignored and new indicator is fetched.
    Then:
        - The fetch_attributes_command function should fetch the next indicator and set the new last run.
    """
    client = Client(base_url="example",
                    authorization="auth",
                    verify=False,
                    proxy=False,
                    timeout=60,
                    performance=False,
                    max_indicator_to_fetch=2000
                    )
    mocked_result_1 = {'response':
                       {'Attribute': [{'id': '1', 'event_id': '1', 'object_id': '0',
                                       'object_relation': None, 'category': 'Payload delivery',
                                       'type': 'sha256', 'to_ids': True, 'uuid': '5fd0c620',
                                       'timestamp': '1607517728', 'distribution': '5', 'sharing_group_id': '0',
                                       'comment': 'malspam', 'deleted': False, 'disable_correlation': False,
                                       'first_seen': None, 'last_seen': None,
                                       'value': 'test1', 'Event': {}},
                                      {'id': '2', 'event_id': '2', 'object_id': '0',
                                       'object_relation': None, 'category': 'Payload delivery',
                                       'type': 'sha256', 'to_ids': True, 'uuid': '5fd0c620',
                                       'timestamp': '1607517729', 'distribution': '5', 'sharing_group_id': '0',
                                       'comment': 'malspam', 'deleted': False, 'disable_correlation': False,
                                       'first_seen': None,
                                       'last_seen': None, 'value': 'test2', 'Event': {}}]}}
    mocked_result_2 = {'response':
                       {'Attribute': []}}
    mocker.patch.object(Client, '_http_request', side_effect=[mocked_result_1, mocked_result_2])
    params_dict = {
        'type': 'attribute',
        'filters': {'category': ['Payload delivery']},
    }
    mocked_last_run = {"last_indicator_timestamp": "1607517728", "last_indicator_value": "test1"}
    mocker.patch.object(demisto, 'getLastRun', return_value=mocked_last_run)
    setLastRun_mocked = mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'createIndicators')
    fetch_attributes_command(client, params_dict)
    indicators = demisto.createIndicators.call_args[0][0]
    # The last ignored indicator will be re-fetched as we query his timestamp,
    # but the new last run will be updated with the new indicator.
    assert len(indicators) == 2
    assert setLastRun_mocked.called


def test_set_last_run_pagination(mocker):
    """
    Given:
         - The set_last_run_pagination function is called with a list of indicators, a next_page value, and a last_run dictionary.
    When:
        - The function is called to set the last run with the appropriate values.
    Then:
        - Ensure the last run is set correctly with the appropriate values
    """
    from FeedMISP import update_candidate

    # Sample indicators
    indicators = [
        {'value': 'test1', 'timestamp': '1607517728'},
        {'value': 'test2', 'timestamp': '1607517729'}
    ]

    # Test parameters
    last_run = {"last_indicator_timestamp": "1607517727", "last_indicator_value": "test0"}
    last_run_timestamp = last_run["last_indicator_timestamp"]
    last_run_value = last_run["last_indicator_value"]
    latest_indicator_timestamp = indicators[-1]["timestamp"]
    latest_indicator_value = indicators[-1]["value"]

    # Call the function
    update_candidate(last_run, last_run_timestamp,
                     latest_indicator_timestamp, latest_indicator_value)

    # Assert that setLastRun was called with the correct arguments
    expected_last_run = {'last_indicator_timestamp': last_run_timestamp, 'candidate_timestamp': latest_indicator_timestamp,
                         'last_indicator_value': last_run_value,
                         'candidate_value': latest_indicator_value}
    assert last_run == expected_last_run


def test_build_indicators_from_galaxies_tool_type():
    """
    Given:
        - An indicator object containing a MISP tag for a MITRE tool.
    
    When:
        - The build_indicators_from_galaxies function is called with the indicator object and a high reputation level.
    
    Then:
        - The extracted indicator should have the correct 'value' corresponding to the tool name.
        - The 'type' should be 'Tool'.
        - The 'service' should be 'MISP'.
        - The 'Reputation' should be 'High'.
    """
    from FeedMISP import build_indicators_from_galaxies

    indicator_obj = {
        'rawJSON': {
            'value': {
                'Tag': [{'name': 'misp-galaxy:mitre-tool="aaa aaa"'}]
            }
        }
    }

    galaxy_indicators = build_indicators_from_galaxies(indicator_obj, 'High')[0]

    assert galaxy_indicators['value'] == 'aaa aaa'
    assert galaxy_indicators['type'] == 'Tool'
    assert galaxy_indicators['service'] == 'MISP'
    assert galaxy_indicators['Reputation'] == 'High'


def test_build_indicators_from_galaxies_attack_type():
    """
    Given:
        - An indicator object containing a MISP tag for a MITRE attack pattern.
    
    When:
        - The build_indicators_from_galaxies function is called with the indicator object and a high reputation level.
    
    Then:
        - The extracted indicator should have the correct 'value' corresponding to the attack pattern name.
        - The 'type' should be 'Attack Pattern'.
        - The 'service' should be 'MISP'.
        - The 'Reputation' should be 'High'.
    """
    from FeedMISP import build_indicators_from_galaxies

    indicator_obj = {
        'rawJSON': {
            'value': {
                'Tag': [{'name': 'misp-galaxy:mitre-attack-pattern="aaa aaa - 1111"'}]
            }
        }
    }

    galaxy_indicators = build_indicators_from_galaxies(indicator_obj, 'High')[0]

    assert galaxy_indicators['value'] == 'aaa aaa'
    assert galaxy_indicators['type'] == 'Attack Pattern'
    assert galaxy_indicators['service'] == 'MISP'
    assert galaxy_indicators['Reputation'] == 'High'
