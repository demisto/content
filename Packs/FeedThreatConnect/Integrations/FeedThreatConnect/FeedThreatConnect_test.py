import json
import demistomock as demisto
import pytest
from FeedThreatConnect import create_or_query, parse_indicator, set_tql_query, create_types_query, should_send_request, \
    build_url_with_query_params, set_fields_query, get_updated_last_run


def load_json_file(path):
    with open(path, 'r') as _json_file:
        return json.load(_json_file)


@pytest.mark.parametrize(argnames="threatconnect_score, dbot_score",
                         argvalues=[(1000, 3),
                                    (830, 3),
                                    (664, 2),
                                    (498, 2),
                                    (332, 1),
                                    (166, 1),
                                    (0, 0)])
def test_calculate_dbot_score(threatconnect_score, dbot_score):
    from FeedThreatConnect import calculate_dbot_score
    assert calculate_dbot_score(threatconnect_score) == dbot_score


def test_parse_indicator(mocker):
    mocker.patch.object(demisto, 'params', return_value={'createRelationships': True, 'tlpcolor': None})
    data_dir = {
        'parsed_indicator.json': './test_data/parsed_indicator.json',  # type: ignore # noqa
        'indicators.json': './test_data/indicators.json'}  # type: ignore # noqa
    indicator = parse_indicator(load_json_file(data_dir['indicators.json']))
    assert load_json_file(data_dir['parsed_indicator.json']) == indicator


def test_create_or_query():
    assert create_or_query('test', '1,2,3,4,5') == 'test="1" OR test="2" OR test="3" OR test="4" OR test="5" '


@pytest.mark.parametrize("params, expected_result, endpoint",
                         [({'indicator_active': False, "indicator_type": ['All'],
                           'createRelationships': False, "confidence": 0, "threat_assess_score": 0}, '', 'indicators'),
                          ({'indicator_active': True, "group_type": ['File'],
                           'createRelationships': False, "confidence": 0, "threat_assess_score": 0},
                           'typeName IN ("File")', 'groups'),
                          ({'indicator_active': False, "group_type": ['Tool'],
                           'createRelationships': False, "confidence": 50, "threat_assess_score": 80},
                           'typeName IN ("Tool")', 'groups')])
def test_set_tql_query(params, expected_result, endpoint):
    """
    Given:
        - an empty from_date value and demisto params
        Case 1: expecting no tql query
        Case 2: expecting a specific group type, and only active indicators

    When:
        - running set_tql_query command

    Then:
        - validate the tql output
    """
    from_date = ''
    output = set_tql_query(from_date, params, endpoint)

    assert output == expected_result


@pytest.mark.parametrize("params, expected_result, endpoint",
                         [({"group_type": ['All'], "indicator_type": []}, 'typeName IN ("Attack Pattern","Campaign",'
                          '"Course of Action","Intrusion Set","Malware","Report","Tool","Vulnerability")', 'groups'),
                          ({"group_type": ['File'], "indicator_type": []}, 'typeName IN ("File")', 'groups'),
                          ({"group_type": ['File'], "indicator_type": ['All']}, 'typeName IN ("File")', 'groups')])
def test_create_types_query(params, expected_result, endpoint):
    """
    Given:
        - demisto params and an endpoint
    When:
        - running create_types_query command
    Then:
        - validate the output
    """
    output = create_types_query(params, endpoint)

    assert output == expected_result


@pytest.mark.parametrize("params, expected_result, endpoint",
                         [({"group_type": ['All'], "indicator_type": []}, False, 'indicators'),
                          ({"group_type": [], "indicator_type": ['All']}, True, 'indicators')])
def test_should_send_request(params, expected_result, endpoint):
    """
    Given:
        - demisto params and an endpoint
    When:
        - running should_send_request command
    Then:
        - validate the result
    """
    output = should_send_request(params, endpoint)

    assert output == expected_result


@pytest.mark.parametrize("params, expected_result, endpoint",
                         [({"indicator_type": ['All'], 'indicator_query': '', 'createRelationships': False},
                           '/api/v3/indicators?tql=indicatorActive%20EQ%20True&fields=tags&fields=threatAssess&resultStart'
                           '=0&resultLimit=100&sorting=dateAdded%20ASC', 'indicators'),
                          ({"group_type": ['All'], 'indicator_query': 'indicatorActive EQ False', 'createRelationships': True},
                           '/api/v3/groups?tql=indicatorActive%20EQ%20False&fields=tags&fields=associatedGroups'
                           '&fields=associatedIndicators&resultStart=0&resultLimit=100&sorting=dateAdded%20ASC', 'groups')])
def test_build_url_with_query_params(mocker, params, expected_result, endpoint):
    """
    Given:
        - demisto params and an endpoint
    When:
        - running build_url_with_query_params command
    Then:
        - validate the result
    """
    mocker.patch('FeedThreatConnect.set_tql_query', return_value='indicatorActive EQ True')
    output = build_url_with_query_params(params, endpoint, {})

    assert output == expected_result


@pytest.mark.parametrize("params, expected_result, endpoint",
                         [({'createRelationships': False}, '&fields=tags&fields=threatAssess', 'indicators'),
                          ({'createRelationships': True}, '&fields=tags&fields=associatedGroups&fields=associatedIndicators',
                          'groups')])
def test_set_fields_query(params, expected_result, endpoint):
    """
    Given:
        - demisto params and an endpoint
    When:
        - running set_fields_query command
    Then:
        - validate the result
    """
    output = set_fields_query(params, endpoint)

    assert output == expected_result


@pytest.mark.parametrize("indicators, groups, previous_run, expected_result",
                         [([{'dateAdded': 'dateAdded'}], [{'dateAdded': 'dateAdded'}], {},
                           {'indicators': {'from_date': 'dateAdded'}, 'groups': {'from_date': 'dateAdded'}}),
                          (([{'dateAdded': 'dateAdded'}], [], {'groups': {'from_date': 'from_date'}},
                           {'indicators': {'from_date': 'dateAdded'}, 'groups': {'from_date': 'from_date'}}))])
def test_get_updated_last_run(indicators, groups, previous_run, expected_result):
    """
    Given:
        - list of indicators, list of groups, and a previouse run
    When:
        - running get_updated_last_run command
    Then:
        - validate the result
    """
    output = get_updated_last_run(indicators, groups, previous_run)

    assert output == expected_result
