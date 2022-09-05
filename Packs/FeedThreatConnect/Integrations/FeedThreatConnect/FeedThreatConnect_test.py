import json
import demistomock as demisto
import pytest
from FeedThreatConnect import create_or_query, parse_indicator, set_tql_query, create_indicator_relationships


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


def test_parse_indicator():
    data_dir = {
        'parsed_indicator.json': './FeedThreatConnect_test/parsed_indicator.json',  # type: ignore # noqa
        'indicators.json': './FeedThreatConnect_test/indicators.json'}  # type: ignore # noqa
    indicator = parse_indicator(load_json_file(data_dir['indicators.json']))
    assert load_json_file(data_dir['parsed_indicator.json']) == indicator


def test_create_or_query():
    assert create_or_query('test', '1,2,3,4,5') == 'test="1" OR test="2" OR test="3" OR test="4" OR test="5" '

@pytest.mark.parametrize(argnames="params, expected_result",
                         argvalues=[({'indicatorActive': False, "groupType": ['All'], "indicatorType": ['All']}, ''),
                                    ({'indicatorActive': True, "groupType": ['File'], "indicatorType": ['All']},
                                      'indicatorActive EQ True AND typeName IN ("File")')])
def test_set_tql_query(mocker, params, expected_result):
    from_date = ''
    mocker.patch.object(demisto, 'params', return_value=params)
    output = set_tql_query(from_date)

    assert output == expected_result
