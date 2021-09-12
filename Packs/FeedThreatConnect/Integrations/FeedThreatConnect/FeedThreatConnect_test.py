import json

import pytest
import demistomock as demisto


def load_json_file(path):
    with open(path, 'r') as _json_file:
        return json.load(_json_file)


@pytest.mark.parametrize(argnames="threatconnect_score, dbot_score",
                         argvalues=[(500, 3),
                                    (450, 3),
                                    (330, 2),
                                    (220, 2),
                                    (120, 1),
                                    (10, 1),
                                    (0, 0)])
def test_calculate_dbot_score(threatconnect_score, dbot_score):
    from FeedThreatConnect import calculate_dbot_score
    assert calculate_dbot_score(threatconnect_score) == dbot_score


def test_parse_indicator(datadir):
    from FeedThreatConnect import parse_indicator

    assert load_json_file(datadir['parsed_indicator.json']) == parse_indicator(load_json_file(datadir['indicators.json']))


def test_parse_indicator_with_tlp(mocker, datadir):
    from FeedThreatConnect import parse_indicator

    expected_result = load_json_file(datadir['parsed_indicator.json'])
    expected_result['fields']['trafficlightprotocol'] = 'AMBER'

    mocker.patch.object(demisto, 'params', return_value={'tlp_color': 'AMBER'})
    assert expected_result == parse_indicator(load_json_file(datadir['indicators.json']))
