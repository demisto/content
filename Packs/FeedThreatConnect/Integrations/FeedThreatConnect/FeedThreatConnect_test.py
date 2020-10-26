import pytest
import demistomock as demisto


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
    from json import load

    assert load(datadir['parsed_indicator.json'].open()) == parse_indicator(load(datadir['indicators.json'].open()))


def test_parse_indicator_with_tlp(mocker, datadir):
    from FeedThreatConnect import parse_indicator
    from json import load

    expected_result = load(datadir['parsed_indicator.json'].open())
    expected_result['fields']['trafficlightprotocol'] = 'AMBER'

    mocker.patch.object(demisto, 'params', return_value={'tlp_color': 'AMBER'})
    assert expected_result == parse_indicator(load(datadir['indicators.json'].open()))
