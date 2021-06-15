import pytest
import demistomock as demisto
import CommonServerPython

GetIndicatorDBotScoreFunc = 'GetIndicatorDBotScore.get_dbot_score_data'


@pytest.mark.parametrize(
    "indicator, indicator_type, expected",
    [
        ('test_indicator', 'File SHA-256', 'file'),
        ('test_indicator', 'File SHA256', 'file'),
        ('test_indicator', 'File', 'file'),
        ('test_indicator', 'CVE', 'cve'),
        ('test_indicator', 'IP', 'ip'),
        ('test_indicator', 'Email', 'email'),
        ('test_indicator', 'Url', 'url')
    ]

)
def test_validate_indicator_type(indicator, indicator_type, expected):
    """
        Given:
            - an indicator's data

        When:
            - running the script

        Then:
            - validating the dbotScoreType matches the correct indicator type
    """
    from GetIndicatorDBotScore import get_dbot_score_data, INDICATOR_TYPES
    indicator_type_after_mapping = INDICATOR_TYPES.get(indicator_type, indicator_type).lower()
    res = get_dbot_score_data(indicator, indicator_type_after_mapping, 'source', 0)
    assert res.get('Type') == expected


RESPONSE = [{u'Type': 1,
             u'Contents': [
                 {
                     u'indicator_type': u'IP',
                     u'sourceBrands': [u'Source1'],
                     u'score': 1,
                     u'value': u'test',
                 }]}]


@pytest.mark.parametrize(
    "input, expected",
    [
        ('test1', 1),
        (['test1', 'test2'], 2),
        (['test1', 'test2', 'test3'], 3),
        ('test1,test2', 1),
        ('https://expired.badssl.com/?q=1,2,3', 1),
        ('["https://expired.badssl.com/?q=1,2,3", "indicator2"]', 2),
    ]

)
def test_multiple_indicators(mocker, input, expected):
    """
    Given:
            - indicator list as input

        When:
            - running the script

        Then:
            - ensures that every indicator in the input returns one valid result (multiple indicators have multiple results)
    """
    from GetIndicatorDBotScore import main
    mocker.patch.object(CommonServerPython, 'appendContext')
    mocker.patch.object(demisto, 'executeCommand', return_value=RESPONSE)
    mocker.patch.object(demisto, 'args', return_value={'indicator': input})
    main()
    assert demisto.executeCommand.call_count == expected
