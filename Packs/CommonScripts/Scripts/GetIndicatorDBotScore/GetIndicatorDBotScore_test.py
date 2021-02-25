import pytest


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
