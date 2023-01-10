import pytest
import dateparser
from ModifyDateTime import apply_variation, main
import demistomock as demisto


@pytest.mark.parametrize('original_time, variation, expected', [
    # sanity
    ('2020/01/01', 'in 1 day', '2020-01-02T00:00:00'),
    # textual variation 1
    ('2020/01/01', 'yesterday', '2019-12-31T00:00:00'),
    # textual variation 2
    ('2020/01/01', 'next month', '2020-02-01T00:00:00'),
    # negative variation
    ('2020-01-01T01:30:00', '-15m', '2020-01-01T01:15:00'),
    # positive variation (treated the same as negative according to datetime.parse)
    ('2020-01-01T01:30:00', '15m', '2020-01-01T01:15:00'),
    # zulu timezone
    ('2020-01-01T10:00:00Z', 'in 15m', '2020-01-01T10:15:00Z'),
    # GMT
    ('2020-01-01T01:30:00+00:00', '15m', '2020-01-01T01:15:00+00:00'),
    # GMT+
    ('2020-01-01T01:30:00+02:00', '15m', '2020-01-01T01:15:00+02:00'),
    # GMT-
    ('2020-01-01T01:30:00-04:00', '15m', '2020-01-01T01:15:00-04:00'),
])
def test_apply_variation(original_time, variation, expected):
    results = apply_variation(dateparser.parse(original_time), variation)
    assert results == (dateparser.parse(expected))


@pytest.mark.parametrize('args', [
    {'value': '2020/01/01', 'variation': 'in 1 day'},
])
def test_modify_date_time_main(mocker, args):
    """
    Given:
        Value and variation.
    When:
        Running ModifyDateTime script.
    Then:
        demisto.results called.
    """
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert demisto.results.call_count == 1
    assert results[0] == '2020-01-02T00:00:00'
