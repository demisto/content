import dateparser
from ModifyDateTime import apply_variation


@pytest.mark.parametrize('original_time, variation, expected', [
    ('2020/01/01', 'in 1 day', '2020-01-02T00:00:00'),  # sanity
    ('2020/01/01', 'yesterday', '2019-12-31T00:00:00'),  # textual variation 1
    ('2020/01/01', 'next month', '2020-02-01T00:00:00'),  # textual variation 2
    ('2020-01-01T01:30:00', '-15m', '2020-01-01T01:15:00'),  # negative variation
    ('2020-01-01T10:00:00Z', '15m', '2020-01-01T10:15:00Z'),  # zulu timezone
    ('2020-01-01T01:00:00+00:00', '15m', '2020-01-01T00:15:00+00:00'),  # GMT
    ('2020-01-01T01:00:00+02:00', '15m', '2020-01-01T00:15:00+02:00'),  # GMT+
    ('2020-01-01T01:00:00-04:00', '15m', '2020-01-01T00:15:00-04:00'),  # GMT-
])
def test_apply_variation(original_time, variation, expected):
    results = apply_variation(dateparser.parse(original_time), variation)
    assert results == (dateparser.parse(expected))
