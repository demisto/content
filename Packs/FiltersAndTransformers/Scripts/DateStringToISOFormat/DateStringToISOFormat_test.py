from DateStringToISOFormat import parse_datestring_to_iso
import demistomock as demisto
import pytest


# date_value, day_first, year_first, fuzzy, expected_output
testdata = [
    ('05-11-2929', True, True, True, True, '2929-11-05T00:00:00+00:00'),
    ('05-11-2929', True, False, True, True, '2929-11-05T00:00:00+00:00'),
    ('05-11-2929', True, True, False, True, '2929-11-05T00:00:00+00:00'),
    ('05-11-2929', True, False, False, False, '2929-11-05T00:00:00'),
    ('05-11-2929', False, True, True, False, '2929-05-11T00:00:00'),
    ('05-11-2929', False, False, True, False, '2929-05-11T00:00:00'),
    ('05-11-2929', False, False, False, False, '2929-05-11T00:00:00'),
    ('2020-06-11T17:34:35.754203+03:00', True, True, True, True, '2020-11-06T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', True, False, True, True, '2020-11-06T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', True, True, False, True, '2020-11-06T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', True, False, False, True, '2020-11-06T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', False, True, True, False, '2020-06-11T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', False, False, True, False, '2020-06-11T17:34:35.754203+03:00'),
    ('2020-06-11T17:34:35.754203+03:00', False, False, False, False, '2020-06-11T17:34:35.754203+03:00'),
    ("June 21st 2020 Eastern Standard Time", True, True, True, True, "2020-06-21T00:00:00+00:00"),
    ("June 21st 2020 Eastern Standard Time", True, False, True, True, "2020-06-21T00:00:00+00:00"),
    ("June 21st 2020 Eastern Standard Time", True, True, False, True, "June 21st 2020 Eastern Standard Time"),
    ("June 21st 2020 Eastern Standard Time", True, False, False, True, "June 21st 2020 Eastern Standard Time"),
    ("June 21st 2020 Eastern Standard Time", False, True, True, False, "2020-06-21T00:00:00"),
    ("June 21st 2020 Eastern Standard Time", False, False, True, False, "2020-06-21T00:00:00"),
    ("June 21st 2020 Eastern Standard Time", False, False, False, False, "June 21st 2020 Eastern Standard Time"),
    ("The 1st of June 2020", True, True, True, True, "2020-06-01T00:00:00+00:00"),
    ("The 1st of June 2020", True, False, True, True, "2020-06-01T00:00:00+00:00"),
    ("The 1st of June 2020", True, True, False, True, "The 1st of June 2020"),
    ("The 1st of June 2020", True, False, False, True, "The 1st of June 2020"),
    ("The 1st of June 2020", False, True, True, False, "2020-06-01T00:00:00"),
    ("The 1st of June 2020", False, False, True, False, "2020-06-01T00:00:00"),
    ("The 1st of June 2020", False, False, False, False, "The 1st of June 2020"),
    ('2020-06-11T17:34:35.754Z', False, False, False, True, '2020-06-11T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', True, True, True, True, '2020-11-06T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', True, False, True, True, '2020-11-06T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', True, True, False, True, '2020-11-06T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', True, False, False, True, '2020-11-06T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', False, True, True, False, '2020-06-11T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', False, False, True, False, '2020-06-11T17:34:35.754000+00:00'),
    ('2020-06-11T17:34:35.754Z', False, False, False, False, '2020-06-11T17:34:35.754000+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', False, False, False, True, '2020-11-20T11:41:42+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', True, True, True, True, '2020-11-20T11:41:42+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', True, False, True, True, '2020-11-20T11:41:42+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', True, True, False, True, '2020-11-20T11:41:42+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', True, False, False, True, '2020-11-20T11:41:42+00:00'),
    ('Fri, 20 Nov 2020 11:41:42', False, True, True, False, '2020-11-20T11:41:42'),
    ('Fri, 20 Nov 2020 11:41:42', False, False, True, False, '2020-11-20T11:41:42'),
    ('Fri, 20 Nov 2020 11:41:42', False, False, False, False, '2020-11-20T11:41:42'),
    ('Fri, 20 Nov 2020 11:41:42', False, False, False, False, '2020-11-20T11:41:42'),
]


@pytest.mark.parametrize('date_value,day_first,year_first,fuzzy,add_utc_timezone,expected_output', testdata)
def test_parse_datestring_to_iso(mocker, date_value, day_first, year_first, fuzzy, add_utc_timezone, expected_output):
    '''Scenario: Parse an arbitrary date string and convert it to ISO 8601 format

    Given
    - An arbitrary date string
    When
    - The date string can be an ambiguous 3-integer date, fuzzy date string or an
      already iso-8601 formatted date string
    Then
    - Ensure the output date string is in iso-8601 format in all cases

    Args:
        date_value (str): A string containing a date stamp.
        day_first (bool): Whether to interpret the first value in an ambiguous 3-integer date
                          (e.g. 01/05/09) as the day or month.
        year_first (bool): Whether to interpret the first value in an ambiguous 3-integer date
                           (e.g. 01/05/09) as the year. If ``True``, the first number is taken to
                           be the year, otherwise the last number is taken to be the year.
        fuzzy (bool): Whether to allow fuzzy parsing, allowing for string like "Today is
                      January 1, 2047 at 8:21:00AM".
        add_utc_timezone (bool): Whether to add UTC timezone to the date string returned in case offset-naive
                                 date was provided as input.
        expected_output (str): The iso 8601 formatted date to check the result against
    '''
    mocker.patch.object(demisto, 'error')
    assert parse_datestring_to_iso(date_value, day_first, year_first, fuzzy, add_utc_timezone) == expected_output
