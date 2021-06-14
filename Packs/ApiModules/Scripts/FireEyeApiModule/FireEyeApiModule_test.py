from FireEyeApiModule import *


def test_to_fe_datetime_converter():
    """Unit test
    Given
    - to_fe_datetime_converter command
    - time in a string
    When
    - running to_fe_datetime_converter
    Then
    - Validate that the FE time is as expected
    """
    # fe time will not change
    assert to_fe_datetime_converter('2021-05-14T01:08:04.000-02:00') == '2021-05-14T01:08:04.000-02:00'

    # "now"/ "1 day" / "3 months:" time will be without any timezone
    assert to_fe_datetime_converter('now')[23:] == '+00:00'
    assert to_fe_datetime_converter('3 months')[23:] == '+00:00'

    # now > 1 day
    assert to_fe_datetime_converter('now') > to_fe_datetime_converter('1 day')