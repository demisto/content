from ConvertTimezoneFromUTC import convert_UTC_Timezone_command
from ConvertTimezoneFromUTC import determine_correct_format


def test_convert_UTC_Timezone_command():
    """
        Given:
           Specific UTC time, timezone and format to convert
        When:
            Converting the time
        Then:
            Validate the result is correct and in local time format.
    """
    timezone = "US/Eastern"
    value = "2023-01-04 18:14:18"
    format = "%Y-%m-%d %H:%M:%S"
    time_as_datetime_type = determine_correct_format(time=value, fmt=format)

    command_result = convert_UTC_Timezone_command(time=time_as_datetime_type, timezone=timezone, fmt=format)
    # Note: This test will fail locally, due to time differences. It will pass in the build.
    assert command_result.readable_output == "2023-01-04 13:14:18"


def test_determine_correct_format():
    """
        Given:
           A time as a string
        When:
            Determine the timezone
        Then:
            Validate the result is a correct datetime object.
    """
    value = "2023-01-04 18:14:18"
    format = "%Y-%m-%d %H:%M:%S"
    time_as_datetime_type = determine_correct_format(time=value, fmt=format)
    assert str(type(time_as_datetime_type)) == "<class 'datetime.datetime'>"
