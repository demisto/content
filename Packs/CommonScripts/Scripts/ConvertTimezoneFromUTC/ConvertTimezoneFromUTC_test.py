from ConvertTimezoneFromUTC import convert_UTC_Timezone_command
from ConvertTimezoneFromUTC import determine_correct_format


def test_convert_UTC_Timezone_command():
    """
        Given -
           UTC time, timezone, format
        When -

        Then -
            the function will return the converted time, from UTC to local timezone
    """
    timezone = "US/Eastern"
    value = "2023-01-04 18:14:18"
    format = "%Y-%m-%d %H:%M:%S"
    time_as_datetime_type = determine_correct_format(time=value, fmt=format)

    command_result = convert_UTC_Timezone_command(time=time_as_datetime_type, timezone=timezone, fmt=format)
    assert command_result.readable_output == "2023-01-04 11:14:18"
