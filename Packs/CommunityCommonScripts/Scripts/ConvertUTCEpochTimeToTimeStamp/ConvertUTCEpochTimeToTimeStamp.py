import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from datetime import datetime, timedelta
from dateutil import parser
import pytz


def convert_utctime_with_utc_offset(timestamp, time_format, utc_offset):

    timedelta_data = utc_offset.strip('+').split(':')
    converted_datetime = (
        timestamp + timedelta(hours=int(timedelta_data[0]), minutes=int(timedelta_data[1]))).strftime(time_format)
    return converted_datetime


def convert_utctime_with_timezone(timestamp, time_format, timezone):

    required_timezone = pytz.timezone(timezone)

    timedelta_data = (timestamp.astimezone(required_timezone)).utcoffset()
    timedelta_data = (str(timedelta_data)).split(':')
    converted_datetime = (
        timestamp + timedelta(hours=int(timedelta_data[0]), minutes=int(timedelta_data[1]))).strftime(time_format)
    return converted_datetime


def epochtime_to_utctime(epoch_time):
    # check the epcoh time is in millisecond,A epoech timestamp that is in milliseconds will have a length of 13
    if len(str(epoch_time)) == 13:
        time_stamp = datetime.fromtimestamp((int(epoch_time) / 1000), timezone.utc)
    elif len(str(epoch_time)) > 13:
        converted_epoch_time = str(epoch_time)
        updated_epoch_time = converted_epoch_time[0:13]
        time_stamp = datetime.fromtimestamp((int(updated_epoch_time) / 1000), timezone.utc)
    else:
        time_stamp = datetime.fromtimestamp(int(epoch_time), timezone.utc)

    converted_timestamp = time_stamp.strftime("%Y-%m-%d %H:%M:%S")

    return converted_timestamp


def datetime_conversions(date_timestamp, time_format, utc_offset, timezone):
    if utc_offset is not None:
        return_results(convert_utctime_with_utc_offset(date_timestamp, time_format, utc_offset))
    elif timezone is not None:
        return_results(convert_utctime_with_timezone(date_timestamp, time_format, timezone))
    else:
        raise DemistoException("Provide utcoffset or timezone to convert")


def main():
    '''Input Arguments '''
    timestamp_value = demisto.args().get('value')

    time_format = demisto.args().get('format')
    utc_offset = demisto.args().get('utcoffset')
    timezone = demisto.args().get('timezone')

    try:
        if isinstance(timestamp_value, int):
            utc_time = epochtime_to_utctime(timestamp_value)
            date_timestamp = parser.parse(utc_time)
            datetime_conversions(date_timestamp, time_format, utc_offset, timezone)
        elif isinstance(timestamp_value, str):
            date_timestamp = parser.parse(timestamp_value)
            datetime_conversions(date_timestamp, time_format, utc_offset, timezone)
        else:
            raise DemistoException("Please select the timestamptype argument")
    except Exception as e:
        return_error(f'Failed to execute ConvertUTCEpochTimeToTimeStamp. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
