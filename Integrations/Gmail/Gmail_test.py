import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from Gmail import create_base_time


def timestamp_to_date_test():
    valid_timestamp = '1566739538000'
    valid_header_date = "Sun, 25 Aug 2019 06:25:38 -0700"
    invalid_header_date = "25 Aug 2019 06:25:38"
    # this does contain the utc time change
    semi_valid_header_date = "25 Aug 2019 06:25:38 -0700"
    assert create_base_time(valid_timestamp, valid_header_date) == "Sun, 25 Aug 2019 06:25:38 -0700"
    assert create_base_time(valid_timestamp, semi_valid_header_date) == "Sun, 25 Aug 2019 06:25:38 -0700"
    assert create_base_time(valid_timestamp, invalid_header_date) == "Sun, 25 Aug 2019 13:25:38 -0000"
