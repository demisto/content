from datetime import datetime
from CommonServerPython import *

def test_convert_datetime_to_string(mocker):
    """
        Given:
        - A datetime object
        When:
        - Calling convert_datetime_to_string()
        Then:
        - Ensure the datetime is converted to a string in the expected format (only 2 numbers after the decimal point)
        """
    mocker.patch.object(demisto, "params", return_value = {})
    from Packs.Snowflake.Integrations.Snowflake.Snowflake import convert_datetime_to_string
    results = convert_datetime_to_string(datetime(2024, 8, 14, 22, 43, 9, 851000))
    assert results == "2024-08-14 22:43:09.85"