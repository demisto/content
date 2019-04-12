import demistomock as demisto
from datetime import datetime, timedelta

def test_get_start_time(mocker):
    integration_context = {
        'stored': int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds()),
        'access_token': 'dummy'
    }
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)

    from PaloAltoNetworksCortex import get_start_time

    five_minutes_start_time = get_start_time('minutes', 5)
    expected_response = datetime.now() - timedelta(minutes=5)
    assert five_minutes_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)

    ten_days_start_time = get_start_time('days', 10)
    expected_response = datetime.now() - timedelta(days=10)
    assert ten_days_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)

    four_weeks_start_time = get_start_time('weeks', 4)
    expected_response = datetime.now() - timedelta(weeks=4)
    assert four_weeks_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)
