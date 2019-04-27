# from Palo_Alto_Networks_WildFire_v2 import prettify_upload


def test_will_return_ok():
    assert 1 == 1


# def test_wont_return_ok():
#     assert 0 == 1


# def test_prettify_upload():
#     expected_json = 'bfdsbfg'
#     prettify_upload_res = prettify_upload("<my_json>")
#     assert expected_json == prettify_upload_res

    # 2nd usecase

# def test_get_start_time(mocker):
#     integration_context = {
#         'stored': int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds()),
#         'access_token': 'dummy'
#     }
#     mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)
#
#     from PaloAltoNetworksCortex import get_start_time
#
#     five_minutes_start_time = get_start_time('minutes', 5)
#     expected_response = datetime.now() - timedelta(minutes=5)
#     assert five_minutes_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)
#
#     ten_days_start_time = get_start_time('days', 10)
#     expected_response = datetime.now() - timedelta(days=10)
#     assert ten_days_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)
#
#     four_weeks_start_time = get_start_time('weeks', 4)
#     expected_response = datetime.now() - timedelta(weeks=4)
#     assert four_weeks_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)
#
#
# def test_process_incident_pairs():
#     from PaloAltoNetworksCortex import process_incident_pairs
#     incident_pairs = [
#         (1, datetime.fromtimestamp(1)),
#         (3, datetime.fromtimestamp(3)),
#         (2, datetime.fromtimestamp(2)),
#     ]
#     incidents, max_ts = process_incident_pairs(incident_pairs, 3)
#     assert incidents[2] == 3
#     assert max_ts == datetime.fromtimestamp(3)
#     incidents, max_ts = process_incident_pairs(incident_pairs, 2)
#     assert incidents[1] == 2
#     assert len(incidents) == 2
#     assert max_ts == datetime.fromtimestamp(2)
