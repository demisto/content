import json
import demistomock as demisto
import FireEyeETP


def test_malware_readable_data():
    """
    Given:
        A dict with only "name" key
    When:
        calling malware_readable_data method on it
    Then:
        Ensure execution does not raise exception on it
    """
    from FireEyeETP import malware_readable_data
    try:
        malware_readable_data({'name': 'some-name'})
    except KeyError:
        assert False, 'malware_readable_data method should not fail on dict with name key only'


def test_get_alert_command(mocker, requests_mock):
    """
    Given:
        - ID of alert to get
        - The alert object contain unicode

    When:
        - Running get-alert command

    Then:
        - Ensure command runs successfully
        - Ensure results are returned
    """
    import FireEyeETP
    base_url = 'https://server_url/api/v1'
    mocker.patch('FireEyeETP.BASE_PATH', base_url)
    mocker.patch.object(demisto, 'args', return_value={'alert_id': 'KgBdei7RQS4u4m8Jl7mG'})
    mocker.patch.object(demisto, 'results')
    requests_mock.get(
        base_url + '/alerts/KgBdei7RQS4u4m8Jl7mG?',
        json={
            'meta': {
                'total': 1
            },
            'data': [
                {
                    'alert': {
                        'explanation': {
                            'malware_detected': {
                                'malware': {}
                            }
                        }
                    },
                    'email': {
                        'headers': {
                            'to': u'\u200b'
                        },
                        'timestamp': {}
                    }
                }
            ]
        }
    )
    FireEyeETP.get_alert_command()
    results = demisto.results.call_args[0][0]
    assert results


def test_fetch_incident_by_status_messages(mocker):
    """
    Given:
        - A status message similar to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure one incident was fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}]}
    expected_incidents = {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                          'alert': {'timestamp': '2023-02-09T19:34:17'}}
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    assert res.call_args.args[0][0].get('rawJSON') == json.dumps(expected_incidents)


def test_fetch_incident_by_status_messages_mismatch_status(mocker):
    """
    Given:
        - A status message differs from to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure no incidents were fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'deleted', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}]}
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    assert len(res.call_args.args[0]) == 0


def test_fetch_incident_by_status_messages_with_two_status(mocker):
    """
    Given:
        - A list of status message similar to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure 2 incidents were fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}},
        {'attributes': {'email': {'status': 'deleted', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}
    ]}
    expected_incidents = [
        {"email": {"status": "delivered (retroactive)", "headers": {"subject": ""}},
         "alert": {"timestamp": '2023-02-09T19:34:17'}},
        {"email": {"status": "deleted", "headers": {"subject": ""}}, "alert": {"timestamp": '2023-02-09T19:34:17'}}]
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)', 'deleted'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    for incident, expected_incident in zip(res.call_args.args[0], expected_incidents):
        assert incident.get('rawJSON') == json.dumps(expected_incident)
