import demistomock as demisto


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


ALERTS = {'meta': {'fromLastModifiedOn':{'end': ''}},
          'data': [
                {'attributes': {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                                'alert': {'timestamp': '2023-02-08T19:34:17'}}}]}


def test_fetch_incident_by_status_messages(mocker):
    from FireEyeETP import fetch_incidents
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value={})
    mocker.patch('FireEyeETP.get_alerts_request', return_value=ALERTS)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    fetch_incidents()
    assert res.call_args.args[0][0].get('rawJSON') == '{"email": {"status": "delivered (retroactive)", "headers": {"subject": ""}}, "alert": {"timestamp": "2023-02-08T19:34:17"}}'


  
ALERTS_2 = {'meta': {'fromLastModifiedOn':{'end': ''}},
            'data': [
                {'attributes': {'email': {'status': 'Moshe', 'headers': {'subject': ''}},
                                'alert': {'timestamp': '2023-02-08T19:34:17'}}}]} 

def test_fetch_incident_by_status_messages_2(mocker):
    from FireEyeETP import fetch_incidents
    mocker.patch('FireEyeETP.MESSAGE_STATUS', return_value='delivered (retroactive)')
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value={})
    mocker.patch('FireEyeETP.get_alerts_request', return_value=ALERTS_2)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    fetch_incidents()
    assert not res.call_args.args[0]
