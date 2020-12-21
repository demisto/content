import demistomock as demisto


def test_parse_alert_to_incident(mocker):
    """
    Given:
        - Alert with event_values as list

    When:
        - Parsing the alert

    Then:
        - Ensure parsing does not fail
        - Verify parsed alert returned as expected
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'server': 'server',
            'credentials': {
                'identifier': 'identifier',
                'password': 'password'
            },
            'insecure': False,
            'version': 'v3'
        }
    )
    from FireEyeHX import parse_alert_to_incident
    assert parse_alert_to_incident({'event_values': []}) == {'name': 'New Event: ', 'rawJSON': '{"event_values": []}'}
