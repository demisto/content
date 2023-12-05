import demistomock as demisto
from CommonServerPython import *
from XCloudIdentitiesWidget import get_additonal_info, main, DemistoException

# Mock the context data


def mock_context(alerts):
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': {
            'Core': {
                'OriginalAlert': alerts
            }
        },
        'ContentsFormat': formats['json']
    })

# Unit test for get_additonal_info function


def test_get_additonal_info_single_alert():
    mock_context([{
        'event': {
            'identity_name': 'John Doe',
            'identity_type': 'User',
            'identity_invoked_by_uuid': '123456',
            'identity_invoked_by_type': 'API Key',
            'identity_invoked_by_sub_type': 'Read Access'
        }
    }])

    results = get_additonal_info()
    assert len(results) == 1
    assert results[0]['Identity Name'] == 'John Doe'
    assert results[0]['Identity Type'] == 'User'
    assert results[0]['Access Key ID'] == '123456'
    assert results[0]['Identity Invoke Type'] == 'API Key'
    assert results[0]['Identity Invoke Sub Type'] == 'Read Access'


def test_get_additonal_info_multiple_alerts():
    mock_context([
        {'event': {'identity_name': 'John Doe'}},
        {'event': {'identity_name': 'Jane Doe'}}
    ])

    results = get_additonal_info()
    assert len(results) == 2
    assert results[0]['Identity Name'] == 'John Doe'
    assert results[1]['Identity Name'] == 'Jane Doe'


def test_get_additonal_info_empty_alert():
    mock_context([{}])

    results = get_additonal_info()
    assert len(results) == 0


def test_get_additonal_info_alert_not_configured():
    mock_context(None)

    try:
        get_additonal_info()
        assert False, "Expected DemistoException, but no exception was raised"
    except DemistoException as e:
        assert str(e) == 'Original Alert is not configured in context'


def test_get_additonal_info_invalid_alert():
    mock_context([{'invalid_key': 'value'}])

    results = get_additonal_info()
    assert len(results) == 0

# Unit test for main function


def test_main(mocker):
    mocker.patch('demistomock.results', side_effect=mocked_demisto_results)
    mocker.patch.object(demisto, 'args', return_value={})

    # Test successful execution
    mock_context([{
        'event': {
            'identity_name': 'John Doe',
            'identity_type': 'User',
            'identity_invoked_by_uuid': '123456',
            'identity_invoked_by_type': 'API Key',
            'identity_invoked_by_sub_type': 'Read Access'
        }
    }])
    main()

    # Test exception handling
    mocker.patch('XCloudIdentitiesWidget.get_additonal_info', side_effect=DemistoException('Test Exception'))
    result = main()
    assert 'Failed to execute XCloudIdentitiesWidget. Error: Test Exception' in result

# Mocked demisto.results function


def mocked_demisto_results(params):
    pass

# Run the unit tests


def run_tests():
    test_get_additonal_info_single_alert()
    test_get_additonal_info_multiple_alerts()
    test_get_additonal_info_empty_alert()
    test_get_additonal_info_alert_not_configured()
    test_get_additonal_info_invalid_alert()
    test_main()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    run_tests()
