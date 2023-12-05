import demistomock as demisto
from CommonServerPython import *
from XCloudIdentitiesWidget import get_additonal_info, main

# Mock the context data
original_alert = {
    'event': {
        'identity_name': 'John Doe',
        'identity_type': 'User',
        'identity_invoked_by_uuid': '123456',
        'identity_invoked_by_type': 'API Key',
        'identity_invoked_by_sub_type': 'Read Access'
    }
}

demisto.results({
    'Type': entryTypes['note'],
    'Contents': original_alert,
    'ContentsFormat': formats['json']
})

# Unit test for get_additonal_info function
def test_get_additonal_info():
    results = get_additonal_info()
    assert len(results) == 1
    assert results[0]['Identity Name'] == 'John Doe'
    assert results[0]['Identity Type'] == 'User'
    assert results[0]['Access Key ID'] == '123456'
    assert results[0]['Identity Invoke Type'] == 'API Key'
    assert results[0]['Identity Invoke Sub Type'] == 'Read Access'

# Unit test for main function
def test_main(mocker):
    mocker.patch('demistomock.results', side_effect=mocked_demisto_results)
    mocker.patch.object(demisto, 'args', return_value={})

    main()

# Mocked demisto.results function
def mocked_demisto_results(params):
    pass

# Run the unit tests
def run_tests():
    test_get_additonal_info()
    test_main()

if __name__ in ('__main__', '__builtin__', 'builtins'):
    run_tests()
