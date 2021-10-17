import demistomock as demisto
from GetEnabledInstances import main


def test_get_enabled_instances(mocker):
    mock_modules = {
        'instanceName1': {'state': 'active', 'brand': 'brandName'},
        'instanceName2': {'state': 'disabled', 'brand': 'brandName'}
    }
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getModules', return_value=mock_modules)
    main()
    result = demisto.results.call_args[0][0]['Contents']
    assert 'instanceName1' in result
    assert 'instanceName2' not in result
