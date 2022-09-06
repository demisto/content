import demistomock as demisto
from IntezerScanHost import main


def test_scan_host_valid(mocker):
    good_result = [{'Type': 1, 'Contents': "all good", 'ContentsFormat': 'text'}]
    mocker.patch.object(demisto, 'executeCommand', return_value=good_result)
    mocker.patch.object(demisto, 'args', return_value={'host': "dummy_test.com", 'intezer_api_key': 'dummy'})
    return_outputs_mock = mocker.patch("IntezerScanHost.return_outputs")
    main()
    assert return_outputs_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    context = return_outputs_mock.call_args[0][1]
    assert context['Intezer.Analysis'] is not None
    assert context['Intezer.Analysis']['Type'] == 'Endpoint'
    assert context['Intezer.Analysis']['Status'] == 'Created'
