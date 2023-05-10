import demistomock as demisto
from ImpSfListEndpoints import main


def test_list_endpoints_empty(mocker):
    empty_result = [{'Type': 1, 'Contents': {}, 'ContentsFormat': 'json'}]
    mocker.patch.object(demisto, 'executeCommand', return_value=empty_result)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0] == 'No results.'
    assert demisto_results_mocker.call_count == 1


def test_list_endpoints_non_empty(mocker):
    empty_result = [{'Type': 1, 'Contents': {'result': [{'last_updated': '1662980143624'}]}, 'ContentsFormat': 'json'}]
    mocker.patch.object(demisto, 'executeCommand', return_value=empty_result)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0].get('ContentsFormat') == 'table'
    assert demisto_results_mocker.call_count == 1
