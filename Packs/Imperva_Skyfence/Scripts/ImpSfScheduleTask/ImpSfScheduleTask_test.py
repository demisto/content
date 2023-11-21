import demistomock as demisto
from ImpSfScheduleTask import main


def test_schedule_task(mocker):
    res = [{'Type': 1, 'Contents': {'id': 'stam'}, 'ContentsFormat': 'json'}]
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    demisto_set_context_mocker = mocker.patch.object(demisto, 'setContext')
    main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0][0].get('ContentsFormat') == 'json'
    assert demisto_results_mocker.call_count == 1
    assert demisto_set_context_mocker.called
