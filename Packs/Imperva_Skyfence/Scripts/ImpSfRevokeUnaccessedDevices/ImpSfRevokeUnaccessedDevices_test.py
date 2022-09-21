import demistomock as demisto
from ImpSfRevokeUnaccessedDevices import main


def test_revoke_empty(mocker):
    empty_result = [{'Type': 1, 'Contents': {}, 'ContentsFormat': 'json'}]
    mocker.patch.object(demisto, 'executeCommand', return_value=empty_result)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0][0].get('ContentsFormat') == 'markdown'
    assert demisto_results_mocker.call_count == 1


def test_revoke_3_months(mocker):
    old_user = [{
        'Type': 1,
        'Contents': [{
            'last_updated': '1627765200000', 'accounts': '[{"account_id": "dummy"}]', 'endpoint_status': 'managed',
            'endpoint_id': 'dummy'
        }],
        'ContentsFormat': 'json'
    }]
    mocker.patch.object(demisto, 'executeCommand', return_value=old_user)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0][0].get('ContentsFormat') == 'markdown'
    assert demisto_results_mocker.call_count == 1
