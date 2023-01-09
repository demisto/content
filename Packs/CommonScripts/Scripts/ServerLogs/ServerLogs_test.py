import pytest
import demistomock as demisto


def test_main(mocker):
    from ServerLogs import main
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'output': 'output'}}])
    return_results = mocker.patch.object(demisto, 'results')
    main()
    return_results.assert_called_with('File: /var/log/demisto/server.log\noutput')


def raise_value_error():
    raise ValueError('error')


def test_main_fail(mocker):
    from ServerLogs import main
    mocker.patch.object(demisto, 'executeCommand', side_effect=raise_value_error)
    with pytest.raises(Exception):
        main()
