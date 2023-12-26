<<<<<<< HEAD
import demistomock as demisto
from ExportIncidentsToCSV import main

side_effect = iter(
    [[{'Contents': {'response': {'test': 'test'}}}], [{'Contents': {'response': b'123'}}]])


def test_main(mocker):
    mocker.patch.object(demisto, 'args', return_value={'query': 'html', 'fetchdays': '6', 'columns': 'id,name'})
    mocker.patch.object(demisto, 'results', return_value={})
    execute_command_mock = mocker.patch.object(demisto, 'executeCommand', side_effect=side_effect)
    main()
    assert execute_command_mock.call_args_list[0][0][1]['body']['columns'] == ['id', 'name']
=======
import pytest

import demistomock as demisto
from ExportIncidentsToCSV import main


def test_main(mocker):
    side_effect = iter(
        [[{'Contents': {'response': {'test': 'test'}}}], [{'Contents': {'response': b'123'}}]])
    mocker.patch.object(demisto, 'args', return_value={'query': 'html', 'fetchdays': '6', 'columns': 'id,name'})
    mocker.patch.object(demisto, 'results', return_value={})
    mocker.patch('ExportIncidentsToCSV.is_error', return_value=False)
    execute_command_mock = mocker.patch.object(demisto, 'executeCommand', side_effect=side_effect)
    main()
    assert execute_command_mock.call_args_list[0][0][1]['body']['columns'] == ['id', 'name']


def test_main_error(mocker):
    side_effect = iter(
        [[{'Contents': {'response': {'test': 'test'}}}], Exception("error")])
    mocker.patch.object(demisto, 'args', return_value={'query': 'html', 'fetchdays': '6'})
    mocker.patch.object(demisto, 'results', return_value={})
    mocker.patch('ExportIncidentsToCSV.is_error', return_value=True)
    mocker.patch('ExportIncidentsToCSV.get_error', return_value="error")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, 'executeCommand', side_effect=side_effect)
    with pytest.raises(Exception):
        main()
>>>>>>> master
