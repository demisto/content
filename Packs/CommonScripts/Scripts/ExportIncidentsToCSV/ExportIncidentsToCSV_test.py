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
