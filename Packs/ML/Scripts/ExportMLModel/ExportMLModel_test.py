from ExportMLModel import main

from CommonServerPython import *

dummy_data = [i for i in range(10)]


def test_main(mocker):
    mocker.patch.object(demisto, 'args', return_value={"modelName": 'model'})

    def get_file_path(entry_id):
        return {'path': './TestData/entry_file'}

    def execute_command(command, args):
        if command == 'getMLModel':
            key_args = ['modelName']
            assert (all(k in args for k in key_args))
            return [{'Contents': dummy_data, 'Type': entryTypes['file']}]

    def results(result):
        file_id = result['FileID']
        with open(demisto.investigation()['id'] + '_' + file_id) as f:
            file_data_str = f.read()
        file_data = json.loads(file_data_str)
        assert (all(x in file_data for x in dummy_data) and all(x in dummy_data for x in file_data))

    mocker.patch.object(demisto, 'getFilePath', side_effect=get_file_path)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    mocker.patch.object(demisto, 'results', side_effect=results)

    main()
