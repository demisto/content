from ImportMLModel import main

import demistomock as demisto

done = False


def test_main(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        "entryID": 'id',
        "modelName": 'model',
        'modelStoreType': 'mlModel'
    })

    def get_file_path(entry_id):
        return {'path': './TestData/entry_file'}

    def execute_command(command, args):
        if command == 'createMLModel':
            key_args = ['modelData', 'modelName', 'modelLabels', 'modelOverride']
        if command == "evaluateMLModel":
            key_args = ['modelConfusionMatrix', 'modelName']
        assert(all(k in args for k in key_args))
        return []

    def results(result):
        global done
        if result == 'done':
            done = True

    # mocker.patch.object('read_file_content', side_effect=get_file_path)
    mocker.patch.object(demisto, 'getFilePath', side_effect=get_file_path)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert (done)
