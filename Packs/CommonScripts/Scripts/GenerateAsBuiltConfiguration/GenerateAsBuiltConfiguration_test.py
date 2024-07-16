import demistomock as demisto
from test_data.execute_command import execute_command


def test_main(mocker):
    import GenerateAsBuiltConfiguration

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'args', return_value={'playbook': 'test-name'})
    return_results_mocked = mocker.patch.object(GenerateAsBuiltConfiguration, 'return_results')

    GenerateAsBuiltConfiguration.main()

    assert return_results_mocked.call_args.args[0]['File'] == 'asbuilt.json'

    mocker.patch.object(demisto, 'args', return_value={})

    GenerateAsBuiltConfiguration.main()

    assert return_results_mocked.call_args.args[0]['File'] == 'asbuilt.json'
