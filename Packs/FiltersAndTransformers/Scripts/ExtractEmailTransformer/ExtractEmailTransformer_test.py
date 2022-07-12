from ExtractEmailTransformer import *
import pytest


data_test_main = [
    ({'value': 'test'}, []),
    ({'value': 'test@test.com'}, ['test@test.com']),
    ({'value': 'test@test.com,test?test@test.com'}, ['test@test.com', 'test@test.com']),
]


@pytest.mark.parametrize('args, command_outputs', data_test_main)
def test_main(args, command_outputs, mocker):
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('ExtractEmailTransformer.execute_command', return_value=command_outputs)
    results_mocker = mocker.patch('ExtractEmailTransformer.return_results')
    main()
    results_mocker.args[0] == command_outputs
