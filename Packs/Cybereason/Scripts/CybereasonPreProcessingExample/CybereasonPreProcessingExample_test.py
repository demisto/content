import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_main(mocker):
    """
    Given:
        - The CyberReasonPreProcessingExample.
    When:
        - Running the script function.
    Then:
        - Validating the incidents outputs as expected.
    """
    from CybereasonPreProcessingExample import main
    value = 'Some value'
    mocker.patch.object(demisto, 'incidents', return_value=[{'labels': [{'type': 'guidString',
                                                                         'value': value}]}])
    execute_command_res = [{'Type': 1, 'Contents': {'data': [{'id': 'id'}]}}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    assert execute_mock.call_count == 2
    assert False in results_mock.call_args[0]
