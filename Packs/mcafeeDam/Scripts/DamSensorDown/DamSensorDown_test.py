import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_main(mocker):
    """
    Given:
        - The script args.
    When:
        - Running main function.
    Then:
        - Validating the outputs as expected.
    """
    from DamSensorDown import main
    value = 'Sensor was disconnected at 12:00.'
    body = 'The issue is with sensor: <sensor-name>. the issue with host: <some-host>. ip: 1.1.1.1, done.'
    mocker.patch.object(demisto, 'incidents', return_value=[{'labels': [{'type': 'Email/subject',
                                                                         'value': value},
                                                                        {'type': 'Email/text',
                                                                         'value': body}]}])
    execute_command_res = [{'Type': 1, 'Contents': {'success': 'true'}}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    mocker.patch.object(demisto, 'results')
    main()
    assert execute_mock.call_count == 1
    assert '1.1.1.1' in execute_mock.call_args[0][1]['addLabels']
