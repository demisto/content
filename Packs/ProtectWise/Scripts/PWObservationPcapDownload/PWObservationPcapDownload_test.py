import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def demisto_get_side_effect(args, key):
    return args.get(key)


def test_main_flow_succeed(mocker):
    """
    Given:
     - burstsize, waitms and sensorID, and ID(s) arguments

    When:
     - executing the main flow.

    Then:
     - make sure that the data is parsed correctly based on the 'protectwise-observation-pcap-download' command output.
     - make sure the executeCommand function was called with the correct arguments.
    """
    from PWObservationPcapDownload import main
    args = {'burstsize': 5, 'waitms': 1, 'sensorId': '1', 'id': '1,2,3'}

    mocker.patch.object(demisto, 'args', return_value=args)
    execute_command_mock = mocker.patch.object(demisto, 'executeCommand', return_value=['test'])
    mocker.patch.object(demisto, 'get', side_effect=demisto_get_side_effect)

    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()

    assert execute_command_mock.call_args.args[0] == 'protectwise-observation-pcap-download'
    assert execute_command_mock.call_args.args[1] == {
        'burstsize': 5, 'waitms': 1, 'sensorId': '1', 'id': '3', 'using-brand': 'ProtectWise', 'filename': '3.pcap'
    }
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0] == ['test', 'test', 'test']
