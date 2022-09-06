import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def demisto_get_side_effect(args, key):
    return args.get(key)


def test_main_flow_succeed(mocker):
    """
    Given:
     - burstsize, waitms and sensorID

    When:
     - executing the main flow.

    Then:
     - make sure no results are found.
    """
    from PWObservationPcapDownload import main
    args = {'burstsize': 5, 'waitms': 1, 'sensorId': '1'}

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', return_value='just a test data')
    mocker.patch.object(demisto, 'get', side_effect=demisto_get_side_effect)

    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()

    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0] == 'No results.'


def test_main_flow_success(mocker):
    """
    Given:
     - a mocked test data from sandblast-query command.
    When:
     - executing the main flow.
    Then:
     - validate that the data is flattened to markdown.
    """
    from PWObservationPcapDownload import main
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value=[])
    mocker.patch('CommonServerPython.is_error', return_value=False)

    mocker.patch.object(demisto, 'get', return_value=[{'a': {'a': 'b'}}, {'c': {'a': 'b'}}])
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()

    assert demisto_results_mocker.call_args.args[0] == {
        'ContentsFormat': 'table', 'Type': 1, 'Contents': [{'a': 'a: b'}, {'c': 'a: b'}]
    }