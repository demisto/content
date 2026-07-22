import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_main_flow_process_exist(mocker):
    """
    Given:
    - a process ID that exists.

    When:
    - executing the main flow.

    Then:
    - Make sure that an entry is returned to the war-room meaning that the process exist
    """
    mocker.patch.object(demisto, 'args', return_value={'filepath': 'path', 'process': 'process-1'})
    from AccessdataCheckProcessExistsInSnapshot import main

    mocked_data = '<?xml version="1.0" encoding="UTF-8" ?><root><Process><Name>process-1<' \
                  '/Name></Process><Process><Name>process-2</Name></Process></root>'

    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value=mocked_data)

    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()

    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0] == {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': {'Name': 'process-1', 'Exists': 'Yes'}, 'HumanReadable': 'Process "process-1" exists: Yes',
        'EntryContext': {'Accessdata.Process(val && val.Name == obj.Name)': {'Name': 'process-1', 'Exists': 'Yes'}}
    }


def test_main_flow_process_does_not_exist(mocker):
    """
    Given:
    - a process ID that does not exist.

    When:
    - executing the main flow.

    Then:
    - Make sure that an entry is returned to the war-room meaning that the process does not exist
    """
    mocker.patch.object(demisto, 'args', return_value={'filepath': 'path', 'process': 'process-3'})
    from AccessdataCheckProcessExistsInSnapshot import main

    mocked_data = '<?xml version="1.0" encoding="UTF-8" ?><root><Process><Name>process-1<' \
                  '/Name></Process><Process><Name>process-2</Name></Process></root>'

    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value=mocked_data)

    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    main()

    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args.args[0] == {
        'Type': 1, 'ContentsFormat': 'json', 'Contents': {'Name': 'process-3', 'Exists': 'No'},
        'HumanReadable': 'Process "process-3" exists: No',
        'EntryContext': {'Accessdata.Process(val && val.Name == obj.Name)': {'Name': 'process-3', 'Exists': 'No'}}
    }
