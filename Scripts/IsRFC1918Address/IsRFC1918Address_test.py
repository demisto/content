import demistomock as demisto
from CommonServerPython import entryTypes
import sys


def exec_command_for_IsInCidrRanges():
    """
    Return an executeCommand function which will return True or False, as to whether an address is RFC-1918.

    Arguments:
        None

    Raises:
        ValueError: if call with differed name from getFilePath or getEntry

    Returns:
        [function] -- function to be used for mocking
    """

    sys.path.append('../IsInCidrRanges')
    sys.path.append('./TestData')
    from IsInCidrRanges import main as cidr_checker

    def executeCommand(name, args=None):
        if name == 'IsInCidrRanges':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': cidr_checker(**args)
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    return executeCommand


def test_main(mocker):
    from IsRFC1918Address import main

    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_IsInCidrRanges())

    mocker.patch.object(demisto, 'args', return_value={
        'value': '172.16.0.1'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is True

    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_IsInCidrRanges())
    mocker.patch.object(demisto, 'args', return_value={
        'value': '8.8.8.8'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is False
