import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from freezegun import freeze_time


def test_change_remediation_to_critical(mocker):
    """
    Given
    - the new severity changed to critical

    When
    - running the script

    Then
    - ensure incident sla was set 60 minutes from now
    """
    import ChangeRemediationSLAOnSevChange

    demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand')

    mocker.patch.object(demisto, 'args', return_value={
        'new': 'Critical'
    })

    ChangeRemediationSLAOnSevChange.main()
    assert demisto_execute_mock.call_count == 1
    execute_command_args = demisto_execute_mock.call_args_list[0][0]
    assert execute_command_args[0] == 'setIncident'
    assert execute_command_args[1] == {'sla': 60, 'slaField': 'remediationsla'}


@freeze_time("2022-01-01 00:00:00 UTC")
def test_change_remediation_to_non_critical(mocker):
    """
    Given
    - the new severity changed to non critical
    - now: 2020-01-01T00:00:00+00:00

    When
    - running the script

    Then
    - ensure incident sla was set 6 days from now: 2020-01-07T00:00:00+00:00
    """
    import ChangeRemediationSLAOnSevChange

    demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand')

    mocker.patch.object(demisto, 'args', return_value={
        'new': 'Low'
    })

    ChangeRemediationSLAOnSevChange.main()
    assert demisto_execute_mock.call_count == 1
    execute_command_args = demisto_execute_mock.call_args_list[0][0]
    assert execute_command_args[0] == 'setIncident'

    assert execute_command_args[1] == {'sla': '2022-01-07T00:00:00+00:00', 'slaField': 'remediationsla'}
