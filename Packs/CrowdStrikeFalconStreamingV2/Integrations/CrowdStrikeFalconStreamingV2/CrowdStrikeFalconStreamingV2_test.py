import json

import pytest

import demistomock as demisto
from CrowdStrikeFalconStreamingV2 import (get_sample_events,
                                          merge_integration_context)


def test_get_sample_events_with_results(mocker):
    """
    Given:
     - Samples events stored in the integration context.
     - Store events integration parameter is enabled.

    When:
     - Running get sample events command.

    Then:
     - Ensure the command runs successfully
     - Verify expected results are returned.
    """
    sample_events = [
        {
            'event': {
                'AuditKeyValues': [
                    {
                        'Key': 'partition',
                        'ValueString': '0'
                    },
                    {
                        'Key': 'offset',
                        'ValueString': '70626'
                    },
                    {
                        'Key': 'appId',
                        'ValueString': 'demisto'
                    },
                    {
                        'Key': 'eventType',
                        'ValueString': 'All event type(s)'
                    }
                ],
                'OperationName': 'streamStarted',
                'ServiceName': 'Crowdstrike Streaming API',
                'Success': True,
                'UTCTimestamp': 1592479007
            },
            'metadata': {
                'eventCreationTime': 1592479007646,
                'eventType': 'AuthActivityAuditEvent',
                'offset': 70627,
                'version': '1.0'
            }
        },
        {
            'event': {
                'CommandLine': 'choice  /m crowdstrike_sample_detection',
                'ComputerName': 'FALCON-CROWDSTR',
                'Description': 'For evaluation only - benign, no action needed.',
                'Name': 'Suspicious Activity',
                'FileName': 'choice.exe',
                'FilePath': '\\Device\\HarddiskVolume1\\Windows\\System32',
                'GrandparentCommandLine': 'C:\\Windows\\Explorer.EXE',
                'GrandparentImageFileName': '\\Device\\HarddiskVolume1\\Windows\\explorer.exe',
                'MD5String': '463b5477ff96ab86a01ba49bcc02b539',
                'MachineDomain': 'FALCON-CROWDSTR',
                'Objective': 'Falcon Detection Method',
                'ParentCommandLine': '\'C:\\Windows\\system32\\cmd.exe\' ',
                'ParentImageFileName': '\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe',
                'ParentProcessId': 79569204402,
                'PatternDispositionDescription': 'Detection, standard detection.',
                'PatternDispositionFlags': {
                    'BootupSafeguardEnabled': False,
                    'CriticalProcessDisabled': False,
                    'Detect': False,
                    'FsOperationBlocked': False,
                    'InddetMask': False,
                    'Indicator': False,
                    'KillParent': False,
                    'KillProcess': False,
                    'KillSubProcess': False,
                    'OperationBlocked': False,
                    'PolicyDisabled': False,
                    'ProcessBlocked': False,
                    'QuarantineFile': False,
                    'QuarantineMachine': False,
                    'RegistryOperationBlocked': False,
                    'Rooting': False,
                    'SensorOnly': False
                },
                'PatternDispositionValue': 0,
                'ProcessEndTime': 1592479032,
                'ProcessId': 79867150228,
                'ProcessStartTime': 1592479032,
                'SHA1String': '0000000000000000000000000000000000000000',
                'SHA256String': '90f352c1fb7b21cc0216b2f0701a236db92b786e4301904d28f4ec4cb81f2a0b',
                'SensorId': '15dbb9d8f06b45fe9f61eb46e829d986',
                'Severity': 2,
                'SeverityName': 'Low',
                'Tactic': 'Falcon Overwatch',
                'Technique': 'Malicious Activity',
                'UserName': 'admin'
            },
            'metadata': {
                'eventCreationTime': 1592479032000,
                'eventType': 'DetectionSummaryEvent',
                'offset': 70628,
                'version': '1.0'
            }
        }
    ]
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'sample_events': json.dumps(sample_events)})
    mocker.patch.object(demisto, 'results')
    get_sample_events()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == sample_events


def test_get_sample_events_integration_param(mocker):
    """
    Given:
     - Samples events not stored in the integration context.
     - Store events integration parameter is disabled.

    When:
     - Running get sample events command.

    Then:
     - Ensure the command runs successfully
     - Verify output message.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'results')
    get_sample_events(store_samples=False)
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == 'No sample events found. The "Store sample events for mapping" integration parameter need to ' \
                      'be enabled for this command to return results.'


@pytest.mark.parametrize('current_integration_context, updated_integration_context', [
    ({'offset': 1}, {'offset': '1'}),
    ({'sample_events': [{'event': {}}]}, {'sample_events': '[{"event": {}}]'}),
    ({'offset': '1', 'sample_events': '[{"event": {}}]'}, {})
])
def test_merge_integration_context(mocker, current_integration_context, updated_integration_context):
    """
    Given:
     - Case A: Integration context with the property offset of type int
     - Case B: Integration context with the property sample_events of type list
     - Case C: Integration context with the properties offset and sample_events of type str

    When:
     - Merging integration context

    Then:
     - Case A: Ensure integration context is updated with offset of type str
     - Case B: Ensure integration context is updated with sample_events of type str
     - Case C: Ensure integration context is not updated as it is in the proper state
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=current_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    merge_integration_context()
    if updated_integration_context:
        # Cases A and B
        assert demisto.setIntegrationContext.call_args[0][0] == updated_integration_context
    else:
        # Case C
        assert not demisto.setIntegrationContext.called
