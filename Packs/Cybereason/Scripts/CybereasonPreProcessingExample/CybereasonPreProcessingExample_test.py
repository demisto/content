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
    from CybereasonPreProcessingExample import get_guid_from_system_incident
    test_data = {
        'labels': [
            {'type': 'x', 'value': 'not found'},
            {'type': 'guidString', 'value': '12345678'},
            {'type': 'x', 'value': 'nothing'},
            {'type': 'GUID', 'value': '12345678'},
            {'type': 'y', 'value': 'nanana'}
        ]
    }

    malopGuid = get_guid_from_system_incident(test_data)

    assert malopGuid == '12345678'
