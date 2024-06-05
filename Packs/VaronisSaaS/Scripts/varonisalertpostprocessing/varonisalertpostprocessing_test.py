import demistomock as demisto
from varonisalertpostprocessing import update_alert_status


def test_update_alert_status(mocker):
    incident = {
        "id": "20212",
        "rawType": "Varonis SaaS Incident",
        "reason": "",
        "reminder": "0001-01-01T00:00:00Z",
        "runStatus": "",
        "severity": 3,
        "sla": 0,
        "sourceBrand": "VaronisSaaS",
        "sourceInstance": "VaronisSaaS_instance_1",
        "status": 1,
        "type": "Varonis SaaS Incident"
    }
    mocker.patch.object(demisto, 'debug', return_value=None)
    mocker.patch.object(demisto, 'incident', return_value=incident)
    execute_mocker = mocker.patch.object(demisto, 'executeCommand')
    expected_command = 'setIncident'
    expected_args = {
        'id': incident['id'],
        'customFields': {'varonissaasalertstatus': 'closed'}
    }
    update_alert_status()
    execute_mocker.assert_called_with(expected_command, expected_args)
