import demistomock as demisto
from SendCPAction import send_action_and_update_incident

FARM = 'mt-rnd-ng-6'
CUSTOMER = 'avananlab'


def test_send_action_and_update_incident(mocker):
    def execute_command(name, args):
        if name == 'checkpointhec-send-action':
            return [{'Contents': {'task': 1}}]

        if name == 'setIncident':
            return None

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = send_action_and_update_incident(FARM, CUSTOMER, '0000', 'quarantine')
    assert result == [{'Contents': {'task': 1}}]
