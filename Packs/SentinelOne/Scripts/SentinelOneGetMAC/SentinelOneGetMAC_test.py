import demistomock as demisto

from SentinelOneGetMAC import get_agent_details


def test_command(mocker):
    """
    Given
        - arguments - agentID
    When
        - running SentinelOneGetMAC command
    Then
        - returns network interface details of an agent.
    """
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = get_agent_details({'agentId': 'agentId_test'})
    output = res.outputs[0]

    assert output.get('agentId') == 'agentId_test'
    assert output.get('ip') == 'ip_test'
    assert output.get('mac') == 'mac_test'


def executeCommand(command, args=None):
    if command == 'sentinelone-get-agent':
        return [{'Contents': [{'computerName': 'computerName_test', 'networkInterfaces': [{
            'int_name': 'int_name_test',
            'inet': 'ip_test',
            'physical': 'mac_test'
        }]}], 'Type': 'note'}]
