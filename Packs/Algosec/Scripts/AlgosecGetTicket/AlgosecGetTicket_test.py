import demistomock as demisto


def test_AlgosecGetTicket(mocker):
    ticket = [{"Contents": {"getTicketResponse": "my_Data"}}]
    demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    
    execute_command_args = demisto_execute_mock.call_args_list[0][0]
    demisto.executeCommand
    