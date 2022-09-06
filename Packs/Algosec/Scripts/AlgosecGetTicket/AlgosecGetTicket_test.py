import demistomock as demisto


def test_AlgosecGetTicket(mocker):
    ticket = [{"Contents": {"getTicketResponse": "my_Data"}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    import AlgosecGetTicket
