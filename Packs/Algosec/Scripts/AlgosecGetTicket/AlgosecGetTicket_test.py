import demistomock as demisto


def test_algosec_get_ticket(mocker):
    """
    Given:
        - response mock.
    When:
        - running AlgosecGetTicket script.
    Then:
        - Ensure that the results were built correctly.
    """
    from AlgosecGetTicket import algosec_get_ticket
    ticket = [{"Type": 3, "Contents": {"getTicketResponse": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    res = algosec_get_ticket()
    content = res.raw_response
    assert {'some_info': 'info: test'} == content
