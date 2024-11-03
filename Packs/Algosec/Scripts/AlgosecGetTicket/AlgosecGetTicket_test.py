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
    from AlgosecGetTicket import main
    ticket = [{"Type": 3, "Contents": {"getTicketResponse": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    res = main()
    content = res.raw_response
    assert content == {'some_info': 'info: test'}
