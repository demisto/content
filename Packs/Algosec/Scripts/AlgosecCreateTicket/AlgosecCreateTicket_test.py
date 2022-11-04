import demistomock as demisto


def test_algosec_create_ticket(mocker):
    """
    Given:
        - response mock.
    When:
        - running AlgosecCreateTicket script.
    Then:
        - Ensure that the results were built correctly.
    """
    from AlgosecCreateTicket import algosec_create_ticket
    ticket = [{"Type": 3, "Contents": {"createTicketResponse": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    results_mock = mocker.patch.object(demisto, 'results')
    algosec_create_ticket()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
