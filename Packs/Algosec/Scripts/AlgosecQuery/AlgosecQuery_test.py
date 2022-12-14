import demistomock as demisto


def test_algosec_query(mocker):
    """
    Given:
        - response mock.
    When:
        - running AlgosecQuery script.
    Then:
        - Ensure that the results were built correctly.
    """
    from AlgosecQuery import algosec_query
    ticket = [{"Type": 3, "Contents": {"QueryResponse": {"QueryResult": {'some_info': 'info: test'}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    results_mock = mocker.patch.object(demisto, 'results')
    algosec_query()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
