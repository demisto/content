import demistomock as demisto


def test_algosec_get_applications(mocker):
    """
    Given:
        - response mock.
    When:
        - running AlgosecGetApplications script.
    Then:
        - Ensure that the results were built correctly.
    """
    from AlgosecGetApplications import algosec_get_applications
    ticket = [{"Type": 3, "Contents": {"some_info": {"info": "test"}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=ticket)
    results_mock = mocker.patch.object(demisto, 'results')
    algosec_get_applications()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
