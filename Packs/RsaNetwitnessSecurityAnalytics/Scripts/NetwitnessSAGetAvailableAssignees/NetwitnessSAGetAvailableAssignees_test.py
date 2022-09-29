import demistomock as demisto


def test_netwitness_im_get_available_assignees(mocker):
    """
    Given:
        - response mock.
    When:
        - running NetwitnessSAGetAvailableAssignees script.
    Then:
        - Ensure that the results were built correctly.
    """
    from NetwitnessSAGetAvailableAssignees import netwitness_im_get_available_assignees
    entry = [{"Type": 3, "Contents": {"availableAssignees": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=entry)
    results_mock = mocker.patch.object(demisto, 'results')
    netwitness_im_get_available_assignees()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
