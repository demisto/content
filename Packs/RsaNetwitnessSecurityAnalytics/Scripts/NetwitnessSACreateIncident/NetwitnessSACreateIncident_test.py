import demistomock as demisto


def test_netwitness_im_create_incident(mocker):
    """
    Given:
        - response mock.
    When:
        - running NetwitnessSACreateIncident script.
    Then:
        - Ensure that the results were built correctly.
    """
    from NetwitnessSACreateIncident import netwitness_im_create_incident
    entry = [{"Type": 3, "Contents": {"incident": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=entry)
    results_mock = mocker.patch.object(demisto, 'results')
    netwitness_im_create_incident()
    assert results_mock.call_args[0][0]['Contents'] == [{'some_info': 'info: test'}]
