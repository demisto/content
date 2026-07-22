import pytest

import demistomock as demisto


@pytest.mark.parametrize(
    "args, need_update", [({"requiredavdefversion": "1/1/1970 1000"}, "no"), ({"requiredavdefversion": "1/1/1971 1000"}, "yes")]
)
def test_check_outdated_endpoints(mocker, args, need_update):
    """
    Given:
        - response mock.
    When:
        - running SEPCheckOutdatedEndpoints script.
    Then:
        - Ensure that the results were built correctly.
    """
    from SEPCheckOutdatedEndpoints import check_outdated_endpoints

    entry = [{"Type": 3, "Contents": {"clientDefStatusList": [{"version": "1970-1-1 1000", "clientsCount": 1}]}}]
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", return_value=entry)
    results_mock = mocker.patch.object(demisto, "results")
    check_outdated_endpoints()
    assert results_mock.call_args[0][0][0] == need_update
