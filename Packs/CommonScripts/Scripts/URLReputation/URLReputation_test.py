import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_url_reputation(mocker):
    """
    Given:
        - The script args.
    When:
        - Running url_reputation function.
    Then:
        - Validating the outputs as expected.
    """
    from URLReputation import url_reputation
    mocker.patch.object(demisto, 'args', return_value={'url': 'www.url.com'})
    execute_command_res = [{'Type': 4, 'Contents': 'Error', 'Brand': 'brand'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    url_reputation()
    assert execute_mock.call_count == 1
    assert 'returned an error' in results_mock.call_args[0][0][0]['Contents']
