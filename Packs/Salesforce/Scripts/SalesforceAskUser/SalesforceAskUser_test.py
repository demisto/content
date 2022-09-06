import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from SalesforceAskUser import salesforce_ask_user


def test_salesforce_ask_user(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the salesforce_ask_user function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'retries': 1,
                                                       'persistent': 'true',
                                                       'option1': '?',
                                                       'option2': '?',
                                                       'additionalOptions': '1,2,3'
                                                       })
    # todo: mock isError
    mocker.patch.object(demisto, 'incidents')
    oid, text = salesforce_ask_user()
    assert 'No entries with' in results_mock.call_args[0][0]['Contents']
