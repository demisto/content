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
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'retries': 1,
                                                       'persistent': 'true',
                                                       'option1': 'yes',
                                                       'option2': 'no',
                                                       'task': 'task1',
                                                       'additionalOptions': '1,2,3'
                                                       })
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': 1}])
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': 'entitlement',
                                                                  'Type': 'text'}])

    _, text = salesforce_ask_user()
    assert 'Please reply with either ' in text
