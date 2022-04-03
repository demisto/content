import json
import io
from DeleteReportedEmail import *
import pytest

from CommonServerPython import *
TEST_DATA = 'test_data'
SEARCH_RESPONSE_SUFFIX = '_search_response.json'

EXPECTED_DELETION_ARGS_RESULTS = {'gmail': {
            'user-id': 'user_id',
            'message-id': 'message_id',
            'permanent': False,
            'using-brand': 'brand',
        },
    'MSGraph': {
            'user_id': 'user_id',
            'message_id': 'message_id',
            'using-brand': 'brand',
        },

    'EWSv2': {
            'item-ids': 'item_id',
            'delete-type': 'soft',
            'using-brand': 'brand',
        },
    'EWS365': {
    'item-ids': 'item_id',
    'delete-type': 'soft',
    'using-brand': 'brand',
    }
}

MISSING_EMAIL_ERROR_MSG = 'Email was not found in mailbox. It is possible that the email was already deleted manually.'

@pytest.mark.parametrize('integration_name', ['EWS365', 'EWSv2', 'gmail', 'MSGraph'])
def test_get_deletion_args(integration_name):
    """
    Given:
    a dict of search args parsed earlier
    and search results retrieved from the search operation priorly
    When:
    Deleting an email
    Then:
    return the suitable deletion args
    """
    args_func = {'EWS365': DeletionArgs.ews, 'EWSv2': DeletionArgs.ews,
                                     'gmail': DeletionArgs.gmail, 'MSGraph': DeletionArgs.msgraph}

    search_args = {
        'delete-type': 'soft',
        'using-brand': 'brand',
        'email_subject': 'subject',
        'message-id': 'message_id',
        'query': 'query',
        'target-mailbox': 'user_id',
        'user_id': 'user_id',
        'odata': 'odata',
        'user-id': 'user_id'
        }
    with open(os.path.join(TEST_DATA, f'{integration_name}{SEARCH_RESPONSE_SUFFIX}'), 'r') as file:
        search_results = json.load(file)
    assert EXPECTED_DELETION_ARGS_RESULTS[integration_name] == args_func[integration_name](search_results, search_args)

@pytest.mark.parametrize('delete_email_context, result', [([],
                                                           ('Skipped', MISSING_EMAIL_ERROR_MSG)),
                                                          ([{'message_id': 'message-id', 'result': 'Success'}], '')])
def test_was_email_already_deleted(mocker, delete_email_context, result):
    """

    Given:
        An email that was not found in the mailbox
    When:
        When deleting an email and checking if it may have been already deleted
    Then:
        Return 'Success' if the email was already deleted priorly, and 'Skipped' otherwise, and the error msg
    """
    delete_email_from_context_was_not_deleted = []
    delete_email_from_context_was_deleted = [{'message_id': 'message-id', 'result': 'Success'}]
    # mocker.patch.object(demisto, 'get', return_value=INCIDENT_IDS)
    # mocker.patch.object(demisto, 'executeCommand', return_value=incident_created)


def test_was_email_found_security_and_compliance():
    success_results_dict = [{'SuccessResults': '{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 1, Total size: 55543}'}]
    assert was_email_found_security_and_compliance(success_results_dict)


def test_security_and_compliance_delete_mail():
    pass

def test_delete_email():
    pass

def test_search_args():
    pass

