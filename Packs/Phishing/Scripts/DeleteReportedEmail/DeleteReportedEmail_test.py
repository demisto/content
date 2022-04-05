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


@pytest.mark.parametrize('delete_email_context, result', [([], ('Skipped', MISSING_EMAIL_ERROR_MSG)),
                                                          ([{'message_id': 'message-id', 'result': 'Success'}],
                                                           ('Success', ''))])
def test_was_email_already_deleted(mocker, delete_email_context, result):
    """

    Given:
        An email that was not found in the mailbox
    When:
        When deleting an email and checking if it may have been already deleted
    Then:
        Return 'Success' if the email was already deleted priorly, and 'Skipped' otherwise, and the error msg
    """
    search_args = {'message_id': 'message-id'}
    mocker.patch.object(demisto, 'get', return_value=delete_email_context)
    e = MissingEmailException()
    assert was_email_already_deleted(search_args, e) == result


def test_was_email_found_security_and_compliance():
    """

    Given:
        Search results from security and compliance
    When:
        When deleting an email and checking if it was found in the search operation done priorly
    Then:
        Return true if the email was found, and false otherwise
    """
    success_results_dict = [{'SuccessResults': '{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 1, Total size: 55543}'}]
    success_results_dict_not_found = [{'SuccessResults': '{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 0, Total size: 55543}'}]

    assert was_email_found_security_and_compliance(success_results_dict)
    assert not was_email_found_security_and_compliance(success_results_dict_not_found)


class TestSecurityAndCompliance:

    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        self.search_args = {
            'delete_type': 'delete-type',
            'using_brand': 'brand',
            'email_subject': 'subject',
            'to_user_id': 'user_id',
            'from_user_id': 'from_user_id'
        }
        self.args = {}
        import DeleteReportedEmail
        mocker.patch.object(DeleteReportedEmail, 'check_demisto_version', return_value=None)
        mocker.patch.object(DeleteReportedEmail, 'schedule_next_command', return_value='')
        mocker.patch.object(DeleteReportedEmail, 'was_email_found_security_and_compliance', return_value=True)

    def test_first_call(self, mocker):
        """
        Given:
            Search arguments to use for the search operation
        When:
            Initiating a delete via security and compliance
        Then:
            Return a polling result that initiates the polling flow
        """

        mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'Status': 'Starting'}, 'Type': 'entry'}, {'Contents': {'Status': 'Starting'}, 'Type': 'entry'}])
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == 'In Progress'

    def test_polled_call(self, mocker):
        """
        Given:
            Search arguments to use for the search operation, including the search_name
        When:
            Initiating a delete via security and compliance
        Then:
            Return a polling result that initiates the polling flow
        """
        mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'Status': 'Complete'}, 'Type': 'entry'}, {'Contents': {'Status': 'Starting'}, 'Type': 'entry'}])
        self.args['search_name'] = 'search_name'


def test_delete_email():
    pass

GENERAL_SEARCH_ARGS = {
        'delete-type': 'emaildeletetype',
        'email_subject': 'reportedemailsubject',
        'message-id': 'reportedemailmessageid',
    }


ADDED_SEARCH_ARGS = {
     'Gmail': {'query': f'Rfc822msgid:reportedemailmessageid', 'user-id': 'reportedemailto'},
     'EWSO365': {'target-mailbox': 'reportedemailto'},
     'EWS v2': {'target-mailbox': 'reportedemailto'},
     'MicrosoftGraphMail': {'user_id': 'reportedemailto',
                            'odata': f'"$filter=internetMessageId eq \'reportedemailmessageid\'"'},
     'SecurityAndCompliance': {'to_user_id': 'reportedemailto',
                               'from_user_id': 'reportedemailfrom'},
                    }


@pytest.mark.parametrize('brand', ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance'])
def test_search_args(mocker, brand):
    """

        Given:
            Script args
        When:
            Initiating a delete
        Then:
            Return the suitable search args

    """
    import DeleteReportedEmail
    INCIDENT_INFO = {
        'CustomFields':
            {
               'reportedemailmessageid': 'reportedemailmessageid',
                'reportedemailto': 'reportedemailto',
                'emaildeletetype': 'emaildeletetype',
                'reportedemailfrom': 'reportedemailfrom',
                'reportedemailsubject': 'reportedemailsubject'
            }
    }
    mocker.patch.object(DeleteReportedEmail, 'delete_from_brand_handler', return_value=brand)
    mocker.patch.object(demisto, 'incident', return_value=INCIDENT_INFO)
    GENERAL_SEARCH_ARGS['using-brand'] = brand
    GENERAL_SEARCH_ARGS.update(ADDED_SEARCH_ARGS[brand])
    assert get_search_args({}) == GENERAL_SEARCH_ARGS



