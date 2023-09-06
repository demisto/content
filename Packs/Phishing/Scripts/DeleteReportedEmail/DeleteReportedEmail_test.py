from copy import deepcopy

import CommonServerPython
from DeleteReportedEmail import *
import DeleteReportedEmail
import pytest

from CommonServerPython import *

TEST_DATA = 'test_data'
SEARCH_RESPONSE_SUFFIX = '_search_response.json'

EXPECTED_DELETION_ARGS_RESULTS = {
    'gmail': {
        'user-id': 'user_id',
        'message-id': 'message_id',
        'permanent': False,
        'using-brand': 'brand'
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
        'target-mailbox': 'user_id'
    },
    'EWS365': {
        'item-ids': 'item_id',
        'delete-type': 'soft',
        'using-brand': 'brand',
        'target-mailbox': 'user_id'
    }
}

ARGS_FUNC = {'EWS365': DeletionArgs.ews, 'EWSv2': DeletionArgs.ews,
             'gmail': DeletionArgs.gmail, 'MSGraph': DeletionArgs.msgraph}

SEARCH_ARGS = {
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

MISSING_EMAIL_ERROR_MSG = 'Email not found in mailbox. It may have been manually deleted.'

WAS_EMAIL_DELETED_EXPECTED_RESULTS = [([], ('Skipped', MISSING_EMAIL_ERROR_MSG)),
                                      ([{'message_id': 'message-id', 'result': 'Success'}], ('Success', ''))]


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
    with open(os.path.join(TEST_DATA, f'{integration_name}{SEARCH_RESPONSE_SUFFIX}'), 'r') as file:
        search_results = json.load(file)
    assert EXPECTED_DELETION_ARGS_RESULTS[integration_name] == ARGS_FUNC[integration_name](search_results, SEARCH_ARGS)


@pytest.mark.parametrize('integration_name', ['EWS365', 'EWSv2', 'gmail', 'MSGraph'])
def test_delete_email(mocker, integration_name):
    """
    Given:
        Search arguments to use for the search operation
    When:
        Initiating a delete
    Then:
        delete the email
    """
    with open(os.path.join(TEST_DATA, f'{integration_name}{SEARCH_RESPONSE_SUFFIX}'), 'r') as file:
        search_results = json.load(file)
    mocker.patch.object(DeleteReportedEmail, 'execute_command', return_value=search_results)
    assert delete_email(SEARCH_ARGS, 'func', ARGS_FUNC[integration_name], 'func', lambda x: False) == 'Success'


@pytest.mark.parametrize('delete_email_context, result', WAS_EMAIL_DELETED_EXPECTED_RESULTS)
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
    assert was_email_already_deleted(search_args, str(e)) == result


def test_was_email_found_security_and_compliance():
    """

    Given:
        Search results from security and compliance
    When:
        When deleting an email and checking if it was found in the search operation done priorly
    Then:
        Return true if the email was found, and false otherwise
    """
    success_results_dict = [{
        'SuccessResults': '{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 1, Total size: 55543}'}]
    success_results_dict_not_found = [{
        'SuccessResults': '{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 0, Total size: 55543}'}]

    assert was_email_found_security_and_compliance(success_results_dict)
    assert not was_email_found_security_and_compliance(success_results_dict_not_found)


def execute_command_search_and_compliance_not_deleted_yet(command, args):
    if command == 'o365-sc-get-search' and args:
        return [{'Status': 'Completed'}]
    elif command == 'o365-sc-list-search-action':
        return []
    elif command == 'o365-sc-new-search-action':
        return None
    elif command == 'o365-sc-get-search-action':
        return {'Status': 'Starting'}


def execute_command_search_and_compliance_deleted_successfully(command, args):
    if command == 'o365-sc-get-search' and args:
        return [{'Status': 'Completed'}]
    elif command == 'o365-sc-list-search-action':
        return [{'Name': 'search_name_Purge'}]
    elif command == 'o365-sc-new-search-action':
        return None
    elif command == 'o365-sc-get-search-action':
        return {'Status': 'Completed'}


class TestSecurityAndCompliance:

    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        self.search_args = {
            'delete_type': 'delete-type',
            'using_brand': 'brand',
            'email_subject': 'subject',
            'to_user_id': 'user_id',
            'from_user_id': 'from_user_id',
            'message_id': 'message_id'
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
            Return that the status is in progress
        """

        mocker.patch.object(demisto, 'executeCommand',
                            return_value=[{'Contents': {'Status': 'Starting'}, 'Type': 'entry'},
                                          {'Contents': {'Status': 'Starting'}, 'Type': 'entry'}])
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == 'In Progress'

    def test_polled_call_create_deletion(self, mocker):
        """
        Given:
            Search arguments to use for the search operation, including the search_name
        When:
            Initiating a delete via security and compliance
        Then:
            Return that the status is in progress
        """
        mocker.patch.object(DeleteReportedEmail, 'execute_command',
                            side_effect=execute_command_search_and_compliance_not_deleted_yet)
        self.args['search_name'] = 'search_name'
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == 'In Progress'

    def test_polled_call_deletion_success(self, mocker):
        """
        Given:
            Search arguments to use for the search operation, including the search_name
        When:
            Initiating a delete via security and compliance
        Then:
            Return Success
        """
        mocker.patch.object(DeleteReportedEmail, 'execute_command',
                            side_effect=execute_command_search_and_compliance_deleted_successfully)
        self.args['search_name'] = 'search_name'
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == 'Success'


GENERAL_SEARCH_ARGS = {
    'delete-type': 'emaildeletetype',
    'email_subject': 'reportedemailsubject',
    'message-id': 'reportedemailmessageid',
}


ADDED_SEARCH_ARGS = {
    'Gmail': {'query': 'Rfc822msgid:reportedemailmessageid', 'user-id': 'reportedemailto'},
    'EWSO365': {'target-mailbox': 'reportedemailto'},
    'EWS v2': {'target-mailbox': 'reportedemailto'},
    'MicrosoftGraphMail': {'user_id': 'reportedemailto',
                           'odata': '"$filter=internetMessageId eq \'reportedemailmessageid\'"'},
    'SecurityAndCompliance': {'to_user_id': 'reportedemailto', 'from_user_id': 'reportedemailfrom'},
    'SecurityAndComplianceV2': {'to_user_id': 'reportedemailto', 'from_user_id': 'reportedemailfrom'},
}


@pytest.mark.parametrize('brand', ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                                   'SecurityAndCompliance', 'SecurityAndComplianceV2'])
def test_search_args(mocker, brand):
    """

        Given:
            Script args
        When:
            Initiating a delete
        Then:
            Return the suitable search args

    """
    INCIDENT_INFO = {
        'CustomFields':
            {
                'reportedemailorigin': 'Attached',
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
    current_search_args = GENERAL_SEARCH_ARGS.copy()
    current_search_args.update(ADDED_SEARCH_ARGS.get(brand, {}))
    assert get_search_args({}) == current_search_args

    # Test 'email_origin' is 'none' exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, 'incident', return_value=incident_info_copy)
    incident_info_copy['CustomFields']["reportedemailorigin"] = "None"
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email Origin' field could not be found" in str(e.value)

    # Test missing message id exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, 'incident', return_value=incident_info_copy)
    incident_info_copy['CustomFields'].pop("reportedemailmessageid")
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email Message ID' field could not be found" in str(e.value)

    # Test missing user id exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, 'incident', return_value=incident_info_copy)
    incident_info_copy['CustomFields'].pop("reportedemailto")
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email To' field could not be found" in str(e.value)


def test_schedule_next_command(mocker):
    """

        Given:
            Script args
        When:
            Initiating a delete using security and compliance
        Then:
            Return a ScheduledCommand object

    """
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    args = {'arg': 'arg'}
    assert isinstance(schedule_next_command(args), ScheduledCommand)
