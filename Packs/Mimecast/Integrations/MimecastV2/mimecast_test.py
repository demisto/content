from __future__ import print_function

import MimecastV2

from CommonServerPython import *

# Parameters for Get arguments test
policy_data = {
    'description': 'new',
    'fromPart': 'bla bla',
    'fromType': 'free_mail_domains',
    'fromValue': 'gmail.com',
    'toType': 'email_domain',
    'toValue': 'gmail.com',
    'option': 'no_action',
    'policy_id': 'IDFROMMIMECAST'
}

policy_args = {
    'description': 'new',
    'fromPart': 'bla bla',
    'fromType': 'free_mail_domains',
    'fromValue': 'gmail.com',
    'toType': 'email_domain',
    'toValue': 'gmail.com'
}

get_args_response = (policy_args, 'no_action')

# Parameters for Update policy test
policy_obj = {
    'description': 'new new',
    'from': {
        'emailDomain': 'gmail.com',
        'type': 'free_mail_domains'
    },
    'to': {
        'emailDomain': 'gmail.com',
        'type': 'email_domain'
    }
}

update_two_args = {'fromType': 'free_mail_domains', 'description': 'new new'}
update_all_args = {'fromType': 'free_mail_domains', 'fromValue': 'gmail.com', 'toType': 'email_domain',
                   'toValue': 'gmail.com', 'description': 'new new'}
update_policy_req_response = {
    'policy': policy_obj,
    'option': 'no_action',
    'id': 'IDFROMMIMECAST'
}

set_empty_value_args_res_list = [update_two_args, 'no_action', 'IDFROMMIMECAST']
set_empty_value_args_res_list_all = [update_all_args, 'no_action', 'IDFROMMIMECAST']
demisto_args = {'policy_id': 'IDFROMMIMECAST'}


def test_get_arguments_for_policy_command():
    res = MimecastV2.get_arguments_for_policy_command(policy_data)
    assert get_args_response == res


def test_update_policy(mocker):
    mocker.patch.object(MimecastV2, 'get_arguments_for_policy_command', return_value=get_args_response)
    mocker.patch.object(MimecastV2, 'set_empty_value_args_policy_update', return_value=set_empty_value_args_res_list)
    mocker.patch.object(MimecastV2, 'create_or_update_policy_request', return_value=update_policy_req_response)
    mocker.patch.object(demisto, 'args', return_value=demisto_args)

    res = MimecastV2.update_policy()
    assert res['Contents']['Description'] == 'new new'
    assert res['Contents']['Sender']['Type'] == 'free_mail_domains'

    mocker.patch.object(MimecastV2, 'get_arguments_for_policy_command', return_value=get_args_response)
    mocker.patch.object(MimecastV2, 'set_empty_value_args_policy_update',
                        return_value=set_empty_value_args_res_list_all)
    mocker.patch.object(MimecastV2, 'create_or_update_policy_request', return_value=update_policy_req_response)
    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    res = MimecastV2.update_policy()
    assert res['Contents']['Description'] == 'new new'
    assert res['Contents']['Sender']['Type'] == 'free_mail_domains'
    assert res['Contents']['Sender']['Domain'] == 'gmail.com'
    assert res['Contents']['Receiver']['Type'] == 'email_domain'
    assert res['Contents']['Receiver']['Domain'] == 'gmail.com'


INCIDENT_API_RESPONSE = {
    'fail': [

    ],
    'meta': {
        'status': 200
    },
    'data': [
        {
            'code': 'TR-CSND1A7780-00045-M',
            'successful': 0,
            'create': '2020-05-25T10:01:53+0000',
            'modified': '2020-05-25T10:01:53+0000',
            'identified': 3,
            'failed': 0,
            'reason': 'test',
            'id': 'test-id',
            'type': 'manual',
            'searchCriteria': {
                'start': '2020-04-25T10:01:53+0000',
                'end': '2020-05-25T22:01:53+0000',
                'messageId': 'test message id'
            },
            'restored': 0
        }
    ]
}

EXPECTED_MARKDOWN_RESPONSE = """### Incident test-id has been created

#### Code: TR-CSND1A7780-00045-M
#### Type: manual
#### Reason: test
#### The number of messages identified based on the search criteria: 3
#### The number successfully remediated messages: 0
#### The number of messages that failed to remediate: 0
#### The number of messages that were restored from the incident: 0

|End date|Message ID|
|---|---|
| 2020-05-25T22:01:53+0000 | test message id |
"""


def test_mimecast_incident_api_response_to_markdown():
    actual_response = MimecastV2.mimecast_incident_api_response_to_markdown(INCIDENT_API_RESPONSE, 'create')
    assert actual_response == EXPECTED_MARKDOWN_RESPONSE


EXPECTED_CONTEXT_RESPONSE = {
    'Mimecast.Incident(val.ID && val.ID == obj.ID)': {
        'Reason': 'test',
        'Code': 'TR-CSND1A7780-00045-M',
        'FailedRemediatedMessages': 0,
        'IdentifiedMessages': 3,
        'MessagesRestored': 0,
        'LastModified': '2020-05-25T10:01:53+0000',
        'SearchCriteria': {
            'StartDate': '2020-04-25T10:01:53+0000',
            'EndDate': '2020-05-25T22:01:53+0000',
            'FileHash': None,
            'To': None,
            'MessageID': 'test message id',
            'From': None
        },
        'Type': 'manual',
        'ID': 'test-id',
        'SuccessfullyRemediatedMessages': 0
    }
}


def test_mimecast_incident_api_response_to_context():
    actual_response = MimecastV2.mimecast_incident_api_response_to_context(INCIDENT_API_RESPONSE)
    assert actual_response == EXPECTED_CONTEXT_RESPONSE


add_member_req_response = {'data': [{'emailAddress': 'test@gmail.com', 'folderId': 'folder_id'}]}
get_group_members_req_response = {'data': [{'groupMembers': {}}]}


def test_mimecast_add_remove_member_to_group_with_email(mocker):
    """Unit test
    Given
    - add_remove_member_to_group command
    - command args - email and group id.
    - command raw response
    When
    - mock the server response to create_add_remove_group_member_request.
    - mock the server response to create_get_group_members_request
    Then
    Validate the content of the HumanReadable.
    """
    mocker.patch.object(demisto, 'args', return_value={'group_id': '1234', 'email_address': 'test@gmail.com'})
    mocker.patch.object(MimecastV2, 'create_add_remove_group_member_request', return_value=add_member_req_response)
    mocker.patch.object(MimecastV2, 'create_get_group_members_request', return_value=get_group_members_req_response)
    readable, _, _ = MimecastV2.add_remove_member_to_group('add')
    assert readable == 'test@gmail.com had been added to group ID folder_id'


add_member_req_response_no_email = {'data': [{'folderId': 'folder_id'}]}


def test_mimecast_add_remove_member_to_group_with_domain(mocker):
    """Unit test
    Given
    - add_remove_member_to_group command
    - command args - domain and group id.
    - command raw response
    When
    - mock the server response to create_add_remove_group_member_request.
    - mock the server response to create_get_group_members_request
    Then
    Validate the content of the HumanReadable.
    """
    mocker.patch.object(demisto, 'args', return_value={'group_id': '1234', 'domain': 'test.com'})
    mocker.patch.object(MimecastV2, 'create_add_remove_group_member_request',
                        return_value=add_member_req_response_no_email)
    mocker.patch.object(MimecastV2, 'create_get_group_members_request', return_value=get_group_members_req_response)
    readable, _, _ = MimecastV2.add_remove_member_to_group('add')
    assert readable == 'Address had been added to group ID folder_id'
