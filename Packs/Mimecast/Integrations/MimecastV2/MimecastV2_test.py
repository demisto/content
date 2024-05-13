
import pytest

import MimecastV2

from CommonServerPython import *

QUERY_XML = """<?xml version=\"1.0\"?>
    <xmlquery trace=\"iql,muse\">
    <metadata query-type=\"emailarchive\" archive=\"true\" active=\"false\" page-size=\"25\" startrow=\"0\">
        <smartfolders/>
        <return-fields>
            <return-field>attachmentcount</return-field>
            <return-field>status</return-field>
            <return-field>subject</return-field>
            <return-field>size</return-field>
            <return-field>receiveddate</return-field>
            <return-field>displayfrom</return-field>
            <return-field>id</return-field>
            <return-field>displayto</return-field>
            <return-field>smash</return-field>
            <return-field>displaytoaddresslist</return-field>
            <return-field>displayfromaddress</return-field>
        </return-fields>
    </metadata>
    <muse>
        <text></text>
        <date select=\"last_year\"/>
        <sent></sent>
        <docs select=\"optional\"></docs>
        <route/>
    </muse>
    </xmlquery>"""

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

MimecastV2.BASE_URL = 'http://test.com'
MimecastV2.APP_KEY = 'test_key'
MimecastV2.EMAIL_ADDRESS = 'test@test.com'
MimecastV2.APP_ID = '1234'
MimecastV2.ACCESS_KEY = '12345'
MimecastV2.SECRET_KEY = 'test_key=='


def util_load_json(path):
    """

    Args:
        path: path to load json from.

    Returns:
        json object read from the path given
    """
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


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
    result = MimecastV2.add_remove_member_to_group('add')
    assert result.readable_output == 'test@gmail.com had been added to group ID folder_id'


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
    results = MimecastV2.add_remove_member_to_group('add')
    assert results.readable_output == 'Address had been added to group ID folder_id'


CREATE_MANAGED_URL_SUCCESSFUL_MOCK = {
    "fail": [],
    "meta": {
        "status": 200
    },
    "data": [
        {
            "comment": "None",
            "domain": "www.test.com",
            "queryString": "",
            "disableRewrite": False,
            "port": -1,
            "disableUserAwareness": False,
            "disableLogClick": False,
            "action": "permit",
            "path": "",
            "matchType": "explicit",
            "scheme": "https",
            "id": "fake_id"
        }
    ]
}


def test_create_managed_url(mocker):
    """Unit test
    Given
    - create_managed_url command
    - the url does not exist
    - command args - url, action, matchType, disableRewrite, disableUserAwareness, disableLogClick
    - command raw response
    When
    - mock the server response to create_managed_url_request.
    Then
    Validate the content of the command result.
    """
    args = {
        'url': 'https://www.test.com',
        'action': 'permit',
        'matchType': 'explicit',
        'disableRewrite': 'false',
        'disableUserAwareness': 'false',
        'disableLogClick': 'false'
    }

    expected_context = {
        'Mimecast.URL(val.ID && val.ID == obj.ID)':
            [{'Domain': 'www.test.com',
              'disableRewrite': False,
              'disableLogClick': False,
              'Action': 'permit',
              'Path': '',
              'matchType': 'explicit',
              'ID': 'fake_id'}]}

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(MimecastV2, 'create_managed_url_request',
                        return_value=CREATE_MANAGED_URL_SUCCESSFUL_MOCK['data'][0])
    results = MimecastV2.create_managed_url()
    assert 'Managed URL https://www.test.com created successfully!' in results.get('HumanReadable')
    assert expected_context == results.get('EntryContext')


def test_add_users_under_group_in_context_dict__dict(mocker):
    """
    Given
    - Users list
    - Group id
    _ Integration context with `group` key with a single group in it
    When
    - adding users under group in context dict as part of `mimecast-get-group-members` command
    Then
    Returns a valid outputs
    """
    context = {'Mimecast': {'Group': {'ID': 'groupID', 'Users': []}}}
    users_list = [
        {'Domain': 'demistodev.com', 'Name': '', 'EmailAddress': 'testing@demistodev.com', 'InternalUser': True,
         'Type': 'created_manually', 'IsRemoved': False}]
    expected = [{'ID': 'groupID', 'Users': [
        {'Domain': 'demistodev.com', 'Name': '', 'EmailAddress': 'testing@demistodev.com', 'InternalUser': True,
         'Type': 'created_manually', 'IsRemoved': False}]}]
    mocker.patch.object(demisto, 'context', return_value=context)
    result = MimecastV2.add_users_under_group_in_context_dict(users_list, 'groupID')
    assert result == expected


def test_add_users_under_group_in_context_dict__list(mocker):
    """
    Given
    - Users list
    - Group id
    _ Integration context with `group` key with list of groups in it
    When
    - adding users under group in context dict as part of `mimecast-get-group-members` command
    Then
    Returns a valid outpus
    """
    context = {'Mimecast': {'Group': [{
        'ID': 'groupID',
        'Users': []},
        {'ID': 'groupID2',
         'Users': []}]}

    }
    users_list = [
        {'Domain': 'demistodev.com', 'Name': '', 'EmailAddress': 'testing@demistodev.com', 'InternalUser': True,
         'Type': 'created_manually', 'IsRemoved': False}]
    expected = [{'ID': 'groupID', 'Users': [
        {'Domain': 'demistodev.com', 'Name': '', 'EmailAddress': 'testing@demistodev.com', 'InternalUser': True,
         'Type': 'created_manually', 'IsRemoved': False}]}, {'ID': 'groupID2', 'Users': []}]
    mocker.patch.object(demisto, 'context', return_value=context)
    result = MimecastV2.add_users_under_group_in_context_dict(users_list, 'groupID')
    assert result == expected


def test_search_message_command(mocker):
    """

        Given:
            - Message id to search.

        When:
            - Running a search message command to retrieve information on given message.

        Then:
            - Make sure search data is returned.
    """

    mock_response = util_load_json('test_data/search_message_response.json')
    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)

    args = {'message_id': '12345'}
    response = MimecastV2.search_message_command(args)

    assert response.outputs == mock_response.get('data')[0].get('trackedEmails')
    assert response.outputs_prefix == 'Mimecast.SearchMessage'
    assert response.outputs_key_field == 'id'


def test_held_message_summary_command(mocker):
    """
        When:
            - Running a hold message summary command to retrieve hold information messages.

        Then:
            - Make sure hold data is returned.
    """

    mock_response = util_load_json('test_data/hold_message_summary_response.json')
    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)

    response = MimecastV2.held_message_summary_command()

    assert response.outputs == mock_response.get('data')
    assert response.outputs_prefix == 'Mimecast.HeldMessageSummary'
    assert response.outputs_key_field == 'policyInfo'


MESSAGE_INFO_ARGS = [
    (
        {'ids': '12345, 1345',
         'show_delivered_message': 'true'}, True, 1),
    ({'ids': '12345, 1345',
      'show_delivered_message': 'false'}, False, 0)
]


@pytest.mark.parametrize('args, delivered, delivered_message_len', MESSAGE_INFO_ARGS)
def test_get_message_info_command(args, delivered, delivered_message_len, requests_mock):
    """

        Given:
            - Message ids to get info for.

        When:
            - Running a get message info to retrieve information for.

        Then:
            - Make sure correct data is returned.
    """

    mock_response = util_load_json('test_data/get_message_info_response.json')
    requests_mock.post('/api/message-finder/get-message-info', json=mock_response)
    response = MimecastV2.get_message_info_command(args)

    assert len(response) == 2
    assert ('test@test.com' in response[0].readable_output) == delivered
    assert isinstance(response[0].outputs.get('deliveredMessage'), list)
    assert len(response[0].outputs.get('deliveredMessage')) == delivered_message_len
    assert response[0].outputs_prefix == 'Mimecast.MessageInfo'


def test_list_held_messages_command(mocker):
    """

        When:
            - Running a list hold messages command.

        Then:
            - Make sure correct data is returned.
    """

    mock_response = util_load_json('test_data/list_hold_messages_response.json')
    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)
    args = {'admin': 'true', 'limit': '10'}
    response = MimecastV2.list_held_messages_command(args)

    assert len(response.outputs) == 10
    assert response.outputs == mock_response.get('data')
    assert response.outputs_prefix == 'Mimecast.HeldMessage'
    assert response.outputs_key_field == 'id'


REJECT_HOLD_MESSAGE = [
    ({"meta": {
        "status": 200
    }, "data": [{"id": "1234",
                 "reject": True
                 },
                {"id": "1233",
                 "reject": True
                 }],
        "fail": []},
        'Held message with id 1234 was rejected successfully.\n'
        'Held message with id 1233 was rejected successfully.\n', False),
    ({"meta": {
        "status": 200
    }, "data": [{"id": "1234",
                 "reject": False
                 },
                {"id": "1233",
                 "reject": True
                 }],
        "fail": []
    }, '', True)]


@pytest.mark.parametrize('mock_response, readable_output, is_exception_raised', REJECT_HOLD_MESSAGE)
def test_reject_held_message_command(mock_response, readable_output, is_exception_raised, mocker):
    """

        When:
            - Running a reject hold messages command.

        Then:
            - Make sure correct data is returned.
    """

    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)
    args = {'ids': '1234,1233', 'message': 'test', 'reason_type': 'MESSAGE CONTAINS UNDESIRABLE CONTENT',
            'notify': 'true'}
    try:
        response = MimecastV2.reject_held_message_command(args)
        assert response.readable_output == readable_output
    except Exception:
        assert is_exception_raised


RELEASE_HOLD_MESSAGE = [
    ({"meta": {
        "status": 200
    },
        "data": [
        {
            "id": "1234",
            "release": True
        }
    ],
        "fail": []
    }, 'Held message with id 1234 was released successfully', False),
    ({"meta": {
        "status": 200
    },
        "data": [
        {
            "id": "1234",
            "release": False
        }
    ],
        "fail": []
    }, 'Message release has failed.', True)]


@pytest.mark.parametrize('mock_response, readable_output, is_exception_raised', RELEASE_HOLD_MESSAGE)
def test_release_held_message_command(mock_response, readable_output, is_exception_raised, mocker):
    """

        When:
            - Running a release hold messages command.

        Then:
            - Make sure correct data is returned.
    """

    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)
    args = {'id': '1234'}
    try:
        response = MimecastV2.release_held_message_command(args)
        assert response.readable_output == readable_output
    except Exception:
        assert is_exception_raised


def test_search_processing_message_command(mocker):
    """
        When:
            - Running a search processing message command to retrieve information regarding messages being proccessed.

        Then:
            - Make sure hold data is returned.
    """

    mock_response = util_load_json('test_data/search_processing_message_response.json')
    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)
    args = {'sort_order': 'ascending', 'from_date': '2015-11-16T14:49:18+0000', 'to_date': '2021-11-16T14:49:18+0000'}
    response = MimecastV2.search_processing_message_command(args)

    assert response.outputs == mock_response.get('data')[0].get('messages')
    assert response.outputs_prefix == 'Mimecast.ProcessingMessage'
    assert response.outputs_key_field == 'id'


def test_list_email_queues_command(mocker):
    """
        When:
            - Running a search processing message command to retrieve information regarding messages being proccessed.

        Then:
            - Make sure hold data is returned.
    """

    mock_response = util_load_json('test_data/search_processing_message_response.json')
    mocker.patch.object(MimecastV2, 'http_request', return_value=mock_response)
    args = {'sort_order': 'ascending', 'from_date': '2015-11-16T14:49:18+0000', 'to_date': '2021-11-16T14:49:18+0000'}
    response = MimecastV2.search_processing_message_command(args)

    assert response.outputs == mock_response.get('data')[0].get('messages')
    assert response.outputs_prefix == 'Mimecast.ProcessingMessage'
    assert response.outputs_key_field == 'id'


def test_parse_queried_fields():
    assert MimecastV2.parse_queried_fields(QUERY_XML) == (
        "attachmentcount", "status", "subject", "size", "receiveddate", "displayfrom",
        "id", "displayto", "smash", "displaytoaddresslist", "displayfromaddress",
    )


def test_query(mocker):
    """
    Test case for the 'query' function of the MimecastV2 integration.

    GIVEN:
        - a mocked HTTP request to Mimecast API with query data,
    WHEN:
        - 'query' function is called with the provided arguments,
    THEN:
        - Make sure all return-field values are returned to context and human-readable.    """
    query_data = util_load_json("test_data/query_response.json")
    mocker.patch.object(MimecastV2, "http_request", return_value=query_data["response"])

    result = MimecastV2.query({"queryXml": QUERY_XML})
    assert result["HumanReadable"] == (
        "### Mimecast archived emails\n"
        "|Subject|Display From|Display To|Received Date|Size|Attachment Count|Status|ID|displayfromaddress|displaytoaddresslist|"
        "smash|\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| Netting | test1 | test1 | 2023-08-06T07:23:00+0000 | 2262 | 0 | ARCHIVED | test1_id | test1 | {'displayableName': '',"
        " 'emailAddress': 'test1'} | test1_smash |\n"
        "| RE | test2 | test2 | 2023-08-06T07:23:00+0000 | 11370 | 0 | ARCHIVED | test2_id | test2 | {'displayableName': '',"
        " 'emailAddress': 'test2'} | test2_smash |\n"
        "| Re | test3 | test3 | 2023-08-06T07:23:00+0000 | 5280 | 0 | ARCHIVED | test3_id | test3 | {'displayableName': '',"
        " 'emailAddress': 'test3'} | test3_smash |\n"
    )
    assert result["Contents"] == query_data["query_contents"]


def test_empty_query(mocker):
    """
    Test case for the 'query' function of the MimecastV2 integration, where no args are given.

    GIVEN:
        - a mocked HTTP request to Mimecast API with query data,
    WHEN:
        - 'query' function is called with no queryXml argument,
    THEN:
        - Make sure no exception is raised.

    """
    error = {"field": "query",
             "code": "err_validation_blank",
             "message": "This field, if present, cannot be blank or empty",
             "retryable": False}

    def query_mocked_api(api_endpoint: str, data: list, response_param: str = None, limit: int = 100,
                         page: int = None,
                         page_size: int = None, use_headers: bool = False, is_file: bool = False):
        if not data[0].get('query'):
            raise Exception(json.dumps(error))
        else:
            return [], None
    mocker.patch.object(MimecastV2, 'request_with_pagination', side_effect=query_mocked_api)
    results = MimecastV2.query({})

    assert len(results.get('Contents')) == 0


def test_get_message_metadata_with_attachments(mocker):
    """
        Given: Message metadata from API with attachments.
        When: Get message command being called.
        Then: Verify the extension value is returned.
    """
    message_id = '123'
    expected_metadata = {
        'subject': 'Test Email',
        'from': {'emailAddress': 'test@example.com'},
        'attachments': [{
            'filename': 'hello world',
            'id': '1',
            'extension': '.txt'
        }]
    }

    mocker.patch.object(MimecastV2, 'http_request', return_value={'data': [expected_metadata]})

    _, actual_metadata = MimecastV2.get_message_metadata(message_id)

    assert expected_metadata.get('subject') == actual_metadata.get('Subject')
    assert expected_metadata.get('from').get('emailAddress') == actual_metadata.get('From')
    assert expected_metadata.get('attachments')[0].get('filename') == actual_metadata.get('Attachments')[0].get('FileName')
    assert expected_metadata.get('attachments')[0].get('extension') == actual_metadata.get('Attachments')[0].get('Extension')
    assert expected_metadata.get('attachments')[0].get('id') == actual_metadata.get('Attachments')[0].get('ID')


def test_get_archive_search_logs_command(mocker):
    """
    Test case for the 'get_archive_search_logs_command' function of the MimecastV2 class,
    where no 'query_xml' argument is given.

    GIVEN:
        - A mocked HTTP request to the Mimecast API (using http_request).

    WHEN:
        - The 'get_archive_search_logs_command' function is called without the 'query_xml' argument.

    THEN:
        - Make sure no exception is raised.
    """

    args = {'limit': '5', 'query': 'integration.com'}
    expected_response = {
        "meta": {
            "pagination": {
                "pageSize": 10,
                "totalCount": 234,
                "next": "asides"
            },
            "status": 200
        },
        "data": [
            {
                "logs": [
                    {
                        "createTime": "2024-03-20T11:39:36+0000",
                        "emailAddr": "aa@aaaa.aaa.aa.com",
                        "source": "archive",
                        "searchText": "aaaaasas",
                        "searchReason": "",
                        "description": "Message Tracking Search"
                    }
                ]
            }
        ],
        "fail": []
    }
    mocker.patch.object(MimecastV2, 'request_with_pagination_api2', return_value=expected_response)
    result = MimecastV2.get_archive_search_logs_command(args)
    assert expected_response['data'][0]['logs'] == result.outputs['data'][0]['logs']


def test_get_search_logs_command(mocker):
    """
    Tests the 'get_archive_search_logs_command' function of the MimecastV2 class with various arguments.

    This test mocks the http_request method to return a sample response containing archive search
    logs data. It then calls the get_archive_search_logs_command function with arguments specifying
    limit, page, page_size, query, and start date. Finally, it asserts that the extracted logs data
    matches the expected response.

    Args:
        mocker (pytest.MonkeyFixture): Pytest mocker fixture used to patch methods.
    """

    args = {'limit': '50', 'page': '1', 'page_size': '1', 'query': 'aa.aa.aa.aa', 'start': '2017-09-16T14:49:18+0000'}
    expected_response = {
        "meta": {
            "pagination": {
                "pageSize": 1,
                "totalCount": 169,
                "next": "eNodjskOgjAUAP-lVzy0ZVFMPFSMuAVUFKM3bAvWqE9bcMH47xKOkznMfNE9K6RRtVQC9UkHGckr3QIifoon8Xt_FWf-LFbpyYlK7NAkHOYFOdx2Nr4slhEjanlystHRWrNNb7zxgU6lr1y6Ul78qKKZSz0Lz7NKfKyazXUdxmzd9exRDof0ApC-kgAGqIN4ZUq4Ss1ByKYebBNGMGXU9hr5lNoouLWLWnLQwpSZLtvp3x9nzD75"
            },
            "status": 200
        },
        "data": [
            {
                "logs": [
                    {
                        "createTime": "2024-03-25T12:04:48+0000",
                        "emailAddr": "aa@aa.aa.aa.com",
                        "source": "archive",
                        "searchText": "{\"mailbox\":\"aa@aa.aaa.aaaa.com\",\"query\":\"[]\"}",
                        "searchPath": "/INBOX/",
                        "searchReason": "",
                        "isAdmin": 'true',
                        "museQuery": "[]",
                        "description": "Archive Mailbox"
                    }
                ]
            }
        ],
        "fail": []
    }
    mocker.patch.object(MimecastV2, 'http_request', return_value=expected_response)
    result = MimecastV2.get_archive_search_logs_command(args)
    assert expected_response.get('data')[0]['logs'] == result.outputs


def test_get_view_logs_command(mocker):
    """
    Test the get_view_logs_command function of the MimecastV2 integration.

    Args:
        mocker (pytest_mock.plugin.MockerFixture): Pytest mocker fixture.
    """

    args = {"end": "2024-09-16T14:49:18+0000", "limit": "2", "query": "aa@aaa.one", "start": "2017-09-16T14:49:18+0000"}
    expected_response = {
        "meta": {"pagination": {"pageSize": 2, "totalCount": 81, "next": "eNo00000"}, "status": 200},
        "data": [
            {
                "viewer": "aa@aa.aa",
                "source": "Message Tracking",
                "viewed": "2022-09-01T08:13:39+0000",
                "from": "aa@aa.aa",
                "to": "aa@aa.aa",
                "subject": "Demand Ken Lay Donate Proceeds from Enron Stock Sales",
                "messageDate": "2022-07-18T13:25:21+0000",
                "contentViewed": False,
                "discoveryCase": False,
            },
            {
                "viewer": "aa@aa.aa",
                "source": "Message Tracking",
                "viewed": "2022-08-31T14:29:48+0000",
                "from": "aa@aa.aa",
                "to": "aa@aa.aa",
                "subject": "Demand Ken Lay Donate Proceeds from Enron Stock Sales",
                "messageDate": "2022-07-18T13:25:21+0000",
                "contentViewed": False,
                "discoveryCase": False,
            },
        ],
        "fail": [],
    }
    mocker.patch.object(MimecastV2, "request_with_pagination_api2", return_value=expected_response)
    result = MimecastV2.get_view_logs_command(args)
    assert expected_response.get("data") == result.outputs["data"]


def test_list_account_command(mocker):
    """


    Args:
    """

    args = {'account_code': 'ABC123'}
    expected_response = {'meta': {'status': 200}, 'data': [{'region': 'us', 'archive': False, 'gateway': True, 'passphrase': '', 'supportCode': '6747', 'maxRetention': 30, 'maxRetentionConfirmed': True, 'minRetentionEnabled': False, 'automatedSegmentPurge': True, 'type': 'full', 'policyInheritance': False, 'databaseCode': 'usterm13', 'searchReason': False, 'contentAdministratorDefaultView': 'Metadata', 'adminSessionTimeout': 60, 'exportApi': False, 'exgestAllowQuery': False, 'exgestAllowExtraction': True, 'expressAccount': False, 'cybergraphV2Enabled': False, 'accountCode': 'ABC123', 'accountName': 'API Alliance - Palo Alto Networks', 'adminEmail': '', 'contactEmail': 'techbd@paloaltonetworks.mime.integration.com', 'domain': '', 'userCount': 10, 'mimecastId': '01-0102-00236', 'contactName': 'Adnan Kharuf', 'telephone': '4088307584', 'packages': ['Journal Services [1053]',
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          'Desktop Apps - Outlook (Pro) [1016]', 'Mobile Apps (Pro) [1036]', 'Threat Remediation [1075]', 'Advanced MTA (Site) [1002]', 'Stationery 1.0 (Site) [1042]', 'Attachment Protection (Pro) [1059]', 'Secure Email Gateway (Site) [1039]', 'Content Control and Data Leak Prevention (Site) [1013]', 'Metadata Track and Trace (Site) [1032]', 'Attachment Protection (Site) [1056]', 'URL Protection (Site) [1043]', 'Branding [1003]', 'Enhanced Logging [1061]', 'Message Recovery Service (Site) [1031]', 'Impersonation Protection [1060]', 'Auto Responders (Site) [1005]', 'Message Recovery Service - User [1058]', 'Desktop Apps - Mac (Pro) [1051]', 'Content Control and Data Leak Prevention (Pro) [1015]', 'Mimecast Mobile Pro (Pro) [1055]', 'Mimecast Platform [1033]', 'Email Encryption and Privacy (Site) [1023]', 'Internal Email Protect [1064]', 'Configuration Backup & Restore [1106]', 'Attachment Management (Site) [1004]', 'BYO: Threat Intelligence [1089]']}], 'fail': []}
    mocker.patch.object(MimecastV2, 'request_with_pagination_api2', return_value=expected_response)
    result = MimecastV2.list_account_command(args)
    assert expected_response.get('data') == result.outputs['data']


def test_list_policies_command(mocker):
    """


    Args:
    """

    args = {"policyType": "address-alteration"}
    expected_response = [
        {
            "option": "no_action",
            "id": "eNo1jr",
            "policy": {
                "description": "test",
                "fromPart": "envelope_from",
                "from": {"type": "internal_addresses"},
                "to": {"type": "external_addresses"},
                "fromType": "internal_addresses",
                "toType": "external_addresses",
                "fromEternal": True,
                "toEternal": True,
                "fromDate": "1900-01-01T00:00:00+0000",
                "toDate": "2100-01-01T23:59:59+0000",
                "override": False,
                "bidirectional": False,
                "conditions": {},
                "enabled": True,
                "enforced": False,
                "createTime": "2024-04-17T09:01:16+0000",
                "lastUpdated": "2024-04-17T09:01:16+0000",
            },
        }
    ]

    mocker.patch.object(MimecastV2, "request_with_pagination_api2", return_value=expected_response)
    result = MimecastV2.list_policies_command(args)
    assert result.outputs == expected_response


def test_create_antispoofing_bypass_policy_command(mocker):
    """


    Args:
    """

    args = {'conditions': 'googl.com', 'description': 'aa', 'enabled': 'true', 'enforced': 'false', 'from_eternal': 'true',
            'from_type': 'everyone', 'option': 'disable_bypass', 'to_eternal': 'true', 'to_type': 'everyone'}
    expected_response = {'meta': {'status': 200}, 'data': [{'option': 'disable_bypass', 'id': 'eNo1jrsOgjAAAP-ls0OhoGDiQHyiYkBe6oalapVSaEECxn8XBve73H2AJLgWhKZgCjoXBtZuIplZOX6Zv7aIFYR5Mbb156QJK-QKfSExdMNFFC_tK7-HuzzRDFXJBHtcUHK-k6DkGz2uqJcUjblG-VNzSk27HVF9iF70tOzS42ovnBkYgYJnFLdDWUGGMR4BXMuKMyIwT0m_Mw99S4GqpaJxT7-JkJTnPfw3g7Yg9mBDCJXvD7UZQZo', 'policy': {'description': 'aa', 'fromPart': 'envelope_from', 'from': {
        'type': 'everyone'}, 'to': {'type': 'everyone'}, 'fromType': 'everyone', 'toType': 'everyone', 'fromEternal': True, 'toEternal': True, 'fromDate': '1900-01-01T00:00:00+0000', 'toDate': '2100-01-01T23:59:59+0000', 'override': False, 'bidirectional': False, 'conditions': {'spfDomains': ['googl.com']}, 'enabled': True, 'enforced': False, 'createTime': '2024-05-08T13:00:06+0000', 'lastUpdated': '2024-05-08T13:00:06+0000'}}], 'fail': []}
    mocker.patch.object(MimecastV2, 'http_request', return_value=expected_response)
    result = MimecastV2.create_antispoofing_bypass_policy_command(args)
    assert expected_response.get('data') == result.outputs['data']


def test_update_antispoofing_bypass_policy_command(mocker):
    """


    Args:
    """

    args = {'description': 'test_1', 'enabled': 'true', 'from_eternal': 'true',
            'id': 'eNo11111', 'option': 'disable_bypass', 'to_eternal': 'true'}
    expected_response = {'meta': {'status': 200}, 'data': [{'option': 'disable_bypass', 'id': 'eNo11111', 'policy': {'description': 'test_1', 'fromPart': 'envelope_from', 'from': {'type': 'everyone'}, 'to': {'type': 'everyone'}, 'fromType': 'everyone', 'toType': 'everyone', 'fromEternal': True,
                                                                                                                     'toEternal': True, 'fromDate': '1900-01-01T00:00:00+0000', 'toDate': '2100-01-01T23:59:59+0000', 'override': False, 'bidirectional': False, 'conditions': {}, 'enabled': True, 'enforced': False, 'createTime': '2024-05-06T13:48:16+0000', 'lastUpdated': '2024-05-07T13:26:34+0000'}}], 'fail': []}
    mocker.patch.object(MimecastV2, 'http_request', return_value=expected_response)
    result = MimecastV2.update_antispoofing_bypass_policy_command(args)
    assert expected_response.get('data') == result.outputs.get('data')
    assert f'{args["id"]} has been updated successfully' == result.readable_output


def test_update_address_alteration_policy_command(mocker):
    """


    Args:
    """

    args = {
        "enabled": "true",
        "enforced": "false",
        "from_eternal": "true",
        "from_type": "everyone",
        "policy_description": "test",
        "policy_id": "eNo11111",
        "to_eternal": "true",
        "to_type": "everyone",
    }
    expected_response = {
        "meta": {"status": 200},
        "data": [
            {
                "addressAlterationSetId": "eNo11111",
                "policy": {
                    "description": "test",
                    "fromPart": "envelope_from",
                    "from": {"type": "everyone"},
                    "to": {"type": "everyone"},
                    "fromType": "everyone",
                    "toType": "everyone",
                    "fromEternal": True,
                    "toEternal": True,
                    "fromDate": "1900-01-01T00:00:00+0000",
                    "toDate": "2100-01-01T23:59:59+0000",
                    "override": False,
                    "bidirectional": False,
                    "conditions": {},
                    "enabled": True,
                    "enforced": False,
                    "createTime": "2024-05-07T14:29:18+0000",
                    "lastUpdated": "2024-05-07T14:29:18+0000",
                },
            }
        ],
        "fail": [],
    }
    mocker.patch.object(MimecastV2, "http_request", return_value=expected_response)
    result = MimecastV2.update_address_alteration_policy_command(args)
    assert expected_response.get("data") == result.outputs.get("data")
