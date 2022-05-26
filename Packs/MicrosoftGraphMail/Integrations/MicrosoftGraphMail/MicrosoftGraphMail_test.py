from urllib.parse import quote

import pytest
import requests_mock

from CommonServerPython import *
from MicrosoftGraphMail import MsGraphClient, build_mail_object, assert_pages, build_folders_path, \
    list_mails_command, item_result_creator, create_attachment, reply_email_command, \
    send_email_command, list_attachments_command, main
from MicrosoftApiModule import MicrosoftClient
import demistomock as demisto


@pytest.mark.parametrize('params, expected_result', [
    ({'creds_tenant_id': {'password': '1234'}, 'creds_auth_id': {'password': '1234'}}, 'Key must be provided.'),
    ({'creds_tenant_id': {'password': '1234'}, 'credentials': {'password': '1234'}}, 'ID must be provided.'),
    ({'credentials': {'password': '1234'}, 'creds_auth_id': {'password': '1234'}}, 'Token must be provided.')
])
def test_params(mocker, params, expected_result):
    """
    Given:
      - Case 1: tenant id and auth id but no key.
      - Case 2: tenant id and key but no auth id.
      - Case 3: key and auth id but no tenant id.
    When:
      - Setting an instance
    Then:
      - Ensure the exception message as expected.
      - Case 1: Should return "Key must be provided.".
      - Case 2: Should return "ID must be provided.".
      - Case 3: Should return "Token must be provided.".
    """

    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(Exception) as e:
        main()

    assert expected_result in str(e.value)


@pytest.mark.parametrize('params, expected_results', [
    ({'creds_tenant_id': {'password': '1234'}, 'creds_auth_id': {'password': '3124'},
      'credentials': {'password': '2412'}}, ['1234', '3124', '2412']),
    ({'tenant_id': '5678', 'enc_key': '8142', 'auth_id': '5678'}, ['5678', '5678', '8142']),
    ({'_tenant_id': '1267', 'credentials': {'password': '1234'}, '_auth_id': '8888'}, ['1267', '8888', '1234'])
])
def test_params_working(mocker, params, expected_results):
    """
    Given:
      - Case 1: tenant id, auth id and key where all three are part of the credentials.
      - Case 2: tenant id, auth id and key where all three aren't part of the credentials.
      - Case 3: tenant id, auth id and key where only the key is part of the credentials.
    When:
      - Setting an instance
    Then:
      - Ensure that the instance can Co-op with previous versions params names and that MsGraphClient.__init__
      was called with the right tenant id, auth id and key.
      - Case 1: MsGraphClient.__init__ Should be called with tenant id, auth id and key extracted from credentials type params.
      - Case 2: MsGraphClient.__init__ Should be called with tenant id, auth id and key
      not extracted from credentials type params.
      - Case 3: MsGraphClient.__init__ Should be called with only key param extracted from credentials type params.
    """

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(MsGraphClient, '__init__', return_value=None)
    main()
    MsGraphClient.__init__.assert_called_with(False, expected_results[0], expected_results[1], expected_results[2],
                                              'ms-graph-mail', '/v1.0', True, False, (200, 201, 202, 204), '', 'Inbox',
                                              '15 minutes', 50, 10, 'com', certificate_thumbprint='', private_key='')


def test_build_mail_object():
    # Testing list of mails
    user_id = 'ex@example.com'
    with open('test_data/mails') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, list)
        assert len(mail[0].get('value')) == len(res)
        assert res[0]['Created'] == '2019-04-16T19:40:00Z'
        assert res[0]['UserID'] == user_id
        assert res[0]['Body']

    with open('test_data/mail') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, dict)
        assert res['UserID'] == user_id
        assert res['Body']


def test_assert_pages():
    assert assert_pages(3) == 3 and assert_pages(None) == 1 and assert_pages('4') == 4


def test_build_folders_path():
    inp = 'i,s,f,q'
    response = build_folders_path(inp)
    assert response == 'mailFolders/i/childFolders/s/childFolders/f/childFolders/q'


def oproxy_client():
    auth_id = "dummy_auth_id"
    enc_key = "dummy_enc_key"
    token_retrieval_url = "url_to_retrieval"
    auth_and_token_url = f'{auth_id}@{token_retrieval_url}'
    app_name = "ms-graph-mail"
    mailbox_to_fetch = "dummy@mailbox.com"  # disable-secrets-detection
    folder_to_fetch = "Phishing"
    first_fetch_interval = "20 minutes"
    emails_fetch_limit = 50
    base_url = "https://graph.microsoft.com/v1.0"
    ok_codes = (200, 201, 202)

    return MsGraphClient(self_deployed=False, tenant_id='', auth_and_token_url=auth_and_token_url,
                         enc_key=enc_key, app_name=app_name, base_url=base_url, use_ssl=True, proxy=False,
                         ok_codes=ok_codes, mailbox_to_fetch=mailbox_to_fetch,
                         folder_to_fetch=folder_to_fetch, first_fetch_interval=first_fetch_interval,
                         emails_fetch_limit=emails_fetch_limit)


def self_deployed_client():
    tenant_id = "dummy_tenant"
    client_id = "dummy_client_id"
    client_secret = "dummy_secret"
    mailbox_to_fetch = "dummy@mailbox.com"  # disable-secrets-detection
    folder_to_fetch = "Phishing"
    first_fetch_interval = "20 minutes"
    emails_fetch_limit = 50
    base_url = "https://graph.microsoft.com/v1.0"
    ok_codes = (200, 201, 202)

    return MsGraphClient(self_deployed=True, tenant_id=tenant_id, auth_and_token_url=client_id, enc_key=client_secret,
                         base_url=base_url, use_ssl=True, proxy=False, ok_codes=ok_codes, app_name='',
                         mailbox_to_fetch=mailbox_to_fetch, folder_to_fetch=folder_to_fetch,
                         first_fetch_interval=first_fetch_interval, emails_fetch_limit=emails_fetch_limit)


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_pages_puller(mocker, client):
    """Unit test
    Given
    - pages_puller function
    - different number of pages to pull
    When
    - mock the requests response.
    Then
    - run the pages_puller command using the Client
    Validate that the number of returned pages is according to the number of pages to pull
    """
    first_response = {
        '@odata.context': 'response_context',
        '@odata.nextLink': 'link_1',
        'value': ['email1', 'email2']
    }
    second_response = {
        '@odata.context': 'response_context',
        '@odata.nextLink': 'link_2',
        'value': ['email3', 'email4']
    }
    responses = client.pages_puller(first_response, 1)
    assert len(responses) == 1
    mocker.patch.object(client.ms_client, 'http_request', return_value=second_response)
    responses = client.pages_puller(first_response, 2)
    assert len(responses) == 2


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_list_mails_command(mocker, client):
    """Unit test
    Given
    - list_mails command
    - different number of mails that are returned in the response
    When
    - mock the client.list_mails function
    Then
    - run the list_mails_command using the Client
    Validate that the human readable output, indicating the number of returned mails is correct
    """
    args = {'user_id': 'test id'}

    # call list mails with two emails
    with open('test_data/mails') as mail_json:
        mail = json.load(mail_json)
        mocker.patch.object(client, 'list_mails', return_value=mail)
        mocker.patch.object(demisto, 'results')
        list_mails_command(client, args)
        hr = demisto.results.call_args[0][0].get('HumanReadable')
        assert '2 mails received \nPay attention there are more results than shown. For more data please ' \
               'increase "pages_to_pull" argument' in hr

    # call list mails with no emails
    with open('test_data/no_mails') as mail_json:
        mail = json.load(mail_json)
        mocker.patch.object(client, 'list_mails', return_value=mail)
        mocker.patch.object(demisto, 'results')
        list_mails_command(client, args)
        hr = demisto.results.call_args[0][0].get('HumanReadable')
        assert '### No mails were found' in hr


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_list_mails_command_encoding(mocker, client):
    """Unit test
    Given
    - an email query
    When
    - calling list_mails
    Then
    - Validate that the queried value is properly url-encoded
    """
    client = MsGraphClient(True, 'tenant', 'auth_token_url', 'enc_key', 'app_name', 'https://example.com',
                           use_ssl=True, proxy=False, ok_codes=(200,), mailbox_to_fetch='mailbox',
                           folder_to_fetch='folder', first_fetch_interval=10, emails_fetch_limit=10)
    mocker.patch.object(client.ms_client, 'get_access_token')

    search = 'Test&$%^'
    search_encoded = quote(search)

    with requests_mock.Mocker() as request_mocker:
        mocked = request_mocker.get(
            f'https://example.com/users/user_id/messages?$top=20&$search=%22{search_encoded}%22', json={}
        )
        client.list_mails('user_id', search=search)
    assert mocked.call_count == 1


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_list_mails_with_page_limit(mocker, client):
    """Unit test
    Given
    - list_mails command with page_size set to 1
    - one mail returned on the response
    When
    - mock the MicrosoftClient.http_request function
    Then
    - run the list_mails_command using the Client
    Validate that the http_request called properly with endpoint top=1
    """
    args = {'user_id': 'test id', 'page_size': 1, 'pages_to_pull': 1}
    with open('test_data/response_with_one_mail') as mail_json:
        mail = json.load(mail_json)
        mock_request = mocker.patch.object(MicrosoftClient, 'http_request', return_value=mail)
        mocker.patch.object(demisto, 'results')
        mocker.patch.object(demisto, 'args', return_value=args)
        list_mails_command(client, args)
        hr = demisto.results.call_args[0][0].get('HumanReadable')
        assert '1 mails received \nPay attention there are more results than shown. For more data please ' \
               'increase "pages_to_pull" argument' in hr
        assert "top=1" in mock_request.call_args_list[0].args[1]


@pytest.fixture()
def expected_incident():
    with open('test_data/expected_incident') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data():
    with open('test_data/emails_data') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture
def last_run_data():
    last_run = {
        'LAST_RUN_TIME': '2019-11-12T15:00:00Z',
        'LAST_RUN_IDS': [],
        'LAST_RUN_FOLDER_ID': 'last_run_dummy_folder_id',
        'LAST_RUN_FOLDER_PATH': "Phishing",
        'LAST_RUN_ACCOUNT': 'dummy@mailbox.com',
    }

    return last_run


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents(mocker, client, emails_data, expected_incident, last_run_data):
    mocker.patch('MicrosoftGraphMail.get_now_utc', return_value='2019-11-12T15:01:00Z')
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails_data)
    mocker.patch.object(demisto, "info")
    result_next_run, result_incidents = client.fetch_incidents(last_run_data)

    assert result_next_run.get('LAST_RUN_TIME') == '2019-11-12T15:00:30Z'
    assert result_next_run.get('LAST_RUN_IDS') == ['dummy_id_1']
    assert result_next_run.get('LAST_RUN_FOLDER_ID') == 'last_run_dummy_folder_id'
    assert result_next_run.get('LAST_RUN_FOLDER_PATH') == 'Phishing'

    result_incidents = result_incidents[0]
    result_raw_json = json.loads(result_incidents.pop('rawJSON'))
    expected_raw_json = expected_incident.pop('rawJSON', None)

    assert result_raw_json == expected_raw_json
    assert result_incidents == expected_incident


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_changed_folder(mocker, client, emails_data, last_run_data):
    changed_folder = "Changed_Folder"
    client._folder_to_fetch = changed_folder
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails_data)
    mocker.patch.object(demisto, "info")
    client.fetch_incidents(last_run_data)

    mocker_folder_by_path.assert_called_once_with('dummy@mailbox.com', changed_folder)


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_changed_account(mocker, client, emails_data, last_run_data):
    changed_account = "Changed_Account"
    client._mailbox_to_fetch = changed_account
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails_data)
    mocker.patch.object(demisto, "info")
    client.fetch_incidents(last_run_data)

    mocker_folder_by_path.assert_called_once_with(changed_account, last_run_data['LAST_RUN_FOLDER_PATH'])


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_detect_initial(mocker, client, emails_data):
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails_data)
    mocker.patch.object(demisto, "info")
    client.fetch_incidents({})

    mocker_folder_by_path.assert_called_once_with('dummy@mailbox.com', "Phishing")


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_parse_email_as_label(client):
    assert client._parse_email_as_labels({'ID': 'dummy_id'}) == [{'type': 'Email/ID', 'value': 'dummy_id'}]
    assert client._parse_email_as_labels({'To': ['dummy@recipient.com']}) == [
        {'type': 'Email/To', 'value': 'dummy@recipient.com'}]


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_recipient_input(client):
    recipient_input = ["dummy1@rec.com", "dummy2@rec.com", "dummy3@rec.com"]  # disable-secrets-detection
    result_recipients_input = client._build_recipient_input(recipient_input)
    expected_recipients_input = [{'emailAddress': {'address': 'dummy1@rec.com'}},
                                 {'emailAddress': {'address': 'dummy2@rec.com'}},
                                 {'emailAddress': {'address': 'dummy3@rec.com'}}]

    assert result_recipients_input == expected_recipients_input


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_body_input(client):
    first_body_input = ["test body 1", "text"]
    second_body_input = ["test body 2", "HTML"]
    first_result_body_input = client._build_body_input(*first_body_input)
    second_result_body_input = client._build_body_input(*second_body_input)

    assert first_result_body_input == {'content': 'test body 1', 'contentType': 'text'}
    assert second_result_body_input == {'content': 'test body 2', 'contentType': 'HTML'}


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_headers_input(client):
    headers_input = ['x-header-one:header1', 'x-header-two:heasder2']
    result_expecte_headers = [{'name': 'x-header-one', 'value': 'header1'},
                              {'name': 'x-header-two', 'value': 'heasder2'}]

    assert client._build_headers_input(headers_input) == result_expecte_headers


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_message(client):
    message_input = {
        'to_recipients': ['dummy@recipient.com'],  # disable-secrets-detection
        'cc_recipients': ['dummyCC@recipient.com'],  # disable-secrets-detection
        'bcc_recipients': ['dummyBCC@recipient.com'],  # disable-secrets-detection
        'reply_to': ['dummyreplyTo@recipient.com'],  # disable-secrets-detection
        'subject': 'Dummy Subject',
        'body': 'Dummy Body',
        'body_type': 'text',
        'flag': 'flagged',
        'importance': 'Normal',
        'internet_message_headers': None,
        'attach_ids': [],
        'attach_names': [],
        'attach_cids': [],
        'manual_attachments': []
    }

    expected_message = {'toRecipients': [{'emailAddress': {'address': 'dummy@recipient.com'}}],
                        # disable-secrets-detection
                        'ccRecipients': [{'emailAddress': {'address': 'dummyCC@recipient.com'}}],
                        # disable-secrets-detection
                        'bccRecipients': [{'emailAddress': {'address': 'dummyBCC@recipient.com'}}],
                        # disable-secrets-detection
                        'replyTo': [{'emailAddress': {'address': 'dummyreplyTo@recipient.com'}}],
                        # disable-secrets-detection
                        'subject': 'Dummy Subject', 'body': {'content': 'Dummy Body', 'contentType': 'text'},
                        'bodyPreview': 'Dummy Body', 'importance': 'Normal', 'flag': {'flagStatus': 'flagged'},
                        'attachments': []}
    result_message = client.build_message(**message_input)

    assert result_message == expected_message


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_get_attachment(client):
    """
    Given:
        - raw response returned from get_attachment_command

    When:
        - response type is itemAttachment and 'item_result_creator' is called

    Then:
        - Validate that the message object created successfully

    """
    output_prefix = 'MSGraphMail(val.ID && val.ID == obj.ID)'
    with open('test_data/mail_with_attachment') as mail_json:
        user_id = 'ex@example.com'
        raw_response = json.load(mail_json)
        res = item_result_creator(raw_response, user_id)
        assert isinstance(res, CommandResults)
        output = res.to_context().get('EntryContext', {})
        assert output.get(output_prefix).get('ID') == 'exampleID'
        assert output.get(output_prefix).get('Subject') == 'Test it'


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_get_attachment_unsupported_type(client):
    """
    Given:
        - raw response returned from get_attachment_command

    When:
        - response type is itemAttachment with attachment that is not supported

    Then:
        - Validate the human readable which explain we do not support the type

    """
    with open('test_data/mail_with_unsupported_attachment') as mail_json:
        user_id = 'ex@example.com'
        raw_response = json.load(mail_json)
        res = item_result_creator(raw_response, user_id)
        assert isinstance(res, CommandResults)
        output = res.to_context().get('HumanReadable', '')
        assert 'Integration does not support attachments from type #microsoft.graph.contact' in output


@pytest.mark.parametrize('function_name, attachment_type', [('file_result_creator', 'fileAttachment'),
                                                            ('item_result_creator', 'itemAttachment')])
def test_create_attachment(mocker, function_name, attachment_type):
    """
    Given:
        - raw response returned from api:
            1. @odata.type is fileAttachment
            2. @odata.type is itemAttachment

    When:
        - create_attachment checks the attachment type and decide which function will handle the response

    Then:
        - item_result_creator and file_result_creator called respectively to the type

    """
    mocked_function = mocker.patch(f'MicrosoftGraphMail.{function_name}', return_value={})
    raw_response = {'@odata.type': f'#microsoft.graph.{attachment_type}'}
    user_id = 'ex@example.com'
    create_attachment(raw_response, user_id)
    assert mocked_function.called


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_list_attachments_with_name(mocker, client):
    """
    Given:
        - list attachments command
        - all attachments has a name

    When:
        - parsing email attachments

    Then:
        - Validate that the attachments are being parsed correctly

    """
    output_prefix = 'MSGraphMailAttachment(val.ID === obj.ID)'
    with open('test_data/list_attachment_result.json') as attachment_result:
        args = {"user_id": "example"}
        raw_response = json.load(attachment_result)
        mocker.patch.object(client, 'list_attachments', return_value=raw_response)
        mocker.patch.object(demisto, 'results')
        list_attachments_command(client, args)
        context = demisto.results.call_args[0][0].get('EntryContext')

        assert context.get(output_prefix).get('Attachment')[0].get('ID') == 'someID'
        assert context.get(output_prefix).get('Attachment')[0].get('Name') == 'someName'
        assert context.get(output_prefix).get('Attachment')[0].get('Type') == 'application/octet-stream'


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_list_attachments_without_name(mocker, client):
    """
    Given:
        - list attachments command
        - there is an attachment without a name

    When:
        - parsing email attachments

    Then:
        - Validate that the attachments are being parsed correctly and the name is equal to the ID

    """
    output_prefix = 'MSGraphMailAttachment(val.ID === obj.ID)'
    with open('test_data/list_attachment_result_no_name.json') as attachment_result:
        args = {"user_id": "example"}
        raw_response = json.load(attachment_result)
        mocker.patch.object(client, 'list_attachments', return_value=raw_response)
        mocker.patch.object(demisto, 'results')
        list_attachments_command(client, args)
        context = demisto.results.call_args[0][0].get('EntryContext')

        assert context.get(output_prefix).get('Attachment')[0].get('ID') == 'someID'
        assert context.get(output_prefix).get('Attachment')[0].get('Name') == 'someID'
        assert context.get(output_prefix).get('Attachment')[0].get('Type') == 'application/octet-stream'


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_reply_mail_command(client, mocker):
    """
    Given:
        - reply-mail arguments

    When:
        - send a reply mail message

    Then:
        - validates that the outputs fit the updated reply mail message

    """
    args = {'to': ['ex@example.com'], 'body': "test body", 'subject': "test subject", "inReplyTo": "id",
            'from': "ex1@example.com"}
    mocker.patch.object(MicrosoftClient, 'http_request')

    reply_message = reply_email_command(client, args)

    assert reply_message.outputs_prefix == "MicrosoftGraph"
    assert reply_message.outputs_key_field == "SentMail"
    assert reply_message.outputs['ID'] == args['inReplyTo']
    assert reply_message.outputs['subject'] == 'Re: ' + args['subject']
    assert reply_message.outputs['toRecipients'] == args['to']
    assert reply_message.outputs['bodyPreview'] == args['body']


SEND_MAIL_COMMAND_ARGS = [
    (
        oproxy_client(),
        {
            'to': ['ex@example.com'],
            'htmlBody': "<b>This text is bold</b>",
            'subject': "test subject",
            'replyTo': ["ex2@example.com", "ex3@example.com"],
            'from': "ex1@example.com"
        },
    ),
    (
        self_deployed_client(),
        {
            'to': ['ex@example.com'],
            'htmlBody': "<b>This text is bold</b>",
            'subject': "test subject",
            'replyTo': ["ex2@example.com", "ex3@example.com"],
            'from': "ex1@example.com"
        },
    ),
    (
        oproxy_client(),
        {
            'to': ['ex@example.com'],
            'body': "test body",
            'subject': "test subject",
            'replyTo': ["ex2@example.com", "ex3@example.com"],
            'from': "ex1@example.com"
        }
    ),
    (
        self_deployed_client(),
        {
            'to': ['ex@example.com'],
            'body': "test body",
            'subject': "test subject",
            'replyTo': ["ex2@example.com", "ex3@example.com"],
            'from': "ex1@example.com"
        }
    )
]


@pytest.mark.parametrize('client, args', SEND_MAIL_COMMAND_ARGS)
def test_send_mail_command(mocker, client, args):
    """
        Given:
            - send-mail command's arguments

        When:
            - sending a mail

        Then:
            - validates that http request to send-mail was called with the correct values.
    """
    with requests_mock.Mocker() as request_mocker:
        from_email = args.get('from')

        mocker.patch.object(client.ms_client, 'get_access_token')
        send_mail_mocker = request_mocker.post(
            f'https://graph.microsoft.com/v1.0/users/{from_email}/SendMail'
        )

        send_email_command(client, args)

        assert send_mail_mocker.called
        message = send_mail_mocker.last_request.json().get('message')
        assert message
        assert message.get('toRecipients')[0].get('emailAddress').get("address") == args.get('to')[0]
        assert message.get('body').get('content') == args.get('htmlBody') or args.get('body')
        assert message.get('subject') == args.get('subject')
        assert message.get('replyTo')[0].get('emailAddress').get("address") == args.get('replyTo')[0]
        assert message.get('replyTo')[1].get('emailAddress').get("address") == args.get('replyTo')[1]


@pytest.mark.parametrize('server_url, expected_endpoint', [('https://graph.microsoft.us', 'gcc-high'),
                                                           ('https://dod-graph.microsoft.us', 'dod'),
                                                           ('https://graph.microsoft.de', 'de'),
                                                           ('https://microsoftgraph.chinacloudapi.cn', 'cn')])
def test_server_to_endpoint(server_url, expected_endpoint):
    """
    Given:
        - Host address for national endpoints
    When:
        - Creating a new MsGraphClient
    Then:
        - Verify that the host address is translated to the correct endpoint code, i.e. com/gcc-high/dod/de/cn
    """
    from MicrosoftApiModule import GRAPH_BASE_ENDPOINTS

    assert GRAPH_BASE_ENDPOINTS[server_url] == expected_endpoint


def test_fetch_last_emails__with_exclude(mocker):
    """
    Given:
        - Last fetch fetched until email 2
        - Next fetch will fetch 5 emails
        - Exclusion list contains 2/5 emails ids
        - fetch limit is set to 2
    When:
        - Calling fetch_incidents
    Then:
        - Fetch 2 emails
        - Save previous 2 fetched mails + 2 new mails
        - Fetch emails after exclude id
        - Don't fetch emails after limit
    """
    emails = {'value': [
        {'receivedDateTime': '1', 'id': '1'},
        {'receivedDateTime': '2', 'id': '2'},
        {'receivedDateTime': '4', 'id': '3'},
        {'receivedDateTime': '4', 'id': '4'},
        {'receivedDateTime': '4', 'id': '5'},
    ]}
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails)
    fetched_emails, ids = client._fetch_last_emails('', last_fetch='2', exclude_ids=['1', '2'])
    assert len(fetched_emails) == 2
    assert ids == ['3', '4']
    assert fetched_emails[0] == emails['value'][2]
    assert fetched_emails[1] == emails['value'][3]


def test_fetch_last_emails__no_exclude(mocker):
    """
    Given:
        - No previous last fetch
        - Next fetch will fetch 1 email
        - fetch limit is set to 2
    When:
        - Calling fetch_incidents
    Then:
        - Fetch 1 email
        - Save mail in exclusion
    """
    emails = {'value': [
        {'receivedDateTime': '1', 'id': '1'},
    ]}
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails)
    fetched_emails, ids = client._fetch_last_emails('', last_fetch='0', exclude_ids=[])
    assert len(fetched_emails) == 1
    assert ids == ['1']
    assert fetched_emails[0] == emails['value'][0]


def test_fetch_last_emails__all_mails_in_exclude(mocker):
    """
    Given:
        - Last fetch fetched until email 2
        - Next fetch will fetch 2 emails
        - Exclusion list contains 2/2 emails ids
    When:
        - Calling fetch_incidents
    Then:
        - Fetch 0 emails
        - Save previous 2 fetched mails
    """
    emails = {'value': [
        {'receivedDateTime': '1', 'id': '1'},
        {'receivedDateTime': '2', 'id': '2'},
    ]}
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails)
    fetched_emails, ids = client._fetch_last_emails('', last_fetch='2', exclude_ids=['1', '2'])
    assert len(fetched_emails) == 0
    assert ids == ['1', '2']
