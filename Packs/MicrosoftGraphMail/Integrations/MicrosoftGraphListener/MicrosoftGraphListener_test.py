import pytest
import demistomock as demisto
import json
from MicrosoftGraphListener import MsGraphListenerClient
import requests_mock
from unittest.mock import mock_open
from CommonServerPython import *


def oproxy_client():
    refresh_token = "dummy_refresh_token"
    auth_id = "dummy_auth_id"
    enc_key = "dummy_enc_key"
    token_retrieval_url = "url_to_retrieval"
    auth_and_token_url = f'{auth_id}@{token_retrieval_url}'
    app_name = "ms-graph-mail-listener"
    mailbox_to_fetch = "dummy@mailbox.com"  # disable-secrets-detection
    folder_to_fetch = "Phishing"
    first_fetch_interval = "20 minutes"
    emails_fetch_limit = 50
    base_url = "https://graph.microsoft.com/v1.0/"
    ok_codes = (200, 201, 202)
    auth_code = "auth_code"
    redirect_uri = "redirect_uri"

    return MsGraphListenerClient(self_deployed=False, tenant_id='', auth_id=auth_and_token_url,
                                 enc_key=enc_key, app_name=app_name, base_url=base_url, verify=True, proxy=False,
                                 ok_codes=ok_codes, refresh_token=refresh_token, mailbox_to_fetch=mailbox_to_fetch,
                                 folder_to_fetch=folder_to_fetch, first_fetch_interval=first_fetch_interval,
                                 emails_fetch_limit=emails_fetch_limit, auth_code=auth_code, redirect_uri=redirect_uri,
                                 )


def self_deployed_client():
    tenant_id = "dummy_tenant"
    client_id = "dummy_client_id"
    client_secret = "dummy_secret"
    mailbox_to_fetch = "dummy@mailbox.com"  # disable-secrets-detection
    folder_to_fetch = "Phishing"
    first_fetch_interval = "20 minutes"
    emails_fetch_limit = 50
    base_url = "https://graph.microsoft.com/v1.0/"
    ok_codes = (200, 201, 202)
    auth_code = "auth_code"
    redirect_uri = "redirect_uri"

    return MsGraphListenerClient(
        self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
        base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes, app_name='',
        refresh_token='', mailbox_to_fetch=mailbox_to_fetch, folder_to_fetch=folder_to_fetch,
        first_fetch_interval=first_fetch_interval, emails_fetch_limit=emails_fetch_limit,
        auth_code=auth_code, redirect_uri=redirect_uri)


@pytest.fixture()
def expected_incident():
    with open('test_data/expected_incident.txt') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_html():
    return emails_data_as_html_including_body()


def emails_data_as_html_including_body():
    with open('test_data/emails_data_html.txt') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_text():
    return emails_data_as_text_including_body()


def emails_data_as_text_including_body():
    with open('test_data/emails_data_text.txt') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_html_without_body():
    with open('test_data/emails_data_html_without_body.txt') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_text_without_body():
    with open('test_data/emails_data_text_without_body.txt') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_full_body_as_html():
    with open('test_data/emails_data_full_body_html.txt') as emails_json:
        return json.load(emails_json)


@pytest.fixture()
def emails_data_full_body_as_text():
    with open('test_data/emails_data_full_body_text.txt') as emails_json:
        return json.load(emails_json)


@pytest.fixture()
def expected_incident_full_body():
    with open('test_data/expected_incident_full_body.txt') as incident:
        return json.load(incident)


@pytest.fixture
def last_run_data():
    last_run = {
        'LAST_RUN_TIME': '2019-11-12T15:00:00Z',
        'LAST_RUN_IDS': [],
        'LAST_RUN_FOLDER_ID': 'last_run_dummy_folder_id',
        'LAST_RUN_FOLDER_PATH': "Phishing"
    }

    return last_run


@pytest.mark.parametrize(
    'client, email_content_html, email_content_text', [
        (
            oproxy_client(),
            emails_data_as_html_including_body(),
            emails_data_as_text_including_body()
        ),
        (
            self_deployed_client(),
            emails_data_as_html_without_body(),
            emails_data_as_text_without_body()
        )
    ]
)
def test_fetch_incidents(client, email_content_html, email_content_text, mocker, last_run_data, expected_incident):
    """
    Given
     - Case A: emails as text and html including the full body key in the api response.
     - Case B: emails as text and html without the full body key in the api response.

    When
     - fetching incidents when there is a body key and when there isn't a body key.

    Then
     - Case A: make sure the 'body' key is being taken even when 'uniqueBody' key exists.
     - Case B: make sure the 'uniqueBody' is being taken instead of the 'body' key.
    """
    mocker.patch(
        'CommonServerPython.get_current_time',
        return_value=dateparser.parse('2019-11-12T15:01:00', settings={'TIMEZONE': 'UTC'})
    )
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, 'http_request', side_effect=[email_content_html, email_content_text, {}])
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
def test_fetch_incidents_changed_folder(mocker, client, emails_data_as_html, emails_data_as_text, last_run_data):
    changed_folder = "Changed_Folder"
    client._folder_to_fetch = changed_folder
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, 'http_request', side_effect=[emails_data_as_html, emails_data_as_text, {}])
    mocker.patch.object(demisto, "info")
    client.fetch_incidents(last_run_data)

    mocker_folder_by_path.assert_called_once_with('dummy@mailbox.com', changed_folder, overwrite_rate_limit_retry=True)


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_detect_initial(mocker, client, emails_data_as_html, emails_data_as_text):
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, 'http_request', side_effect=[emails_data_as_html, emails_data_as_text, {}])
    mocker.patch.object(demisto, "info")
    client.fetch_incidents({})

    mocker_folder_by_path.assert_called_once_with('dummy@mailbox.com', "Phishing", overwrite_rate_limit_retry=True)

# def test_add_second_to_str_date():
#     assert add_second_to_str_date("2019-11-12T15:00:00Z") == "2019-11-12T15:00:01Z"
#     assert add_second_to_str_date("2019-11-12T15:00:00Z", 10) == "2019-11-12T15:00:10Z"


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_with_full_body(
    mocker, client, emails_data_full_body_as_html,
    emails_data_full_body_as_text, expected_incident_full_body, last_run_data
):
    """
    Given -
        a flag to fetch the entire email body

    When -
        fetching incidents

    Then -
        Make sure that in the details section, there is the full email body content.
    """
    mocker.patch(
        'CommonServerPython.get_current_time',
        return_value=dateparser.parse('2019-11-12T15:01:00', settings={'TIMEZONE': 'UTC'})
    )
    client._display_full_email_body = True
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(
        client, 'http_request', side_effect=[emails_data_full_body_as_html, emails_data_full_body_as_text, {}]
    )
    mocker.patch.object(demisto, "info")
    result_next_run, result_incidents = client.fetch_incidents(last_run_data)

    assert result_next_run.get('LAST_RUN_TIME') == '2019-11-12T15:00:30Z'
    assert result_next_run.get('LAST_RUN_IDS') == ['dummy_id_1']
    assert result_next_run.get('LAST_RUN_FOLDER_ID') == 'last_run_dummy_folder_id'
    assert result_next_run.get('LAST_RUN_FOLDER_PATH') == 'Phishing'

    result_incidents = result_incidents[0]
    result_raw_json = json.loads(result_incidents.pop('rawJSON'))

    expected_raw_json = expected_incident_full_body.pop('rawJSON', None)

    assert result_raw_json == expected_raw_json
    assert result_incidents == expected_incident_full_body


def test_parse_email_as_label():
    from MicrosoftGraphListener import GraphMailUtils
    assert GraphMailUtils.parse_email_as_labels({'ID': 'dummy_id'}) == [{'type': 'Email/ID', 'value': 'dummy_id'}]
    assert GraphMailUtils.parse_email_as_labels({'To': ['dummy@recipient.com']}) == [
        {'type': 'Email/To', 'value': 'dummy@recipient.com'}]


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_recipient_input(client):
    from MicrosoftGraphListener import GraphMailUtils
    recipient_input = ["dummy1@rec.com", "dummy2@rec.com", "dummy3@rec.com"]  # disable-secrets-detection
    result_recipients_input = GraphMailUtils.build_recipient_input(recipient_input)
    expected_recipients_input = [{'emailAddress': {'address': 'dummy1@rec.com'}},
                                 {'emailAddress': {'address': 'dummy2@rec.com'}},
                                 {'emailAddress': {'address': 'dummy3@rec.com'}}]

    assert result_recipients_input == expected_recipients_input


def test_build_body_input():
    from MicrosoftGraphListener import GraphMailUtils
    first_body_input = ["test body 1", "text"]
    second_body_input = ["test body 2", "HTML"]
    first_result_body_input = GraphMailUtils.build_body_input(*first_body_input)
    second_result_body_input = GraphMailUtils.build_body_input(*second_body_input)

    assert first_result_body_input == {'content': 'test body 1', 'contentType': 'text'}
    assert second_result_body_input == {'content': 'test body 2', 'contentType': 'HTML'}


def test_build_headers_input():
    from MicrosoftGraphListener import GraphMailUtils
    headers_input = ['x-header-one:header1', 'x-header-two:heasder2']
    result_expecte_headers = [{'name': 'x-header-one', 'value': 'header1'},
                              {'name': 'x-header-two', 'value': 'heasder2'}]

    assert GraphMailUtils.build_headers_input(headers_input) == result_expecte_headers


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_build_message(client, tmp_path, mocker):
    from MicrosoftGraphListener import GraphMailUtils
    attachment_name = 'attachment.txt'
    attachment = tmp_path / attachment_name
    attachment.touch()
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': str(attachment), 'name': attachment_name})
    message_input = {
        'to_recipients': ['dummy@recipient.com'],  # disable-secrets-detection
        'cc_recipients': ['dummyCC@recipient.com'],  # disable-secrets-detection
        'bcc_recipients': ['dummyBCC@recipient.com'],  # disable-secrets-detection
        'reply_to': ['dummyReplyTo@recipient.com'],  # disable-secrets-detection
        'subject': 'Dummy Subject',
        'body': 'Dummy Body',
        'body_type': 'text',
        'flag': 'flagged',
        'importance': 'Normal',
        'internet_message_headers': None,
        'attach_ids': [],
        'attach_names': [],
        'attach_cids': [str(attachment)],
        'manual_attachments': []
    }

    expected_message = {'toRecipients': [{'emailAddress': {'address': 'dummy@recipient.com'}}],
                        # disable-secrets-detection
                        'ccRecipients': [{'emailAddress': {'address': 'dummyCC@recipient.com'}}],
                        # disable-secrets-detection
                        'bccRecipients': [{'emailAddress': {'address': 'dummyBCC@recipient.com'}}],
                        # disable-secrets-detection
                        'replyTo': [{'emailAddress': {'address': 'dummyReplyTo@recipient.com'}}],
                        # disable-secrets-detection
                        'subject': 'Dummy Subject', 'body': {'content': 'Dummy Body', 'contentType': 'text'},
                        'bodyPreview': 'Dummy Body', 'importance': 'Normal', 'flag': {'flagStatus': 'flagged'},
                        'attachments': [{
                            '@odata.type': client.FILE_ATTACHMENT,
                            'contentBytes': '',
                            'isInline': True,
                            'name': attachment_name,
                            'size': 0,
                            'contentId': str(attachment)
                        }]
                        }
    result_message = GraphMailUtils.build_message(**message_input)

    assert result_message == expected_message


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_reply_email_command(client, mocker):
    """
    Given:
        - reply-email arguments
    When:
        - send a reply mail message
    Then:
        - validates that the outputs fit the updated reply mail message
    """
    import MicrosoftGraphListener
    args = {'to': ['ex@example.com'], 'body': "test body", 'subject': "test subject", "inReplyTo": "id",
            'from': "ex1@example.com"}
    mocker.patch.object(client, 'http_request')

    reply_message = MicrosoftGraphListener.reply_email_command(client, args)

    assert reply_message.outputs_prefix == "MicrosoftGraph.SentMail"
    assert reply_message.outputs_key_field == "ID"
    assert reply_message.outputs['ID'] == args['inReplyTo']
    assert reply_message.outputs['subject'] == f'Re: {args["subject"]}'
    assert reply_message.outputs['toRecipients'] == args['to']
    assert reply_message.outputs['bodyPreview'] == args['body']


def test_list_emails(mocker):
    from MicrosoftGraphListener import list_mails_command
    RAW_RESPONSE = [
        {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('mailbox%40company.com')/messages",
            "value":
                [
                    {
                        "@odata.etag": "W/\"ABCDEF/iABCDEF\"",
                        "bccRecipients": [],
                        "body": {
                            "content": "test",
                            "contentType": "text"
                        },
                        "bodyPreview": "test",
                        "categories": [],
                        "ccRecipients": [],
                        "changeKey": "ABCDEF/iABCDEF",
                        "conversationId": "asdasdasd",
                        "conversationIndex": "adqweqwe",
                        "createdDateTime": "2021-01-01T10:18:41Z",
                        "flag": {
                            "flagStatus": "notFlagged"
                        },
                        "from": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "hasAttachments": True,
                        "id": "qwe",
                        "importance": "normal",
                        "inferenceClassification": "focused",
                        "internetMessageId": "\u003cqwe@qwe.eurprd05.prod.outlook.com\u003e",
                        "isDeliveryReceiptRequested": None,
                        "isDraft": False,
                        "isRead": False,
                        "isReadReceiptRequested": False,
                        "lastModifiedDateTime": "2021-01-01T10:18:41Z",
                        "parentFolderId": "PARENT==",
                        "receivedDateTime": "2021-01-01T10:18:41Z",
                        "replyTo": [],
                        "sender": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "sentDateTime": "2021-08-20T10:18:40Z",
                        "subject": "Test",
                        "toRecipients": [
                            {
                                "emailAddress": {
                                    "address": "mailbox@company.com",
                                    "name": "My mailbox"
                                }
                            }
                        ],
                        "webLink": "https://outlook.office365.com/owa/?ItemID=ABCDEF"
                    }
                ]
        }]
    client = self_deployed_client()
    mocker.patch.object(client, 'list_mails', return_value=RAW_RESPONSE)

    results = list_mails_command(client, {})
    assert 'Total of 1 mails received' in results['HumanReadable']
    assert 'john.doe@company.com' in results['HumanReadable']
    assert 'qwe' in results['HumanReadable']


def test_list_emails_raw_response_contains_list(mocker):
    from MicrosoftGraphListener import list_mails_command
    RAW_RESPONSE = [
        {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('mailbox%40company.com')/messages",
            "value":
                [
                    {
                        "@odata.etag": "W/\"ABCDEF/iABCDEF\"",
                        "bccRecipients": [],
                        "body": {
                            "content": "test",
                            "contentType": "text"
                        },
                        "bodyPreview": "test",
                        "categories": [],
                        "ccRecipients": [],
                        "changeKey": "ABCDEF/iABCDEF",
                        "conversationId": "asdasdasd",
                        "conversationIndex": "adqweqwe",
                        "createdDateTime": "2021-01-01T10:18:41Z",
                        "flag": {
                            "flagStatus": "notFlagged"
                        },
                        "from": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "hasAttachments": True,
                        "id": "qwe",
                        "importance": "normal",
                        "inferenceClassification": "focused",
                        "internetMessageId": "\u003cqwe@qwe.eurprd05.prod.outlook.com\u003e",
                        "isDeliveryReceiptRequested": None,
                        "isDraft": False,
                        "isRead": False,
                        "isReadReceiptRequested": False,
                        "lastModifiedDateTime": "2021-01-01T10:18:41Z",
                        "parentFolderId": "PARENT==",
                        "receivedDateTime": "2021-01-01T10:18:41Z",
                        "replyTo": [],
                        "sender": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "sentDateTime": "2021-08-20T10:18:40Z",
                        "subject": "Test",
                        "toRecipients": [
                            {
                                "emailAddress": {
                                    "address": "mailbox@company.com",
                                    "name": "My mailbox"
                                }
                            }
                        ],
                        "webLink": "https://outlook.office365.com/owa/?ItemID=ABCDEF"
                    },
                    {
                        "@odata.etag": "W/\"KAHSKD/iABCDEF\"",
                        "bccRecipients": [],
                        "body": {
                            "content": "test",
                            "contentType": "text"
                        },
                        "bodyPreview": "test",
                        "categories": [],
                        "ccRecipients": [],
                        "changeKey": "ABCDEF/iABCDEF",
                        "conversationId": "asdasdasd",
                        "conversationIndex": "adqweqwe",
                        "createdDateTime": "2021-01-01T10:18:41Z",
                        "flag": {
                            "flagStatus": "notFlagged"
                        },
                        "from": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "hasAttachments": True,
                        "id": "qwe",
                        "importance": "normal",
                        "inferenceClassification": "focused",
                        "internetMessageId": "\u003cqwe@qwe.eurprd05.prod.outlook.com\u003e",
                        "isDeliveryReceiptRequested": None,
                        "isDraft": False,
                        "isRead": False,
                        "isReadReceiptRequested": False,
                        "lastModifiedDateTime": "2021-01-01T10:18:41Z",
                        "parentFolderId": "PARENT==",
                        "receivedDateTime": "2021-01-01T10:18:41Z",
                        "replyTo": [],
                        "sender": {
                            "emailAddress": {
                                "address": "john.doe@company.com",
                                "name": "John Doe"
                            }
                        },
                        "sentDateTime": "2021-08-20T10:18:40Z",
                        "subject": "Test",
                        "toRecipients": [
                            {
                                "emailAddress": {
                                    "address": "mailbox@company.com",
                                    "name": "My mailbox"
                                }
                            }
                        ],
                        "webLink": "https://outlook.office365.com/owa/?ItemID=ABCDEF"
                    }
                ],
                '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users/avishai@demistodev.onmicrosoft.com'
        }]
    client = self_deployed_client()
    mocker.patch.object(client, 'list_mails', return_value=RAW_RESPONSE)

    results = list_mails_command(client, {})
    assert 'MSGraphMail(val.NextPage.indexOf(\'http\')>=0)' in results['EntryContext']  # next page
    assert '2 mails received' in results['HumanReadable']
    assert 'john.doe@company.com' in results['HumanReadable']
    assert 'qwe' in results['HumanReadable']


def test_list_attachments(mocker):
    from MicrosoftGraphListener import list_attachments_command
    RAW_RESPONSE = {
        "@odata.context":
            "",
        "value": [
            {
                "@odata.mediaContentType": "text/plain",
                "@odata.type": "#microsoft.graph.fileAttachment",
                "contentId": None,
                "contentLocation": None,
                "contentType": "text/plain",
                "id": "id=",
                "isInline": False,
                "lastModifiedDateTime": "2022-07-18T12:34:29Z",
                "name": "Attachment.txt",
                "size": 3843
            }
        ]}
    client = self_deployed_client()
    mocker.patch.object(client, 'list_attachments', return_value=RAW_RESPONSE)
    list_attachments_command_results = list_attachments_command(client, {})
    assert 'Total of 1 attachments found' in list_attachments_command_results.readable_output
    assert 'Attachment.txt' in list_attachments_command_results.readable_output


def test_get_email_as_eml(mocker):
    from MicrosoftGraphListener import get_email_as_eml_command
    RAW_RESPONSE = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('my@company.com')/messages/$entity",
        "@odata.etag": "W/\"SOMEID\"",
        "id": "MSGID-MSGID_B-MSGID_C-MSGID_D=",
        "createdDateTime": "2022-07-18T12:34:29Z",
        "lastModifiedDateTime": "2022-07-18T12:34:29Z",
        "changeKey": "SOMEID",
        "categories": [],
        "receivedDateTime": "2022-07-18T12:34:29Z",
        "sentDateTime": "2022-07-18T12:34:28Z",
        "hasAttachments": True,
        "internetMessageId": "<imsgid@host.eurprd05.prod.outlook.com>",
        "subject": "Test",
        "bodyPreview": "Test",
        "importance": "normal",
        "parentFolderId": "parentfolderid==",
        "conversationId": "conversationid=",
        "conversationIndex": "conversationindex==",
        "isDeliveryReceiptRequested": False,
        "isReadReceiptRequested": False,
        "isRead": True,
        "isDraft": False,
        "webLink": "",
        "inferenceClassification": "focused",
        "body": {
            "contentType": "html",
            "content":
                "<html><head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><m"
                "eta name=\"Generator\" content=\"Microsoft Word 15 (filtered medium)\"><style>\r\n<!--\r\n@fo"
                "nt-face\r\n\t{font-family:\"Cambria Math\"}\r\n@font-face\r\n\t{font-family:Calibri}\r\n@font-"
                "face\r\n\t{font-family:Verdana}\r\np.MsoNormal, li.MsoNormal, div.MsoNormal\r\n\t{margin:0"
                "in;\r\n\tfont-size:11.0pt;\r\n\tfont-family:\"Calibri\",sans-serif}\r\nspan.EmailStyle1"
                "8\r\n\t{font-family:\"Calibri\",sans-serif;\r\n\tcolor:windowtext}\r\n.MsoChpDefault\r\n\t{font"
                "-family:\"Calibri\",sans-serif}\r\n@page WordSection1\r\n\t{margin:1.0in 1.0in 1.0in 1.0in}\r\ndiv.Wor"
                "dSection1\r\n\t{}\r\n-->\r\n</style></head><body lang=\"EN-US\" link=\"#0563C1\" vlink=\"#954F72\" sty"
                "le=\"word-wrap:break-word\"><div class=\"WordSection1\"><div><p class=\"MsoNormal\" style=\"\">Test<s"
                "pan style=\"font-size:7.5pt; font-family:&quot;Verdana&quot;,sans-serif; color:black\"> </span></p>"
                "</div></div></body></html>"
        },
        "sender": {
            "emailAddress": {
                "name": "Jon Doe",
                "address": "you@company.com"
            }
        },
        "from": {
            "emailAddress": {
                "name": "Jon Doe",
                "address": "you@company.com"
            }
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "name": "My",
                    "address": "my@company.com"
                }
            }
        ],
        "ccRecipients": [],
        "bccRecipients": [],
        "replyTo": [],
        "flag": {
            "flagStatus": "notFlagged"
        }
    }
    client = self_deployed_client()
    mocker.patch.object(client, 'get_email_as_eml', return_value=RAW_RESPONSE['body']['content'])
    get_email_as_eml_command_results = get_email_as_eml_command(client, {'message_id': 'id'})
    assert get_email_as_eml_command_results['File'] == 'id.eml'


@pytest.mark.parametrize("args",
                         [
                             ({"message_ids": "EMAIL1", "status": "Read"}),
                             ({"message_ids": "EMAIL1", "folder_id": "Inbox", "status": "Read"}),
                             ({"message_ids": "EMAIL1", "status": "Unread"}),
                             ({"message_ids": "EMAIL1", "folder_id": "Inbox", "status": "Unread"}),
                         ])
def test_update_email_status_command(mocker, args: dict):
    import MicrosoftGraphListener
    from MicrosoftGraphListener import GraphMailUtils

    client = self_deployed_client()
    mocker.patch.object(client, "http_request")

    result = MicrosoftGraphListener.update_email_status_command(client=client, args=args)

    mark_as_read = (args["status"].lower() == 'read')
    folder_id = args.get('folder_id')
    folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
    url_suffix = f"/users/{client._mailbox_to_fetch}{folder_path}/messages/{args['message_ids']}"

    assert result.outputs is None
    client.http_request.assert_called_with(method="PATCH", url_suffix=url_suffix, json_data={'isRead': mark_as_read})


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftGraphListener import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import MicrosoftGraphListener
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(MicrosoftGraphListener, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in MicrosoftGraphListener.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


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
    from MicrosoftGraphListener import GraphMailUtils
    output_prefix = 'MSGraphMail(val.ID && val.ID == obj.ID)'
    with open('test_data/mail_with_attachment.txt') as mail_json:
        user_id = 'ex@example.com'
        raw_response = json.load(mail_json)
        args = {}
        res = GraphMailUtils.item_result_creator(raw_response, user_id, args, client)
        assert isinstance(res, CommandResults)
        output = res.to_context().get('EntryContext', {})
        assert output.get(output_prefix).get('ID') == 'exampleID'
        assert output.get(output_prefix).get('Subject') == 'Test it'


@pytest.mark.parametrize('client', [oproxy_client(), self_deployed_client()])
def test_get_attachments_without_attachment_id(mocker, client):
    """
    Given:
        - A user ID 'ex@example.com'

    When:
        - Calling 'get_attachment_command' method.

    Then:
        - Validate that the message object created successfully and all the attachment where downloaded.

    """
    from MicrosoftGraphListener import get_attachment_command
    file_attachments_result = {'2': 'f1145f66-90fe-4604-a7ea-faac8c33684e-attachmentName-image2.png',
                               '3': 'image3.png'}
    output_prefix = 'MSGraphMail(val.ID && val.ID == obj.ID)'
    with open('test_data/mail_with_attachments.txt') as mail_json:
        test_args = {}
        raw_response = json.load(mail_json)
        mocker.patch.object(client, 'get_attachment', return_value=raw_response)
        res = get_attachment_command(client, test_args)
        assert isinstance(res, List)
        assert len(res) == len(raw_response)
        for i, attachment in enumerate(res):
            if isinstance(attachment, CommandResults):
                output = attachment.to_context().get('EntryContext', {})
                assert output.get(output_prefix).get('ID') == f'exampleID{i}'
                assert output.get(output_prefix).get('Subject') == f'Test it{i}'
            else:
                assert attachment['File'] == file_attachments_result.get(str(i))


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
    from MicrosoftGraphListener import GraphMailUtils
    with open('test_data/mail_with_unsupported_attachment.txt') as mail_json:
        user_id = 'ex@example.com'
        args = {}
        raw_response = json.load(mail_json)
        res = GraphMailUtils.item_result_creator(raw_response, user_id, args, client)
        assert isinstance(res, CommandResults)
        output = res.to_context().get('HumanReadable', '')
        assert 'Integration does not support attachments from type #microsoft.graph.contact' in output


class MockedResponse:

    def __init__(self, status_code):
        self.status_code = status_code


class TestCommandsWithLargeAttachments:

    SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS = [
        (
            self_deployed_client(),
            {'to': 'ex@example.com',
             'cc': '',
             'bcc': '',
             'subject': "test subject",
             'replyTo': 'ex2@example.com,ex3@example.com',
             'body': "<b>This text is bold</b>",
             'body_type': 'html',
             'flag': 'notFlagged',
             'importance': 'Low',
             'internet_message_headers': '',
             'attach_ids': '1',
             'attach_names': '',
             'attach_cids': '',
             'manual_attachments': []
             },
        ),
        (
            oproxy_client(),
            {'to': 'ex@example.com',
             'cc': '',
             'bcc': '',
             'subject': "test subject",
             'body': "<b>This text is bold</b>",
             'body_type': 'html',
             'replyTo': 'ex2@example.com,ex3@example.com',
             'flag': 'notFlagged',
             'importance': 'Low',
             'internet_message_headers': '',
             'attach_ids': '2',
             'attach_names': '',
             'attach_cids': '',
             'manual_attachments': []
             },
        ),
        (
            self_deployed_client(),
            {'to': 'ex@example.com',
             'cc': '',
             'bcc': '',
             'subject': "test subject",
             'body': "<b>This text is bold</b>",
             'body_type': 'html',
             'flag': 'notFlagged',
             'importance': 'Low',
             'replyTo': 'ex2@example.com,ex3@example.com',
             'internet_message_headers': '',
             'attach_ids': '1,2',
             'attach_names': '',
             'attach_cids': '',
             'manual_attachments': []
             }
        )
    ]

    REPLY_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS = [
        (
            self_deployed_client(),
            {
                'to': ['ex@example.com'], 'body': "test body", 'subject': "test subject", "inReplyTo": "123",
                'from': "ex1@example.com", 'attachIDs': '3'
            },
        ),
        (
            oproxy_client(),
            {
                'to': ['ex@example.com'], 'body': "test body", 'subject': "test subject", "inReplyTo": "123",
                'from': "ex1@example.com", 'attachIDs': '4'
            }
        ),
        (
            self_deployed_client(),
            {
                'to': ['ex@example.com'], 'body': "test body", 'subject': "test subject", "inReplyTo": "123",
                'from': "ex1@example.com", 'attachIDs': '3,4'
            }
        )
    ]

    @staticmethod
    def expected_upload_headers(world_file=True):
        if world_file:
            for header in [  # testing on the world.jpg file.
                {'Content-Length': '3145728', 'Content-Range': 'bytes 0-3145727/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 3145728-6291455/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 6291456-9437183/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 9437184-12582911/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 12582912-15728639/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 15728640-18874367/21796912',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '2922544', 'Content-Range': 'bytes 18874368-21796911/21796912',
                 'Content-Type': 'application/octet-stream'}
            ]:
                yield header
        else:
            for header in [   # testing on the test.pdf
                {'Content-Length': '3145728', 'Content-Range': 'bytes 0-3145727/4512758',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '1367030', 'Content-Range': 'bytes 3145728-4512757/4512758',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '3145728', 'Content-Range': 'bytes 6291456-9437183/10520433',
                 'Content-Type': 'application/octet-stream'},
                {'Content-Length': '1083249', 'Content-Range': 'bytes 9437184-10520432/10520433',
                 'Content-Type': 'application/octet-stream'},
            ]:
                yield header

    @staticmethod
    def get_attachment_file_details_by_attachment_id(attach_id):
        attachment_info = {
            '1': {
                'path': 'test_data/world.jpg',  # bigger than 3mb attachment
                'name': 'world.jpg'
            },
            '2': {
                'path': 'test_data/plant.jpeg',  # smaller than 3mb attachment
                'name': 'plant.jpeg'
            },
            '3': {
                'path': 'test_data/test.pdf',  # bigger than 3mb attachment
                'name': 'test.pdf'
            },
            '4': {
                'path': 'test_data/sample.pdf',  # smaller than 3mb attachment
                'name': 'sample-pdf'
            }
        }
        return attachment_info.get(attach_id)

    @staticmethod
    def upload_response_side_effect(**kwargs):
        headers = kwargs.get('headers')
        if int(headers['Content-Length']) < MsGraphListenerClient.MAX_ATTACHMENT_SIZE:
            return MockedResponse(status_code=201)
        return MockedResponse(status_code=200)

    def validate_upload_attachments_flow(self, create_upload_mock, upload_query_mock, world_file=True):
        """
        Validates that the upload flow is working as expected, each piece of headers is sent as expected.
        """
        if not create_upload_mock.called:
            return False

        if create_upload_mock.call_count != 1:
            return False

        expected_headers = iter(self.expected_upload_headers(world_file=world_file))
        for i in range(upload_query_mock.call_count):
            current_headers = next(expected_headers)
            if upload_query_mock.mock_calls[i].kwargs['headers'] != current_headers:
                return False
        return True

    @pytest.mark.parametrize('client, args', SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
    def test_send_mail_command(self, mocker, client, args):
        """
        Given:
            Case 1: send email command arguments and attachment > 3mb.
            Case 2: send email command arguments and attachment < 3mb.
            Case 3: send email command arguments and one attachment > 3m and one attachment < 3mb.
        When:
            - sending a mail
        Then:
            Case1:
             * make sure an upload session was created and that the correct headers were sent
             * make sure the endpoint to send an email without creating draft mail was not called.
             * make sure the endpoint to create a draft mail and send a draft mail were called.
            Case2:
             * make sure an upload session was not created
             * make sure the endpoints to create a draft email and send the draft email were not called.
             * make sure the endpoint to send an email was called.
            Case3:
             * make sure an upload session was created and that the correct headers were sent.
             * make sure the endpoint to send an email without creating draft mail was not called.
             * make sure the endpoint to create a draft email and send the draft mail were called.
             * make sure the the attachment < 3mb was sent when creating a draft mail not through an upload session.
            - Make sure for all three cases the expected context output is returned.
        """
        import MicrosoftGraphListener
        with requests_mock.Mocker() as request_mocker:
            mocked_draft_id = '123'
            mocker.patch.object(client, 'get_access_token')
            mocker.patch.object(demisto, 'getFilePath', side_effect=self.get_attachment_file_details_by_attachment_id)

            create_draft_mail_mocker = request_mocker.post(
                f'https://graph.microsoft.com/v1.0/users/{client._mailbox_to_fetch}/messages', json={'id': mocked_draft_id}
            )
            send_draft_mail_mocker = request_mocker.post(  # mock the endpoint to send a draft mail
                f'https://graph.microsoft.com/v1.0/users/{client._mailbox_to_fetch}/messages/{mocked_draft_id}/send'
            )

            send_mail_mocker = request_mocker.post(
                f'https://graph.microsoft.com/v1.0/users/{client._mailbox_to_fetch}/SendMail'
            )

            create_upload_mock = mocker.patch.object(
                client, 'get_upload_session', return_value={"uploadUrl": "test.com"}
            )
            upload_query_mock = mocker.patch.object(requests, 'put', side_effect=self.upload_response_side_effect)

            MicrosoftGraphListener.send_email_command(client, args)

            # attachment 1 is an attachment bigger than 3MB
            # means the attachment should be created in the upload session
            if (args.get('attach_ids') and '1' in args.get('attach_ids')):
                assert create_draft_mail_mocker.called
                assert send_draft_mail_mocker.called
                assert not send_mail_mocker.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock)

                if (args.get('attach_ids') and '2' in args.get('attach_ids')):
                    assert create_draft_mail_mocker.last_request.json().get('attachments')

                draft_sent_json = create_draft_mail_mocker.last_request.json()
                assert draft_sent_json
                assert draft_sent_json.get('toRecipients')
                assert draft_sent_json.get('subject')
            else:
                assert not create_draft_mail_mocker.called
                assert not send_draft_mail_mocker.called
                assert send_mail_mocker.called

                message = send_mail_mocker.last_request.json().get('message')
                assert message
                assert message.get('toRecipients')[0].get('emailAddress').get("address") == args.get('to')
                assert message.get('body').get('content') == args.get('htmlBody') or args.get('body')
                assert message.get('subject') == args.get('subject')
                reply_to_list = argToList(args.get('replyTo'))
                assert message.get('replyTo')[0].get('emailAddress').get("address") == reply_to_list[0]
                assert message.get('replyTo')[1].get('emailAddress').get("address") == reply_to_list[1]
                assert message.get('attachments')

    @pytest.mark.parametrize('client, args', REPLY_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
    def test_reply_email_command(self, mocker, client, args):
        """
        Given:
            Case 1: reply email command arguments and attachment > 3mb.
            Case 2: reply email command arguments and attachment < 3mb.
            Case 3: reply email command arguments and one attachment > 3m and one attachment < 3mb.
        When:
            - sending a reply mail
        Then:
            Case1:
             * make sure an upload session was created and that the correct headers were sent
             * make sure the endpoint to send a reply without creating draft mail was not called.
             * make sure the endpoint to create a draft reply mail and send a reply draft mail were called.
            Case2:
             * make sure an upload session was not created
             * make sure the endpoints to create a draft reply and send a draft reply were not called.
            Case3:
             * make sure an upload session was created and that the correct headers were sent.
             * make sure the endpoint to send a reply without creating draft mail was not called.
             * make sure the endpoint to create a draft reply mail and send a reply draft mail were called.
             * make sure the the attachment < 3mb was sent when creating a draft reply not through an upload session.
            - Make sure for all three cases the expected context output is returned.
        """
        import MicrosoftGraphListener
        with requests_mock.Mocker() as request_mocker:
            from_email = args.get('from')
            mocked_draft_id = '123'
            reply_message_id = args.get('inReplyTo')
            mocker.patch.object(client, 'get_access_token')
            mocker.patch.object(demisto, 'getFilePath', side_effect=self.get_attachment_file_details_by_attachment_id)

            create_draft_mail_mocker = request_mocker.post(  # mock the endpoint to create a draft for an existing message
                f'https://graph.microsoft.com/v1.0/users/{from_email}/messages/{reply_message_id}/createReply',
                json={'id': mocked_draft_id}
            )
            send_reply_draft_mail_mocker = request_mocker.post(  # mock the endpoint to reply a draft mail
                f'https://graph.microsoft.com/v1.0/users/{from_email}/messages/{mocked_draft_id}/send'
            )

            create_upload_mock = mocker.patch.object(
                client, 'get_upload_session', return_value={"uploadUrl": "test.com"}
            )
            upload_query_mock = mocker.patch.object(requests, 'put', side_effect=self.upload_response_side_effect)
            reply_mail_mocker = request_mocker.post(
                f'https://graph.microsoft.com/v1.0/users/{from_email}/messages/{reply_message_id}/reply'
            )

            command_results = MicrosoftGraphListener.reply_email_command(client, args)

            if '3' in args.get('attachIDs'):
                assert create_draft_mail_mocker.called
                assert send_reply_draft_mail_mocker.called  # sending the draft reply email should be called
                assert not reply_mail_mocker.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock, world_file=False)

                if '4' in args.get('attachIDs'):
                    # make sure when creating draft to send a reply that the attachments are being added to the api
                    # call the create a draft and not through upload session
                    assert create_draft_mail_mocker.last_request.json().get('message').get('attachments')
            else:
                assert reply_mail_mocker.called
                assert not create_draft_mail_mocker.called
                assert not create_upload_mock.called
                assert not send_reply_draft_mail_mocker.called
            assert command_results.outputs == {
                'toRecipients': ['ex@example.com'], 'subject': 'Re: test subject', 'bodyPreview': 'test body',
                'ID': '123'
            }

    @pytest.mark.parametrize('client, args', SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
    def test_create_draft_email_command(self, mocker, client, args):
        """
        Given:
            Case 1: create draft command arguments and attachment > 3mb.
            Case 2: create draft command arguments and attachment < 3mb.
            Case 3: create draft command arguments and one attachment > 3m and one attachment < 3mb.
        When:
            creating a draft mail.
        Then:
            Case1:
             * make sure an upload session was created and that the correct headers were sent
             * make sure the endpoint to create a draft email was called.
            Case2:
             * make sure an upload session was not created
             * make sure the endpoint to create a draft mail was called with the attachment.
            Case3:
             * make sure an upload session was created and that the correct headers were sent.
             * make sure the endpoint to create a draft mail was called.
             * make sure the the attachment < 3mb was sent when creating a draft reply not through an upload session
            - Make sure for all three cases the expected context output is returned.
        """
        import MicrosoftGraphListener
        with requests_mock.Mocker() as request_mocker:
            mocker.patch.object(client, 'get_access_token')
            create_draft_mail_mocker = request_mocker.post(
                f'https://graph.microsoft.com/v1.0/users/{client._mailbox_to_fetch}/messages', json={'id': '123'}
            )
            mocker.patch.object(demisto, 'getFilePath', side_effect=self.get_attachment_file_details_by_attachment_id)

            create_upload_mock = mocker.patch.object(
                client, 'get_upload_session', return_value={"uploadUrl": "test.com"}
            )
            upload_query_mock = mocker.patch.object(requests, 'put', side_effect=self.upload_response_side_effect)

            command_result = MicrosoftGraphListener.create_draft_command(client, args)

            # attachment 1 is an attachment bigger than 3MB
            # means the attachment should be created in the upload session
            if (args.get('attachIDs') and '1' in args.get('attachIDs')) or \
               (args.get('attach_ids') and '1' in args.get('attach_ids')):
                assert create_upload_mock.called
                assert upload_query_mock.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock)
                if (args.get('attachIDs') and '2' in args.get('attachIDs')) or \
                   (args.get('attach_ids') and '2' in args.get('attach_ids')):
                    assert create_draft_mail_mocker.last_request.json()['attachments']

            else:
                assert not create_upload_mock.called
                assert not upload_query_mock.called
                assert create_draft_mail_mocker.last_request.json()['attachments']
        assert command_result.outputs['ID'] == '123'
        assert command_result.outputs_prefix == 'MicrosoftGraph.Draft'
        assert create_draft_mail_mocker.called
        assert create_draft_mail_mocker.last_request.json()

    @pytest.mark.parametrize('command_args, expected_http_params',
                             [(
                                 {
                                     "exclude_ids": [], "last_fetch": "2022-12-31T09:38:15Z", "folder_id": "XYZ",
                                     "overwrite_rate_limit_retry": True
                                 },
                                 {
                                     "method": 'GET',
                                     "url_suffix":
                                     "/users/dummy@mailbox.com/mailFolders/XYZ/messages",
                                         "params": {
                                             "$filter": "receivedDateTime ge 2022-12-31T09:38:16Z",
                                             "$orderby": "receivedDateTime asc",
                                             "select": "*",
                                             "$top": 50,
                                         },
                                     "headers": {"Prefer": "outlook.body-content-type='text'"},
                                     "overwrite_rate_limit_retry": True,
                                 }
                             ),
                             ])
    def test_get_emails(self, mocker, command_args: dict, expected_http_params: dict):
        """
        Given: Command arguments and expected http request parameters.
        When: Running the `get_emails` command.
        Then: Ensure the expected http params are sent to the API.
        """
        client = oproxy_client()
        http_mock = mocker.patch.object(client, 'http_request')
        client.get_emails(**command_args)

        http_mock.assert_called_with(**expected_http_params)


def test_special_chars_in_attachment_name(mocker):
    """
    Given: A attachment file name containing special characters.
    When: Running the `_get_email_attachments` function.
    Then: Ensure the file name was decoded correctly.
    """
    client = oproxy_client()
    attachment_file_name = 'Moving_Form_ชั้น_26_แผงหลัง.xlsx'
    mocker.patch.object(client, 'http_request', return_value={'value': [{
        '@odata.type': '#microsoft.graph.fileAttachment',
        'name': attachment_file_name,
        'id': '123',
        'contentBytes': 'contentBytes'}]})
    mocker.patch.object(demisto, 'uniqueFile')
    mocker.patch("builtins.open", mock_open())

    res = client._get_email_attachments('message_id')

    assert res[0].get('name') == attachment_file_name


@pytest.mark.parametrize('attachment_file_name', ['1.png', 'file_example_JPG_100kB.jpg', 'sdsdagdsga.png'])
def test_regular_chars_in_attachment_name(mocker, attachment_file_name):
    """
    Given: A attachment file name containing Latin alphabet + some other characters but not from some other alphabet.
    When: Running the `_get_email_attachments` function.
    Then: Ensure the file name remains the same (without decoding).
    """
    client = oproxy_client()
    mocker.patch.object(client, 'http_request', return_value={'value': [{
        '@odata.type': '#microsoft.graph.fileAttachment',
        'name': attachment_file_name,
        'id': '1234',
        'contentBytes': 'contentBytes'}]})
    mocker.patch.object(demisto, 'uniqueFile')
    mocker.patch("builtins.open", mock_open())

    res = client._get_email_attachments('message_id')

    assert res[0].get('name') == attachment_file_name


@pytest.mark.parametrize('str_to_check, expected_result', [('slabiky, ale liší se podle významu', False),
                                                           ('English', True), ('ގެ ފުރަތަމަ ދެ އަކުރު ކަ', False),
                                                           ('how about this one : 通 asfަ', False),
                                                           ('?fd4))45s&', True)])
def test_is_only_ascii(str_to_check, expected_result):
    """
    Given: A string which contains Latin alphabet + some other characters or some other alphabet.
    When: Running the `is_only_ascii` function.
    Then: Ensure the function works and returns true for English strings and false for everything else.
    """
    result = str_to_check.isascii()
    assert expected_result == result


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function msgraph-mail-generate-login-url
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftGraphListener import main, Scopes
    import MicrosoftGraphListener

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'self_deployed': 'True',
        'creds_refresh_token': {'password': tenant_id},
        'creds_auth_id': {
            'password': client_id
        },
        'creds_enc_key': {
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='msgraph-mail-generate-login-url')
    mocker.patch.object(MicrosoftGraphListener, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   f'response_type=code&scope=offline_access%20{Scopes.graph}' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri}'
    res = MicrosoftGraphListener.return_results.call_args[0][0].readable_output
    assert expected_url in res


@pytest.mark.parametrize("raw_attachment, legacy_name, expected_name, expect_exception", [
    (
        {'name': 'test.png', 'contentId': '123', 'isInline': True,
            'contentBytes': base64.b64encode(b'test data').decode('utf-8')},
        False,
        "123-attachmentName-test.png",
        False
    ),
    (
        {'name': 'test.png', 'contentId': None, 'isInline': False,
            'contentBytes': base64.b64encode(b'test data').decode('utf-8')},
        False,
        "test.png",
        False
    ),
    (
        {'name': 'test.png', 'contentId': '123', 'isInline': True,
            'contentBytes': base64.b64encode(b'test data').decode('utf-8')},
        True,
        "test.png",
        False
    ),
    (
        {'name': 'test.png', 'contentId': 'None', 'isInline': True,
            'contentBytes': base64.b64encode(b'test data').decode('utf-8')},
        False,
        "test.png",
        False
    ),
    (
        {'name': 'test.png', 'contentId': '123', 'isInline': True, 'contentBytes': 'invalid_base64'},
        False,
        None,
        True
    )
])
def test_file_result_creator(monkeypatch, raw_attachment, legacy_name, expected_name, expect_exception):
    from MicrosoftGraphMailApiModule import GraphMailUtils
    monkeypatch.setattr('MicrosoftGraphListener.fileResult', fileResult)
    monkeypatch.setattr('MicrosoftGraphListener.DemistoException', DemistoException)

    if expect_exception:
        with pytest.raises(DemistoException):
            GraphMailUtils.file_result_creator(raw_attachment, legacy_name)
    else:
        result = GraphMailUtils.file_result_creator(raw_attachment, legacy_name)
        assert result['File'] == expected_name
