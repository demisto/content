import pytest
from CommonServerPython import *
from MicrosoftGraphMail import MsGraphClient, build_mail_object, assert_pages, build_folders_path, \
    add_second_to_str_date, list_mails_command
import demistomock as demisto


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
        assert '### Total of 2 mails received' in hr

    # call list mails with no emails
    with open('test_data/no_mails') as mail_json:
        mail = json.load(mail_json)
        mocker.patch.object(client, 'list_mails', return_value=mail)
        mocker.patch.object(demisto, 'results')
        list_mails_command(client, args)
        hr = demisto.results.call_args[0][0].get('HumanReadable')
        assert '### No mails were found' in hr


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
        'LAST_RUN_FOLDER_PATH': "Phishing"
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
def test_fetch_incidents_detect_initial(mocker, client, emails_data):
    mocker_folder_by_path = mocker.patch.object(client, '_get_folder_by_path',
                                                return_value={'id': 'some_dummy_folder_id'})
    mocker.patch.object(client.ms_client, 'http_request', return_value=emails_data)
    mocker.patch.object(demisto, "info")
    client.fetch_incidents({})

    mocker_folder_by_path.assert_called_once_with('dummy@mailbox.com', "Phishing")


def test_add_second_to_str_date():
    assert add_second_to_str_date("2019-11-12T15:00:00Z") == "2019-11-12T15:00:01Z"
    assert add_second_to_str_date("2019-11-12T15:00:00Z", 10) == "2019-11-12T15:00:10Z"


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
                        'subject': 'Dummy Subject', 'body': {'content': 'Dummy Body', 'contentType': 'text'},
                        'bodyPreview': 'Dummy Body', 'importance': 'Normal', 'flag': {'flagStatus': 'flagged'},
                        'attachments': []}
    result_message = client.build_message(**message_input)

    assert result_message == expected_message
