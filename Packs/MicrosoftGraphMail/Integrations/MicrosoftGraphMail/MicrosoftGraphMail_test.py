from urllib.parse import quote

import pytest
import requests_mock
from MicrosoftGraphMail import *

import demistomock as demisto
from CommonServerPython import *
from MicrosoftApiModule import MicrosoftClient


class MockedResponse:
    def __init__(self, status_code):
        self.status_code = status_code


@pytest.mark.parametrize(
    "params, expected_result",
    [
        ({"creds_tenant_id": {"password": "1234"}, "creds_auth_id": {"password": "1234"}}, "Key must be provided."),
        ({"creds_tenant_id": {"password": "1234"}, "credentials": {"password": "1234"}}, "ID must be provided."),
        ({"credentials": {"password": "1234"}, "creds_auth_id": {"password": "1234"}}, "Token must be provided."),
    ],
)
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
    import MicrosoftGraphMail

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(MicrosoftGraphMail, "return_error")

    main()

    assert expected_result in MicrosoftGraphMail.return_error.call_args[0][0]


@pytest.mark.parametrize(
    "params, expected_results",
    [
        (
            {"creds_tenant_id": {"password": "1234"}, "creds_auth_id": {"password": "3124"}, "credentials": {"password": "2412"}},
            ["1234", "3124", "2412"],
        ),
        ({"tenant_id": "5678", "enc_key": "8142", "auth_id": "5678"}, ["5678", "5678", "8142"]),
        ({"_tenant_id": "1267", "credentials": {"password": "1234"}, "_auth_id": "8888"}, ["1267", "8888", "1234"]),
    ],
)
def test_params_working(mocker, params, expected_results):
    """
    Given:
      - Case 1: tenant id, auth id and key where all three are part of the credentials.
      - Case 2: tenant id, auth id and key where all three aren't part of the credentials.
      - Case 3: tenant id, auth id and key where only the key is part of the credentials.
    When:
      - Setting an instance
    Then:
      - Ensure that the instance can Co-op with previous versions params names and that MsGraphMailClient.__init__
      was called with the right tenant id, auth id and key.
      - Case 1: MsGraphMailClient.__init__ Should be called with tenant id,
      auth id and key extracted from credentials type params.
      - Case 2: MsGraphMailClient.__init__ Should be called with tenant id, auth id and key
      not extracted from credentials type params.
      - Case 3: MsGraphMailClient.__init__ Should be called with only key param extracted from credentials type params.
    """

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(MsGraphMailBaseClient, "__init__", return_value=None)
    main()
    MsGraphMailBaseClient.__init__.assert_called_with(
        self_deployed=False,
        tenant_id=expected_results[0],
        auth_id=expected_results[1],
        enc_key=expected_results[2],
        app_name="ms-graph-mail",
        base_url="/v1.0",
        verify=True,
        proxy=False,
        ok_codes=(200, 201, 202, 204),
        mailbox_to_fetch="",
        folder_to_fetch="Inbox",
        first_fetch_interval="15 minutes",
        emails_fetch_limit=50,
        timeout=10,
        endpoint="com",
        certificate_thumbprint="",
        private_key="",
        display_full_email_body=False,
        mark_fetched_read=False,
        look_back=0,
        managed_identities_client_id=None,
        legacy_name=False,
    )


def test_build_mail_object():
    # Testing list of mails
    user_id = "ex@example.com"
    with open("test_data/mails") as mail_json:
        mail = json.load(mail_json)
        res = GraphMailUtils.build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, list)
        assert len(mail[0].get("value")) == len(res)
        assert res[0]["Created"] == "2019-04-16T19:40:00Z"
        assert res[0]["UserID"] == user_id
        assert res[0]["Body"]

    with open("test_data/mail") as mail_json:
        mail = json.load(mail_json)
        res = GraphMailUtils.build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, dict)
        assert res["UserID"] == user_id
        assert res["Body"]


def test_assert_pages():
    assert GraphMailUtils.assert_pages(3) == 3
    assert GraphMailUtils.assert_pages(None) == 1
    assert GraphMailUtils.assert_pages("4") == 4


def test_build_folders_path():
    inp = "i,s,f,q"
    response = GraphMailUtils.build_folders_path(inp)
    assert response == "mailFolders/i/childFolders/s/childFolders/f/childFolders/q"


def oproxy_client():
    auth_id = "dummy_auth_id"
    enc_key = "dummy_enc_key"
    token_retrieval_url = "url_to_retrieval"
    auth_and_token_url = f"{auth_id}@{token_retrieval_url}"
    app_name = "ms-graph-mail"
    mailbox_to_fetch = "dummy@mailbox.com"  # disable-secrets-detection
    folder_to_fetch = "Phishing"
    first_fetch_interval = "20 minutes"
    emails_fetch_limit = 50
    base_url = "https://graph.microsoft.com/v1.0"
    ok_codes = (200, 201, 202)

    return MsGraphMailClient(
        self_deployed=False,
        tenant_id="",
        auth_id=auth_and_token_url,
        enc_key=enc_key,
        app_name=app_name,
        base_url=base_url,
        verify=True,
        proxy=False,
        ok_codes=ok_codes,
        mailbox_to_fetch=mailbox_to_fetch,
        folder_to_fetch=folder_to_fetch,
        first_fetch_interval=first_fetch_interval,
        emails_fetch_limit=emails_fetch_limit,
    )


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

    return MsGraphMailClient(
        self_deployed=True,
        tenant_id=tenant_id,
        auth_id=client_id,
        enc_key=client_secret,
        base_url=base_url,
        verify=True,
        proxy=False,
        ok_codes=ok_codes,
        app_name="",
        mailbox_to_fetch=mailbox_to_fetch,
        folder_to_fetch=folder_to_fetch,
        first_fetch_interval=first_fetch_interval,
        emails_fetch_limit=emails_fetch_limit,
    )


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
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
    first_response = {"@odata.context": "response_context", "@odata.nextLink": "link_1", "value": ["email1", "email2"]}
    second_response = {"@odata.context": "response_context", "@odata.nextLink": "link_2", "value": ["email3", "email4"]}
    responses = client.pages_puller(first_response, 1)
    assert len(responses) == 1
    mocker.patch.object(client, "http_request", return_value=second_response)
    responses = client.pages_puller(first_response, 2)
    assert len(responses) == 2


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
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
    args = {"user_id": "test id"}

    # call list mails with two emails
    with open("test_data/mails") as mail_json:
        mail = json.load(mail_json)
        mocker.patch.object(client, "list_mails", return_value=mail)
        mocker.patch.object(demisto, "results")
        result_entry = list_mails_command(client, args)
        hr = result_entry.get("HumanReadable")
        assert (
            "2 mails received\nPay attention there are more results than shown. For more data please "
            'increase "pages_to_pull" argument' in hr
        )

    # call list mails with no emails
    with open("test_data/no_mails") as mail_json:
        mail = json.load(mail_json)
        mocker.patch.object(client, "list_mails", return_value=mail)
        mocker.patch.object(demisto, "results")
        command_result = list_mails_command(client, args)
        hr = command_result.readable_output
        assert "### No mails were found" in hr


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_list_mails_command_encoding(mocker, client):
    """Unit test
    Given
    - an email query
    When
    - calling list_mails
    Then
    - Validate that the queried value is properly url-encoded
    """
    client = MsGraphMailClient(
        self_deployed=True,
        tenant_id="tenant",
        auth_id="auth_token_url",
        enc_key="enc_key",
        app_name="app_name",
        base_url="https://example.com",
        verify=True,
        proxy=False,
        ok_codes=(200,),
        mailbox_to_fetch="mailbox",
        folder_to_fetch="folder",
        first_fetch_interval=10,
        emails_fetch_limit=10,
    )
    mocker.patch.object(client, "get_access_token")

    search = "Test&$%^"
    search_encoded = quote(search)

    with requests_mock.Mocker() as request_mocker:
        mocked = request_mocker.get(f"https://example.com/users/user_id/messages?$top=20&$search=%22{search_encoded}%22", json={})
        client.list_mails("user_id", search=search)
    assert mocked.call_count == 1


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
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
    args = {"user_id": "test id", "page_size": 1, "pages_to_pull": 1}
    with open("test_data/response_with_one_mail") as mail_json:
        mail = json.load(mail_json)
        mock_request = mocker.patch.object(MicrosoftClient, "http_request", return_value=mail)
        mocker.patch.object(demisto, "results")
        mocker.patch.object(demisto, "args", return_value=args)
        result_entry = list_mails_command(client, args)
        hr = result_entry.get("HumanReadable")
        assert (
            "1 mails received\nPay attention there are more results than shown. For more data please "
            'increase "pages_to_pull" argument' in hr
        )
        assert "top=1" in mock_request.call_args_list[0].args[1]


@pytest.fixture()
def expected_incident():
    with open("test_data/expected_incident") as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_html():
    return emails_data_as_html_including_body()


def emails_data_as_html_including_body():
    with open("test_data/emails_data_html") as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_text():
    return emails_data_as_text_including_body()


def emails_data_as_text_including_body():
    with open("test_data/emails_data_text") as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_html_without_body():
    with open("test_data/emails_data_html_without_body") as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_text_without_body():
    with open("test_data/emails_data_text_without_body") as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_full_body_as_html():
    with open("test_data/emails_data_full_body_html") as emails_json:
        return json.load(emails_json)


@pytest.fixture()
def emails_data_full_body_as_text():
    with open("test_data/emails_data_full_body_text") as emails_json:
        return json.load(emails_json)


@pytest.fixture()
def expected_incident_full_body():
    with open("test_data/expected_incident_full_body") as incident:
        return json.load(incident)


@pytest.fixture
def last_run_data():
    last_run = {
        "LAST_RUN_TIME": "2019-11-12T15:00:00Z",
        "LAST_RUN_IDS": [],
        "LAST_RUN_FOLDER_ID": "last_run_dummy_folder_id",
        "LAST_RUN_FOLDER_PATH": "Phishing",
        "LAST_RUN_ACCOUNT": "dummy@mailbox.com",
    }

    return last_run


@pytest.mark.parametrize(
    "client, email_content_html, email_content_text",
    [
        (oproxy_client(), emails_data_as_html_including_body(), emails_data_as_text_including_body()),
        (self_deployed_client(), emails_data_as_html_without_body(), emails_data_as_text_without_body()),
    ],
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
        "CommonServerPython.get_current_time", return_value=dateparser.parse("2019-11-12T15:01:00", settings={"TIMEZONE": "UTC"})
    )
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, "http_request", side_effect=[email_content_html, email_content_text, {}])
    mocker.patch.object(demisto, "info")
    result_next_run, result_incidents = client.fetch_incidents(last_run_data)

    assert result_next_run.get("time") == "2019-11-12T15:00:30Z"
    assert result_next_run.get("LAST_RUN_IDS") == ["dummy_id_1"]
    assert result_next_run.get("LAST_RUN_FOLDER_ID") == "last_run_dummy_folder_id"
    assert result_next_run.get("LAST_RUN_FOLDER_PATH") == "Phishing"

    result_incidents = result_incidents[0]
    result_raw_json = json.loads(result_incidents.pop("rawJSON"))
    expected_raw_json = expected_incident.pop("rawJSON", None)

    assert result_raw_json == expected_raw_json
    assert result_incidents == expected_incident


class TestFetchIncidentsWithLookBack:
    FREEZE_TIMESTAMP = "2022-07-28T12:09:17Z"

    @staticmethod
    def start_freeze_time(timestamp):
        from freezegun import freeze_time

        _start_freeze_time = freeze_time(timestamp)
        _start_freeze_time.start()
        return datetime.now()

    def create_incidents_queue(self):
        first_email = {
            "id": "1",
            "subject": "email-1",
            "receivedDateTime": (self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=2)).strftime(API_DATE_FORMAT),
        }

        second_email = {
            "id": "2",
            "subject": "email-2",
            "receivedDateTime": (self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=5)).strftime(API_DATE_FORMAT),
        }

        third_email = {
            "id": "3",
            "subject": "email-3",
            "receivedDateTime": (self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=10)).strftime(API_DATE_FORMAT),
        }

        return [([third_email], []), ([second_email, third_email], []), ([first_email, second_email, third_email], [])]

    @pytest.mark.parametrize("look_back", [30, 40, 400])
    def test_fetch_emails_with_look_back_greater_than_zero(self, mocker, look_back):
        """
        Given
         - a look back parameter.
         - incidents queue.

        When
         - trying to fetch emails with the look-back mechanism.

        Then
         - make sure only one incident is being returned each time, based on the 'cache' look-back mechanism.
         - make sure the correct timestamp to query the api was called based on the look-back parameter.
         - make sure the correct incident is being returned by its name without any duplication whatsoever.
         - make sure the 'time' for the look-back for the last run is being set to the latest incident occurred incident
         - make sure the 'ID' field is being removed from the incidents before fetching.
        """
        client = self_deployed_client()
        client._look_back = look_back

        last_emails_mocker = mocker.patch.object(client, "_fetch_last_emails", side_effect=self.create_incidents_queue())
        mocker.patch.object(client, "_get_email_attachments", return_value=[])

        last_run = {
            "LAST_RUN_FOLDER_ID": "last_run_dummy_folder_id",
            "LAST_RUN_FOLDER_PATH": "Phishing",
            "LAST_RUN_ACCOUNT": "dummy@mailbox.com",
            "LAST_RUN_TIME": (datetime.now() - timedelta(minutes=20)).strftime(API_DATE_FORMAT),
        }

        expected_last_run_timestamps = ["2022-07-28T12:07:17Z", "2022-07-28T12:04:17Z", "2022-07-28T11:59:17Z"]

        for i in range(3, 0, -1):
            next_run, incidents = client.fetch_incidents(last_run=last_run)
            assert last_emails_mocker.call_args.kwargs["last_fetch"] == (datetime.now() - timedelta(minutes=look_back)).strftime(
                API_DATE_FORMAT
            )
            assert next_run["time"] == expected_last_run_timestamps[i - 1]
            assert len(incidents) == 1
            assert incidents[0]["name"] == f"email-{i}"
            assert "ID" not in incidents[0]


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_changed_folder(mocker, client, emails_data_as_html, emails_data_as_text, last_run_data):
    changed_folder = "Changed_Folder"
    client._folder_to_fetch = changed_folder
    mocker_folder_by_path = mocker.patch.object(client, "_get_folder_by_path", return_value={"id": "some_dummy_folder_id"})
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, "http_request", side_effect=[emails_data_as_html, emails_data_as_text, {}])
    mocker.patch.object(demisto, "info")
    client.fetch_incidents(last_run_data)

    mocker_folder_by_path.assert_called_once_with("dummy@mailbox.com", changed_folder, overwrite_rate_limit_retry=True)


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_changed_account(mocker, client, emails_data_as_html, emails_data_as_text, last_run_data):
    changed_account = "Changed_Account"
    client._mailbox_to_fetch = changed_account
    mocker_folder_by_path = mocker.patch.object(client, "_get_folder_by_path", return_value={"id": "some_dummy_folder_id"})
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, "http_request", side_effect=[emails_data_as_html, emails_data_as_text, {}])
    mocker.patch.object(demisto, "info")
    client.fetch_incidents(last_run_data)

    mocker_folder_by_path.assert_called_once_with(
        changed_account, last_run_data["LAST_RUN_FOLDER_PATH"], overwrite_rate_limit_retry=True
    )


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_detect_initial(mocker, client, emails_data_as_html, emails_data_as_text):
    mocker_folder_by_path = mocker.patch.object(client, "_get_folder_by_path", return_value={"id": "some_dummy_folder_id"})
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, "http_request", side_effect=[emails_data_as_html, emails_data_as_text, {}])
    mocker.patch.object(demisto, "info")
    client.fetch_incidents({})

    mocker_folder_by_path.assert_called_once_with("dummy@mailbox.com", "Phishing", overwrite_rate_limit_retry=True)


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_fetch_incidents_with_full_body(
    mocker, client, emails_data_full_body_as_html, emails_data_full_body_as_text, expected_incident_full_body, last_run_data
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
        "CommonServerPython.get_current_time", return_value=dateparser.parse("2019-11-12T15:01:00", settings={"TIMEZONE": "UTC"})
    )
    client._display_full_email_body = True
    # the third argument in side effect is for attachments (no-attachments here)
    mocker.patch.object(client, "http_request", side_effect=[emails_data_full_body_as_html, emails_data_full_body_as_text, {}])
    mocker.patch.object(demisto, "info")
    result_next_run, result_incidents = client.fetch_incidents(last_run_data)

    assert result_next_run.get("time") == "2019-11-12T15:00:30Z"
    assert result_next_run.get("LAST_RUN_IDS") == ["dummy_id_1"]
    assert result_next_run.get("LAST_RUN_FOLDER_ID") == "last_run_dummy_folder_id"
    assert result_next_run.get("LAST_RUN_FOLDER_PATH") == "Phishing"

    result_incidents = result_incidents[0]
    result_raw_json = json.loads(result_incidents.pop("rawJSON"))

    expected_raw_json = expected_incident_full_body.pop("rawJSON", None)

    assert result_raw_json == expected_raw_json
    assert result_incidents == expected_incident_full_body


def test_parse_email_as_label():
    assert GraphMailUtils.parse_email_as_labels({"ID": "dummy_id"}) == [{"type": "Email/ID", "value": "dummy_id"}]
    assert GraphMailUtils.parse_email_as_labels({"To": ["dummy@recipient.com"]}) == [
        {"type": "Email/To", "value": "dummy@recipient.com"}
    ]


def test_build_recipient_input():
    recipient_input = ["dummy1@rec.com", "dummy2@rec.com", "dummy3@rec.com"]  # disable-secrets-detection
    result_recipients_input = GraphMailUtils.build_recipient_input(recipient_input)
    expected_recipients_input = [
        {"emailAddress": {"address": "dummy1@rec.com"}},
        {"emailAddress": {"address": "dummy2@rec.com"}},
        {"emailAddress": {"address": "dummy3@rec.com"}},
    ]

    assert result_recipients_input == expected_recipients_input


def test_build_body_input():
    first_body_input = ["test body 1", "text"]
    second_body_input = ["test body 2", "HTML"]
    first_result_body_input = GraphMailUtils.build_body_input(*first_body_input)
    second_result_body_input = GraphMailUtils.build_body_input(*second_body_input)

    assert first_result_body_input == {"content": "test body 1", "contentType": "text"}
    assert second_result_body_input == {"content": "test body 2", "contentType": "HTML"}


def test_build_headers_input():
    headers_input = ["x-header-one:header1", "x-header-two:heasder2"]
    result_expecte_headers = [{"name": "x-header-one", "value": "header1"}, {"name": "x-header-two", "value": "heasder2"}]

    assert GraphMailUtils.build_headers_input(headers_input) == result_expecte_headers


def test_build_message():
    message_input = {
        "to_recipients": ["dummy@recipient.com"],  # disable-secrets-detection
        "cc_recipients": ["dummyCC@recipient.com"],  # disable-secrets-detection
        "bcc_recipients": ["dummyBCC@recipient.com"],  # disable-secrets-detection
        "reply_to": ["dummyreplyTo@recipient.com"],  # disable-secrets-detection
        "subject": "Dummy Subject",
        "body": "Dummy Body",
        "body_type": "text",
        "flag": "flagged",
        "importance": "Normal",
        "internet_message_headers": None,
        "attach_ids": [],
        "attach_names": [],
        "attach_cids": [],
        "manual_attachments": [],
    }

    expected_message = {
        "toRecipients": [{"emailAddress": {"address": "dummy@recipient.com"}}],
        # disable-secrets-detection
        "ccRecipients": [{"emailAddress": {"address": "dummyCC@recipient.com"}}],
        # disable-secrets-detection
        "bccRecipients": [{"emailAddress": {"address": "dummyBCC@recipient.com"}}],
        # disable-secrets-detection
        "replyTo": [{"emailAddress": {"address": "dummyreplyTo@recipient.com"}}],
        # disable-secrets-detection
        "subject": "Dummy Subject",
        "body": {"content": "Dummy Body", "contentType": "text"},
        "bodyPreview": "Dummy Body",
        "importance": "Normal",
        "flag": {"flagStatus": "flagged"},
        "attachments": [],
    }
    result_message = GraphMailUtils.build_message(**message_input)

    assert result_message == expected_message


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_get_attachment_as_command_result(client):
    """
    Given:
        - raw response returned from get_attachment_command

    When:
        - response type is itemAttachment and 'item_result_creator' is called
        - The 'should_download_message_attachment' command argument value is False (by default)

    Then:
        - Validate that the message object created successfully
        - GraphMailUtils.item_result_creator function should return a command result

    """
    output_prefix = "MSGraphMail(val.ID && val.ID == obj.ID)"
    with open("test_data/mail_with_attachment") as mail_json:
        user_id = "ex@example.com"
        raw_response = json.load(mail_json)
        args = {}
        res = GraphMailUtils.item_result_creator(raw_response, user_id, args, client)
        assert isinstance(res, CommandResults)
        output = res.to_context().get("EntryContext", {})
        assert output.get(output_prefix).get("ID") == "exampleID"
        assert output.get(output_prefix).get("Subject") == "Test it"


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_get_attachment_as_file_result(mocker, client):
    """
    Given:
        - raw response returned from get_attachment_command

    When:
        - response type is itemAttachment and 'item_result_creator' is called.
        - The 'should_download_message_attachment' command argument is True

    Then:
        - Validate that the message object created successfully
        - GraphMailUtils.item_result_creator function should return a command result

    """

    mocker.patch.object(MsGraphMailBaseClient, "_get_attachment_mime", return_value="raw data")
    with open("test_data/mail_with_attachment") as mail_json:
        user_id = "ex@example.com"
        args = {
            "message_id": "example_message_id",
            "attachment_id": "example_attachment_id",
            "should_download_message_attachment": True,
        }
        raw_response = json.load(mail_json)
        res = GraphMailUtils.item_result_creator(raw_response, user_id, args, client)
        assert isinstance(res, dict)
        assert res["File"] == "Test_it.eml"
        assert res["FileID"]


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_get_attachments_without_attachment_id(mocker, client):
    """
    Given:
        - A user ID 'ex@example.com'

    When:
        - Calling 'get_attachment_command' method.

    Then:
        - Validate that the message object created successfully and all the attachment where downloaded.

    """
    from MicrosoftGraphMail import get_attachment_command

    file_attachments_result = {"2": "f1145f66-90fe-4604-a7ea-faac8c33684e-attachmentName-image2.png", "3": "image3.png"}
    output_prefix = "MSGraphMail(val.ID && val.ID == obj.ID)"
    with open("test_data/mail_with_attachments") as mail_json:
        user_id = "ex@example.com"
        test_args = {"user_id": user_id}
        raw_response = json.load(mail_json)
        mocker.patch.object(client, "get_attachment", return_value=raw_response)
        res = get_attachment_command(client, test_args)
        assert isinstance(res, List)
        assert len(res) == len(raw_response)
        for i, attachment in enumerate(res):
            if isinstance(attachment, CommandResults):
                output = attachment.to_context().get("EntryContext", {})
                assert output.get(output_prefix).get("ID") == f"exampleID{i}"
                assert output.get(output_prefix).get("Subject") == f"Test it{i}"
            else:
                assert attachment["File"] == file_attachments_result.get(str(i))


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_get_attachment_unsupported_type(client):
    """
    Given:
        - raw response returned from get_attachment_command

    When:
        - response type is itemAttachment with attachment that is not supported

    Then:
        - Validate the human readable which explain we do not support the type

    """
    with open("test_data/mail_with_unsupported_attachment") as mail_json:
        user_id = "ex@example.com"
        raw_response = json.load(mail_json)
        args = {}
        res = GraphMailUtils.item_result_creator(raw_response, user_id, args, client)
        assert isinstance(res, CommandResults)
        output = res.to_context().get("HumanReadable", "")
        assert "Integration does not support attachments from type #microsoft.graph.contact" in output


@pytest.mark.parametrize(
    "function_name, attachment_type, client",
    [("file_result_creator", "fileAttachment", oproxy_client()), ("item_result_creator", "itemAttachment", oproxy_client())],
)
def test_create_attachment(mocker, function_name, attachment_type, client):
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
    mocker.patch(f"MicrosoftGraphMail.GraphMailUtils.{function_name}", return_value=function_name)
    raw_response = {"@odata.type": f"#microsoft.graph.{attachment_type}"}
    user_id = "ex@example.com"
    args = {}
    called_function = GraphMailUtils.create_attachment(raw_response, user_id, args, client)
    assert called_function == function_name


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
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
    output_prefix = "MSGraphMailAttachment(val.ID && val.ID == obj.ID)"
    with open("test_data/list_attachment_result.json") as attachment_result:
        args = {"user_id": "example"}
        raw_response = json.load(attachment_result)
        mocker.patch.object(client, "list_attachments", return_value=raw_response)
        mocker.patch.object(demisto, "results")
        command_result = list_attachments_command(client, args)
        context = command_result.to_context().get("EntryContext")

        assert context.get(output_prefix).get("Attachment")[0].get("ID") == "someID"
        assert context.get(output_prefix).get("Attachment")[0].get("Name") == "someName"
        assert context.get(output_prefix).get("Attachment")[0].get("Type") == "application/octet-stream"


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
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
    output_prefix = "MSGraphMailAttachment(val.ID && val.ID == obj.ID)"
    with open("test_data/list_attachment_result_no_name.json") as attachment_result:
        args = {"user_id": "example"}
        raw_response = json.load(attachment_result)
        mocker.patch.object(client, "list_attachments", return_value=raw_response)
        mocker.patch.object(demisto, "results")
        command_result = list_attachments_command(client, args)
        context = command_result.to_context().get("EntryContext")

        assert context.get(output_prefix).get("Attachment")[0].get("ID") == "someID"
        assert context.get(output_prefix).get("Attachment")[0].get("Name") == "someID"
        assert context.get(output_prefix).get("Attachment")[0].get("Type") == "application/octet-stream"


@pytest.mark.parametrize("client", [oproxy_client(), self_deployed_client()])
def test_reply_mail_command(client, mocker):
    """
    Given:
        - reply-mail arguments

    When:
        - send a reply mail message

    Then:
        - validates that the outputs fit the updated reply mail message

    """
    args = {
        "to": ["ex@example.com"],
        "body": "test body",
        "subject": "test subject",
        "inReplyTo": "id",
        "from": "ex1@example.com",
        "replyTo": ["ex2@example.com"],
    }
    mocker.patch.object(client, "http_request")

    reply_message = reply_email_command(client, args)

    assert reply_message.outputs_prefix == "MicrosoftGraph.SentMail"
    assert reply_message.outputs_key_field == "ID"
    assert reply_message.outputs["ID"] == args["inReplyTo"]
    assert reply_message.outputs["subject"] == "Re: " + args["subject"]
    assert reply_message.outputs["toRecipients"] == args["to"]
    assert reply_message.outputs["bodyPreview"] == args["body"]
    assert reply_message.outputs["replyTo"] == args["replyTo"]


SEND_MAIL_COMMAND_ARGS = [
    (
        oproxy_client(),
        {
            "to": ["ex@example.com"],
            "htmlBody": "<b>This text is bold</b>",
            "subject": "test subject",
            "replyTo": ["ex2@example.com", "ex3@example.com"],
            "from": "ex1@example.com",
        },
    ),
    (
        self_deployed_client(),
        {
            "to": ["ex@example.com"],
            "htmlBody": "<b>This text is bold</b>",
            "subject": "test subject",
            "replyTo": ["ex2@example.com", "ex3@example.com"],
            "from": "ex1@example.com",
        },
    ),
    (
        oproxy_client(),
        {
            "to": ["ex@example.com"],
            "body": "test body",
            "subject": "test subject",
            "replyTo": ["ex2@example.com", "ex3@example.com"],
            "from": "ex1@example.com",
        },
    ),
    (
        self_deployed_client(),
        {
            "to": ["ex@example.com"],
            "body": "test body",
            "subject": "test subject",
            "replyTo": ["ex2@example.com", "ex3@example.com"],
            "from": "ex1@example.com",
        },
    ),
]


@pytest.mark.parametrize("client, args", SEND_MAIL_COMMAND_ARGS)
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
        from_email = args.get("from")

        mocker.patch.object(client, "get_access_token")
        send_mail_mocker = request_mocker.post(f"https://graph.microsoft.com/v1.0/users/{from_email}/SendMail")

        send_email_command(client, args)

        assert send_mail_mocker.called
        message = send_mail_mocker.last_request.json().get("message")
        assert message
        assert message.get("toRecipients")[0].get("emailAddress").get("address") == args.get("to")[0]
        assert message.get("body").get("content") == args.get("htmlBody") or args.get("body")
        assert message.get("subject") == args.get("subject")
        assert message.get("replyTo")[0].get("emailAddress").get("address") == args.get("replyTo")[0]
        assert message.get("replyTo")[1].get("emailAddress").get("address") == args.get("replyTo")[1]


class TestCommandsWithLargeAttachments:
    SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS = [
        (
            self_deployed_client(),
            {
                "to": ["ex@example.com"],
                "htmlBody": "<b>This text is bold</b>",
                "subject": "test subject",
                "replyTo": ["ex2@example.com", "ex3@example.com"],
                "from": "ex1@example.com",
                "attachIDs": "1",
            },
        ),
        (
            oproxy_client(),
            {
                "to": ["ex@example.com"],
                "body": "test body",
                "subject": "test subject",
                "replyTo": ["ex2@example.com", "ex3@example.com"],
                "from": "ex1@example.com",
                "attachIDs": "2",
            },
        ),
        (
            self_deployed_client(),
            {
                "to": ["ex@example.com"],
                "body": "test body",
                "subject": "test subject",
                "replyTo": ["ex2@example.com", "ex3@example.com"],
                "from": "ex1@example.com",
                "attachIDs": "1,2",
            },
        ),
    ]

    REPLY_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS = [
        (
            self_deployed_client(),
            {
                "to": ["ex@example.com"],
                "body": "test body",
                "subject": "test subject",
                "inReplyTo": "123",
                "from": "ex1@example.com",
                "attachIDs": "3",
            },
        ),
        (
            oproxy_client(),
            {
                "to": ["ex@example.com"],
                "body": "test body",
                "subject": "test subject",
                "inReplyTo": "123",
                "from": "ex1@example.com",
                "attachIDs": "4",
            },
        ),
        (
            self_deployed_client(),
            {
                "to": ["ex@example.com"],
                "body": "test body",
                "subject": "test subject",
                "inReplyTo": "123",
                "from": "ex1@example.com",
                "attachIDs": "3,4",
            },
        ),
    ]

    @staticmethod
    def expected_upload_headers(world_file=True):
        if world_file:
            for header in [  # testing on the world.jpg file.
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 0-3145727/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 3145728-6291455/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 6291456-9437183/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 9437184-12582911/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 12582912-15728639/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 15728640-18874367/21796912",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "2922544",
                    "Content-Range": "bytes 18874368-21796911/21796912",
                    "Content-Type": "application/octet-stream",
                },
            ]:
                yield header
        else:
            for header in [  # testing on the test.pdf
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 0-3145727/4512758",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "1367030",
                    "Content-Range": "bytes 3145728-4512757/4512758",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "3145728",
                    "Content-Range": "bytes 6291456-9437183/10520433",
                    "Content-Type": "application/octet-stream",
                },
                {
                    "Content-Length": "1083249",
                    "Content-Range": "bytes 9437184-10520432/10520433",
                    "Content-Type": "application/octet-stream",
                },
            ]:
                yield header

    @staticmethod
    def get_attachment_file_details_by_attachment_id(attach_id):
        attachment_info = {
            "1": {
                "path": "test_data/world.jpg",  # bigger than 3mb attachment
                "name": "world.jpg",
            },
            "2": {
                "path": "test_data/plant.jpg",  # smaller than 3mb attachment
                "name": "plant.jpg",
            },
            "3": {
                "path": "test_data/test.pdf",  # bigger than 3mb attachment
                "name": "test.pdf",
            },
            "4": {
                "path": "test_data/sample.pdf",  # smaller than 3mb attachment
                "name": "sample-pdf",
            },
        }
        return attachment_info.get(attach_id)

    @staticmethod
    def upload_response_side_effect(**kwargs):
        headers = kwargs.get("headers")
        if int(headers["Content-Length"]) < MsGraphMailClient.MAX_ATTACHMENT_SIZE:
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
            if upload_query_mock.mock_calls[i].kwargs["headers"] != current_headers:
                return False
        return True

    @pytest.mark.parametrize("client, args", SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
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
        with requests_mock.Mocker() as request_mocker:
            from_email = args.get("from")
            mocked_draft_id = "123"
            mocker.patch.object(client, "get_access_token")
            mocker.patch.object(demisto, "getFilePath", side_effect=self.get_attachment_file_details_by_attachment_id)

            create_draft_mail_mocker = request_mocker.post(
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages", json={"id": mocked_draft_id}
            )
            send_draft_mail_mocker = request_mocker.post(  # mock the endpoint to send a draft mail
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages/{mocked_draft_id}/send"
            )

            send_mail_mocker = request_mocker.post(f"https://graph.microsoft.com/v1.0/users/{from_email}/SendMail")

            create_upload_mock = mocker.patch.object(client, "get_upload_session", return_value={"uploadUrl": "test.com"})
            upload_query_mock = mocker.patch.object(requests, "put", side_effect=self.upload_response_side_effect)

            send_email_command(client, args)

            # attachment 1 is an attachment bigger than 3MB
            if "1" in args.get("attachIDs"):  # means the attachment should be created in the upload session
                assert create_draft_mail_mocker.called
                assert send_draft_mail_mocker.called
                assert not send_mail_mocker.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock)

                if "2" in args.get("attachIDs"):
                    assert create_draft_mail_mocker.last_request.json().get("attachments")

                draft_sent_json = create_draft_mail_mocker.last_request.json()
                assert draft_sent_json
                assert draft_sent_json.get("toRecipients")
                assert draft_sent_json.get("subject")
            else:
                assert not create_draft_mail_mocker.called
                assert not send_draft_mail_mocker.called
                assert send_mail_mocker.called

                message = send_mail_mocker.last_request.json().get("message")
                assert message
                assert message.get("toRecipients")[0].get("emailAddress").get("address") == args.get("to")[0]
                assert message.get("body").get("content") == args.get("htmlBody") or args.get("body")
                assert message.get("subject") == args.get("subject")
                assert message.get("replyTo")[0].get("emailAddress").get("address") == args.get("replyTo")[0]
                assert message.get("replyTo")[1].get("emailAddress").get("address") == args.get("replyTo")[1]
                assert message.get("attachments")

    @pytest.mark.parametrize("client, args", REPLY_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
    def test_reply_mail_command(self, mocker, client, args):
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
        with requests_mock.Mocker() as request_mocker:
            from_email = args.get("from")
            mocked_draft_id = "123"
            reply_message_id = args.get("inReplyTo")
            mocker.patch.object(client, "get_access_token")
            mocker.patch.object(demisto, "getFilePath", side_effect=self.get_attachment_file_details_by_attachment_id)

            create_draft_mail_mocker = request_mocker.post(  # mock the endpoint to create a draft for an existing message
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages/{reply_message_id}/createReply",
                json={"id": mocked_draft_id},
            )
            send_reply_draft_mail_mocker = request_mocker.post(  # mock the endpoint to reply a draft mail
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages/{mocked_draft_id}/send"
            )

            create_upload_mock = mocker.patch.object(client, "get_upload_session", return_value={"uploadUrl": "test.com"})
            upload_query_mock = mocker.patch.object(requests, "put", side_effect=self.upload_response_side_effect)
            reply_mail_mocker = request_mocker.post(
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages/{reply_message_id}/reply"
            )

            command_results = reply_email_command(client, args)

            if "3" in args.get("attachIDs"):
                assert create_draft_mail_mocker.called
                assert send_reply_draft_mail_mocker.called  # sending the draft reply email should be called
                assert not reply_mail_mocker.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock, world_file=False)

                if "4" in args.get("attachIDs"):
                    # make sure when creating draft to send a reply that the attachments are being added to the api
                    # call the create a draft and not through upload session
                    assert create_draft_mail_mocker.last_request.json().get("message").get("attachments")
            else:
                assert reply_mail_mocker.called
                assert not create_draft_mail_mocker.called
                assert not create_upload_mock.called
                assert not send_reply_draft_mail_mocker.called
            assert command_results.outputs == {
                "toRecipients": ["ex@example.com"],
                "subject": "Re: test subject",
                "bodyPreview": "test body",
                "ID": "123",
            }

    @pytest.mark.parametrize("client, args", SEND_MAIL_WITH_LARGE_ATTACHMENTS_COMMAND_ARGS)
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
        from MicrosoftGraphMail import create_draft_command

        with requests_mock.Mocker() as request_mocker:
            from_email = args.get("from")
            mocker.patch.object(client, "get_access_token")
            create_draft_mail_mocker = request_mocker.post(
                f"https://graph.microsoft.com/v1.0/users/{from_email}/messages", json={"id": "123"}
            )
            mocker.patch.object(demisto, "getFilePath", side_effect=self.get_attachment_file_details_by_attachment_id)

            create_upload_mock = mocker.patch.object(client, "get_upload_session", return_value={"uploadUrl": "test.com"})
            upload_query_mock = mocker.patch.object(requests, "put", side_effect=self.upload_response_side_effect)

            command_result = create_draft_command(client, args)

            # attachment 1 is an attachment bigger than 3MB
            if "1" in args.get("attachIDs"):  # means the attachment should be created in the upload session
                assert create_upload_mock.called
                assert upload_query_mock.called
                assert self.validate_upload_attachments_flow(create_upload_mock, upload_query_mock)
                if "2" in args.get("attachIDs"):
                    assert create_draft_mail_mocker.last_request.json()["attachments"]

            else:
                assert not create_upload_mock.called
                assert not upload_query_mock.called
                assert create_draft_mail_mocker.last_request.json()["attachments"]
        assert command_result.outputs["ID"] == "123"
        assert create_draft_mail_mocker.called
        assert create_draft_mail_mocker.last_request.json()


@pytest.mark.parametrize(
    "server_url, expected_endpoint",
    [
        ("https://graph.microsoft.us", "gcc-high"),
        ("https://dod-graph.microsoft.us", "dod"),
        ("https://graph.microsoft.de", "de"),
        ("https://microsoftgraph.chinacloudapi.cn", "cn"),
    ],
)
def test_server_to_endpoint(server_url, expected_endpoint):
    """
    Given:
        - Host address for national endpoints
    When:
        - Creating a new MsGraphMailClient
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
    emails = {
        "value": [
            {"receivedDateTime": "1", "id": "1"},
            {"receivedDateTime": "2", "id": "2"},
            {"receivedDateTime": "4", "id": "3"},
            {"receivedDateTime": "4", "id": "4"},
            {"receivedDateTime": "4", "id": "5"},
        ]
    }
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client, "http_request", return_value=emails)
    fetched_emails, ids = client._fetch_last_emails("", last_fetch="2022-07-28T12:09:17Z", exclude_ids=["1", "2"])
    assert len(fetched_emails) == 2
    assert ids == ["3", "4"]
    assert fetched_emails[0] == emails["value"][2]
    assert fetched_emails[1] == emails["value"][3]


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
    emails = {
        "value": [
            {"receivedDateTime": "1", "id": "1"},
        ]
    }
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client, "http_request", return_value=emails)
    fetched_emails, ids = client._fetch_last_emails("", last_fetch="2022-07-28T12:09:17Z", exclude_ids=[])
    assert len(fetched_emails) == 1
    assert ids == ["1"]
    assert fetched_emails[0] == emails["value"][0]


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
    emails = {
        "value": [
            {"receivedDateTime": "1", "id": "1"},
            {"receivedDateTime": "2", "id": "2"},
        ]
    }
    client = oproxy_client()
    client._emails_fetch_limit = 2
    mocker.patch.object(client, "http_request", return_value=emails)
    fetched_emails, ids = client._fetch_last_emails("", last_fetch="2022-07-28T12:09:17Z", exclude_ids=["1", "2"])
    assert len(fetched_emails) == 0
    assert ids == ["1", "2"]


@pytest.mark.parametrize(
    "args",
    [
        ({"user_id": "test@mail.com", "message_ids": "EMAIL1", "status": "Read"}),
        ({"user_id": "test@mail.com", "message_ids": "EMAIL1", "folder_id": "Inbox", "status": "Read"}),
        ({"user_id": "test@mail.com", "message_ids": "EMAIL1", "status": "Unread"}),
        ({"user_id": "test@mail.com", "message_ids": "EMAIL1", "folder_id": "Inbox", "status": "Unread"}),
    ],
)
def test_update_email_status_command(mocker, args: dict):
    import MicrosoftGraphMail

    client = self_deployed_client()
    mocker.patch.object(client, "http_request")

    result = MicrosoftGraphMail.update_email_status_command(client=client, args=args)

    mark_as_read = args["status"].lower() == "read"
    folder_id = args.get("folder_id")
    folder_path = f"/{GraphMailUtils.build_folders_path(folder_id)}" if folder_id else ""
    url_suffix = f"/users/{args['user_id']}{folder_path}/messages/{args['message_ids']}"

    assert result.outputs is None
    client.http_request.assert_called_with(method="PATCH", url_suffix=url_suffix, json_data={"isRead": mark_as_read})


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """
    import re

    from MicrosoftGraphMail import MANAGED_IDENTITIES_TOKEN_URL, Resources, main

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.graph}.*"), json={})

    params = {"managed_identities_client_id": {"password": client_id}, "use_managed_identities": "True"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert client_id and qs["client_id"] == [client_id] or "client_id" not in qs


@pytest.mark.parametrize(
    "raw_attachment, legacy_name, expected_name, expect_exception",
    [
        (
            {
                "name": "test.png",
                "contentId": "123",
                "isInline": True,
                "contentBytes": base64.b64encode(b"test data").decode("utf-8"),
            },
            False,
            "123-attachmentName-test.png",
            False,
        ),
        (
            {
                "name": "test.png",
                "contentId": None,
                "isInline": False,
                "contentBytes": base64.b64encode(b"test data").decode("utf-8"),
            },
            False,
            "test.png",
            False,
        ),
        (
            {
                "name": "test.png",
                "contentId": "123",
                "isInline": True,
                "contentBytes": base64.b64encode(b"test data").decode("utf-8"),
            },
            True,
            "test.png",
            False,
        ),
        (
            {
                "name": "test.png",
                "contentId": "None",
                "isInline": True,
                "contentBytes": base64.b64encode(b"test data").decode("utf-8"),
            },
            False,
            "test.png",
            False,
        ),
        ({"name": "test.png", "contentId": "123", "isInline": True, "contentBytes": "invalid_base64"}, False, None, True),
    ],
)
def test_file_result_creator(monkeypatch, raw_attachment, legacy_name, expected_name, expect_exception):
    from MicrosoftGraphMailApiModule import GraphMailUtils

    monkeypatch.setattr("MicrosoftGraphMail.fileResult", fileResult)
    monkeypatch.setattr("MicrosoftGraphMail.DemistoException", DemistoException)

    if expect_exception:
        with pytest.raises(DemistoException):
            GraphMailUtils.file_result_creator(raw_attachment, legacy_name)
    else:
        result = GraphMailUtils.file_result_creator(raw_attachment, legacy_name)
        assert result["File"] == expected_name
