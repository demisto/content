from CommonServerPython import *
import pytest
import demistomock as demisto
import json
from MicrosoftGraphMailApiModule import MsGraphMailBaseClient

TENANT_ID = "dummy_tenant"
CLIENT_ID = "dummy_client_id"
CLIENT_SECRET = "dummy_secret"
REDIRECT_URI = "redirect_uri"

REFRESH_TOKEN = "dummy_refresh_token"
AUTH_ID = "dummy_auth_id"
ENC_KEY = "dummy_enc_key"
TOKEN_RETRIEVAL_URL = "url_to_retrieval"
APP_NAME = "ms-graph-mail-listener"
MAILBOX_TO_FETCH = "dummy@mailbox.com"  # disable-secrets-detection
FOLDER_TO_FETCH = "Phishing"
FIRST_FETCH_INTERVAL = "20 minutes"
EMAILS_FETCH_LIMIT = 50
BASE_URL = "https://graph.microsoft.com/v1.0/"
OK_CODES = (200, 201, 202)
AUTH_CODE = "auth_code"


def oproxy_client():
    auth_id = AUTH_ID
    enc_key = ENC_KEY
    token_retrieval_url = TOKEN_RETRIEVAL_URL
    auth_and_token_url = f'{auth_id}@{token_retrieval_url}'
    app_name = APP_NAME
    mailbox_to_fetch = MAILBOX_TO_FETCH
    folder_to_fetch = FOLDER_TO_FETCH
    first_fetch_interval = FIRST_FETCH_INTERVAL
    emails_fetch_limit = EMAILS_FETCH_LIMIT
    base_url = BASE_URL
    ok_codes = OK_CODES
    tenant_id = TENANT_ID

    return MsGraphMailBaseClient(mailbox_to_fetch=mailbox_to_fetch, folder_to_fetch=folder_to_fetch,
                                 first_fetch_interval=first_fetch_interval, emails_fetch_limit=emails_fetch_limit,
                                 self_deployed=False, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                 enc_key=enc_key, app_name=app_name, base_url=base_url, verify=True,
                                 proxy=False, ok_codes=ok_codes
                                 )


def self_deployed_client():
    tenant_id = TENANT_ID
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    mailbox_to_fetch = MAILBOX_TO_FETCH
    folder_to_fetch = FOLDER_TO_FETCH
    first_fetch_interval = FIRST_FETCH_INTERVAL
    emails_fetch_limit = EMAILS_FETCH_LIMIT
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MsGraphMailBaseClient(mailbox_to_fetch=mailbox_to_fetch, folder_to_fetch=folder_to_fetch,
                                 first_fetch_interval=first_fetch_interval, emails_fetch_limit=emails_fetch_limit,
                                 self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
                                 base_url=base_url, app_name='', verify=True, proxy=False, ok_codes=ok_codes
                                 )


def expected_incident():
    with open('test_data/expected_incident') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_html():
    return emails_data_as_html_including_body()


def emails_data_as_html_including_body():
    with open('test_data/emails_data_html') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


@pytest.fixture()
def emails_data_as_text():
    return emails_data_as_text_including_body()


def emails_data_as_text_including_body():
    with open('test_data/emails_data_text') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_html_without_body():
    with open('test_data/emails_data_html_without_body') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_as_text_without_body():
    with open('test_data/emails_data_text_without_body') as emails_json:
        mocked_emails = json.load(emails_json)
        return mocked_emails


def emails_data_full_body_as_html():
    with open('test_data/emails_data_full_body_html') as emails_json:
        return json.load(emails_json)


def emails_data_full_body_as_text():
    with open('test_data/emails_data_full_body_text') as emails_json:
        return json.load(emails_json)


def expected_incident_full_body():
    with open('test_data/expected_incident_full_body') as incident:
        return json.load(incident)


def expected_email_with_body():
    with open('test_data/expected_email_with_body') as email:
        return json.load(email)


def expected_email_without_body():
    with open('test_data/expected_email_without_body') as email:
        return json.load(email)


def expected_email_full_body():
    with open('test_data/expected_email_full_body') as email:
        return json.load(email)


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
    'client, email_content_html, email_content_text, expected_email', [
        (
            oproxy_client(),
            emails_data_as_html_including_body(),
            emails_data_as_text_including_body(),
            expected_email_with_body()
        ),
        (
            self_deployed_client(),
            emails_data_as_html_without_body(),
            emails_data_as_text_without_body(),
            expected_email_without_body()
        )
    ]
)
def test__fetch_last_emails(client, email_content_html, email_content_text, expected_email, mocker, last_run_data):
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
    new_emails, exclude_ids = client._fetch_last_emails(last_run_data["LAST_RUN_FOLDER_ID"],
                                                        last_run_data["LAST_RUN_TIME"],
                                                        last_run_data["LAST_RUN_IDS"]
                                                        )

    assert exclude_ids[0] == expected_email['id']
    assert new_emails[0] == expected_email


@pytest.mark.parametrize(
    'client, email_content_html, email_content_text, expected_email', [
        (
            self_deployed_client(),
            emails_data_full_body_as_html(),
            emails_data_full_body_as_text(),
            expected_email_full_body()
        )
    ]
)
def test__fetch_last_emails_with_full_body(
    mocker, client, email_content_html,
    email_content_text, expected_email, last_run_data
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
        client, 'http_request', side_effect=[email_content_html, email_content_text, {}]
    )
    mocker.patch.object(demisto, "info")
    new_emails, exclude_ids = client._fetch_last_emails(last_run_data["LAST_RUN_FOLDER_ID"],
                                                        last_run_data["LAST_RUN_TIME"],
                                                        last_run_data["LAST_RUN_IDS"]
                                                        )

    assert exclude_ids[0] == expected_email['id']
    assert new_emails[0] == expected_email


@pytest.mark.parametrize(
    'client, email, parsed_incident', [
        (
            self_deployed_client(),
            expected_email_with_body(),
            expected_incident()
        )
    ]
)
def test__parse_email_as_incident(client, email, mocker, parsed_incident):
    mocker.patch.object(client, 'http_request', return_value={})
    incident = client._parse_email_as_incident(email)

    parsed_incident.pop("rawJSON", None)
    incident.pop("rawJSON", None)
    assert incident == parsed_incident
