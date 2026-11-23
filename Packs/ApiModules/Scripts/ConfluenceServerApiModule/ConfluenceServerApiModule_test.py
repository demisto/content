import base64

import CommonServerPython
import ConfluenceServerApiModule
import demistomock as demisto
import pytest
from CommonServerPython import entryTypes
from pytest_mock import MockerFixture

LEGACY_PARAMS = {"url": "https://confluence.acme.com/", "credentials": {"identifier": "identifier", "password": "password"}}
PAT_PARAMS = {"url": "https://confluence.acme.com", "personal_access_token": {"password": "legacy-pat"}}
UCP_PARAMS = {"url": "https://confluence.acme.com", "credentials": None, "personal_access_token": None, "unsecure": True}
UCP_CREDENTIALS = {
    "plain": {"type": "plain", "plain": {"username": "ucp-user", "password": "ucp-pass"}},
    "api_key": {"type": "api_key", "api_key": {"key": "ucp-pat"}},
}


@pytest.fixture(autouse=True)
def legacy_globals():
    """
    Initialise the module globals from username / password parameters, as the
    integration entry point does before running a command.
    """
    ConfluenceServerApiModule.init_globals(LEGACY_PARAMS)


@pytest.fixture
def ucp_profile(monkeypatch):
    """
    Run as if the Atlassian Standard Connector selected a typed connection
    profile; the real CommonServerPython UCP code path is exercised, only the
    platform calls are faked.
    """

    def configure(profile_type: str) -> list:
        fetched: list = []
        profile = {"method_unique_id": "m1", "type": profile_type, "capability": "automation-and-remediation"}

        def get_ucp_credentials(method_unique_id=None, from_cache=True, body=None):
            fetched.append(method_unique_id)
            return UCP_CREDENTIALS[profile_type]

        monkeypatch.setattr(CommonServerPython, "_ucp_creds_cache", {})
        monkeypatch.setattr(demisto, "unifiedConnectorMetadata", lambda: {"connectionProfiles": [profile]})
        monkeypatch.setattr(demisto, "getUCPCredentials", get_ucp_credentials)
        return fetched

    return configure


def test_create_space_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_space_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"description": "description", "key": "key", "name": "name"})

    mocker.patch.object(ConfluenceServerApiModule, "http_request", return_value={"id": "id", "key": "key", "name": "name"})

    ConfluenceServerApiModule.create_space_command()

    assert "Space created successfully" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_create_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"type": "type", "title": "title", "space": "space", "body": "body"})

    mocker.patch.object(
        ConfluenceServerApiModule, "http_request", return_value={"id": "id", "title": "title", "space": "space", "body": "body"}
    )

    ConfluenceServerApiModule.create_content_command()

    assert "New Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_get_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"key": "key", "title": "title"})

    mocker.patch.object(
        ConfluenceServerApiModule,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "title": "title",
                    "type": "type",
                    "version": {"number": "number"},
                    "body": {"view": {"value": "value"}},
                }
            ]
        },
    )

    ConfluenceServerApiModule.get_content_command()

    assert "Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_list_spaces_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_host_status_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"status": "status", "type": "type"})

    mocker.patch.object(
        ConfluenceServerApiModule,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "key": "key",
                    "name": "name",
                }
            ]
        },
    )

    ConfluenceServerApiModule.list_spaces_command()

    assert "Spaces" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_delete_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a delete_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"id": "id"})

    mocker.patch.object(
        ConfluenceServerApiModule, "http_request", return_value={"Results": "Successfully Deleted Content ID id", "ID": "id"}
    )

    ConfluenceServerApiModule.delete_content_command()

    assert "Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_update_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a pdate_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "pageid": "pageid",
            "title": "title",
            "space": "space",
            "body": "body",
            "type": "type",
            "currentversion": "1",
        },
    )

    mocker.patch.object(
        ConfluenceServerApiModule,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "key": "key",
                    "name": "name",
                }
            ]
        },
    )

    ConfluenceServerApiModule.update_content_command()

    assert "Updated Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_search_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a search_content_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={"cql": "cql", "cqlcontext": "cqlcontext", "expand": "expand", "start": "start", "limit": "limit"},
    )

    mocker.patch.object(
        ConfluenceServerApiModule,
        "http_request",
        return_value={"results": [{"id": "id", "title": "title", "type": "type", "version": {"number": "number"}}]},
    )

    ConfluenceServerApiModule.search_content_command()

    assert "Content Search" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_get_page_as_pdf_command_success(mocker: MockerFixture, monkeypatch, tmp_path):
    """
    Given: A page ID is provided to download the page as PDF.
    When: The get_page_as_pdf_command function is called.
    Then: The function should return the PDF file as a file result with the correct filename.
    """
    # fileResult writes the file to the working directory: keep it out of the repo.
    monkeypatch.chdir(tmp_path)
    # Mock arguments
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"pageid": "12345"})

    # Mock the get_pdf function to return sample PDF data
    mock_pdf_data = b"sample pdf data"
    mocker.patch("ConfluenceServerApiModule.get_pdf", return_value=mock_pdf_data)

    # Mock the demisto.results function
    results_mock = mocker.patch.object(demisto, "results")

    # Call the function
    ConfluenceServerApiModule.get_page_as_pdf_command()

    # Assert the expected file result was returned
    results_mock.assert_called_once()
    file_result = results_mock.call_args[0][0]
    assert file_result["Type"] == entryTypes["file"]
    assert file_result["File"] == "Confluence_page_12345.pdf"
    assert file_result["FileID"] is not None


def test_get_pdf_success(mocker):
    """
    Given: A valid page_id is provided to the get_pdf function.
    When: The function calls http_request to fetch the PDF content.
    Then: The function should return the response content.
    """
    # Mock the http_request function
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mock_response = b"mock pdf content"
    mock_http_request = mocker.patch("ConfluenceServerApiModule.http_request", return_value=mock_response)

    # Call the function
    page_id = "12345"
    result = ConfluenceServerApiModule.get_pdf(page_id)

    # Assert the result and that http_request was called with the correct parameters
    assert result == mock_response
    mock_http_request.assert_called_once_with(
        "GET",
        ConfluenceServerApiModule.SERVER + "/spaces/flyingpdf/pdfpageexport.action",
        None,
        params={"pageId": page_id},
        resp_type="content",
    )


class TestInitGlobals:
    def test_username_password_sets_globals_without_authorization_header(self):
        assert ConfluenceServerApiModule.SERVER == "https://confluence.acme.com"
        assert ConfluenceServerApiModule.BASE_URL == "https://confluence.acme.com/rest/api"
        assert ConfluenceServerApiModule.VERIFY_CERTIFICATE is True
        assert (ConfluenceServerApiModule.USERNAME, ConfluenceServerApiModule.PASSWORD) == ("identifier", "password")
        assert "Authorization" not in ConfluenceServerApiModule.HEADERS

    def test_personal_access_token_sets_bearer_header(self):
        ConfluenceServerApiModule.init_globals(PAT_PARAMS)

        assert ConfluenceServerApiModule.HEADERS["Authorization"] == "Bearer legacy-pat"

    def test_missing_credentials_returns_error(self, monkeypatch):
        errors: list = []
        monkeypatch.setattr(ConfluenceServerApiModule, "return_error", errors.append)

        ConfluenceServerApiModule.init_globals({"url": "https://confluence.acme.com"})

        assert errors == [ConfluenceServerApiModule.MISSING_CREDENTIALS_MESSAGE]

    def test_ucp_skips_credential_check_and_legacy_header(self, ucp_profile, monkeypatch):
        ucp_profile("api_key")
        errors: list = []
        monkeypatch.setattr(ConfluenceServerApiModule, "return_error", errors.append)

        ConfluenceServerApiModule.init_globals(UCP_PARAMS | {"personal_access_token": {"password": "legacy-pat"}})

        assert errors == []
        assert "Authorization" not in ConfluenceServerApiModule.HEADERS
        assert ConfluenceServerApiModule.VERIFY_CERTIFICATE is False


class TestGetRequestAuth:
    def test_legacy_username_password_returns_basic_tuple(self):
        headers, auth = ConfluenceServerApiModule.get_request_auth()

        assert auth == ("identifier", "password")
        assert "Authorization" not in headers

    def test_legacy_personal_access_token_returns_no_basic_tuple(self):
        ConfluenceServerApiModule.init_globals(PAT_PARAMS)

        headers, auth = ConfluenceServerApiModule.get_request_auth()

        assert auth is None
        assert headers["Authorization"] == "Bearer legacy-pat"

    def test_ucp_plain_returns_ucp_basic_tuple(self, ucp_profile):
        ucp_profile("plain")
        ConfluenceServerApiModule.init_globals(UCP_PARAMS)

        headers, auth = ConfluenceServerApiModule.get_request_auth()

        assert auth == ("ucp-user", "ucp-pass")
        assert "Authorization" not in headers
        assert headers["X-Atlassian-Token"] == "no-check"

    def test_ucp_api_key_returns_bearer_header(self, ucp_profile):
        ucp_profile("api_key")
        ConfluenceServerApiModule.init_globals(UCP_PARAMS)

        headers, auth = ConfluenceServerApiModule.get_request_auth()

        assert auth is None
        assert headers["Authorization"] == "Bearer ucp-pat"
        assert "Authorization" not in ConfluenceServerApiModule.HEADERS


class TestHttpRequest:
    URL = "https://confluence.acme.com/rest/api/user/current"

    def test_ucp_plain_sends_basic_auth(self, ucp_profile, requests_mock):
        ucp_profile("plain")
        ConfluenceServerApiModule.init_globals(UCP_PARAMS)
        requests_mock.get(self.URL, json={"username": "ucp-user"})

        result = ConfluenceServerApiModule.http_request("GET", self.URL)

        assert result == {"username": "ucp-user"}
        expected = "Basic " + base64.b64encode(b"ucp-user:ucp-pass").decode()
        assert requests_mock.last_request.headers["Authorization"] == expected

    def test_ucp_api_key_sends_bearer(self, ucp_profile, requests_mock):
        ucp_profile("api_key")
        ConfluenceServerApiModule.init_globals(UCP_PARAMS)
        requests_mock.get(self.URL, json={})

        ConfluenceServerApiModule.http_request("GET", self.URL)

        assert requests_mock.last_request.headers["Authorization"] == "Bearer ucp-pat"

    def test_ucp_401_invalidates_cached_credentials(self, ucp_profile, requests_mock):
        fetched = ucp_profile("api_key")
        ConfluenceServerApiModule.init_globals(UCP_PARAMS)
        requests_mock.get(self.URL, status_code=401, text="unauthorized")

        res = ConfluenceServerApiModule.http_request("GET", self.URL, is_test=True)
        ConfluenceServerApiModule.http_request("GET", self.URL, is_test=True)

        assert res.status_code == 401
        assert fetched == ["m1", "m1"]

    def test_legacy_sends_basic_auth_from_params(self, requests_mock):
        requests_mock.get(self.URL, json={})

        ConfluenceServerApiModule.http_request("GET", self.URL)

        expected = "Basic " + base64.b64encode(b"identifier:password").decode()
        assert requests_mock.last_request.headers["Authorization"] == expected
