import pytest
from CommonServerPython import *
from freezegun import freeze_time
from requests import Response
from test_data import input_data
from VersaDirector import Client, AsyncClient
from unittest.mock import AsyncMock
from aiohttp import ClientResponseError, RequestInfo
from datetime import UTC

SERVER_URL = "some_mock_url"
PROXY = False
VERIFY = False
USERNAME = "username"
PASSWORD = "password"


@pytest.fixture
def client():
    return Client(
        server_url=SERVER_URL,
        proxy=PROXY,
        headers={},
        auth=(USERNAME, PASSWORD),
        verify=VERIFY,
        organization_params="",
    )


@pytest.fixture()
def async_client():
    return AsyncClient(server_url="some_mock_url", headers={}, verify=False, proxy=False)


def mock_async_session_response(
    response_json: dict | None = None,
    error_status_code: int | None = None,
    error_message: str = "Server error",
) -> AsyncMock | ClientResponseError:
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(return_value=response_json)
    if error_status_code:
        return ClientResponseError(
            status=error_status_code,
            history=(),
            request_info=RequestInfo("", "GET", {}, real_url=""),
            message=error_message,
        )
    else:
        mock_response.raise_for_status = AsyncMock()
        mock_response.status_code = 200
    return AsyncMock(__aenter__=AsyncMock(return_value=mock_response))


# HEADING: """ COMMAND FUNCTIONS TESTS """


def test_auth_start_command(mocker):
    """
    Given:
        - token_name argument is passed as argument

    When:
        - vd-auth-start command is executed

    Then:
        - Create Auth Client
        - Create Auth Token
        - Return message to user
    """
    from VersaDirector import auth_start_command

    mocker.patch("VersaDirector.request_access_token", return_value={"access_token": "access_token_mock"})
    mocker.patch(
        "VersaDirector.request_auth_credentials",
        return_value={"client_id": "client_id_mock", "client_secret": "client_secret_mock"},
    )

    command_result = auth_start_command(
        server_url=SERVER_URL,
        verify=VERIFY,
        proxy=PROXY,
        username=USERNAME,
        password=PASSWORD,
        use_basic_auth=True,
        client_id_param=None,
        client_secret_param=None,
        args={"auth_client_name": "token_name_mock"},
    )
    assert command_result.readable_output == (
        "Auth Client Created Successfully.\nClient ID: client_id_mock, Auth Client Name: token_name_mock.\n\n"
        + "Authentication request was successful, Auth Token was created and saved in the Integration Context.\n"
        + "Please uncheck the 'Use Basic Authentication' checkbox in the configuration screen.\n"
        + "To ensure the authentication is valid, run the 'vd-auth-test' command."
    )


def test_auth_start_command_basic_credentials_fail():
    """
    Given:
        - client._auth is invalid

    When:
        - vd-auth-start command is executed

    Then:
        - Raise DemistoException with valid message
    """
    from VersaDirector import BASIC_CREDENTIALS_COULD_NOT_START, auth_start_command

    with pytest.raises(DemistoException) as e:
        auth_start_command(
            server_url=SERVER_URL,
            verify=VERIFY,
            proxy=PROXY,
            username="",
            password="",
            use_basic_auth=False,
            client_id_param=None,
            client_secret_param=None,
            args={},
        )
    assert str(e.value.message) == BASIC_CREDENTIALS_COULD_NOT_START


@pytest.mark.parametrize(
    "status_code, args, expected_output",
    input_data.test_handle_auth_token_fail_args,
)
def test_auth_start_fail(mocker, client, args, status_code, expected_output):
    """
    Given:
        - An exception is thrown from one of the HTTP requests

    When:
        - vd-auth-start command is executed

    Then:
        - Raise DemistoException with valid message
    """
    from VersaDirector import auth_start_command

    status_code_response = Response()
    status_code_response.status_code = status_code

    mocker.patch(
        "VersaDirector.request_access_token",
        return_value={},
        side_effect=DemistoException(message="", res=status_code_response),
    )

    with pytest.raises(DemistoException) as e:
        auth_start_command(
            server_url=SERVER_URL,
            verify=VERIFY,
            proxy=PROXY,
            username=USERNAME,
            password=PASSWORD,
            use_basic_auth=True,
            client_id_param=None,
            client_secret_param=None,
            args=args,
        )
    assert str(e.value.message) == expected_output


def test_appliance_list_command(mocker, client):
    """
    Given:
        - No arguments are passed

    When:
        - vd-appliance-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliance_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"page_size": 0}
    appliance_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="vnms/cloud/systems/getAllAppliancesBasicDetails",
        params={"offset": 0, "limit": 25},
        headers={},
    )


def test_organization_list_command(mocker, client):
    """
    Given:
        - No arguments are passed

    When:
        - vd-organization-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import organization_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"page_size": 0}
    organization_list_command(client, args)
    http_request.assert_called_with("GET", url_suffix="nextgen/organization", params={"offset": 0}, headers={})


def test_appliances_list_by_organization_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-organization-appliance-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliances_list_by_organization_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name"}
    appliances_list_by_organization_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="vnms/appliance/filter/org_name",
        params={"limit": 50, "offset": 0},
        headers={},
    )


def test_appliances_group_list_by_organization_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-appliance-group-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliances_group_list_by_organization_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name"}
    appliances_group_list_by_organization_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="nextgen/deviceGroup",
        params={"organization_name": "org_name"},
        headers={},
    )


def test_appliances_list_by_device_group_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-appliance-group-template-appliance-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliances_list_by_device_group_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"device_group": "device_group", "template_name": "template_name"}
    appliances_list_by_device_group_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="nextgen/deviceGroup/device_group/template/template_name",
        params={},
        headers={},
    )


def test_template_list_by_organization_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-template-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_list_by_organization_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name", "page_size": 0}
    template_list_by_organization_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="vnms/template/metadata",
        params={"organization": "org_name", "type": "MAIN", "offset": 0},
        headers={},
    )


def test_template_list_by_datastore_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-datastore-template-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_list_by_datastore_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name"}
    template_list_by_datastore_command(client, args)
    http_request.assert_called_with(
        "GET", url_suffix="api/config/devices/template/org_name-DataStore/config/orgs/org", params={}, headers={}
    )


def test_application_service_template_list_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-application-service-template-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import application_service_template_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name", "page_size": 0}
    application_service_template_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="/nextgen/applicationServiceTemplate",
        params={"organization": "org_name", "offset": 0},
        headers={},
    )


def test_template_custom_url_category_list_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization Name)

    When:
        - vd-datastore-template-list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_custom_url_category_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"template_name": "temp_name", "organization": "org_name", "page_size": 0}
    template_custom_url_category_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="/api/config/devices/template/temp_name/config/orgs/org-services"
        + "/org_name/url-filtering/user-defined-url-categories/url-category",
        params={"offset": 0},
        headers={},
    )


def test_template_custom_url_category_create_command(mocker, client):
    """
    Given:
        - Required arguments passed

    When:
        - vd-template-custom-url-category-create command is executed

    Then:
        - The http request is called with the right default arguments
    """

    from VersaDirector import template_custom_url_category_create_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"template_name": "temp_name", "organization": "org_name"}
    template_custom_url_category_create_command(client, args)
    http_request.assert_called_with(
        "POST",
        url_suffix="api/config/devices/template/temp_name/config/orgs/org-services"
        + "/org_name/url-filtering/user-defined-url-categories",
        headers={},
        json_data={
            "url-category": {
                "category-name": "",
                "category-description": "",
                "confidence": "",
                "urls": {
                    "strings": [],
                    "patterns": [],
                },
            }
        },
        ok_codes=(200, 201),
        resp_type="response",
    )


def test_template_custom_url_category_edit_command(mocker, client):
    """
    Given:
        - Required arguments passed

    When:
        - vd-template-custom-url-category-edit command is executed

    Then:
        - The http request is called with the right default arguments
    """

    from VersaDirector import template_custom_url_category_edit_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "template_name": "temp_name",
        "url_category_name": "url_category_name",
    }
    template_custom_url_category_edit_command(client, args)
    http_request.assert_called_with(
        "PUT",
        url_suffix="/api/config/devices/template/temp_name/config/orgs/org-services/org_name/url-filtering/"
        + "user-defined-url-categories/url-category/url_category_name",
        headers={},
        json_data={
            "url-category": {
                "category-name": "url_category_name",
                "category-description": "",
                "confidence": "",
                "urls": {
                    "strings": [],
                    "patterns": [],
                },
            }
        },
        ok_codes=(200, 201, 204),
        return_empty_response=True,
    )


def test_template_custom_url_category_delete_command(mocker, client):
    """
    Given:
        - Required valid arguments passed

    When:
        - vd-template-custom-url-category-delete command is executed

    Then:
        - The http request is called with the right default arguments
    """

    from VersaDirector import template_custom_url_category_delete_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "template_name": "temp_name",
        "organization": "org_name",
        "url_category_name": "url_category_name",
    }
    template_custom_url_category_delete_command(client, args)
    http_request.assert_called_with(
        "DELETE",
        url_suffix="api/config/devices/template/temp_name/config/orgs/org-services/org_name/url-filtering/"
        + "user-defined-url-categories/url-category/url_category_name",
        headers={},
        ok_codes=(200, 201, 204),
        return_empty_response=True,
    )


def test_template_access_policy_list_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization, template_name)

    When:
        - template_access_policy_list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_access_policy_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {"organization": "org_name", "template_name": "template_name"}
    template_access_policy_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services"
        + "/org_name/security/access-policies/access-policy-group",
        params={},
        headers={},
    )


def test_template_access_policy_rule_list_command(mocker, client):
    """
    Given:
        - Minimum arguments passed (organization, access_policy_name, template_name)

    When:
        - template_access_policy_rule_list command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_access_policy_rule_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "access_policy_name": "access_policy_name",
        "page_size": 0,
    }
    template_access_policy_rule_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/org_name/security/access-policies"
        + "/access-policy-group/access_policy_name/rules/access-policy",
        params={"offset": 0},
        headers={},
    )


def test_template_access_policy_rule_create_command(mocker, client):
    """
    Given:
        - Required arguments passed

    When:
        - vd-template-access-policy-rule-create command is executed

    Then:
        - The http request is called with the right arguments
    """

    from VersaDirector import template_access_policy_rule_create_command

    args = {
        "organization": "org_name",
        "access_policy_name": "Default-Policy",
        "rule_name": "test1",
        "template_name": "test_template",
    }
    mocker.patch.object(client, "_http_request", return_value={})
    command_results = template_access_policy_rule_create_command(client, args)
    assert command_results.readable_output == input_data.template_access_policy_rule_command_custom_rule_readable_output


def test_template_access_policy_rule_edit_command(mocker, client):
    """
    Given:
        - Required arguments passed

    When:
        - vd-template-access-policy-rule-edit command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_access_policy_rule_edit_command

    args = {
        "organization": "org_name",
        "access_policy_name": "Default-Policy",
        "rule_name": "test1",
        "template_name": "test_template",
    }
    mocker.patch.object(client, "_http_request", return_value={})
    command_results = template_access_policy_rule_edit_command(client, args)
    assert command_results.readable_output == input_data.template_access_policy_rule_command_custom_rule_readable_output


def test_template_access_policy_rule_delete_command(mocker, client):
    """
    Given:
        - Required arguments passed

    When:
        - vd-template-access-policy-rule-delete command is executed

    Then:
        - The http request is called with the right arguments
    """

    from VersaDirector import template_access_policy_rule_delete_command

    args = {
        "organization": "org_name",
        "access_policy_name": "Default-Policy",
        "rule_name": "test1",
        "template_name": "test_template",
    }
    mocker.patch.object(client, "template_access_policy_rule_delete_request", return_value={})
    command_results = template_access_policy_rule_delete_command(client, args)
    assert command_results.readable_output == "Command run successfully."


@pytest.mark.parametrize("url_category_name, suffix", [("url_category_name", "/url_category_name"), ("", "")])
def test_appliance_custom_url_category_list_command(mocker, client, url_category_name, suffix):
    """
    Given:
        - Arguments passed: organization, appliance_name, appliance_name (optional)

    When:
        - appliance_custom_url_category_list_command command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliance_custom_url_category_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "url_category_name": url_category_name,
    }

    appliance_custom_url_category_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services"
        + "/org_name/url-filtering/user-defined-url-categories/url-category"
        + suffix,
        params={},
        headers={},
    )


def test_appliance_custom_url_category_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, url_category_name, description, confidence

    When:
        - appliance_custom_url_category_create_command command is executed

    Then:
        - The http request is called with a valid request body
    """
    from VersaDirector import appliance_custom_url_category_create_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "url_category_name": "test",
        "description": "description",
        "confidence": 100,
    }
    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_custom_url_category_create_command(client, args)
    assert command_results.readable_output == input_data.appliance_custom_url_category_command_readable_output


def test_appliance_custom_url_category_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, url_category_name, description, confidence

    When:
        - appliance_custom_url_category_edit_command command is executed

    Then:
        - The http request is called with a valid request body
    """
    from VersaDirector import appliance_custom_url_category_edit_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "url_category_name": "test",
        "description": "description",
        "confidence": 100,
    }
    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_custom_url_category_edit_command(client, args)
    assert command_results.readable_output == input_data.appliance_custom_url_category_command_readable_output


def test_appliance_custom_url_category_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, url_category_name

    When:
        - appliance_custom_url_category_delete_command command is executed

    Then:
        - The http request is called with a valid request body
    """
    from VersaDirector import appliance_custom_url_category_delete_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "url_category_name": "test",
    }
    mocker.patch.object(client, "appliance_custom_url_category_delete_request", return_value={})
    command_results = appliance_custom_url_category_delete_command(client, args)
    assert command_results.readable_output == "Command run successfully."


def test_appliance_access_policy_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name

    When:
        - appliance_access_policy_list_command command is executed

    Then:
        - The http request is called with the right default arguments
    """

    from VersaDirector import appliance_access_policy_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
    }

    appliance_access_policy_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services"
        + "/org_name/security/access-policies/access-policy-group",
        params={},
        headers={},
        ok_codes=(200, 201),
    )


def test_appliance_access_policy_rule_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, access_policy_name

    When:
        - appliance_access_policy_rule_list_command command is executed

    Then:
        - The http request is called with the right default arguments
    """

    from VersaDirector import appliance_access_policy_rule_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "access_policy_name": "access_policy_name",
    }

    appliance_access_policy_rule_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/org_name/security/access-policies"
        + "/access-policy-group/access_policy_name/rules/access-policy",
        params={},
        headers={},
    )


def test_appliance_access_policy_rule_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, access_policy_name, rule_name

    When:
        - vd-appliance-access-policy-rule-create command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliance_access_policy_rule_create_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "access_policy_name": "access_policy_name",
        "rule_name": "test_rule",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_access_policy_rule_create_command(client, args)
    assert command_results.readable_output == input_data.appliance_access_policy_rule_command_readable_output


def test_appliance_access_policy_rule_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, access_policy_name, rule_name

    When:
        - vd-appliance-access-policy-edit command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliance_access_policy_rule_edit_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "access_policy_name": "access_policy_name",
        "rule_name": "test_rule",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_access_policy_rule_edit_command(client, args)
    assert command_results.readable_output == input_data.appliance_access_policy_rule_command_readable_output


def test_appliance_access_policy_rule_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, access_policy_name, rule_name

    When:
        - vd-appliance-access-policy-edit-delete command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import appliance_access_policy_rule_delete_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "access_policy_name": "access_policy_name",
        "rule_name": "rule_name",
    }
    mocker.patch.object(client, "appliance_access_policy_rule_delete_request", return_value={})
    command_results = appliance_access_policy_rule_delete_command(client, args)
    assert command_results.readable_output == "Command run successfully."


def test_template_sdwan_policy_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name

    When:
        - vd-template-sdwan-policy-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_sdwan_policy_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "template_name": "template_name",
    }

    template_sdwan_policy_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/"
        + "org-services/org_name/sd-wan/policies/sdwan-policy-group",
        params={},
        headers={},
    )


def test_template_sdwan_policy_rule_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name

    When:
        - vd-template-sdwan-policy-rule-list command is executed

    Then:
        - The http request is called with the right arguments
    """

    from VersaDirector import template_sdwan_policy_rule_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "organization",
        "template_name": "template_name",
        "sdwan_policy_name": "sdwan_policy_name",
    }

    template_sdwan_policy_rule_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/"
        + "organization/sd-wan/policies/sdwan-policy-group/sdwan_policy_name/rules/rule",
        params={},
        headers={},
    )


def test_template_sdwan_policy_rule_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name, rule_name

    When:
        - vd-template-sdwan-policy-rule-create command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_sdwan_policy_rule_create_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = template_sdwan_policy_rule_create_command(client, args)
    assert command_results.readable_output == input_data.template_sdwan_policy_rule_command_readable_output


def test_template_sdwan_policy_rule_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name, rule_name

    When:
        - vd-template-sdwan-policy-rule-edit command is executed

    Then:
        - The http request is called with the right default arguments
    """
    from VersaDirector import template_sdwan_policy_rule_edit_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = template_sdwan_policy_rule_edit_command(client, args)
    assert command_results.readable_output == input_data.template_sdwan_policy_rule_command_readable_output


def test_template_sdwan_policy_rule_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name, rule_name

    When:
        - vd-template-sdwan-policy-rule-delete command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_sdwan_policy_rule_delete_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    http_request = mocker.patch.object(client, "_http_request")
    template_sdwan_policy_rule_delete_command(client, args)
    http_request.assert_called_with(
        "DELETE",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/org_name/sd-wan/policies"
        + "/sdwan-policy-group/sdwan_policy_name/rules/rule/rule_name",
        ok_codes=(200, 201, 204),
        headers={},
        return_empty_response=True,
    )


def test_appliance_sdwan_policy_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name

    When:
        - vd-appliance-sdwan-policy-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_sdwan_policy_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "organization",
        "appliance_name": "appliance_name",
    }

    appliance_sdwan_policy_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services"
        + "/organization/sd-wan/policies/sdwan-policy-group",
        params={},
        headers={},
    )


def test_appliance_sdwan_policy_rule_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, sdwan_policy_name

    When:
        - vd-appliance-sdwan-policy-rule-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_sdwan_policy_rule_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "organization",
        "appliance_name": "appliance_name",
        "sdwan_policy_name": "sdwan_policy_name",
    }

    appliance_sdwan_policy_rule_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/"
        + "organization/sd-wan/policies/sdwan-policy-group/sdwan_policy_name/rules/rule",
        params={},
        headers={},
    )


def test_appliance_sdwan_policy_rule_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name, rule_name

    When:
        - vd-appliance-sdwan-policy-rule-create command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_sdwan_policy_rule_create_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_sdwan_policy_rule_create_command(client, args)
    assert command_results.readable_output == input_data.template_sdwan_policy_rule_command_readable_output


def test_appliance_sdwan_policy_rule_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, sdwan_policy_name, rule_name

    When:
        - vd-appliance-sdwan-policy-rule-edit command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_sdwan_policy_rule_edit_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    mocker.patch.object(client, "_http_request", return_value={})
    command_results = appliance_sdwan_policy_rule_edit_command(client, args)
    assert command_results.readable_output == input_data.template_sdwan_policy_rule_command_readable_output


def test_appliance_sdwan_policy_rule_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, sdwan_policy_name, rule_name

    When:
        - vd-appliance-sdwan-policy-rule-delete command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_sdwan_policy_rule_delete_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "sdwan_policy_name": "sdwan_policy_name",
        "rule_name": "rule_name",
    }

    http_request = mocker.patch.object(client, "_http_request")
    appliance_sdwan_policy_rule_delete_command(client, args)
    http_request.assert_called_with(
        "DELETE",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/"
        + "org_name/sd-wan/policies/sdwan-policy-group/sdwan_policy_name/rules/rule/rule_name",
        resp_type="response",
        ok_codes=(200, 204),
        headers={},
        return_empty_response=True,
    )


def test_template_address_object_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name

    When:
        - vd-template-address-object-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_address_object_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "organization",
        "template_name": "template_name",
    }

    template_address_object_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/organization/objects/addresses/address",
        params={},
        headers={},
    )


def test_template_address_object_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, object_name, address_object_type, object_value

    When:
        - vd-template-address-object-create command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_address_object_create_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "object_name": "object_name",
        "address_object_type": "address_object_type",
        "object_value": "object_value",
    }

    data = {
        "address": {
            "name": "object_name",
            "description": "",
            "tag": [],
            "address_object_type": "object_value",
        }
    }

    http_request = mocker.patch.object(client, "_http_request")

    command_results = template_address_object_create_command(client, args)
    http_request.assert_called_with(
        "POST",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/org_name/objects/addresses",
        headers={},
        ok_codes=(200, 201),
        resp_type="response",
        json_data=data,
    )
    assert command_results.readable_output == input_data.template_address_object_command_readable_output


def test_template_address_object_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, object_name, address_object_type, object_value

    When:
        - vd-template-address-object-edit command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_address_object_edit_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "object_name": "object_name",
        "address_object_type": "address_object_type",
        "object_value": "object_value",
    }

    data = {
        "address": {
            "name": "object_name",
            "description": "",
            "tag": [],
            "address_object_type": "object_value",
        }
    }

    http_request = mocker.patch.object(client, "_http_request")

    command_results = template_address_object_edit_command(client, args)
    http_request.assert_called_with(
        "PUT",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services"
        + "/org_name/objects/addresses/address/object_name",
        headers={},
        json_data=data,
        ok_codes=(200, 201, 204),
        resp_type="response",
        return_empty_response=True,
    )
    assert command_results.readable_output == input_data.template_address_object_command_readable_output


def test_template_address_object_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name, object_name

    When:
        - vd-template-address-object-delete command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_address_object_delete_command

    args = {
        "organization": "org_name",
        "template_name": "template_name",
        "object_name": "object_name",
    }

    http_request = mocker.patch.object(client, "_http_request")
    template_address_object_delete_command(client, args)
    http_request.assert_called_with(
        "DELETE",
        url_suffix="api/config/devices/template/template_name/config/orgs/"
        + "org-services/org_name/objects/addresses/address/object_name",
        headers={},
        ok_codes=(200, 201, 204),
        resp_type="response",
        return_empty_response=True,
    )


def test_appliance_address_object_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name

    When:
        - vd-appliance-address-object-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_address_object_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "organization",
        "appliance_name": "appliance_name",
    }

    appliance_address_object_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/organization/objects/addresses/address",
        params={},
        headers={},
    )


def test_appliance_address_object_create_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, object_name, address_object_type, object_value

    When:
        - vd-appliance-address-object-create command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_address_object_create_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "object_name": "object_name",
        "address_object_type": "address_object_type",
        "object_value": "object_value",
    }

    data = {
        "address": {
            "name": "object_name",
            "description": "",
            "tag": [],
            "address_object_type": "object_value",
        }
    }

    http_request = mocker.patch.object(client, "_http_request")

    command_results = appliance_address_object_create_command(client, args)
    http_request.assert_called_with(
        "POST",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/org_name/objects/addresses",
        headers={},
        json_data=data,
        ok_codes=(200, 201),
        resp_type="response",
    )
    assert command_results.readable_output == input_data.appliance_address_object_command_readable_output


def test_appliance_address_object_edit_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, object_name, address_object_type, object_value

    When:
        - vd-appliance-address-object-edit command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_address_object_edit_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "object_name": "object_name",
        "address_object_type": "address_object_type",
        "object_value": "object_value",
    }

    data = {
        "address": {
            "name": "object_name",
            "description": "",
            "tag": [],
            "address_object_type": "object_value",
        }
    }

    http_request = mocker.patch.object(client, "_http_request")

    command_results = appliance_address_object_edit_command(client, args)
    http_request.assert_called_with(
        "PUT",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/"
        + "org-services/org_name/objects/addresses/address/object_name",
        headers={},
        json_data=data,
        ok_codes=(200, 201, 204),
        resp_type="response",
        return_empty_response=True,
    )
    assert command_results.readable_output == input_data.appliance_address_object_command_readable_output


def test_appliance_address_object_delete_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name, object_name

    When:
        - vd-appliance-address-object-delete command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_address_object_delete_command

    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
        "object_name": "object_name",
    }

    http_request = mocker.patch.object(client, "_http_request")
    appliance_address_object_delete_command(client, args)
    http_request.assert_called_with(
        "DELETE",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/"
        + "org-services/org_name/objects/addresses/address/object_name",
        headers={},
        ok_codes=(200, 201, 204),
        resp_type="response",
        return_empty_response=True,
    )


def test_template_user_defined_application_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name

    When:
        - vd-template-user-defined-application-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_user_defined_application_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "template_name": "template_name",
    }

    template_user_defined_application_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/org_name/"
        + "application-identification/user-defined-applications/user-defined-application",
        params={},
        headers={},
        ok_codes=(200, 201, 204),
    )


def test_appliance_user_defined_application_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name

    When:
        - vd-appliance-user-defined-application-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_user_defined_application_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
    }

    appliance_user_defined_application_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/org_name/"
        + "application-identification/user-defined-applications/user-defined-application",
        params={},
        headers={},
        ok_codes=(200, 201),
    )


def test_template_user_modified_application_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, template_name

    When:
        - vd-template-user-modified-application-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import template_user_modified_application_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "template_name": "template_name",
    }

    template_user_modified_application_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/template/template_name/config/orgs/org-services/org_name/"
        + "application-identification/application-specific-options/app-specific-option-list",
        params={},
        headers={},
        ok_codes=(200, 201),
    )


def test_appliance_user_modified_application_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization, appliance_name

    When:
        - vd-appliance-user-modified-application-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import appliance_user_modified_application_list_command

    http_request = mocker.patch.object(client, "_http_request")
    args = {
        "organization": "org_name",
        "appliance_name": "appliance_name",
    }

    appliance_user_modified_application_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="api/config/devices/device/appliance_name/config/orgs/org-services/org_name/"
        + "application-identification/application-specific-options/app-specific-option-list",
        params={},
        headers={},
        ok_codes=(200, 201),
    )


def test_predefined_application_list_command(mocker, client):
    """
    Given:
        - Arguments passed: organization

    When:
        - vd-predefined-application-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    from VersaDirector import predefined_application_list_command

    http_request = mocker.patch.object(client, "_http_request", return_value=None)
    args = {"organization": "org_name"}
    predefined_application_list_command(client, args)
    http_request.assert_called_with(
        "GET",
        url_suffix="vnms/spack/predefined?xPath=/predefined/config/predefined-applications/"
        + "application-identification/applications/application",
        params={},
        headers={},
        resp_type="json",
        ok_codes=(200, 201, 204),
    )


# HEADING: """ HELPER FUNCTIONS TESTS """


@pytest.mark.parametrize("input", [None, 1])
def test_check_limit(input):
    """
    Given:
        - 'limit' value is passed as argument
    When:
        - A command that has the option to choose 'limit' argument is executed
    Then:
        - Return None if value is valid
    """
    from VersaDirector import check_limit

    assert check_limit(input) is None


@pytest.mark.parametrize("input", [-1, 0])
def test_check_limit_fail(input):
    """
    Given:
        - Invalid 'limit' argument (not a positive number)
    When:
        - A command that has the option to choose 'limit' argument is executed
    Then:
        - Raises exception
    """
    from VersaDirector import check_limit

    with pytest.raises(DemistoException) as e:
        check_limit(input)
    assert str(e.value.message) == "Please provide a positive value for 'limit' argument."


@pytest.mark.parametrize(
    "organization_args, organization_params, expected_output",
    input_data.set_organization_args,
)
def test_set_organization(organization_args, organization_params, expected_output):
    """
    Given:
        - Organization Name is passed as an argument or a parameter (by this priority)
    When:
        - A command that has the option to choose 'organization' argument is executed
    Then:
        - Return preferred organization name
    """
    from VersaDirector import set_organization

    assert set_organization(organization_args, organization_params) == expected_output


def test_set_organization_fail():
    """
    Given:
        - Organization Name has None value (not given through parameters or arguments)

        - A command that has the option to choose 'organization' argument is executed
    Then:
        - Raise DemistoException with valid message
    """
    from VersaDirector import set_organization

    with pytest.raises(DemistoException) as e:
        set_organization(None, None)
    assert str(e.value.message) == "Please provide 'Organization Name' via integration configuration or command argument."


@pytest.mark.parametrize(
    "page, page_size, expected_output",
    input_data.set_offset_args,
)
def test_set_offset(page, page_size, expected_output):
    """
    Given:
        - 'page' and 'page_size' arguments
    When:
        - A command that has page and page_size arguments is run
    Then:
        - Return valid page * page_size value as output
    """
    from VersaDirector import set_offset

    assert set_offset(page, page_size) == expected_output


@pytest.mark.parametrize(
    "page, page_size",
    input_data.set_offset_args_fail,
)
def test_set_offset_fail(page, page_size):
    """
    Given:
        - Invalid 'page' and 'page_size' arguments
    When:
        - A command that has 'page' and 'page_size' arguments is run
    Then:
        - Raise DemistoException with valid message
    """
    from VersaDirector import set_offset

    with pytest.raises(DemistoException) as e:
        set_offset(page, page_size)
    assert str(e.value.message) == "'page' or 'page_size' arguments are invalid."


@pytest.mark.parametrize(
    "use_basic_auth, username, password, client_id, client_secret, access_token, expected_output",
    input_data.create_client_header_args,
)
def test_create_client_header(
    mocker,
    use_basic_auth,
    username,
    password,
    client_id,
    client_secret,
    access_token,
    expected_output,
):
    """
    Given:
        - Parameters related to authentication (use_basic_auth, username, password, client_id, client_secret, access_token)
    When:
        - Before creating Client object in main function
    Then:
        - Return (Auth, Headers) value according to chosen authentication method
    """
    from VersaDirector import create_client_header

    assert create_client_header(use_basic_auth, username, password, client_id, client_secret, access_token) == expected_output


@pytest.mark.asyncio
async def test_get_audit_logs(async_client: AsyncClient, mocker):
    """
    Given:
     - An AsyncClient instance.
     - A limit that requires fetching two pages of events.
     - A list of already fetched event IDs.
    When:
     - Calling get_audit_logs.
    Then:
     - Ensure that the API is called twice (for two pages).
     - Ensure that the events are formatted, sorted by time, and deduplicated.
    """
    from VersaDirector import get_audit_logs, DEFAULT_AUDIT_LOGS_PAGE_SIZE, FILTER_DATE_FORMAT
    from datetime import datetime

    # Setup mock responses
    mock_responses = [
        mock_async_session_response(input_data.audit_logs_page1_response),
        mock_async_session_response(input_data.audit_logs_page2_response),
    ]

    # Mock the session 'get' method
    async with async_client as client:
        mocker.patch.object(client._session, "get", side_effect=mock_responses)

        # Define test parameters
        from_date = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).strftime(FILTER_DATE_FORMAT)
        limit = DEFAULT_AUDIT_LOGS_PAGE_SIZE + 3
        last_fetched_ids = ["app-a0"]  # Should be deduplicated

        # Call the function under test
        events = await get_audit_logs(
            client=client,
            from_date=from_date,
            limit=limit,
            last_fetched_ids=last_fetched_ids,
        )

        # Assertions
        assert len(events) == limit
        assert events[0]["applianceuuid"] == "app-a1"  # Skipped "app-a0" since it was in last fetched IDs
        assert client._session.get.call_count == 2  # Called for both pages

        # Verify call arguments for pagination
        first_call_kwargs = client._session.get.call_args_list[0].kwargs
        assert first_call_kwargs["params"] == {"searchKey": "time>=2025-01-01 00:00:00", "offset": "0", "limit": "2500"}

        second_call_kwargs = client._session.get.call_args_list[1].kwargs
        assert second_call_kwargs["params"] == {"searchKey": "time>=2025-01-01 00:00:00", "offset": "2500", "limit": "2500"}


@freeze_time("2025-01-01T00:00:00Z")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "last_run, expected_next_run, expected_events",
    input_data.fetch_events_test_params,
)
async def test_fetch_events_command(
    last_run: dict,
    expected_next_run: dict,
    expected_events: list,
    async_client: AsyncClient,
    mocker,
):
    """
    Given:
     - An AsyncClient instance.
     - A last run object
    When:
     - Calling fetch_events_command.
    Then:
     - Ensure that the next run is as expected with "from_date" and "last_fetched_ids".
     - Ensure that the events are formatted, sorted by time, and deduplicated.
    """
    from VersaDirector import fetch_events_command

    max_fetch = 2000

    async with async_client as client:
        mocker.patch.object(
            client._session, "get", side_effect=[mock_async_session_response(input_data.audit_logs_page1_response)]
        )
        next_run, events = await fetch_events_command(client, last_run, max_fetch)

    assert next_run == expected_next_run
    assert events == expected_events
