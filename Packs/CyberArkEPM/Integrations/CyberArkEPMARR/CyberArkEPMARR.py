"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
CONTEXT_KEY = "CyberArkEPMARR_Context"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(
        self,
        base_url,
        username,
        password,
        application_id,
        authentication_url=None,
        application_url=None,
        verify=True,
        proxy=False
    ):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.username = username
        self.password = password
        self.application_id = application_id
        self.authentication_url = authentication_url
        self.application_url = application_url
        if self.authentication_url and self.application_url:
            self.saml_auth_to_cyber_ark()
        else:
            self.epm_auth_to_cyber_ark()


    def epm_auth_to_cyber_ark(self):  # pragma: no cover
        data = {
            "Username": self.username,
            "Password": self.password,
            "ApplicationID": self.application_id or "CyberArkXSOAR",
        }
        result = self._http_request("POST", url_suffix="/EPM/API/Auth/EPM/Logon", json_data=data)

        # TODO: reinstate after local testing
        # if result.get("IsPasswordExpired"):
        #     return_error("CyberArk is reporting that the user password is expired. Terminating script.")
        self._base_url = urljoin(result.get("ManagerURL"), "/EPM/API/")
        self._headers["Authorization"] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_session_token(self) -> str:  # pragma: no cover
        # Reference: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
        data = {
            "username": self.username,
            "password": self.password,
        }
        result = self._http_request("POST", full_url=self.authentication_url, json_data=data)
        demisto.debug(f"result is: {result}")
        if result.get("status", "") != "SUCCESS":
            raise DemistoException(
                f"Retrieving session token returned status: {result.get('status')},"
                f" Check your credentials and make sure the user is not blocked by a role."
            )
        return result.get("sessionToken")

    def get_saml_response(self) -> str:  # pragma: no cover
        # Reference: https://devforum.okta.com/t/how-to-get-saml-assertion-through-an-api/24580
        full_url = f"{self.application_url}?onetimetoken={self.get_session_token()}"
        result = self._http_request("POST", full_url=full_url, resp_type="response")
        soup = BeautifulSoup(result.text, features="html.parser")
        saml_response = soup.find("input", {"name": "SAMLResponse"}).get("value")

        return saml_response

    def saml_auth_to_cyber_ark(self):  # pragma: no cover
        # Reference: https://docs.cyberark.com/EPM/Latest/en/Content/WebServices/SAMLAuthentication.htm
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"SAMLResponse": self.get_saml_response()}
        result = self._http_request("POST", url_suffix="/SAML/Logon", headers=headers, data=data)
        if result.get("IsPasswordExpired"):
            return_error("CyberArk is reporting that the user password is expired. Terminating script.")
        self._base_url = urljoin(result.get("ManagerURL"), "/EPM/API/")
        self._headers["Authorization"] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_sets(self) -> dict:
        return self._http_request("GET", url_suffix="Sets")


""" HELPER FUNCTIONS """

def search_endpoints(endpoint_name: str, external_ip: str, client: Client) -> list:
    data = {
        "filter": f"name EQ {endpoint_name} and ip EQ {external_ip}"
    }
    sets = client.get_sets()
    set_ids = [set["Id"] for set in sets.get("Sets", [])]
    _ = get_integration_context().get(CONTEXT_KEY, {})
    for set_id in set_ids:
        url_suffix = f"Sets/{set_id}/Endpoints/Search"
        result = client._http_request("POST", url_suffix=url_suffix, json_data=data)
        if result.get("endpoints"):
            endpoint_ids = [endpoint.get("id") for endpoint in result.get("endpoints")]
            set_integration_context({
                CONTEXT_KEY: {
                    "set_id": set_id
                }
            })
            return endpoint_ids
    return []

def search_endpoint_group_id(group_name: str, client: Client) -> str:
    data = {
        "filter": f"name EQ {group_name}"
    }
    context = get_integration_context().get(CONTEXT_KEY, {})
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/Search"
    result = client._http_request("POST", url_suffix=url_suffix, json_data=data)
    if result:
        endpoint_group_id = result[0].get("id")
        return endpoint_group_id
    return None


def add_endpoint_to_group(endpoint_id: str, endpoint_group_id: str, client: Client) -> None:
    data = {
        "membersIds": [endpoint_id]
    }
    context = get_integration_context().get(CONTEXT_KEY, {})
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids"
    client._http_request("POST", url_suffix=url_suffix, json_data=data)

""" COMMAND FUNCTIONS """


def activate_risk_plan_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    risk_plan = args.get("risk_plan")
    endpoint_name = args.get("endpoint_name")
    external_ip = args.get("external_ip")

    if not risk_plan:
        return_error("Risk plan is required")
    if not endpoint_name:
        return_error("Endpoint name is required")
    if not external_ip:
        return_error("External IP is required")

    # Search for endpoints
    endpoint_ids = search_endpoints(endpoint_name, external_ip, client)

    if not endpoint_ids:
        return_error(f"No Endpoints not found matching the name: {endpoint_name} and External IP: {external_ip}")

    # Search for endpoint group by risk plan name
    endpoint_group_id = search_endpoint_group_id(risk_plan, client)
    if not endpoint_group_id:
        return_error(f"No Endpoint Group not found matching the name: {risk_plan}")

    for endpoint_id in endpoint_ids:
        add_endpoint_to_group(endpoint_id, endpoint_group_id, client)

    human_readable = tableToMarkdown(name="Endpoints Added to Risk Plan",
                                     t={"Endpoint IDs": endpoint_ids, "Risk Plan": risk_plan},
                                     headers=["Endpoint ID", "Risk Plan"])
    return CommandResults(
        readable_output=human_readable,
        raw_response=endpoint_ids,
    )

def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    client.get_sets()
    return "ok"


def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    base_url = params.get("url")
    application_id = params.get("application_id")
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            application_id=application_id
        )
        args = demisto.args()
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        elif command == "cyberarkepm-activate-risk-plan":
            result = activate_risk_plan_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
