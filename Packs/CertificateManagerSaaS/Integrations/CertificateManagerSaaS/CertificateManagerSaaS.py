import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from CertificateManagerSaaSApiModule import *  # noqa: F401

import urllib3
from typing import Any

urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_BASE_URL = "https://api.venafi.cloud"
# CM SaaS authenticates with a custom header, not a standard HTTP auth mechanism.
# The value is only ever written into the session headers - never logged.
API_KEY_HEADER = "tppl-api-key"
# Must track `currentVersion` in pack_metadata.json. Identifies this integration to CyberArk, whose
# server-side request logs are the only place usage can be aggregated across customers.
# The platform injects the installed pack version at runtime; the literal is only the fallback outside it.
PACK_VERSION = get_pack_version() or "1.0.0"
USER_AGENT = f"CortexXSOAR-CertificateManagerSaaS/{PACK_VERSION}"

USER_ACCOUNTS_URL_SUFFIX = "/v1/useraccounts"
# REST, because the GraphQL `applications` root field is not allow-listed. The REST call
# answers 200 with `{applications, totalCount, ownershipCount}`. The NGTS integration doesn't use applications.
APPLICATIONS_URL_SUFFIX = "/outagedetection/v1/applications"

PRODUCT = ProductProfile(
    name="Certificate Manager SaaS",
    brand="CertificateManagerSaaS",
    user_agent=USER_AGENT,
    http_error_messages={
        401: (
            "Authentication failed (HTTP 401). The API key was rejected by this host. Verify the key, and verify "
            "that the Server URL matches the region the key belongs to - a key from another region returns 401."
        ),
        403: (
            "Forbidden (HTTP 403). On the CM SaaS GraphQL gateway this means the requested root field is not "
            "allow-listed for this tenant; it does not mean the credential is wrong."
        ),
    },
)

""" CLIENT CLASS """


class Client(CertificateManagerClient):
    """Authenticates to CM SaaS with an API key sent in a custom header."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            product=PRODUCT,
            verify=verify,
            proxy=proxy,
            headers={API_KEY_HEADER: api_key},
        )

    def get_user_accounts(self) -> Any:
        """Read the caller's user accounts. Used only to prove the credential works."""
        return self._http_request("GET", url_suffix=USER_ACCOUNTS_URL_SUFFIX, error_handler=self.raise_http_error)

    def list_applications(self) -> Any:
        """List applications."""
        return self._http_request("GET", url_suffix=APPLICATIONS_URL_SUFFIX, error_handler=self.raise_http_error)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Prove that the credential works on both surfaces.

    Args:
        client: The CM SaaS client.

    Returns:
        str: 'ok' when both surfaces answer.
    """
    client.get_user_accounts()
    # The GraphQL gateway is separately allow-listed, so a working REST call does not imply a
    # working certificate search. Probe it with the smallest possible page.
    client.search_certificates(first=1)
    demisto.debug(threshold_alignment_message(client))
    return "ok"


def application_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List applications.

    Args:
        client: The CM SaaS client.
        args: Command arguments.

    Returns:
        CommandResults: The applications.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    raw = client.list_applications()
    applications = extract_list(raw, "applications")[:limit]
    context = [assign_params(ID=app.get("id"), Name=app.get("name"), Description=app.get("description")) for app in applications]
    return CommandResults(
        readable_output=tableToMarkdown(f"{PRODUCT.name} applications", context, removeNull=True),
        outputs_prefix=f"{CONTEXT_PREFIX}.Application",
        outputs_key_field="ID",
        outputs=context or None,
        raw_response=raw,
    )


""" MAIN FUNCTION """


def build_client(params: dict[str, Any]) -> Client:
    """Construct the client from instance parameters.

    Args:
        params: `demisto.params()`.

    Returns:
        Client: A configured client.
    """
    api_key = (params.get("credentials") or {}).get("password")
    if not api_key:
        raise DemistoException(
            "An API key is required. Set it in the 'API Key' field of the instance configuration "
            "(the user name half of the credential is unused)."
        )
    return Client(
        base_url=(params.get("url") or DEFAULT_BASE_URL).rstrip("/"),
        api_key=api_key,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = build_client(params)
        if command == "test-module":
            return_results(test_module(client))
        elif command == "certificate":
            return_results(
                certificate_command(client, args, resolve_reliability(params), resolve_reported_key_compromise_score(params))
            )
        elif command == "cmsaas-certificate-search":
            return_results(certificate_search_command(client, args))
        elif command == "cmsaas-certificate-get":
            return_results(certificate_get_command(client, args))
        elif command == "cmsaas-certificate-list-expiring":
            return_results(certificate_list_expiring_command(client, args))
        elif command == "cmsaas-application-list":
            return_results(application_list_command(client, args))
        elif command == "cmsaas-machine-list":
            return_results(machine_list_command(client, args))
        elif command == "cmsaas-machine-get":
            return_results(machine_get_command(client, args))
        elif command == "cmsaas-certificate-revoke":
            return_results(certificate_revoke_command(client, args))
        elif command == "cmsaas-certificate-request":
            return_results(certificate_request_command(client, args))
        elif command == "cmsaas-certificate-request-status":
            return_results(certificate_request_status_command(client, args))
        elif command == "cmsaas-certificate-download":
            return_results(certificate_download_command(client, args))
        elif command == "cmsaas-certificate-keystore-download":
            return_results(certificate_keystore_download_command(client, args, keystore_passphrase(params)))
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(client, params, demisto.getLastRun() or {})
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
