import json
from typing import Any

import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

LOG_LINE = "HyddenControlDebugLog: "


def _as_blast_radius_string(response: Any) -> str:
    if isinstance(response, dict):
        value = response.get("blast_radius")
        if value is None:
            raise DemistoException("Hydden response did not include blast_radius.")
    else:
        value = response
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise DemistoException("Hydden response did not include blast_radius.")
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


class Client(BaseClient):
    def get_blast_radius(self, account_id: str) -> Any:
        return self._http_request(
            method="GET",
            url_suffix="blast-radius",
            params={"account_id": account_id},
        )

    def deprovision_account(self, account_id: str) -> str:
        return self._http_request(
            method="POST",
            url_suffix="account-actions/deprovision",
            params={"account_id": account_id},
            resp_type="text",
        )


def _get_account_id(args: dict[str, Any]) -> str:
    account_id = args.get("account_id") or args.get("account")
    if account_id is None or str(account_id).strip() == "":
        raise DemistoException("Please provide account_id.")
    return str(account_id)


def test_module(client: Client) -> str:
    """Validate connectivity and authentication."""
    try:
        client.get_blast_radius("00000000-0000-0000-0000-000000000000")
    except DemistoException as e:
        err = str(e)
        if any(token in err for token in ("401", "403", "Unauthorized", "Forbidden")):
            raise DemistoException("Authorization failed. Check the Client ID and Client Secret.") from e
        if "404" not in err and "Not Found" not in err:
            raise
    return "ok"


def hydden_deprovision_account_command(client: Client, args: dict[str, Any]) -> CommandResults:
    account_id = _get_account_id(args)
    raw = client.deprovision_account(account_id)

    return CommandResults(
        readable_output=f"Account {account_id} was deprovisioned successfully.",
        outputs_prefix="Hydden.Identity",
        outputs={"deprovisioned": True},
        raw_response=raw,
    )


def hydden_blast_radius_command(client: Client, args: dict[str, Any]) -> CommandResults:
    account_id = _get_account_id(args)
    response = client.get_blast_radius(account_id)
    blast_radius = _as_blast_radius_string(response)

    return CommandResults(
        readable_output=f"Blast radius for account {account_id}: {blast_radius}",
        outputs_prefix="Hydden.Identity",
        outputs={"blast_radius": blast_radius},
        raw_response=response,
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials = params.get("credentials") or {}
    client_id = credentials.get("identifier")
    client_secret = credentials.get("password")
    if not client_id or not client_secret:
        raise DemistoException("Client ID and Client Secret are required.")

    base_url = (params.get("url") or "").rstrip("/") + "/"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    demisto.debug(f"{LOG_LINE}Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            headers=headers,
            auth=(client_id, client_secret),
            ok_codes=(200, 201, 204),
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "hydden-blast-radius":
            return_results(hydden_blast_radius_command(client, args))
        elif command == "hydden-deprovision-account":
            return_results(hydden_deprovision_account_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
