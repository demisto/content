import json
import re
import time
import traceback
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *  # noqa: F401,F403

LOG_LINE = "HyddenControlDebugLog: "

TOKEN_URL_SUFFIX = "oauth/token"

# The blast-radius endpoint names its headline number "score". Some deployments
# have been seen to answer a flat "blast_radius" instead, so accept either
# rather than fail on a tenant that returns the older shape.
BLAST_RADIUS_VALUE_FIELDS = ("score", "blast_radius")
DEFAULT_TOKEN_LIFETIME_SECONDS = 300
# Refresh this far ahead of expiry so a token can't die mid-request. Capped at
# half the lifetime: Hydden clamps expires_in to the credential's own expiry,
# and a flat margin against a shorter-lived token would put the refresh point
# in the past and re-issue on every single call.
TOKEN_REFRESH_MARGIN_SECONDS = 60

# blast-radius computes the tenant reachability graph on a cold cache, which has
# been measured at over three minutes on a warm-up; every call after that is
# sub-second. BaseClient defaults to 60s, which turns that first call into a
# read timeout, so default well above it and let the instance override.
DEFAULT_TIMEOUT_SECONDS = 300
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_LOOKUP_UUID_FIELDS = ("uuid", "id", "ref", "account_id", "account_ref", "accountId")
_LOOKUP_COLLECTION_KEYS = ("accounts", "items", "data", "results", "uuids", "ids")


def _as_blast_radius_string(response: Any) -> str:
    """The headline reach value from a blast-radius response, as a string."""
    if isinstance(response, dict):
        value = None
        for field in BLAST_RADIUS_VALUE_FIELDS:
            # Not "or": a score of 0 is a real answer, not a missing one.
            if response.get(field) is not None:
                value = response[field]
                break
        if value is None:
            # Name what did come back, so a contract change diagnoses itself.
            returned = ", ".join(sorted(response)) if response else "(empty response)"
            raise DemistoException("Hydden response did not include a blast radius score. " f"Fields returned: {returned}")
    else:
        value = response
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise DemistoException("Hydden response did not include a blast radius score.")
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


class Client(ContentClient):  # noqa: F405
    """Client for the Hydden Control public API.

    The public API accepts nothing but a client-credentials bearer token, so
    every command is a two-step: exchange the Client ID and Client Secret at
    the token endpoint, then send the issued token as an Authorization header
    on the call itself. Tokens are cached until shortly before they expire, so
    a playbook that runs several commands on one instance pays for one token
    issuance rather than one per call.
    """

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._token_expires_at = 0.0

    def get_bearer_token(self) -> str:
        """Exchange the client credentials for a bearer token, cached until near expiry."""
        if self._token and time.time() < self._token_expires_at:
            return self._token

        response = self._http_request(
            method="POST",
            url_suffix=TOKEN_URL_SUFFIX,
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )

        token = response.get("access_token") if isinstance(response, dict) else None
        if not token:
            raise DemistoException("Hydden token response did not include access_token.")

        expires_in = int(response.get("expires_in") or DEFAULT_TOKEN_LIFETIME_SECONDS)
        margin = min(TOKEN_REFRESH_MARGIN_SECONDS, expires_in // 2)
        self._token = str(token)
        self._token_expires_at = time.time() + max(1, expires_in - margin)
        return self._token

    def _bearer_headers(self, token: str) -> dict[str, str]:
        return {**(self._headers or {}), "Authorization": f"Bearer {token}"}

    def lookup_accounts(self, query: str, token: str) -> Any:
        # Cortex issues carry a name or email, not a Hydden UUID. blast-radius
        # and deprovision both require the UUID as ref; this is the resolver.
        return self._http_request(
            method="GET",
            url_suffix="accounts/lookup",
            headers=self._bearer_headers(token),
            params={"q": query},
        )

    def get_blast_radius(self, account_id: str, token: str, subject_type: str = "account") -> Any:
        # The endpoint names its subject "ref", not "account_id": sending
        # account_id gets a 400 "the 'ref' query parameter is required".
        return self._http_request(
            method="GET",
            url_suffix="blast-radius",
            headers=self._bearer_headers(token),
            params={"ref": account_id, "type": subject_type},
        )

    def deprovision_account(self, account_id: str, token: str) -> str:
        return self._http_request(
            method="POST",
            url_suffix="account-actions/deprovision",
            headers=self._bearer_headers(token),
            params={"ref": account_id},
            resp_type="text",
        )


def _get_account_id(args: dict[str, Any]) -> str:
    account_id = args.get("account_id") or args.get("account")
    if account_id is None or str(account_id).strip() == "":
        raise DemistoException("Please provide account_id.")
    return str(account_id)


def _uuid_from_value(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        if _UUID_RE.fullmatch(stripped):
            return stripped
    return None


def _uuids_from_item(item: Any) -> list[str]:
    if uuid := _uuid_from_value(item):
        return [uuid]
    if not isinstance(item, dict):
        return []
    for field in _LOOKUP_UUID_FIELDS:
        if uuid := _uuid_from_value(item.get(field)):
            return [uuid]
    return []


def _uuids_from_lookup(response: Any) -> list[str]:
    """Unique Hydden UUIDs from an accounts/lookup payload, in first-seen order."""
    if isinstance(response, list):
        items = response
    elif isinstance(response, dict):
        items = None
        for key in _LOOKUP_COLLECTION_KEYS:
            value = response.get(key)
            if isinstance(value, list):
                items = value
                break
        if items is None:
            items = [response]
    else:
        items = [response]

    seen: list[str] = []
    seen_keys: set[str] = set()
    for item in items:
        for uuid in _uuids_from_item(item):
            key = uuid.lower()
            if key not in seen_keys:
                seen_keys.add(key)
                seen.append(uuid)
    return seen


def _resolve_account_uuid(client: Client, token: str, identifier: str) -> str:
    try:
        response = client.lookup_accounts(identifier, token)
    except DemistoException as e:
        err = str(e)
        if "404" in err or "Not Found" in err:
            raise DemistoException(f"Hydden accounts lookup returned no matches for {identifier}.") from e
        raise
    uuids = _uuids_from_lookup(response)
    if not uuids:
        raise DemistoException(f"Hydden accounts lookup returned no matches for {identifier}.")
    if len(uuids) > 1:
        raise DemistoException(f"Hydden accounts lookup returned more than one match for {identifier}.")
    return uuids[0]


def test_module(client: Client) -> str:
    """Validate connectivity and authentication."""
    try:
        token = client.get_bearer_token()
        client.get_blast_radius("00000000-0000-0000-0000-000000000000", token)
    except DemistoException as e:
        err = str(e)
        if any(token in err for token in ("401", "403", "Unauthorized", "Forbidden")):
            raise DemistoException("Authorization failed. Check the Client ID and Client Secret.") from e
        if "404" not in err and "Not Found" not in err:
            raise
    return "ok"


def hydden_deprovision_account_command(client: Client, args: dict[str, Any]) -> CommandResults:
    identifier = _get_account_id(args)
    token = client.get_bearer_token()
    account_id = _resolve_account_uuid(client, token, identifier)
    raw = client.deprovision_account(account_id, token)

    return CommandResults(
        readable_output=f"Account {identifier} ({account_id}) was deprovisioned successfully.",
        outputs_prefix="Hydden.Identity",
        outputs={"deprovisioned": True},
        raw_response=raw,
    )


def hydden_blast_radius_command(client: Client, args: dict[str, Any]) -> CommandResults:
    identifier = _get_account_id(args)
    subject_type = str(args.get("type") or "account")
    token = client.get_bearer_token()
    account_id = _resolve_account_uuid(client, token, identifier)
    response = client.get_blast_radius(account_id, token, subject_type)
    blast_radius = _as_blast_radius_string(response)

    # Carry the whole payload into context, not just the headline string: a
    # playbook gating on "how much does this account reach" needs score and
    # reachable_resources as numbers, which a formatted string can't give it.
    outputs = {"blast_radius": blast_radius}
    if isinstance(response, dict):
        outputs = {**response, **outputs}

    return CommandResults(
        readable_output=f"Blast radius for account {identifier} ({account_id}): {blast_radius}",
        outputs_prefix="Hydden.Identity",
        outputs=outputs,
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
    timeout = arg_to_number(params.get("timeout")) or DEFAULT_TIMEOUT_SECONDS
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    demisto.debug(f"{LOG_LINE}Command being called is {command}")

    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            headers=headers,
            ok_codes=(200, 201, 204),
            timeout=timeout,
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
        demisto.error(f"{LOG_LINE}Failed to execute {command}: {traceback.format_exc()}")
        return_error(f"Failed to execute {command} command. Error: {str(e)}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
