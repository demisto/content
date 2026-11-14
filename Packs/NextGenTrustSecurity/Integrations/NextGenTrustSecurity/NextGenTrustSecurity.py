import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from CertificateManagerSaaSApiModule import *  # noqa: F401

import hashlib
import time
import requests
import urllib3
from dataclasses import dataclass, field
from typing import Any

urllib3.disable_warnings()

""" CONSTANTS """

# NGTS is Certificate Manager SaaS behind the Strata Cloud Manager gateway. The gateway serves the CM SaaS
# paths unchanged under `/ngts` - GraphQL at `/ngts/graphql`, REST keeping `/outagedetection` - so the
# shared module's paths apply as they are.
DEFAULT_BASE_URL = "https://api.strata.paloaltonetworks.com/ngts"
DEFAULT_TOKEN_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
# The GraphQL `getCertExpActiveThresholds` is 403 on NGTS; this REST resource carries the same thresholds.
EXPIRY_THRESHOLDS_URL_SUFFIX = "/outagedetection/v1/inventorymonitoringconfig/CERTIFICATE_EXPIRATION"
# Must track `currentVersion` in pack_metadata.json. The platform injects the installed pack version at
# runtime; the literal is only the fallback outside it.
PACK_VERSION = get_pack_version() or "1.0.0"
USER_AGENT = f"CortexXSOAR-NextGenTrustSecurity/{PACK_VERSION}"
# SCM tokens live about 15 minutes. Refreshing a minute early keeps a token from lapsing between the
# cache check and the request that uses it.
TOKEN_EXPIRY_MARGIN_SECONDS = 60
# Used when a token response omits `expires_in`: well under the ~15-minute SCM lifetime, so a cached token
# is never trusted past its real expiry, while still sparing a token request per command.
DEFAULT_TOKEN_LIFETIME_SECONDS = 600
# A 401 on a token minted this recently is a real rejection (wrong environment, missing role), not a stale
# token, so it is reported rather than retried.
FRESH_TOKEN_SECONDS = 60
# The integration context is shared with anything else this instance stores, so the token lives under
# one key of its own.
TOKEN_CACHE_CONTEXT_KEY = "ngts_access_token"

PRODUCT = ProductProfile(
    name="Next-Gen Trust Security",
    brand="NextGenTrustSecurity",
    user_agent=USER_AGENT,
    http_error_messages={
        401: (
            "Authentication failed (HTTP 401). The gateway rejected a freshly issued access token. Verify that the "
            "Server URL and the Token URL belong to the same Strata Cloud Manager environment."
        ),
        # The gateway authorizes per operation and answers an unrouted path with the same 403, so this
        # cannot tell a missing permission from an unsupported operation.
        403: (
            "Forbidden (HTTP 403). The service account's role does not permit this operation, or the NGTS gateway "
            "does not serve it. See the integration help for the permission sets each command needs."
        ),
    },
)

# The Strata Cloud Manager gateway runs a web filter over the URL and body of every request, read-only ones
# included. A block is an HTML 403 carrying this header; an authorization failure is a JSON AUTHZ_DENIED body.
# SQL-, script- and path-like text is blocked, and so is plain English that tokenizes like SQL,
# e.g. the revocation comment "Revoked in Cortex case 123" (keyword, word, "case", number).
WEB_FILTER_HEADER = "x-request-flow-error"
# The free-text arguments sent to NGTS - what the filter reacts to. Search matches its text arguments locally.
FREE_TEXT_ARGUMENTS = (
    "comment",
    "common_name",
    "sans",
    "organization",
    "organizational_units",
    "locality",
    "state",
    "tags",
)

""" HELPER FUNCTIONS """


class TokenRejectedError(DemistoException):
    """Raised internally when the gateway answers 401, so the request can be retried with a fresh token."""


class WebFilterBlockedError(DemistoException):
    """Raised when the gateway's web filter rejects a request before it reaches NGTS."""


def web_filter_message(args: dict[str, Any]) -> str:
    """Explain a web-filter block, quoting the free text the user supplied.

    Args:
        args: The command arguments.

    Returns:
        str: The message.
    """
    typed = [f'"{name}" ("{args[name]}")' for name in FREE_TEXT_ARGUMENTS if args.get(name)]
    cause = f"because of the text in {', '.join(typed)}" if typed else "because part of the request looked like an attack"
    return (
        "Next-Gen Trust Security never received this request: the Strata Cloud Manager gateway's security filter "
        f"blocked it (HTTP 403) {cause}. The filter rejects text that resembles an attack, such as SQL-like phrases "
        '(for example "on Cortex case 123"), HTML or script tags, and file paths. This is not a permission problem. '
        "Reword that text or leave it out, and run the command again."
    )


# When a revocation approval rule covers the certificate's CA, NGTS refuses a revocation requested by a tenant
# service account with this bare error, whatever its role; the root account's request goes to PENDING_APPROVAL,
# and listing the account as a requester exception on the rule lets it through.
REDACTED_ERROR_MARKER = "Subgraph errors redacted"
REDACTED_REVOKE_HINT = (
    "NGTS hid the reason. A common cause is a revocation approval rule that covers this certificate's CA: NGTS then "
    "refuses revocations requested by a tenant service account, and nothing was changed. Revoke the certificate in the "
    "NGTS console, or add this integration's dedicated service account as an exception to that rule (its revocations "
    'then skip NGTS approval). See "Revocation approval rules" in the integration help before you do.'
)


def error_message(command: str, args: dict[str, Any], error: Exception) -> str:
    """Turn a command failure into the message the user sees, explaining the cases NGTS leaves unexplained.

    Args:
        command: The command that failed.
        args: The command arguments.
        error: The exception.

    Returns:
        str: The message.
    """
    if isinstance(error, WebFilterBlockedError):
        return web_filter_message(args)
    if command == "ngts-certificate-revoke" and REDACTED_ERROR_MARKER in str(error):
        return f"{error} {REDACTED_REVOKE_HINT}"
    return str(error)


def raise_token_error(response: requests.Response) -> None:
    """Translate a Strata Cloud Manager token failure into an actionable message.

    Args:
        response: The failing token response.

    Raises:
        DemistoException: Always.
    """
    raise DemistoException(
        f"Strata Cloud Manager rejected the client credentials (HTTP {response.status_code}). Verify the client ID, "
        "the client secret, the TSG ID, and that the Token URL belongs to the same environment as the Server URL."
    )


@dataclass(frozen=True)
class OAuthSettings:
    """The Strata Cloud Manager client-credentials settings.

    Attributes:
        token_url: The OAuth2 token endpoint.
        client_id: The service account client ID.
        client_secret: The service account client secret. Excluded from `repr`, so it never reaches a log.
        tsg_id: The tenant service group that scopes the token.
    """

    token_url: str
    client_id: str
    client_secret: str = field(repr=False)
    tsg_id: str


def token_cache_key(oauth: OAuthSettings, server_url: str) -> str:
    """Identify the token owner and the endpoints it was issued for.

    A reconfigured instance - another account, a rotated secret, another environment - must never reuse
    the previous configuration's token. The secret and URLs enter only as a truncated hash, so the
    integration context never holds the secret itself.

    Args:
        oauth: The client-credentials settings.
        server_url: The NGTS base URL the token is used against.

    Returns:
        str: The cache key.
    """
    material = "\0".join((oauth.client_secret, oauth.token_url, server_url))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{oauth.client_id}:{oauth.tsg_id}:{digest}"


def cached_token_entry(context: dict[str, Any], cache_key: str, now: float) -> dict[str, Any] | None:
    """Return the cached token entry when it belongs to `cache_key` and is still valid.

    Args:
        context: The integration context.
        cache_key: The owner the token must have been issued to.
        now: The current epoch time.

    Returns:
        dict | None: The entry, with `access_token` and `valid_until`, or None when there is no usable one.
    """
    entry = context.get(TOKEN_CACHE_CONTEXT_KEY) or {}
    if entry.get("cache_key") == cache_key and entry.get("valid_until", 0) > now and entry.get("access_token"):
        return entry
    return None


def thresholds_from_configuration(response: dict[str, Any] | None) -> list[int]:
    """Read the thresholds out of an `inventorymonitoringconfig` response.

    Args:
        response: The decoded `CERTIFICATE_EXPIRATION` configuration.

    Returns:
        list: The thresholds in days, or an empty list.
    """
    return ((response or {}).get("configuration") or {}).get("thresholds") or []


""" CLIENT CLASS """


class Client(CertificateManagerClient):
    """Authenticates to NGTS with the Strata Cloud Manager OAuth2 client-credentials flow."""

    def __init__(self, base_url: str, oauth: OAuthSettings, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, product=PRODUCT, verify=verify, proxy=proxy)
        self._oauth = oauth
        self._cache_key = token_cache_key(oauth, base_url)
        # One command run is one client, so the token lives here and the integration context is touched
        # at most once per run to read and only when a token is minted to write.
        self._context: dict[str, Any] | None = None
        self._token: str | None = None
        self._token_valid_until = 0.0
        self._token_minted_at: float | None = None

    def _integration_context(self) -> dict[str, Any]:
        """Read the integration context on first need, then reuse that copy for the rest of the run."""
        if self._context is None:
            self._context = get_integration_context() or {}
        return self._context

    def get_access_token(self, force_refresh: bool = False) -> str:
        """Return a bearer token: the one held for this run, else a valid cached one, else a new one.

        Args:
            force_refresh: Ignore any held or cached token, e.g. after the gateway rejected it.

        Returns:
            str: The access token.
        """
        now = time.time()
        if not force_refresh:
            if self._token is None and self._context is None:
                entry = cached_token_entry(self._integration_context(), self._cache_key, now)
                if entry:
                    self._token, self._token_valid_until = entry["access_token"], entry["valid_until"]
            if self._token and self._token_valid_until > now:
                return self._token
        return self._mint_token()

    def _mint_token(self) -> str:
        """Request a new token, hold it for the run and cache it in the integration context."""
        response = self.request_token()
        access_token = response.get("access_token")
        if not access_token:
            raise DemistoException("Strata Cloud Manager answered the token request without an access token.")
        expires_in = arg_to_number(response.get("expires_in")) or DEFAULT_TOKEN_LIFETIME_SECONDS
        self._token_minted_at = time.time()
        self._token = access_token
        self._token_valid_until = self._token_minted_at + expires_in - TOKEN_EXPIRY_MARGIN_SECONDS
        # Read-modify-write of the whole context: fine while the token is its only writer, but it would clobber
        # other keys if the shared module ever cached there too.
        context = self._integration_context()
        context[TOKEN_CACHE_CONTEXT_KEY] = {
            "cache_key": self._cache_key,
            "access_token": access_token,
            "valid_until": self._token_valid_until,
        }
        set_integration_context(context)
        return access_token

    def _holds_fresh_token(self) -> bool:
        """Whether the held token was minted by this run moments ago, so a 401 on it is not staleness."""
        return self._token_minted_at is not None and time.time() - self._token_minted_at < FRESH_TOKEN_SECONDS

    def request_token(self) -> dict[str, Any]:
        """Exchange the client credentials for an access token.

        Returns:
            dict: The token response, with `access_token` and `expires_in`.
        """
        # BaseClient's request, not ours: the token call must not carry a bearer token or retry on 401.
        response = BaseClient._http_request(
            self,
            "POST",
            full_url=self._oauth.token_url,
            auth=(self._oauth.client_id, self._oauth.client_secret),
            data={"grant_type": "client_credentials", "scope": f"tsg_id:{self._oauth.tsg_id}"},
            headers={**self._headers, "Content-Type": "application/x-www-form-urlencoded"},
            error_handler=raise_token_error,
        )
        return response or {}

    def _http_request(self, *args: Any, **kwargs: Any) -> Any:
        """Attach the bearer token, and retry once with a fresh token if the gateway answers 401.

        A cached token can be revoked or expire early; one retry separates that from a real rejection. A
        token this run minted moments ago is not retried, so a real rejection costs one request, not a loop.
        """
        error_handler = kwargs.get("error_handler") or self.raise_http_error
        headers = kwargs.get("headers") or self._headers

        def reject_stale_token(response: requests.Response) -> None:
            if response.status_code == 401 and not self._holds_fresh_token():
                raise TokenRejectedError("The gateway rejected the access token.")
            error_handler(response)

        kwargs["headers"] = {**headers, "Authorization": f"Bearer {self.get_access_token()}"}
        kwargs["error_handler"] = reject_stale_token
        try:
            return super()._http_request(*args, **kwargs)
        except TokenRejectedError:
            demisto.debug("The gateway rejected the access token; retrying once with a fresh one.")
        kwargs["headers"] = {**headers, "Authorization": f"Bearer {self.get_access_token(force_refresh=True)}"}
        kwargs["error_handler"] = error_handler
        return super()._http_request(*args, **kwargs)

    def raise_http_error(self, response: requests.Response) -> None:
        """Tell a web-filter block apart from a missing permission before the shared translation."""
        if response.status_code == 403 and (
            WEB_FILTER_HEADER in response.headers or "text/html" in response.headers.get("Content-Type", "")
        ):
            raise WebFilterBlockedError(web_filter_message({}))
        super().raise_http_error(response)

    def get_expiry_thresholds(self) -> list[int]:
        """Read the expiry thresholds the tenant notifies on, over REST."""
        return thresholds_from_configuration(
            self._http_request("GET", url_suffix=EXPIRY_THRESHOLDS_URL_SUFFIX, error_handler=self.raise_http_error)
        )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Prove that the client credentials yield a token the gateway accepts for a certificate search.

    `/v1/useraccounts`, which the CM SaaS integration uses, is 403 on NGTS; a one-certificate search
    exercises the token, the TSG and the inventory permission in one call. The token is minted fresh:
    a cached one would let the test pass on credentials that no longer work.

    Args:
        client: The NGTS client.

    Returns:
        str: 'ok' when the search succeeds.
    """
    client.get_access_token(force_refresh=True)
    client.search_certificates(first=1)
    demisto.debug(threshold_alignment_message(client))
    return "ok"


""" MAIN FUNCTION """


def build_client(params: dict[str, Any]) -> Client:
    """Construct the client from instance parameters.

    Args:
        params: `demisto.params()`.

    Returns:
        Client: A configured client.
    """
    credentials = params.get("credentials") or {}
    client_id = (credentials.get("identifier") or "").strip()
    client_secret = credentials.get("password") or ""
    tsg_id = (params.get("tsg_id") or "").strip()
    if not client_id or not client_secret or not tsg_id:
        raise DemistoException("The client ID, the client secret and the TSG ID are all required.")
    return Client(
        base_url=(params.get("url") or DEFAULT_BASE_URL).strip().rstrip("/"),
        oauth=OAuthSettings(
            token_url=(params.get("token_url") or DEFAULT_TOKEN_URL).strip(),
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
        ),
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
        elif command == "ngts-certificate-search":
            return_results(certificate_search_command(client, args))
        elif command == "ngts-certificate-get":
            return_results(certificate_get_command(client, args))
        elif command == "ngts-certificate-list-expiring":
            return_results(certificate_list_expiring_command(client, args))
        elif command == "ngts-machine-list":
            return_results(machine_list_command(client, args))
        elif command == "ngts-machine-get":
            return_results(machine_get_command(client, args))
        elif command == "ngts-certificate-revoke":
            return_results(certificate_revoke_command(client, args))
        elif command == "ngts-certificate-request":
            return_results(certificate_request_command(client, args))
        elif command == "ngts-certificate-request-status":
            return_results(certificate_request_status_command(client, args))
        elif command == "ngts-certificate-download":
            return_results(certificate_download_command(client, args))
        elif command == "ngts-certificate-keystore-download":
            return_results(certificate_keystore_download_command(client, args, keystore_passphrase(params)))
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(client, params, demisto.getLastRun() or {})
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error_message(command, args, error)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
