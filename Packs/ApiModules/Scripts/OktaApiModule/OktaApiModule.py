import uuid
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import jwt
from CommonServerPython import *

TOKEN_EXPIRATION_TIME = 60  # In minutes. This value must be a maximum of only an hour (according to Okta's documentation).
TOKEN_RENEWAL_TIME_LIMIT = 60  # In seconds. The minimum time before the token expires to renew it.


class JWTAlgorithm(Enum):
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"


class AuthType(Enum):
    API_TOKEN = 1
    OAUTH = 2
    NO_AUTH = 3


def resolve_ucp_auth_type(default=AuthType.API_TOKEN):
    """
    Map the UCP-brokered credential to an AuthType (OAUTH for oauth2*, API_TOKEN for api_key).

    Args:
        default (AuthType): The AuthType to return when UCP auth is off (legacy path).

    Returns:
        AuthType: The AuthType matching the brokered credential, or default when UCP is off.

    Raises:
        DemistoException: When UCP is active but the brokered envelope type is unrecognized.
    """
    if not should_use_ucp_auth():
        return default
    creds = get_ucp_credentials()
    cred_type = creds.get("type") if isinstance(creds, dict) else None
    if cred_type and str(cred_type).startswith("oauth2"):
        return AuthType.OAUTH
    if cred_type == "api_key":
        return AuthType.API_TOKEN
    raise DemistoException(
        "UCP authentication failed: the system does not recognize the authentication method "
        f"(unrecognized credential type {cred_type!r})."
    )


class OktaClient(BaseClient):
    def __init__(
        self,
        auth_type: AuthType = AuthType.API_TOKEN,
        api_token: str | None = None,
        client_id: str | None = None,
        scopes: list[str] | None = None,
        private_key: str | None = None,
        jwt_algorithm: JWTAlgorithm | None = None,
        key_id: str | None = None,
        *args,
        **kwargs,
    ):
        """
        Args:
            auth_type (AuthType, optional): The type of authentication to use.
            api_token (str | None, optional): API token for authentication (required if 'auth_type' is AuthType.API_TOKEN).
            client_id (str | None, optional): Client ID for OAuth authentication (required if 'auth_type' is AuthType.OAUTH).
            scopes (list[str] | None, optional): A list of scopes to request for the token
                (required if 'auth_type' is AuthType.OAUTH).
            private_key (str | None, optional): Private key for OAuth authentication (required if 'auth_type' is AuthType.OAUTH).
            jwt_algorithm (str | None, optional): The algorithm to use for JWT signing
                (required if 'auth_type' is AuthType.OAUTH).
        """
        super().__init__(*args, **kwargs)
        self.auth_type = auth_type

        self.api_token = api_token

        self.client_id = client_id
        self.scopes = scopes
        self.jwt_algorithm = jwt_algorithm
        self.private_key = private_key
        self.key_id = key_id
        self.request_metadata: dict = {}

        missing_required_params = []

        # Under UCP the legacy auth params are not in demisto.params(), so skip these presence
        # checks; BaseClient injects the brokered credential at request time instead.
        if not should_use_ucp_auth():
            if self.auth_type == AuthType.API_TOKEN and not api_token:
                raise ValueError("API token is missing")

            if self.auth_type == AuthType.OAUTH:
                if not self.client_id:
                    missing_required_params.append("Client ID")

                if not self.scopes:
                    missing_required_params.append("Scopes")

                if not self.jwt_algorithm:
                    missing_required_params.append("JWT algorithm")

                if not self.private_key:
                    missing_required_params.append("Private key")

                if missing_required_params:
                    raise ValueError(f"Required OAuth parameters are missing: {', '.join(missing_required_params)}")

    def assign_app_role(self, client_id: str, role: str, auth_type: AuthType) -> dict:
        """
        Assign a role to a client application.

        Args:
            client_id (str): The ID of the client application.
            role (str): The role to assign to the client application.
            auth_type (AuthType, optional): Authentication type to use for the request. Defaults to AuthType.API_TOKEN.

        Returns:
            dict: The response from the API.
        """
        return self.http_request(
            auth_type=auth_type,
            url_suffix=f"/oauth2/v1/clients/{client_id}/roles",
            method="POST",
            json_data={
                "type": role,
            },
        )

    def generate_jwt_token(self, url: str) -> str:
        """
        Generate a JWT token to use for OAuth authentication.

        Args:
            url (str): The URL to use for the JWT token (for the 'aud' claim).

        Returns:
            str: The JWT token.
        """
        current_time = datetime.utcnow()
        expiration_time = current_time + timedelta(minutes=TOKEN_EXPIRATION_TIME)

        payload = {
            "aud": url,
            "iat": int((current_time - datetime(1970, 1, 1)).total_seconds()),
            "exp": int((expiration_time - datetime(1970, 1, 1)).total_seconds()),
            "iss": self.client_id,
            "sub": self.client_id,
            "jti": str(uuid.uuid4()),
        }

        headers = {}
        if self.key_id:
            headers["kid"] = self.key_id

        return jwt.encode(
            payload=payload,
            key=self.private_key,  # type: ignore[arg-type]
            algorithm=self.jwt_algorithm.value,  # type: ignore[union-attr]
            headers=headers,
        )

    def generate_oauth_token(self, scopes: list[str]) -> dict:
        """
        Generate an OAuth token to use for authentication.

        Args:
            scopes (list[str]): A list of scopes to request for the token.

        Returns:
            dict: The response from the API.
        """
        auth_url = self._base_url + "/oauth2/v1/token"
        jwt_token = self.generate_jwt_token(url=auth_url)

        return self.http_request(
            auth_type=AuthType.NO_AUTH,
            full_url=auth_url,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "client_credentials",
                "scope": " ".join(scopes),
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": jwt_token,
            },
        )

    def get_token(self):
        """
        Get an OAuth token for authentication.
        If there isn't an existing one, or the existing one is expired, a new one will be generated.
        """
        expiration_time_format = "%Y-%m-%dT%H:%M:%S"

        integration_context = get_integration_context()
        token = integration_context.get("token")

        if token:
            if "token_expiration" not in integration_context:
                raise ValueError("Token expiration data must be assigned along with the token.")

            token_expiration = datetime.strptime(integration_context["token_expiration"], expiration_time_format)

            if datetime.utcnow() + timedelta(seconds=TOKEN_RENEWAL_TIME_LIMIT) < token_expiration:
                return token

            demisto.debug("An existing token was found, but expired. A new token will be generated.")

        else:
            demisto.debug("No existing token was found. A new token will be generated.")

        token_generation_response = self.generate_oauth_token(scopes=self.scopes)  # type: ignore[arg-type]
        token: str = token_generation_response["access_token"]
        expires_in: int = token_generation_response["expires_in"]
        token_expiration = datetime.utcnow() + timedelta(seconds=expires_in)

        integration_context["token"] = token
        integration_context["token_expiration"] = token_expiration.strftime(expiration_time_format)
        set_integration_context(integration_context)
        demisto.debug(f"New token generated. Expiration time: {token_expiration}")

        return token

    @staticmethod
    def get_rate_limit_context(headers) -> dict:
        """Takes the response headers and returns the rate limit data to the context

        Args:
            headers: The response headers (can be dict or CaseInsensitiveDict)

        Returns:
            dict: The rate limit data to the context
        """
        rate_limit_context = {
            "x-rate-limit-limit": headers["x-rate-limit-limit"],
            "x-rate-limit-remaining": headers["x-rate-limit-remaining"],
            "x-rate-limit-reset": headers["x-rate-limit-reset"],
        }
        return rate_limit_context

    def parse_response_headers(self, raw_response: requests.Response):
        """deconstruct the raw response to headers and content"""
        headers = raw_response.headers
        self.request_metadata = self.get_rate_limit_context(headers)

    def _apply_ucp_api_key(self, credentials, ctx):
        """
        Override BaseClient._apply_ucp_api_key to place the brokered API token using Okta's
        ``SSWS`` scheme instead of the default ``Bearer`` scheme.

        Args:
            credentials (dict): The brokered credentials from getUCPCredentials().
            ctx (UcpRequestContext): The request context to mutate.
        """
        api_key_data = credentials.get("api_key", credentials)
        key = api_key_data.get("key", "")
        if not key:
            demisto.error("[UCP][OktaApiModule] API key is empty in UCP credentials")
            raise UcpException
        ctx.headers["Authorization"] = f"SSWS {key}"

    def http_request(self, auth_type: AuthType | None = None, resp_type: str = "json", **kwargs):
        """
        Override BaseClient._http_request() to automatically add authentication headers.

        Args:
            auth_type (AuthType | None): Type of authentication to use for the request.
                If not provided, 'self.auth_type' will be used.
        """
        auth_type = auth_type if auth_type is not None else self.auth_type
        auth_headers = {}

        # Under UCP the platform brokers the credential and BaseClient injects the header;
        # build the legacy header only when UCP is off (also covers the grouped connector).
        if not should_use_ucp_auth():
            if auth_type == AuthType.OAUTH:
                auth_headers["Authorization"] = f"Bearer {self.get_token()}"
            elif auth_type == AuthType.API_TOKEN:
                auth_headers["Authorization"] = f"SSWS {self.api_token}"

        original_headers = kwargs.get("headers") or self._headers or {}
        kwargs["headers"] = {**auth_headers, **original_headers}
        response = self._http_request(resp_type="response", **kwargs)

        self.parse_response_headers(response)

        resp_type = resp_type.lower()
        try:
            if resp_type == "json":
                return response.json()
            if resp_type == "text":
                return response.text
            if resp_type == "content":
                return response.content
            if resp_type == "xml":
                ET.fromstring(response.text)
            if resp_type == "response":
                return response
            return response
        except ValueError as exception:
            raise DemistoException(
                f"Failed to parse {resp_type} object from response: {response.content}",  # type: ignore[str-bytes-safe]
                exception,
                response,
            )


def reset_integration_context():
    """
    Reset the integration context.
    """
    integration_context = get_integration_context()
    integration_context["token"] = "XXX"

    set_integration_context({})
    demisto.debug(f"Integration context reset successfully.\nIntegration context before reset: {integration_context=}")


"""  OKTA V2 INTEGRATION  """


# CONSTANTS
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SEARCH_LIMIT = 200
OAUTH_TOKEN_SCOPES = [  # Scopes to request when generating an OAuth token
    "okta.apps.manage",
    "okta.apps.read",
    "okta.groups.manage",
    "okta.groups.read",
    "okta.logs.read",
    "okta.networkZones.manage",
    "okta.networkZones.read",
    "okta.sessions.manage",
    "okta.sessions.read",
    "okta.users.manage",
    "okta.users.read",
]
PROFILE_ARGS = [
    "firstName",
    "lastName",
    "email",
    "login",
    "secondEmail",
    "middleName",
    "honorificPrefix",
    "honorificSuffix",
    "title",
    "displayName",
    "nickName",
    "profileUrl",
    "primaryPhone",
    "mobilePhone",
    "streetAddress",
    "city",
    "state",
    "zipCode",
    "countryCode",
    "postalAddress",
    "preferredLanguage",
    "locale",
    "timezone",
    "userType",
    "employeeNumber",
    "costCenter",
    "organization",
    "division",
    "department",
    "managerId",
    "manager",
]
GROUP_PROFILE_ARGS = ["name", "description"]

MAX_LOGS_LIMIT = 1000
DEFAULT_POLLING_TIME = 5
DEFAULT_MAX_POLLING_CALLS = 10


class Client(OktaClient):
    # Getting Group Id with a given group name
    def get_group_id(self, group_name):
        uri = "/api/v1/groups"
        query_params = {"q": encode_string_results(group_name)}
        res = self.http_request(method="GET", url_suffix=uri, params=query_params)
        return next((r.get("id") for r in (res or []) if r.get("profile", {}).get("name") == group_name), None)

    def get_app_id(self, app_name):
        uri = "/api/v1/apps"
        query_params = {"q": encode_string_results(app_name)}
        res = self.http_request(method="GET", url_suffix=uri, params=query_params)
        if res and len(res) == 1:
            return res[0].get("id")
        return None

    # Getting User Id with a given username
    def get_user_id(self, username):
        uri = "/api/v1/users"
        query_params = {"filter": encode_string_results(f'profile.login eq "{username}"')}
        res = self.http_request(method="GET", url_suffix=uri, params=query_params)
        if res and len(res) == 1:
            return res[0].get("id")
        raise Exception(f"Failed to find userID for: {username} username.")

    def unlock_user(self, user_id):
        """
        sending a POST request to unlock a specific user
        """
        uri = f"/api/v1/users/{user_id}/lifecycle/unlock"
        return self.http_request(method="POST", url_suffix=uri)

    def deactivate_user(self, user_id):
        uri = f"/api/v1/users/{user_id}/lifecycle/deactivate"
        return self.http_request(method="POST", url_suffix=uri)

    def activate_user(self, user_id):
        uri = f"/api/v1/users/{user_id}/lifecycle/activate"
        return self.http_request(method="POST", url_suffix=uri)

    def suspend_user(self, user_id):
        uri = f"/api/v1/users/{user_id}/lifecycle/suspend"
        return self.http_request(method="POST", url_suffix=uri)

    def unsuspend_user(self, user_id):
        uri = f"/api/v1/users/{user_id}/lifecycle/unsuspend"
        return self.http_request(method="POST", url_suffix=uri)

    def get_user_factors(self, user_id):
        uri = f"/api/v1/users/{user_id}/factors"
        return self.http_request(method="GET", url_suffix=uri)

    def reset_factor(self, user_id, factor_id):
        uri = f"/api/v1/users/{user_id}/factors/{factor_id}"
        return self.http_request(method="DELETE", url_suffix=uri, resp_type="text")

    def set_password(self, user_id, password):
        uri = f"/api/v1/users/{user_id}"
        body = {"credentials": {"password": {"value": password}}}

        return self.http_request(method="POST", url_suffix=uri, json_data=body)

    def revoke_session(self, user_id):
        uri = f"/api/v1/users/{user_id}/lifecycle/expire_password_with_temp_password"
        params = {"revokeSessions": "true"}
        return self.http_request(method="POST", url_suffix=uri, params=params)

    def expire_password(self, user_id, args):
        uri = f"/api/v1/users/{user_id}/lifecycle/expire_password"
        params = {"tempPassword": args.get("temporary_password", "false")}
        return self.http_request(method="POST", url_suffix=uri, params=params)

    def add_user_to_group(self, user_id, group_id):
        uri = f"/api/v1/groups/{group_id}/users/{user_id}"
        return self.http_request(method="PUT", url_suffix=uri, resp_type="text")

    def remove_user_from_group(self, user_id, group_id):
        uri = f"/api/v1/groups/{group_id}/users/{user_id}"
        return self.http_request(method="DELETE", url_suffix=uri, resp_type="text")

    def get_groups_for_user(self, user_id):
        uri = f"/api/v1/users/{user_id}/groups"
        return self.http_request(method="GET", url_suffix=uri)

    @staticmethod
    def get_readable_groups(raw_groups):
        groups = []
        raw_groups = raw_groups if isinstance(raw_groups, list) else [raw_groups]
        for group in raw_groups:
            group = {
                "ID": group.get("id"),
                "Created": group.get("created"),
                "ObjectClass": group.get("objectClass"),
                "LastUpdated": group.get("lastUpdated"),
                "LastMembershipUpdated": group.get("lastMembershipUpdated"),
                "Type": group.get("type"),
                "Name": group.get("profile", {}).get("name"),
                "Description": group.get("profile", {}).get("description"),
            }
            groups.append(group)
        return groups

    @staticmethod
    def get_readable_logs(raw_logs):
        logs = []
        browser = ""
        device = ""
        os = ""
        raw_logs = raw_logs if isinstance(raw_logs, list) else [raw_logs]
        for log in raw_logs:
            if log.get("client", {}).get("userAgent"):
                browser = log.get("client", {}).get("userAgent").get("browser")
                if (not browser) or browser.lower() == "unknown":
                    browser = "Unknown browser"
                os = log.get("client", {}).get("userAgent").get("os")
                if (not os) or os.lower() == "unknown":
                    os = "Unknown OS"
                device = log.get("client", {}).get("device")
                if (not device) or device.lower() == "unknown":
                    device = "Unknown device"
            targets = ""
            if log.get("target"):
                for target in log.get("target"):
                    targets += f"{target.get('displayName')} ({target.get('type')})\n"
            time_published = datetime.strptime(log.get("published"), "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%m/%d/%Y, %H:%M:%S")
            log = {
                "Actor": f"{log.get('actor', {}).get('displayName')} ({log.get('actor', {}).get('type')})",
                "ActorAlternaneId": log.get("actor", {}).get("alternateId"),
                "EventInfo": log.get("displayMessage"),
                "EventOutcome": log.get("outcome", {}).get("result")
                + (f": {log.get('outcome', {}).get('reason')}" if log.get("outcome", {}).get("reason") else ""),
                "EventSeverity": log.get("severity"),
                "Client": f"{browser} on {os} {device}" if browser else "Unknown client",
                "RequestIP": log.get("client", {}).get("ipAddress"),
                "ChainIP": [ip_chain.get("ip") for ip_chain in log.get("request", {}).get("ipChain", [])],
                "Targets": targets or "-",
                "Time": time_published,
            }
            logs.append(log)
        return logs

    @staticmethod
    def get_readable_factors(raw_factors):
        factors = []
        for factor in raw_factors:
            factor = {
                "ID": factor.get("id"),
                "FactorType": factor.get("factorType"),
                "Provider": factor.get("provider"),
                "Status": factor.get("status"),
                "Profile": factor.get("profile"),
            }
            factors.append(factor)
        return factors

    def verify_push_factor(self, user_id, factor_id):
        """
        Creates a new transaction and sends an asynchronous push notification to the device for the user to approve or reject.
        You must poll the transaction to determine when it completes or expires.
        """
        uri = f"/api/v1/users/{user_id}/factors/{factor_id}/verify"
        return self.http_request(method="POST", url_suffix=uri)

    def poll_verify_push(self, url, polling_time: int = DEFAULT_POLLING_TIME, max_polling_calls: int = DEFAULT_MAX_POLLING_CALLS):
        """
        Keep polling authentication transactions with WAITING result until the challenge completes or expires.
        time limit defined by us = one minute
        """
        counter = 0
        while counter < max_polling_calls:
            response = self.http_request(method="GET", full_url=url, url_suffix="")
            if response.get("factorResult") != "WAITING":
                return response
            counter += 1
            time.sleep(polling_time)  # pylint: disable=E9003
        response["factorResult"] = "TIMEOUT"
        return response

    def get_push_factor_status(self, polling_url: str):
        """Get the status of the push factor"""
        response = self.http_request(method="GET", full_url=polling_url, url_suffix="")
        return response

    def search(self, term, limit, advanced_search):
        uri = "/api/v1/users"
        query_params = assign_params(limit=limit, q=encode_string_results(term), search=encode_string_results(advanced_search))
        return self.http_request(method="GET", url_suffix=uri, params=query_params)

    @staticmethod
    def get_users_context(raw_users):
        users = []
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        for user in raw_users:
            user = {
                "ID": user.get("id"),
                "Username": user.get("profile", {}).get("login"),
                "DisplayName": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}",
                "Email": user.get("profile", {}).get("email"),
                "Status": user.get("status"),
                "Type": "Okta",
                "Created": user.get("created"),
                "Activated": user.get("activated"),
                "StatusChanged": user.get("statusChanged"),
                "PasswordChanged": user.get("passwordChanged"),
                "Manager": user.get("profile", {}).get("manager"),
                "ManagerEmail": user.get("profile", {}).get("managerEmail"),
            }
            if user.get("group"):
                user["Group"] = user.get("group")
            users.append(user)
        return users

    @staticmethod
    def get_apps_context(raw_apps):
        apps = []
        raw_apps = raw_apps if isinstance(raw_apps, list) else [raw_apps]
        for app in raw_apps:
            app = {
                "ID": app.get("id"),
            }
            apps.append(app)
        return apps

    @staticmethod
    def get_groups_context(raw_groups):
        groups = []
        raw_groups = raw_groups if isinstance(raw_groups, list) else [raw_groups]
        for group in raw_groups:
            group = {
                "ID": group.get("id"),
                "Name": group.get("profile", {}).get("name"),
                "Description": group.get("profile", {}).get("description"),
                "Type": group.get("type"),
            }
            groups.append(group)
        return groups

    @staticmethod
    def get_readable_users(raw_users, verbose="false"):
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        if verbose == "true":
            users_verbose = ""
            for user in raw_users:
                profile = {
                    "First Name": user.get("profile", {}).get("firstName"),
                    "Last Name": user.get("profile", {}).get("lastName"),
                    "Mobile Phone": user.get("profile", {}).get("mobilePhone"),
                    "Login": user.get("profile", {}).get("login"),
                    "Email": user.get("profile", {}).get("email"),
                    "Second Email": user.get("profile", {}).get("secondEmail"),
                    "Manager": user.get("profile", {}).get("manager"),
                    "Manager Email": user.get("profile", {}).get("managerEmail"),
                }
                additionalData = {
                    "ID": user.get("id"),
                    "Status": user.get("status"),
                    "Created": user.get("created"),
                    "Activated": user.get("activated"),
                    "Status Changed": user.get("userChanged"),
                    "Last Login": user.get("lastLogin"),
                    "Last Updated": user.get("lastUpdated"),
                    "Password Changed": user.get("passwordChanged"),
                    "Type": user.get("type"),
                    "Credentials": user.get("credentials"),
                    "_links": user.get("_links"),
                }
                if user.get("group"):
                    additionalData["Group"] = user.get("group")
                users_verbose += (
                    f"### User:{profile.get('Login')}\n"
                    f"{tableToMarkdown('Profile', profile)}\n {tableToMarkdown('Additional Data', additionalData)}"
                )
            return users_verbose

        else:
            users = []
            for user in raw_users:
                user = {
                    "ID": user.get("id"),
                    "Login": user.get("profile").get("login"),
                    "First Name": user.get("profile").get("firstName"),
                    "Last Name": user.get("profile").get("lastName"),
                    "Mobile Phone": user.get("profile").get("mobilePhone"),
                    "Last Login": user.get("lastLogin"),
                    "Status": user.get("status"),
                    "Manager": user.get("profile", {}).get("manager"),
                    "Manager Email": user.get("profile", {}).get("managerEmail"),
                }
                users.append(user)
            return users

    def get_user(self, user_term):
        uri = f"/api/v1/users/{encode_string_results(user_term)}"
        return self.http_request(method="GET", url_suffix=uri)

    def create_user(self, cred, profile, group_ids, activate):
        body = {"profile": profile, "groupIds": group_ids or [], "credentials": cred}
        uri = "/api/v1/users"
        query_params = {"activate": activate, "provider": "true" if cred.get("provider") else None}
        return self.http_request(method="POST", url_suffix=uri, json_data=body, params=query_params)

    def create_group(self, profile):
        body = {
            "profile": profile,
        }
        uri = "/api/v1/groups"
        return self.http_request(method="POST", url_suffix=uri, json_data=body)

    # Build profile dict with pre-defined keys (for user)
    @staticmethod
    def build_profile(args):
        profile = {}
        keys = args.keys()
        for key in PROFILE_ARGS:
            if key in keys:
                profile[key] = args[key]
        return profile

    # Build profile dict with pre-defined keys (for group)
    @staticmethod
    def build_group_profile(args):
        profile = {}
        keys = args.keys()
        for key in GROUP_PROFILE_ARGS:
            if key in keys:
                profile[key] = args[key]
        return profile

    # Build credentials dict with predefined keys (for user)
    @staticmethod
    def build_credentials(args):
        cred = {}
        if args.get("password"):
            cred["password"] = {"value": args.get("password")}
        if args.get("passwordQuestion") and args.get("passwordAnswer"):
            cred["recovery_question"] = {"question": args.get("passwordQuestion"), "answer": args.get("passwordAnswer")}
        if args.get("providerName") and args.get("providerType"):
            cred["provider"] = {"name": args.get("providerName"), "type": args.get("providerType")}
        return cred

    def update_user(self, user_id, profile, cred):
        body = {"profile": profile, "credentials": cred}
        uri = f"/api/v1/users/{user_id}"
        return self.http_request(method="POST", url_suffix=uri, json_data=body)

    def get_paged_results(self, uri, query_param=None, max_limit=None):
        response = self.http_request(method="GET", url_suffix=uri, resp_type="response", params=query_param)
        paged_results = response.json()
        while "next" in response.links and len(response.json()) > 0:
            next_page = response.links.get("next").get("url")
            response = self.http_request(
                method="GET", full_url=next_page, url_suffix="", resp_type="response", params=query_param
            )
            paged_results += response.json()
            if max_limit and len(paged_results) >= max_limit:
                return paged_results[:max_limit]
        return paged_results

    def get_group_members(self, group_id, limit):
        uri = f"/api/v1/groups/{group_id}/users"
        if limit:
            query_params = {"limit": limit}
            return self.http_request(method="GET", url_suffix=uri, params=query_params)
        return self.get_paged_results(uri)

    def list_users(self, args):
        # Base url - if none of the above specified - returns all the users (default 200 items)
        uri = "/api/v1/users"
        query_params = {}
        for key, value in args.items():
            if key == "query":
                key = "q"
            query_params[key] = encode_string_results(value)
        limit = int(args.get("limit"))
        response = self.http_request(method="GET", url_suffix=uri, resp_type="response", params=query_params)
        paged_results = response.json()
        if limit > 200:
            query_params = {}
            limit -= 200
            while limit > 0 and "next" in response.links and len(response.json()) > 0:
                query_params["limit"] = encode_string_results(str(limit))
                next_page = delete_limit_param(response.links.get("next").get("url"))
                response = self.http_request(
                    method="GET", full_url=next_page, url_suffix="", resp_type="response", params=query_params
                )
                paged_results += response.json()
                limit -= 200
        after = None
        if "next" in response.links and len(response.json()) > 0:
            after = get_after_tag(response.links.get("next").get("url"))
        return (paged_results, after)

    def list_groups(self, args):
        # Base url - if none of the the above specified - returns all the groups (default 200 items)
        uri = "/api/v1/groups"
        query_params = {}
        for key, value in args.items():
            if key == "query":
                key = "q"
            query_params[key] = encode_string_results(value)
        if args.get("limit"):
            return self.http_request(method="GET", url_suffix=uri, params=query_params)
        return self.get_paged_results(uri, query_params)

    def get_logs(self, args):
        uri = "/api/v1/logs"
        query_params = {}
        for key, value in args.items():
            if key == "query":
                key = "q"
            query_params[key] = encode_string_results(value)
        limit = args.get("limit")
        limit = int(limit) if limit else None
        if limit and limit <= MAX_LOGS_LIMIT:
            return self.http_request(method="GET", url_suffix=uri, params=query_params)
        if limit and limit > MAX_LOGS_LIMIT:
            query_params["limit"] = MAX_LOGS_LIMIT
        return self.get_paged_results(uri, query_params, max_limit=limit)

    def delete_user(self, user_term):
        uri = f"/api/v1/users/{encode_string_results(user_term)}"
        return self.http_request(method="DELETE", url_suffix=uri, resp_type="text")

    def clear_user_sessions(self, user_id, revoke_oauth_tokens=True):
        uri = f"/api/v1/users/{user_id}/sessions"
        params = {"oauthTokens": revoke_oauth_tokens}
        return self.http_request(method="DELETE", url_suffix=uri, params=params, resp_type="text")

    def get_zone(self, zoneID):
        uri = f"/api/v1/zones/{zoneID}"
        return self.http_request(method="GET", url_suffix=uri)

    def list_zones(self, limit):
        uri = "/api/v1/zones"
        if limit:
            query_params = {"limit": encode_string_results(limit)}
            return self.http_request(method="GET", url_suffix=uri, params=query_params)
        return self.get_paged_results(uri)

    def create_zone(self, zoneObject):
        uri = "/api/v1/zones"
        return self.http_request(method="POST", url_suffix=uri, json_data=zoneObject)

    def update_zone(self, zoneObject):
        zoneID = zoneObject["id"]
        uri = f"/api/v1/zones/{zoneID}"

        return self.http_request(method="PUT", url_suffix=uri, data=json.dumps(zoneObject))

    def assign_group_to_app(self, group_id, app_id):
        uri = f"/api/v1/apps/{app_id}/groups/{group_id}"
        return self.http_request(method="PUT", url_suffix=uri, resp_type="text")


def module_test(client, args):
    if client.auth_type == AuthType.OAUTH:
        # For OAuth 2.0, there's no user the token belongs to, but an app. So the '/users/me' endpoint won't work.
        uri = "/api/v1/users"

    else:
        uri = "/api/v1/users/me"

    client.http_request(method="GET", url_suffix=uri)
    return "ok", None, None


def unlock_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.unlock_user(user_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }

    readable_output = f"### {args.get('username')} unlocked"

    return (
        readable_output,
        outputs,
        raw_response,  # raw response - the original response
    )


def activate_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.activate_user(user_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }

    readable_output = f"### {args.get('username')} is active now"
    return (readable_output, outputs, raw_response)


def deactivate_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.deactivate_user(user_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }

    readable_output = f"### User {args.get('username')} deactivated"

    return (
        readable_output,
        outputs,
        raw_response,  # raw response - the original response
    )


def suspend_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.suspend_user(user_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }

    readable_output = f"### {args.get('username')} status is Suspended"
    return (readable_output, outputs, raw_response)


def unsuspend_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.unsuspend_user(user_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }

    readable_output = f"### {args.get('username')} is no longer SUSPENDED"
    return (readable_output, outputs, raw_response)


def get_user_factors_command(client, args):
    user_id = args.get("userId")

    if not (args.get("username") or user_id):
        raise Exception("You must supply either 'Username' or 'userId")

    if not user_id:
        user_id = client.get_user_id(args.get("username"))

    raw_response = client.get_user_factors(user_id)
    if not raw_response or len(raw_response) == 0:
        return "No Factors found"

    factors = client.get_readable_factors(raw_response)
    context = createContext(factors, removeNull=True)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": {"Factor": context, "ID": user_id},
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"Factors for user: {user_id}\n {tableToMarkdown('Factors', factors)}"
    return (readable_output, outputs, raw_response)


def reset_factor_command(client, args):
    factor_id = args.get("factorId")
    user_id = args.get("userId")

    if not (args.get("username") or user_id):
        raise Exception("You must supply either 'Username' or 'userId")

    if not user_id:
        user_id = client.get_user_id(args.get("username"))

    raw_response = client.reset_factor(user_id, factor_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"Factor: {factor_id} deleted"
    return (readable_output, outputs, raw_response)


def set_password_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    password = args.get("password")

    raw_response = client.set_password(user_id, password)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"{args.get('username')} password was last changed on {raw_response.get('passwordChanged')}"

    if argToBoolean(args.get("temporary_password", False)):
        expire_password_response = client.expire_password(user_id, args)
        expire_password_readable_output = tableToMarkdown("Okta Temporary Password", expire_password_response, removeNull=True)
        readable_output = f"{readable_output}\n{expire_password_readable_output}"

    return readable_output, outputs, raw_response


def expire_password_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    hide_password = argToBoolean(args.get("hide_password", False))
    revoke_session = argToBoolean(args.get("revoke_session", False))

    if not (args.get("username") or user_id):
        raise Exception("You must supply either 'Username' or 'userId")
    if revoke_session is True:
        raw_response = client.revoke_session(user_id)
    else:
        raw_response = client.expire_password(user_id, args)
    if "tempPassword" in raw_response and hide_password:
        raw_response["tempPassword"] = "Output removed by user. hide_password argument set to True"
    user_context = client.get_users_context(raw_response)

    readable_output = tableToMarkdown("Okta Expired Password", raw_response, removeNull=True)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": createContext(user_context, removeNull=True),
        "Okta.Metadata(true)": client.request_metadata,
    }

    return (readable_output, outputs, raw_response)


def add_user_to_group_command(client, args):
    group_id = args.get("groupId")
    user_id = args.get("userId")

    if (not (args.get("username") or user_id)) or (not (args.get("groupName") or group_id)):
        raise Exception("You must supply either 'Username' or 'userId")
    if not user_id:
        user_id = client.get_user_id(args.get("username"))
    if not group_id:
        group_id = client.get_group_id(args.get("groupName"))
        if group_id is None:
            raise ValueError("The group was not found.")
    raw_response = client.add_user_to_group(user_id, group_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"User: {user_id} added to group: {args.get('groupName')} successfully"
    return (readable_output, outputs, raw_response)


def remove_from_group_command(client, args):
    group_id = args.get("groupId")
    user_id = args.get("userId")

    if (not (args.get("username") or user_id)) or (not (args.get("groupName") or group_id)):
        raise Exception("You must supply either 'Username' or 'userId' and either 'groupName' or 'groupId'")
    if not user_id:
        user_id = client.get_user_id(args.get("username"))
    if not group_id:
        group_id = client.get_group_id(args.get("groupName"))
        if group_id is None:
            raise ValueError("The group was not found.")
    raw_response = client.remove_user_from_group(user_id, group_id)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"User: {user_id} was removed from group: {args.get('groupName')} successfully"
    return (readable_output, outputs, raw_response)


def get_groups_for_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.get_groups_for_user(user_id)
    groups = client.get_readable_groups(raw_response)

    context = createContext(groups, removeNull=True)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": {"Group": context, "ID": user_id, "Type": "Okta"},
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"Okta groups for user: {args.get('username')}\n {tableToMarkdown('Groups', groups)}"

    return (readable_output, outputs, raw_response)


def verify_push_factor_command(client, args):
    user_id = args.get("userId")
    factor_id = args.get("factorId")
    polling_time = arg_to_number(args.get("polling_time", DEFAULT_POLLING_TIME))
    max_polling_calls = arg_to_number(args.get("max_polling_calls", DEFAULT_MAX_POLLING_CALLS))
    polling = argToBoolean(args.get("polling", True))

    raw_response = client.verify_push_factor(user_id, factor_id)
    poll_link = raw_response.get("_links").get("poll")
    if not poll_link:
        raise Exception("No poll link for the push factor challenge")
    if not polling:
        outputs = {"Okta.PollingStatusURL(true)": poll_link.get("href")}
        readable_output = (
            "Push factor challenge has been initiated. To check the push factor challenge status, "
            f"use the 'okta-verify-mfa-status' command with url: {poll_link.get('href')}"
        )
        return (readable_output, outputs, raw_response)

    poll_response = client.poll_verify_push(poll_link.get("href"), polling_time, max_polling_calls)

    outputs = {
        "Account(val.ID && val.ID === obj.ID)": {"ID": user_id, "VerifyPushResult": poll_response.get("factorResult")},
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"Verify push factor result for user {user_id}: {poll_response.get('factorResult')}"
    return (readable_output, outputs, raw_response)


def verify_mfa_status_command(client: Client, args: dict):
    """Checks the status of a push factor procedure

    Args:
        client (Client): The Okta client
        args (dict): The command arguments
    """
    polling_url = args.get("polling_url", "")
    user_id, factor_id = extract_user_and_factor_id_from_url(polling_url)

    raw_response = client.get_push_factor_status(polling_url)
    status = raw_response.get("factorResult")
    outputs = {
        "Okta.FactorResult(val.ID && val.ID === obj.ID)": {
            "ID": factor_id,
            "factorResult": status,
            "UserID": user_id,
        },
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"The status of the push factor challenge is {status}"
    return (readable_output, outputs, raw_response)


def search_command(client, args):
    term = args.get("term")
    limit = args.get("limit") or SEARCH_LIMIT
    verbose = args.get("verbose")
    advanced_search = args.get("advanced_search", "")
    if not term and not advanced_search:
        raise DemistoException("Please provide either the term or advanced_search argument")
    raw_response = client.search(term, limit, advanced_search)

    if raw_response and len(raw_response) > 0:
        users_context = client.get_users_context(raw_response)
        users_readable = client.get_readable_users(raw_response, verbose)
        context = createContext(users_context, removeNull=True)
        outputs = {
            "Account(val.ID && val.ID === obj.ID)": context,
            "Okta.Metadata(true)": client.request_metadata,
        }
        if verbose == "true":
            readable_output = f"### Okta users found:\n {users_readable}"
        else:
            readable_output = f"### Okta users found:\n {tableToMarkdown('Users:', users_readable)} "
        return (readable_output, outputs, raw_response)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    return "No users found in Okta", outputs, raw_response


def get_user_command(client: Client, args: dict):
    if not (args.get("username") or args.get("userId") or args.get("userEmail")):
        raise Exception("You must supply either 'Username' or 'userId' or 'userEmail'")

    raw_response = None
    if user_term := args.get("userEmail"):
        raw_response, _ = client.list_users({"filter": f'profile.email eq "{user_term}"', "limit": 1})
    else:
        user_term = args.get("userId") or args.get("username")
        try:
            raw_response = client.get_user(user_term)
        except Exception as e:
            if "404" not in str(e):
                raise e

    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return (f"User {user_term!r} was not found.", outputs, {})

    verbose = args.get("verbose")

    user_context = client.get_users_context(raw_response)
    user_readable = client.get_readable_users(raw_response, verbose)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": createContext(user_context),
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = user_readable if verbose == "true" else f"{tableToMarkdown(f'User:{user_term}', user_readable)} "
    return (readable_output, outputs, raw_response)


def create_user_command(client, args):
    group_ids = args.get("groupIds")
    cred = client.build_credentials(args)
    profile = client.build_profile(args)
    if group_ids:
        group_ids = args.get("groupIds").split(",")
    activate = "true" if args.get("activate") == "true" else "false"
    raw_response = client.create_user(cred, profile, group_ids, activate)
    user_context = client.get_users_context(raw_response)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": createContext(user_context),
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = tableToMarkdown(f"Okta User Created: {args.get('login')}:", client.get_readable_users(raw_response))
    return (readable_output, outputs, raw_response)


def update_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    cred = client.build_credentials(args)
    profile = client.build_profile(args)
    profile["login"] = args.get("username")
    raw_response = client.update_user(user_id, profile, cred)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = tableToMarkdown(f"Okta user: {args.get('username')} Updated:", raw_response.get("profile"))
    return (readable_output, outputs, raw_response)


def get_group_members_command(client, args):
    if not (args.get("groupId") or args.get("groupName")):
        raise Exception("You must supply either 'groupName' or 'groupId")
    limit = args.get("limit")
    group_id = args.get("groupId") or client.get_group_id(args.get("groupName"))
    if group_id is None:
        raise ValueError("The group was not found.")
    raw_members = client.get_group_members(group_id, limit)
    users_context = client.get_users_context(raw_members)
    users_readable = client.get_readable_users(raw_members, args.get("verbose"))
    context = createContext(users_context, removeNull=True)
    outputs = {
        "Account(val.ID && val.ID === obj.ID)": context,
        "Okta.Metadata(true)": client.request_metadata,
    }
    if args.get("verbose") == "true":
        return (f"### Users for group: {args.get('groupName') or group_id}:\n {users_readable}", outputs, raw_members)
    return (tableToMarkdown(f"Users for group: {args.get('groupName') or group_id}", users_readable), outputs, raw_members)


def list_users_command(client, args):
    raw_response, after_tag = client.list_users(args)
    verbose = args.get("verbose")
    users = client.get_readable_users(raw_response, verbose)
    user_context = client.get_users_context(raw_response)
    context = createContext(user_context, removeNull=True)
    if verbose == "true":
        readable_output = f"### Okta users found:\n {users}"
    else:
        readable_output = f"### Okta users found:\n {tableToMarkdown('Users', users)} "
    if after_tag:
        readable_output += f"\n### tag: {after_tag}"
    outputs = {
        "Account(val.ID && val.ID == obj.ID)": context,
        "Okta.User(val.tag)": {"tag": after_tag},
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def list_groups_command(client, args):
    raw_response = client.list_groups(args)
    groups = client.get_readable_groups(raw_response)
    context = createContext(groups, removeNull=True)
    outputs = {
        "Okta.Group(val.ID && val.ID === obj.ID)": context,
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = tableToMarkdown("Groups", groups)

    return (readable_output, outputs, raw_response)


def get_logs_command(client, args):
    raw_response = client.get_logs(args)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No logs found", outputs, raw_response

    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown("Okta Events", logs)
    outputs = {
        "Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def get_failed_login_command(client, args):
    args["filter"] = 'eventType eq "user.session.start" and outcome.result eq "FAILURE"'
    raw_response = client.get_logs(args)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No logs found", outputs, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown("Failed Login Events", logs)
    outputs = {
        "Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def get_group_assignments_command(client, args):
    args["filter"] = 'eventType eq "group.user_membership.add"'
    raw_response = client.get_logs(args)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No logs found", outputs, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown("Group Assignment Events", logs)
    outputs = {
        "Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def get_application_assignments_command(client, args):
    args["filter"] = 'eventType eq "application.user_membership.add"'
    raw_response = client.get_logs(args)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No logs found", outputs, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown("Application Assignment Events", logs)
    outputs = {
        "Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def get_application_authentication_command(client, args):
    args["filter"] = 'eventType eq "user.authentication.sso"'
    raw_response = client.get_logs(args)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No logs found", outputs, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown("Application Authentication Events", logs)
    outputs = {
        "Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def delete_user_command(client, args):
    if not (args.get("username") or args.get("userId")):
        raise Exception("You must supply either 'Username' or 'userId")
    user_term = args.get("userId") or args.get("username")
    # Deletes a user permanently. This operation can only be performed on users that have a DEPROVISIONED status.
    # This action cannot be recovered!This operation on a user that hasn't been deactivated
    # causes that user to be deactivated. A second delete operation is required to delete the user.
    user = client.get_user(user_term)
    if user.get("status") != "DEPROVISIONED":
        client.deactivate_user(args.get("userId") or client.get_user_id(args.get("username")))
    raw_response = client.delete_user(user_term)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"User: {user_term} was Deleted successfully"
    return (readable_output, outputs, raw_response)


def clear_user_sessions_command(client, args):
    user_id = args.get("userId")
    revoke_oauth_tokens = argToBoolean(args.get("revokeOauthTokens", True))
    raw_response = client.clear_user_sessions(user_id, revoke_oauth_tokens)
    outputs = {
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"### User session was cleared for: {user_id}"

    return readable_output, outputs, raw_response


def get_zone_command(client, args):
    raw_response = client.get_zone(args.get("zoneID", ""))
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No zones found.", outputs, raw_response
    readable_output = tableToMarkdown(
        "Okta Zones", raw_response, headers=["name", "id", "gateways", "status", "system", "lastUpdated", "created"]
    )
    outputs = {
        "Okta.Zone(val.id && val.id === obj.id)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def list_zones_command(client, args):
    raw_response = client.list_zones(args.get("limit"))
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "No zones found.", outputs, raw_response
    readable_output = tableToMarkdown(
        "Okta Zones", raw_response, headers=["name", "id", "gateways", "status", "system", "lastUpdated", "created"]
    )
    outputs = {
        "Okta.Zone(val.id && val.id === obj.id)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def apply_zone_updates(zoneObject, zoneName, gatewayIPs, proxyIPs, updateType="OVERRIDE"):
    # If user provided a new zone name - set it
    if zoneName:
        zoneObject["name"] = zoneName

    gateways = []
    proxies = []
    existing_gateways: list = zoneObject.get("gateways")
    existing_proxies: list = zoneObject.get("proxies")

    if gatewayIPs:
        for ip in gatewayIPs:
            if "-" in ip:  # Check for IP range notation
                gateways.append({"type": "RANGE", "value": ip})
            else:  # If not a range, treat it as a single IP
                cidr_value = f"{ip}/32" if "/" not in ip else f"{ip}"
                gateways.append({"type": "CIDR", "value": cidr_value})

        if existing_gateways is not None and updateType == "APPEND":
            zoneObject["gateways"] = existing_gateways + gateways
        else:
            zoneObject["gateways"] = gateways

    if proxyIPs:
        for ip in proxyIPs:
            if "-" in ip:  # Check for IP range notation
                proxies.append({"type": "RANGE", "value": ip})
            else:  # If not a range, treat it as a single IP
                cidr_value = f"{ip}/32" if "/" not in ip else f"{ip}"
                proxies.append({"type": "CIDR", "value": cidr_value})

        if existing_proxies is not None and updateType == "APPEND":
            zoneObject["proxies"] = existing_proxies + proxies
        else:
            zoneObject["proxies"] = proxies

    return zoneObject


def create_zone_command(client, args):
    zone_name = args.get("name")
    gateway_ips = argToList(args.get("gateway_ips"))
    proxies = argToList(args.get("proxies"))
    if not (gateway_ips or proxies):
        raise Exception("You must supply either 'gateway_ips' or 'proxies'.")

    zoneObject = {"name": "", "type": "IP", "status": "ACTIVE", "gateways": [], "proxies": []}
    zoneObject = apply_zone_updates(zoneObject, zone_name, gateway_ips, proxies)

    raw_response = client.create_zone(zoneObject)
    if not raw_response:
        outputs = {
            "Okta.Metadata(true)": client.request_metadata,
        }
        return "Zone not created.", outputs, raw_response
    readable_output = tableToMarkdown(
        "Okta Zones", raw_response, headers=["name", "id", "gateways", "status", "system", "lastUpdated", "created"]
    )
    outputs = {
        "Okta.Zone(val.id && val.id === obj.id)": createContext(raw_response),
        "Okta.Metadata(true)": client.request_metadata,
    }
    return (readable_output, outputs, raw_response)


def update_zone_command(client, args):
    if not args.get("zoneName", "") and not args.get("gatewayIPs", "") and not args.get("proxyIPs", ""):
        return ("Nothing to update", {}, "Nothing to update")
    zoneID = args.get("zoneID", "")
    updateType = args.get("updateType")
    zoneObject = client.get_zone(zoneID)
    if zoneID == zoneObject.get("id"):
        zoneName = args.get("zoneName", "")
        gatewayIPs = argToList(args.get("gatewayIPs", ""))
        proxyIPs = argToList(args.get("proxyIPs", ""))
        zoneObject = apply_zone_updates(zoneObject, zoneName, gatewayIPs, proxyIPs, updateType)

        raw_response = client.update_zone(zoneObject)
        if not raw_response:
            outputs = {
                "Okta.Metadata(true)": client.request_metadata,
            }
            return "Got empty response.", outputs, raw_response

        readable_output = tableToMarkdown(
            "Okta Zones", raw_response, headers=["name", "id", "gateways", "status", "system", "lastUpdated", "created"]
        )
        outputs = {
            "Okta.Zone(val.id && val.id === obj.id)": createContext(raw_response),
            "Okta.Metadata(true)": client.request_metadata,
        }
        return (readable_output, outputs, raw_response)
    else:
        return "No zone found in Okta with this ID.", {}, {}


def assign_group_to_app_command(client, args):
    group_id = args.get("groupId")
    if not group_id:
        group_id = client.get_group_id(args.get("groupName"))
        if group_id is None:
            raise ValueError("The group was not found.")
    app_id = client.get_app_id(args.get("appName"))
    raw_response = client.assign_group_to_app(group_id, app_id)
    outputs = {"Okta.Metadata(true)": client.request_metadata}
    readable_output = f"Group: {args.get('groupName')} added to PA App successfully"
    return (readable_output, outputs, raw_response)


def create_group_command(client, args):
    profile = client.build_group_profile(args)
    raw_response = client.create_group(profile)
    group_context = client.get_groups_context(raw_response)
    outputs = {
        "OktaGroup(val.ID && val.ID === obj.ID)": createContext(group_context),
        "Okta.Metadata(true)": client.request_metadata,
    }
    readable_output = f"Group Created: [GroupID:{raw_response['id']}, GroupName: {raw_response['profile']['name']}]"
    return (readable_output, outputs, raw_response)


def reset_auth_command(client, args):
    # Under UCP the token is cached per method_unique_id in CSP, not the integration context;
    # invalidate the UCP cache. Off UCP (grouped/legacy), clear the integration context as before.
    if should_use_ucp_auth():
        invalidate_ucp_credentials(get_ucp_method_unique_id())
    else:
        reset_integration_context()
    return CommandResults(readable_output="Authentication data cleared successfully.")


def get_after_tag(url):
    """retrieve the after param from the url

    Args:
        url: some url

    Returns:
        String: the value of the 'after' query param.
    """
    parsed_url = urlparse(url)
    captured_value = parse_qs(parsed_url.query)["after"][0]
    return captured_value


def delete_limit_param(url):
    """Delete the limit param from the url

    Args:
        url: some url

    Returns:
        String: the url with the limit query param.
    """
    parsed_url = urlparse(url)
    query_dict = parse_qs(parsed_url.query)
    query_dict.pop("limit")
    return urlunparse(parsed_url._replace(query=urlencode(query_dict, True)))


def extract_user_and_factor_id_from_url(url: str) -> tuple[str, str]:
    """Extracts the user ID and Factor ID from the polling url.

    Args:
        url (str): The polling url.

    Returns:
        tuple[str, str]: The user ID and Factor ID.
    """
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.split("/")
    # Example for url: https://example.okta.com/api/v1/users/user-id/factors/factor-id
    # path_parts: ['', 'api', 'v1', 'users', 'user-id', 'factors', 'factor-id']
    try:
        user_id = path_parts[path_parts.index("users") + 1]
        factor_id = path_parts[path_parts.index("factors") + 1]
        return user_id, factor_id
    except (ValueError, IndexError):
        raise DemistoException(f"Could not extract user ID and Factor ID from the polling URL: {url}")


def run_okta_v2_integration():
    try:
        params = demisto.params()

        demisto.debug(f"Command being called is {demisto.command()}")
        commands = {
            "test-module": module_test,
            "okta-unlock-user": unlock_user_command,
            "okta-deactivate-user": deactivate_user_command,
            "okta-activate-user": activate_user_command,
            "okta-suspend-user": suspend_user_command,
            "okta-unsuspend-user": unsuspend_user_command,
            "okta-reset-factor": reset_factor_command,
            "okta-set-password": set_password_command,
            "okta-expire-password": expire_password_command,
            "okta-add-to-group": add_user_to_group_command,
            "okta-remove-from-group": remove_from_group_command,
            "okta-get-groups": get_groups_for_user_command,
            "okta-get-user-factors": get_user_factors_command,
            "okta-verify-push-factor": verify_push_factor_command,
            "okta-verify-mfa-status": verify_mfa_status_command,
            "okta-search": search_command,
            "okta-get-user": get_user_command,
            "okta-create-user": create_user_command,
            "okta-update-user": update_user_command,
            "okta-get-group-members": get_group_members_command,
            "okta-list-users": list_users_command,
            "okta-list-groups": list_groups_command,
            "okta-get-logs": get_logs_command,
            "okta-get-failed-logins": get_failed_login_command,
            "okta-get-application-assignments": get_application_assignments_command,
            "okta-get-group-assignments": get_group_assignments_command,
            "okta-get-application-authentication": get_application_authentication_command,
            "okta-delete-user": delete_user_command,
            "okta-clear-user-sessions": clear_user_sessions_command,
            "okta-list-zones": list_zones_command,
            "okta-get-zone": get_zone_command,
            "okta-update-zone": update_zone_command,
            "okta-create-zone": create_zone_command,
            "okta-create-group": create_group_command,
            "okta-assign-group-to-app": assign_group_to_app_command,
            "okta-auth-reset": reset_auth_command,
        }

        command = demisto.command()

        client = Client(
            base_url=params["url"].rstrip("/"),
            verify=(not params.get("insecure", False)),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            proxy=params.get("proxy", False),
            ok_codes=(200, 201, 204),
            api_token=params.get("credentials", {}).get("password") or params.get("apitoken"),
            # Under UCP derive the auth type from the brokered envelope (an OAuth app token has no
            # "me" user); fall back to the legacy `use_oauth` param when UCP is off.
            auth_type=resolve_ucp_auth_type(
                default=AuthType.OAUTH if argToBoolean(params.get("use_oauth", False)) else AuthType.API_TOKEN
            ),
            client_id=params.get("client_id"),
            scopes=OAUTH_TOKEN_SCOPES,
            private_key=params.get("private_key"),
            jwt_algorithm=JWTAlgorithm(params["jwt_algorithm"]) if params.get("jwt_algorithm") else None,
            key_id=params.get("key_id", None),
        )

        if command in commands:
            result = commands[command](client, demisto.args())

            if isinstance(result, CommandResults | str | dict):
                return_results(result)

            else:
                human_readable, outputs, raw_response = result
                return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")
