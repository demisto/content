import uuid
from datetime import UTC

import jwt

from CommonServerPython import *

from CommonServerUserPython import *

OAUTH_URL = "/oauth_token.do"


class ServiceNowClient(BaseClient):
    def __init__(
        self,
        username: str = "",
        password: str = "",
        use_oauth: bool = False,
        client_id: str = "",
        client_secret: str = "",
        url: str = "",
        verify: bool = False,
        proxy: bool = False,
        headers: dict = None,
        jwt_params: dict = None,
    ):
        """
        ServiceNow Client class. The class can use either basic authorization with username and password, or OAuth2.
        Args:
            - username: the username for authentication.
            - password: the password for authentication.
            - client_id: the client id of the application of the user.
            - client_secret - the client secret of the application of the user.
            - url: the instance url of the user, i.e: https://<instance>.service-now.com.
                   NOTE - url should be given without an API specific suffix as it is also used for the OAuth process.
            - verify: Whether the request should verify the SSL certificate.
            - proxy: Whether to run the integration using the system proxy.
            - headers: The request headers, for example: {'Accept`: `application/json`}. Can be None.
            - use_oauth: a flag indicating whether the user wants to use OAuth 2.0 or basic authorization.
            - jwt_params: a dict containing the JWT parameters
        """
        self.auth = None
        self.use_oauth = use_oauth
        self.username = username
        self.password = password

        if self.use_oauth:  # if user selected the `Use OAuth` box use OAuth authorization, else use basic authorization
            self.client_id = client_id
            self.client_secret = client_secret
        else:
            self.auth = (self.username, self.password)

        self.jwt = self.create_jwt(jwt_params) if jwt_params else None

        if "@" in client_id:  # for use in OAuth test-playbook
            self.client_id, refresh_token = client_id.split("@")
            set_integration_context({"refresh_token": refresh_token})

        self.base_url = url
        super().__init__(base_url=self.base_url, verify=verify, proxy=proxy, headers=headers, auth=self.auth)  # type
        # : ignore[misc]

    def http_request(
        self,
        method,
        url_suffix,
        full_url=None,
        headers=None,
        json_data=None,
        params=None,
        data=None,
        files=None,
        return_empty_response=False,
        auth=None,
        timeout=None,
    ):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            if self.use_oauth:  # add a valid access token to the headers when using OAuth
                access_token = self.get_access_token()
                self._headers.update({"Authorization": "Bearer " + access_token})
            res = super()._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                resp_type="response",
                headers=headers,
                json_data=json_data,
                params=params,
                data=data,
                files=files,
                ok_codes=ok_codes,
                return_empty_response=return_empty_response,
                auth=auth,
                timeout=timeout,
            )
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)

            if res.status_code in [401]:
                if self.use_oauth:
                    if demisto.getIntegrationContext().get("expiry_time", 0) <= date_to_timestamp(datetime.now()):
                        access_token = self.get_access_token()
                        self._headers.update({"Authorization": "Bearer " + access_token})
                        return self.http_request(method, url_suffix, full_url=full_url, params=params)
                    try:
                        err_msg = f"Unauthorized request: \n{res.json()!s}"
                    except ValueError:
                        err_msg = f"Unauthorized request: \n{res!s}"
                    raise DemistoException(err_msg)
                else:
                    raise Exception(f"Authorization failed. Please verify that the username and password are correct.\n{res}")

        except Exception as e:
            if self._verify and "SSL Certificate Verification Failed" in e.args[0]:
                return_error(
                    "SSL Certificate Verification Failed - try selecting 'Trust any certificate' "
                    "checkbox in the integration configuration."
                )
            raise DemistoException(e.args[0])

    def login(self, username: str, password: str):
        """
        Generate a refresh token using the given client credentials and save it in the integration context.
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            res = super()._http_request(method="POST", url_suffix=OAUTH_URL, resp_type="response", headers=headers, data=data)
            try:
                res = res.json()
            except ValueError as exception:
                raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
            if "error" in res:
                return_error(
                    f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
                    f"and that the given username and password are correct.\n{res}"
                )
            if res.get("refresh_token"):
                refresh_token = {"refresh_token": res.get("refresh_token")}
                set_integration_context(refresh_token)
        except Exception as e:
            return_error(
                f"Login failed. Please check the instance configuration and the given username and password.\n{e.args[0]}"
            )

    @staticmethod
    def _validate_and_format_private_key(private_key: str) -> str:
        """
        Validate the private key format and reformat it to a valid PEM format.

        Supports these private key types:
            - PRIVATE KEY
            - RSA PRIVATE KEY
            - EC PRIVATE KEY
            - ENCRYPTED PRIVATE KEY

        Args:
            private_key (str): The user Private key.

        Raises:
            ValueError: If the private key format is incorrect.

        Returns:
            str: Key formatted in valid PEM with consistent newlines.
        """
        # Match and extract the first valid private key block
        pem_pattern = re.compile(
            r"-----BEGIN (?P<label>(ENCRYPTED )?(RSA |EC )?PRIVATE KEY)-----\s*" r"(?P<content>.*?)" r"\s*-----END \1-----",
            re.DOTALL,
        )

        match = pem_pattern.search(private_key)
        if not match:
            raise ValueError("Invalid private key format.")

        key_type = match.group("label")
        key_content = match.group("content")

        # Clean content: remove all non-base64 characters
        key_content = re.sub(r"[^A-Za-z0-9+/=]", "", key_content)

        # Format content into 64-character lines
        key_lines = [key_content[i : i + 64] for i in range(0, len(key_content), 64)]

        # Reattach markers
        processed_key = f"-----BEGIN {key_type}-----\n" + "\n".join(key_lines) + f"\n-----END {key_type}-----"

        return processed_key

    def create_jwt(self, jwt_params: dict) -> str:
        """
        Create JWT token
        Returns:
            JWT token
        """
        private_key = self._validate_and_format_private_key(jwt_params.get("private_key", ""))

        header = {
            "alg": "RS256",  # Signing algorithm
            "typ": "JWT",  # Token type
            "kid": jwt_params.get("kid"),
        }
        now = datetime.now(UTC)
        payload = {
            "sub": jwt_params.get("sub"),
            "aud": jwt_params.get("aud"),
            "iss": jwt_params.get("iss"),
            "iat": now,
            "exp": now + timedelta(hours=1),
            "jti": str(uuid.uuid4()),  # Unique JWT ID
        }
        try:
            jwt_token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
        except Exception:
            # Regenerate if failed
            jwt_token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
        return jwt_token

    def _can_auto_login(self) -> bool:
        """Check whether automatic login via username/password is possible."""
        return bool(self.use_oauth and self.username and self.password)

    def _attempt_auto_login(self, *, retry_attempted: bool, reason: str) -> str:
        """
        Try to automatically log in and retry token acquisition.

        Args:
            retry_attempted: Whether a retry has already been attempted.
            reason: Debug message explaining why auto-login is being attempted.

        Returns:
            A valid access token if auto-login succeeds.

        Raises:
            Exception: If retry was already attempted or credentials are unavailable.
        """
        if self._can_auto_login() and not retry_attempted:
            demisto.debug(reason)
            self.login(username=self.username, password=self.password)
            return self.get_access_token(retry_attempted=True)

        raise Exception(
            "Could not create an access token. User might be not logged in. "
            "Try running the oauth-login command first."
        )

    def _build_token_request_data(self, previous_token: dict, *, retry_attempted: bool) -> dict:
        """
        Build the request payload for the OAuth token endpoint.

        Determines the correct grant type based on available credentials:
        1. JWT assertion (if configured)
        2. Refresh token (if stored in integration context)
        3. Auto-login via username/password (first-time login fallback)

        Args:
            previous_token: The current integration context containing any stored tokens.
            retry_attempted: Whether a retry has already been attempted.

        Returns:
            The request data dict ready to POST to the token endpoint.

        Raises:
            Exception: If no grant type can be determined and auto-login is unavailable.
        """
        data: dict[str, str] = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        if self.jwt:
            data["assertion"] = self.jwt
            data["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        elif previous_token.get("refresh_token"):
            data["refresh_token"] = previous_token["refresh_token"]
            data["grant_type"] = "refresh_token"
        else:
            # No JWT and no refresh token — attempt first-time login if credentials are available.
            # This call either returns a token (via recursive get_access_token) or raises.
            self._attempt_auto_login(
                retry_attempted=retry_attempted,
                reason="No refresh token found. Attempting automatic first-time login.",
            )

        return data

    def _store_and_return_token(self, res: dict) -> str:
        """
        Persist a successful token response in the integration context and return the access token.

        Args:
            res: The parsed JSON response from the token endpoint.

        Returns:
            The new access token string.

        Raises:
            DemistoException: If the response does not contain an access token.
        """
        access_token = res.get("access_token")
        if not access_token:
            raise DemistoException(
                f"Token endpoint returned a successful response but no access_token was found.\n{res}"
            )

        expiry_time = date_to_timestamp(datetime.now(), date_format="%Y-%m-%dT%H:%M:%S")
        expiry_time += res.get("expires_in", 0) * 1000 - 10
        new_token = {
            "access_token": access_token,
            "refresh_token": res.get("refresh_token"),
            "expiry_time": expiry_time,
        }
        set_integration_context(new_token)
        return access_token

    def get_access_token(self, retry_attempted: bool = False) -> str:
        """
        Return a valid access token — reusing a cached one if still valid, otherwise requesting a new one.

        The method handles three grant flows transparently:
        1. **JWT bearer** — used when ``jwt_params`` were provided at init time.
        2. **Refresh token** — used when a refresh token is stored in the integration context.
        3. **Password grant (auto-login)** — used as a fallback when no refresh token exists
           and ``username``/``password`` are available (first-time login or expired refresh token).

        Args:
            retry_attempted: Internal flag to prevent infinite retry loops. Should not be set by callers.

        Returns:
            A valid access token string.

        Raises:
            Exception: If no token can be obtained and auto-login is not possible.
        """
        previous_token = get_integration_context()

        # 1. Return cached token if still valid
        if previous_token.get("access_token") and previous_token.get("expiry_time", 0) > date_to_timestamp(datetime.now()):
            return previous_token["access_token"]

        # 2. Build the token request (determines grant type or triggers auto-login)
        data = self._build_token_request_data(previous_token, retry_attempted=retry_attempted)

        # 3. Request a new token from the OAuth endpoint
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            res = super()._http_request(
                method="POST",
                url_suffix=OAUTH_URL,
                resp_type="response",
                headers=headers,
                data=data,
                ok_codes=(200, 201, 401),
            )
            try:
                res = res.json()
            except ValueError as exception:
                raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
        except Exception as e:
            return_error(
                f"Error occurred while creating an access token. "
                f"Please check the instance configuration.\n\n{e.args[0]}"
            )

        # 4. Handle error responses (e.g. expired refresh token)
        if "error" in res:
            # Attempt auto-login to regenerate the refresh token; raises if retry already attempted.
            return self._attempt_auto_login(
                retry_attempted=retry_attempted,
                reason="Refresh token may have expired, automatically generating new refresh token via login",
            )

        # 5. Persist and return the new token
        return self._store_and_return_token(res)
