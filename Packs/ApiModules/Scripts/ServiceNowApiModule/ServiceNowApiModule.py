import uuid
from datetime import UTC

import jwt

from CommonServerPython import *

from CommonServerUserPython import *

OAUTH_URL = "/oauth_token.do"


class ServiceNowClient(BaseClient):
    def __init__(
        self,
        credentials: dict,
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
            - credentials: the username and password given by the user.
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
        if self.use_oauth:  # if user selected the `Use OAuth` box use OAuth authorization, else use basic authorization
            self.client_id = client_id
            self.client_secret = client_secret
        else:
            self.username = credentials.get("identifier")
            self.password = credentials.get("password")
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

    def get_access_token(self):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the client id, client secret and refresh token.
        """
        ok_codes = (200, 201, 401)
        previous_token = get_integration_context()

        # Check if there is an existing valid access token
        if previous_token.get("access_token") and previous_token.get("expiry_time") > date_to_timestamp(datetime.now()):
            return previous_token.get("access_token")
        else:
            data = {"client_id": self.client_id, "client_secret": self.client_secret}

            # Check if a refresh token exists. If not, raise an exception indicating to call the login function first.
            if previous_token.get("refresh_token"):
                data["refresh_token"] = previous_token.get("refresh_token")
                data["grant_type"] = "refresh_token"
            elif not self.jwt:
                raise Exception(
                    "Could not create an access token. User might be not logged in. Try running the oauth-login command first."
                )

            try:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if self.jwt:
                    data["assertion"] = self.jwt
                    data["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"

                res = super()._http_request(
                    method="POST", url_suffix=OAUTH_URL, resp_type="response", headers=headers, data=data, ok_codes=ok_codes
                )
                try:
                    res = res.json()
                except ValueError as exception:
                    raise DemistoException(f"Failed to parse json object from response: {res.content}", exception)
                if "error" in res:
                    return_error(
                        f"Error occurred while creating an access token. Please check the Client ID, Client Secret "
                        f"and try to run again the login command to generate a new refresh token as it "
                        f"might have expired.\n{res}"
                    )
                if res.get("access_token"):
                    expiry_time = date_to_timestamp(datetime.now(), date_format="%Y-%m-%dT%H:%M:%S")
                    expiry_time += res.get("expires_in", 0) * 1000 - 10
                    new_token = {
                        "access_token": res.get("access_token"),
                        "refresh_token": res.get("refresh_token"),
                        "expiry_time": expiry_time,
                    }
                    set_integration_context(new_token)
                    return res.get("access_token")
            except Exception as e:
                return_error(
                    f"Error occurred while creating an access token. Please check the instance configuration.\n\n{e.args[0]}"
                )
