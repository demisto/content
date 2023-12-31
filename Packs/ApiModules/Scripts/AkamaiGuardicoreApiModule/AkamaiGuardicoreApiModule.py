from requests import Response
import demistomock as demisto
from CommonServerPython import *


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INTEGRATION_NAME = "Akamai Guardicore Api Module"


class AkamaiGuardicoreClient(BaseClient):
    """
    Client for Akamai Guardicore API

    Args:
       username (str): The GuardiCore username for API access.
       password (str): The GuardiCore password for API access.
       base_url (str): The GuardiCore API server URL.
    """

    def __init__(
        self, proxy: bool, verify: bool, base_url: str, username: str, password: str
    ):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.username = username
        self.password = password
        self.base_url = base_url
        self.access_token = ""
        self._headers = {}

        self.login()

    def http_request(
        self,
        method: str,
        url_suffix: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        timeout: Optional[int] = None,
    ):
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            timeout=timeout,
            error_handler=self._error_handler,
        )

    def _error_handler(self, res: Response):
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}\n"
        try:
            # Try to parse json error response
            error_entry = res.json()
            if "Invalid Credentials" in res.text:
                err_msg = "Authorization Error: make sure your username and password are correctly set."
            else:
                err_msg += json.dumps(error_entry)
            raise DemistoException(err_msg, res=res)

        except ValueError:
            err_msg += res.text
            raise DemistoException(err_msg, res=res)

    def login(self):
        integration_context = get_integration_context()

        if self._is_access_token_valid(integration_context):
            access_token = integration_context.get("access_token", "")
            self._set_access_token(access_token)
        else:
            demisto.debug(
                f"{INTEGRATION_NAME} - Generating a new token (old one isn't valid anymore)."
            )
            self.generate_new_token()

    def _set_access_token(self, access_token: str):
        self.access_token = access_token
        self._headers = {"Authorization": f"bearer {access_token}"}

    def _is_access_token_valid(self, integration_context: dict) -> bool:
        access_token_expiration = integration_context.get("expires_in")
        access_token = integration_context.get("access_token")
        demisto.debug(
            f"{INTEGRATION_NAME} - Checking if context has valid access token..."
            + f"expiration: {access_token_expiration}, access_token: {access_token}"
        )
        if access_token and access_token_expiration:
            access_token_expiration_datetime = datetime.strptime(
                access_token_expiration, DATE_FORMAT
            )
            return access_token_expiration_datetime > datetime.now()
        return False

    def generate_new_token(self):
        token = self.authenticate()
        self.save_jwt_token(token)
        self._set_access_token(token)

    def save_jwt_token(self, access_token: str):
        expiration = self.get_jwt_expiration(access_token)
        expiration_timestamp = datetime.fromtimestamp(expiration)
        context = {
            "access_token": access_token,
            "expires_in": expiration_timestamp.strftime(DATE_FORMAT),
        }
        set_integration_context(context)
        demisto.debug(
            f"New access token that expires in : {expiration_timestamp.strftime(DATE_FORMAT)}"
            f" was set to integration_context."
        )

    @staticmethod
    def get_jwt_expiration(token: str):
        if "." not in token:
            return 0
        jwt_token = base64.b64decode(token.split(".")[1] + "==")
        jwt_token = json.loads(jwt_token)
        return jwt_token.get("exp")

    def authenticate(self):
        body = {"username": self.username, "password": self.password}
        new_token = self.http_request(
            method="POST", url_suffix="/authenticate", json_data=body
        )

        if not new_token or not new_token.get("access_token"):
            raise DemistoException(
                f"{INTEGRATION_NAME} error: The client credentials are invalid."
            )

        new_token = new_token.get("access_token")
        return new_token
