from CommonServerPython import *

import uuid
from datetime import datetime, timedelta
from enum import Enum

import jwt


TOKEN_EXPIRATION_TIME = 60  # In minutes. This value must be a maximum of only an hour (according to Okta's documentation).
TOKEN_RENEWAL_TIME_LIMIT = 60  # In seconds. The minimum time before the token expires to renew it.


class JWTAlgorithm(Enum):
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'


class AuthType(Enum):
    API_TOKEN = 1
    OAUTH = 2
    NO_AUTH = 3


class OktaClient(BaseClient):
    def __init__(self, auth_type: AuthType = AuthType.API_TOKEN, api_token: str | None = None,
                 client_id: str | None = None, scopes: list[str] | None = None, private_key: str | None = None,
                 jwt_algorithm: JWTAlgorithm | None = None, key_id: str | None = None, *args, **kwargs):
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

        missing_required_params = []

        if self.auth_type == AuthType.API_TOKEN and not api_token:
            raise ValueError('API token is missing')

        if self.auth_type == AuthType.OAUTH:
            if not self.client_id:
                missing_required_params.append('Client ID')

            if not self.scopes:
                missing_required_params.append('Scopes')

            if not self.jwt_algorithm:
                missing_required_params.append('JWT algorithm')

            if not self.private_key:
                missing_required_params.append('Private key')

            if missing_required_params:
                raise ValueError(f'Required OAuth parameters are missing: {", ".join(missing_required_params)}')

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
            url_suffix=f'/oauth2/v1/clients/{client_id}/roles',
            method='POST',
            json_data={
                'type': role,
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
            'aud': url,
            'iat': int((current_time - datetime(1970, 1, 1)).total_seconds()),
            'exp': int((expiration_time - datetime(1970, 1, 1)).total_seconds()),
            'iss': self.client_id,
            'sub': self.client_id,
            'jti': str(uuid.uuid4()),
        }

        headers = {}
        if self.key_id:
            headers['kid'] = self.key_id

        return jwt.encode(
            payload=payload,
            key=self.private_key,  # type: ignore[arg-type]
            algorithm=self.jwt_algorithm.value,  # type: ignore[union-attr]
            headers=headers
        )

    def generate_oauth_token(self, scopes: list[str]) -> dict:
        """
        Generate an OAuth token to use for authentication.

        Args:
            scopes (list[str]): A list of scopes to request for the token.

        Returns:
            dict: The response from the API.
        """
        auth_url = self._base_url + '/oauth2/v1/token'
        jwt_token = self.generate_jwt_token(url=auth_url)

        return self.http_request(
            auth_type=AuthType.NO_AUTH,
            full_url=auth_url,
            method='POST',
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data={
                'grant_type': 'client_credentials',
                'scope': ' '.join(scopes),
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': jwt_token,
            },
        )

    def get_token(self):
        """
        Get an OAuth token for authentication.
        If there isn't an existing one, or the existing one is expired, a new one will be generated.
        """
        expiration_time_format = '%Y-%m-%dT%H:%M:%S'

        integration_context = get_integration_context()
        token = integration_context.get('token')

        if token:
            if 'token_expiration' not in integration_context:
                raise ValueError('Token expiration data must be assigned along with the token.')

            token_expiration = datetime.strptime(integration_context['token_expiration'], expiration_time_format)

            if datetime.utcnow() + timedelta(seconds=TOKEN_RENEWAL_TIME_LIMIT) < token_expiration:
                return token

            demisto.debug('An existing token was found, but expired. A new token will be generated.')

        else:
            demisto.debug('No existing token was found. A new token will be generated.')

        token_generation_response = self.generate_oauth_token(scopes=self.scopes)  # type: ignore[arg-type]
        token: str = token_generation_response['access_token']
        expires_in: int = token_generation_response['expires_in']
        token_expiration = datetime.utcnow() + timedelta(seconds=expires_in)

        integration_context['token'] = token
        integration_context['token_expiration'] = token_expiration.strftime(expiration_time_format)
        set_integration_context(integration_context)
        demisto.debug(f'New token generated. Expiration time: {token_expiration}')

        return token

    def http_request(self, auth_type: AuthType | None = None, **kwargs):
        """
        Override BaseClient._http_request() to automatically add authentication headers.

        Args:
            auth_type (AuthType | None): Type of authentication to use for the request.
                If not provided, 'self.auth_type' will be used.
        """
        auth_type = auth_type if auth_type is not None else self.auth_type
        auth_headers = {}

        if auth_type == AuthType.OAUTH:
            auth_headers['Authorization'] = f'Bearer {self.get_token()}'

        elif auth_type == AuthType.API_TOKEN:
            auth_headers['Authorization'] = f'SSWS {self.api_token}'

        original_headers = kwargs.get('headers') or self._headers or {}
        kwargs['headers'] = {**auth_headers, **original_headers}
        return self._http_request(**kwargs)


def reset_integration_context():
    """
    Reset the integration context.
    """
    integration_context = get_integration_context()
    integration_context["token"] = "XXX"

    set_integration_context({})
    demisto.debug('Integration context reset successfully.\n'
                  f'Integration context before reset: {integration_context=}')
