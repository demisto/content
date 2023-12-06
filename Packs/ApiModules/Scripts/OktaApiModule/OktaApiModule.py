from CommonServerPython import *

import jwt
import uuid
from datetime import datetime, timedelta
from enum import Enum


AUTH_ENDPOINT = '/oauth2/v1/token'
TOKEN_EXPIRATION_TIME = 60  # In minutes. This value must be a maximum of only an hour (according to Okta's documentation).


class JWTAlgorithm(Enum):
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'


class OktaClient(BaseClient):
    def __init__(self, api_token: str, use_oauth: bool = False, client_id: str | None = None, scopes: list[str] | None = None,
                 private_key: str | None = None, jwt_algorithm: JWTAlgorithm | None = None, *args, **kwargs):
        """
        Args:
            api_token (str): API token for authentication.
            use_oauth (bool, optional): Whether to use OAuth authentication.
            client_id (str | None, optional): Client ID for OAuth authentication (required if 'use_oauth' is True).
            scopes (list[str] | None, optional): A list of scopes to request for the token (required if 'use_oauth' is True).
            private_key (str | None, optional): Private key for OAuth authentication (required if 'use_oauth' is True).
            jwt_algorithm (str | None, optional): The algorithm to use for JWT signing (required if 'use_oauth' is True).
        """
        super().__init__(*args, **kwargs)
        self.api_token = api_token
        self.use_oauth = use_oauth
        self.client_id = client_id
        self.scopes = scopes
        self.private_key = private_key
        self.jwt_algorithm = jwt_algorithm

        if self.use_oauth:
            if not self.client_id:
                raise ValueError('Client ID must be provided when using OAuth authentication.')

            if not scopes:
                raise ValueError('Scopes must be provided when using OAuth authentication.')

            if not jwt_algorithm:
                raise ValueError('JWT algorithm must be provided when using OAuth authentication.')

            if not private_key:
                raise ValueError('Private key must be provided when using OAuth authentication.')

            # Add "SUPER_ADMIN" role to client application, which is required for OAuth authentication
            self.assign_app_role(client_id=self.client_id, role="SUPER_ADMIN", use_oauth=False)

            self.get_token()

    def assign_app_role(self, client_id: str, role: str, use_oauth: bool | None = None) -> dict:
        """
        Assign a role to a client application.

        Args:
            client_id (str): The ID of the client application.
            role (str): The role to assign to the client application.
            use_oauth (bool | None, optional): Whether to use OAuth authentication.

        Returns:
            dict: The response from the API.
        """
        return self._http_request(
            url_suffix=f'/oauth2/v1/clients/{client_id}/roles',
            method='POST',
            json_data={
                'type': role,
            },
            use_oauth=use_oauth,
        )

    def generate_jwt_token(self, url_suffix: str):
        """
        Generate a JWT token to use for OAuth authentication.

        Args:
            url_suffix (str): The URL suffix to use for the JWT token (for the 'aud' claim).

        """
        current_time = datetime.utcnow()
        expiration_time = current_time + timedelta(minutes=TOKEN_EXPIRATION_TIME)

        return jwt.encode(
            payload={
                'aud': self._base_url + url_suffix,
                'iat': int((current_time - datetime(1970, 1, 1)).total_seconds()),
                'exp': int((expiration_time - datetime(1970, 1, 1)).total_seconds()),
                'iss': self.client_id,
                'sub': self.client_id,
                'jti': str(uuid.uuid4()),
            },
            key=self.private_key,
            algorithm=self.jwt_algorithm.value,
        )

    def generate_oauth_token(self, scopes: list[str]) -> dict:
        """
        Generate an OAuth token to use for authentication.

        Args:
            scopes (list[str]): A list of scopes to request for the token.

        Returns:
            dict: The response from the API.
        """
        auth_endpoint = '/oauth2/v1/token'
        jwt_token = self.generate_jwt_token(url_suffix=auth_endpoint)

        return self._http_request(
            url_suffix=auth_endpoint,
            method='POST',
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            params={
                'grant_type': 'client_credentials',
                'scope': ' '.join(scopes),
            },
            client_assertion_type=jwt_token,
        )

    def get_token(self):
        """
        Get an API token for authentication.
        If there isn't an existing one, or the existing one is expired, a new one will be generated.
        """
        expiration_time_format = '%Y-%m-%dT%H:%M:%S'

        integration_context = get_integration_context()
        token = integration_context.get('token')

        if token:
            if 'token_expiration' not in integration_context:
                raise ValueError('Token expiration data must be assigned along with the token.')

            token_expiration = integration_context['token_expiration'].strptime(expiration_time_format)

            if token_expiration > datetime.utcnow():
                demisto.debug('An existing token was found valid, and will be used.')
                return token

            demisto.debug('An existing token was found but expired. A new token will be generated.')

        else:
            demisto.debug('No existing token was found. A new token will be generated.')

        token_generation_response = self.generate_oauth_token(scopes=self.scopes)
        token = token_generation_response['access_token']
        token_expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_TIME)

        set_integration_context({
            'token': token,
            'token_expiration': token_expiration.strftime(expiration_time_format),
        })

        return token

    def _http_request(self, use_oauth: bool | None = None, **kwargs):
        """
        Override BaseClient._http_request() to automatically add authentication headers.

        Args:
            use_oauth (bool): Whether to use OAuth authentication. If not provided, the value of 'self.use_oauth' will be used.
        """
        use_oauth = use_oauth if use_oauth is not None else self.use_oauth

        if use_oauth:
            auth_headers = {'Authorization': f'Bearer {self.get_token()}'}

        else:
            auth_headers = {'Authorization': f'SSWS {self.api_token}'}

        original_headers = kwargs.get('headers', {})
        kwargs['headers'] = {**auth_headers, **original_headers}
        demisto.debug('kwargs: ' + str(kwargs))
        return super()._http_request(**kwargs)
