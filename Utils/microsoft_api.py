from CommonServerPython import *
import demistomock as demisto

import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'


def get_access_token(auth_type, **kwargs):
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    valid_until = integration_context.get('valid_until')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token

    if auth_type == OPROXY_AUTH_TYPE:
        access_token, expires_in = oproxy_authorize(**kwargs)
    else:
        access_token, expires_in = get_self_deployed_token(**kwargs)

    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    demisto.setIntegrationContext({
        'access_token': access_token,
        'valid_until': time_now + expires_in
    })
    return access_token


def oproxy_authorize(url: str, app_name: str, tenant_id: str, auth_id: str, enc_key: str, use_ssl: bool = True):
    headers = {'Accept': 'application/json'}

    dbot_response = requests.post(
        url,
        headers=headers,
        data=json.dumps({
            'app_name': app_name,
            'registration_id': auth_id,
            'encrypted_token': get_encrypted(tenant_id, enc_key)
        }),
        verify=use_ssl
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info(f'Authentication failure from server: {dbot_response.status_code} {dbot_response.reason} '
                         f'{dbot_response.text}')
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += f' Server message: {server_msg}'
        except Exception as ex:
            demisto.error(f'Failed parsing error response - Exception: {ex}')
        raise Exception(msg)
    try:
        gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
        demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)

    return access_token, expires_in


def get_self_deployed_token(resource: str, tenant_id: str, client_id: str, client_secret: str, use_ssl: bool = True):
    url = f'https://login.windows.net/{tenant_id}/oauth2/token'
    resource_app_id_uri = resource
    data = {
        'resource': resource_app_id_uri,
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials'
    }
    body = {}
    try:
        response = requests.post(url, data, verify=use_ssl)
        body = response.json()
        if response.status_code != 200:
            return_error(f'Error in Microsoft authorization: {error_parser(body)}')

    except Exception as e:
        return_error(f'Error in Microsoft authorization: {str(e)}')

    access_token = body.get('access_token')
    expires_in = body.get('expires_on', 3595)

    return access_token, expires_in


def error_parser(error: requests.Response) -> str:
    """

    Args:
        error (requests.Response): response with error

    Returns:
        str: string of error

    """
    try:
        response = error.json()
        error = response.get('error', {})
        err_str = f"{error.get('code')}: {error.get('message')}"
        if err_str:
            return err_str
        # If no error message
        raise ValueError
    except ValueError:
        return error.text


def epoch_seconds(d: datetime = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.

    Args:
        d (datetime): timestamp
    Returns:
         int: timestamp in epoch
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted
