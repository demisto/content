import json
import tempfile
from base64 import b64decode, b64encode

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

''' HELPER FUNCTIONS '''


def isBase64(sb):
    try:
        if isinstance(sb, str):
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def isJSON(sb):
    try:
        if json.loads(sb):
            return True
    except Exception:
        return False


def get_server_url():
    url = demisto.params()['server']
    url = re.sub('/[\/]+$/', '', url)  # guardrails-disable-line
    url = re.sub('\/$', '', url)  # guardrails-disable-line
    return url


def getMetadata(strMeta):
    metadata = {}
    try:
        if strMeta:
            if isJSON(strMeta):
                metadata = json.loads(strMeta)
    except Exception:
        LOG('Metadata is null')
    if metadata is None or len(metadata) == 0:
        raw_meta = strMeta.strip().split(',')
        for attr in raw_meta:
            k_v = attr.strip().split('=')
            metadata[k_v[0]] = k_v[1]
    return metadata


def get_headers():
    headers = {'Content-Type': 'application/json'}

    if BEARER:
        headers['Authorization'] = 'Bearer ' + BEARER
    if USERNAME and PASSWORD:
        if USERNAME.find('CERTIFICATE') < 0 and PASSWORD.find('PRIVATE KEY') < 0:
            headers['Authorization'] = 'Basic ' + \
                b64encode(b":".join([USERNAME.encode("latin1"),
                                     PASSWORD.encode("latin1")])).decode('ascii')
    elif TOKEN:
        headers['Authorization'] = 'Basic ' + TOKEN

    return headers


def get_client_cert():
    if USERNAME.find('CERTIFICATE') > 0 and PASSWORD.find('PRIVATE KEY') > 0:
        fBundle = tempfile.NamedTemporaryFile(delete=False)
        fName = fBundle.name
        fBundle.write(bytes(USERNAME.replace('\\n', '\n'), 'ascii'))
        fBundle.write(bytes(PASSWORD.replace('\\n', '\n'), 'ascii'))
        fBundle.seek(0)
        fBundle.flush()
        fBundle.close()
        return (fName)
    else:
        return None


def login():
    path = 'sys/v1/session/auth'
    url = '{}/{}'.format(SERVER_URL, path)

    res = requests.request('POST', url, headers=get_headers(), cert=get_client_cert(), verify=VERIFY_SSL)

    if (res.status_code < 200 or res.status_code >= 300) and res.status_code not in DEFAULT_STATUS_CODES:
        try:
            error_body = res.json()
            if 'errors' in error_body and isinstance(error_body['errors'], list):
                error_body = ';'.join(error_body['errors']) if len(error_body['errors']) > 0 else 'None'
        except Exception as ex:
            demisto.error("Error in login: {}".format(ex))
            error_body = res.content

        return_error('Login failed with: {}, Error: {}'.format(str(res.status_code), error_body))

    auth_res = res.json()
    if not auth_res or 'expires_in' not in auth_res or 'access_token' not in auth_res:
        return_error('Could not authenticate user')

    return auth_res['access_token']


def send_request(path, method='get', body=None, params=None, headers=None):

    data = json.dumps(body) if body is not None else None
    params = params if params is not None else {}
    headers = headers if headers is not None else get_headers()

    url = '{}/{}'.format(SERVER_URL, path)

    res = requests.request(method, url, headers=headers, cert=get_client_cert(), data=data, params=params, verify=VERIFY_SSL)

    if res.status_code < 200 or res.status_code >= 300:
        try:
            error_body = res.json()
            if 'errors' in error_body and isinstance(error_body['errors'], list):
                error_body = ';'.join(error_body['errors']) if len(error_body['errors']) > 0 else 'None'
        except Exception as ex:
            demisto.error("Error in send_request (parsing error msg): {}".format(ex))
            error_body = res.content

        return_error('Request failed. Status code: {}, details: {}'.format(str(res.status_code), error_body))

    if res.content:
        return res.json()
    return ''


''' COMMAND FUNCTIONS '''


def test_command(cmd):
    path = 'sys/v1/health'
    if cmd == 'fortanix-test':
        path = 'sys/v1/version'
    res = send_request(path)
    if cmd == 'fortanix-test':
        readable_output = tableToMarkdown(f'Fortanix DSM status', res)
        return CommandResults(
            outputs_prefix='Fortanix.DSM',
            readable_output=readable_output,
            outputs=res
        )
    else:
        demisto.results('ok')


def list_secrets_command():
    group_id = demisto.args()['group_id'] if 'group_id' in demisto.args() else None
    name = demisto.args()['name'] if 'name' in demisto.args() else None
    kid = demisto.args()['kid'] if 'kid' in demisto.args() else None
    state = demisto.args()['state'] if 'state' in demisto.args() else None
    page = int(demisto.args()['page']) if 'page' in demisto.args() else None

    path = 'crypto/v1/keys'
    params = {
        'obj_type': 'SECRET',
        'sort': 'name:asc'
    }
    if state:
        if state == 'enabled':
            state = True
        if state == 'disabled':
            state = False
        elif state == 'deleted':
            params['show_deleted'] = 'true'
        elif state == 'destroyed':
            params['show_destroyed'] = 'true'

    if page and page > 1:
        params['offset'] = (page - 1) * 100 + 1
    if kid:
        path = path + '/' + kid
    elif name:
        params['name'] = name
    else:
        if group_id:
            params['group_id'] = group_id
        elif GROUP_IDS and len(GROUP_IDS) and GROUP_IDS.find(' ') < 0 and GROUP_IDS.find(',') < 0:
            params['group_id'] = GROUP_IDS

    res = send_request(path, 'get', params=params)
    if not res:
        return_error('Secrets not found')

    if kid and res:
        readable_output = tableToMarkdown(f'Fortanix DSM Secret', res)
        return CommandResults(
            outputs_prefix='Fortanix.Secret',
            readable_output=readable_output,
            outputs=res
        )
    elif len(res) == 1:
        readable_output = tableToMarkdown(f'Fortanix DSM Secret', res[0])
        return CommandResults(
            outputs_prefix='Fortanix.Secret',
            readable_output=readable_output,
            outputs=res[0]
        )
    else:
        mapped_secrets = [{
            'Name': secret['name'],
            'ID': secret['kid'],
            'Group': secret['group_id']
        } for secret in res if state == None or (state == secret['state'].lower() or state == secret['enabled'])]

        readable_output = tableToMarkdown(f'Found {len(mapped_secrets)} Fortanix DSM Secrets', mapped_secrets)
        return CommandResults(
            outputs_prefix='Fortanix.Secret',
            outputs_key_field='Kid',
            readable_output=readable_output,
            outputs=mapped_secrets
        )


def fetch_secret_command():

    if 'kid' in demisto.args():
        kid = demisto.args()['kid']
    else:
        return_error('Secret cannot be fetched without a key ID')

    path = 'crypto/v1/keys/export'
    body = {
        'kid': kid
    }

    res = send_request(path, "post", body)
    value = ''
    if not res:
        raise ValueError('Secret cannot be fetched.')
    else:
        try:
            if 'value' in res:
                if isBase64(res['value']):
                    value = b64decode(res['value']).decode("utf-8")
                else:
                    value = res['value']
            else:
                value = res
        except Exception:
            value = res['value']

    mapped_value = [{
        'Value': value
    }]
    readable_output = tableToMarkdown(f'Fortanix DSM Secret', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Secret.Value',
        readable_output=readable_output,
        outputs=mapped_value
    )


def import_secret_command(rotate=False):

    path = 'crypto/v1/keys'
    method = 'put'
    if rotate:
        path = path + '/rekey'
        method = 'post'

    group_id = demisto.args()['group_id'] if 'group_id' in demisto.args() else None
    body = {
        'name': demisto.args()['name'],
        'value': b64encode(demisto.args()['value'].encode("utf-8")).decode('ascii'),
        'obj_type': 'SECRET',
        'key_ops': ['EXPORT', 'APPMANAGEABLE']
    }
    if group_id:
        body['group_id'] = group_id
    elif GROUP_IDS and len(GROUP_IDS) and GROUP_IDS.find(' ') < 0 and GROUP_IDS.find(',') < 0:
        body['group_id'] = GROUP_IDS

    metadata = getMetadata(demisto.args()['metadata']) \
        if 'metadata' in demisto.args() else None
    if metadata:
        body['custom_metadata'] = metadata

    res = send_request(path, method, body)
    if not res:
        msg = 'Secret cannot be '
        msg = msg + 'created.' if rotate else msg + 'rotated.'
        raise ValueError(msg)

    readable_output = tableToMarkdown(f'Fortanix DSM Secret', res)
    return CommandResults(
        outputs_prefix='Fortanix.Secret',
        readable_output=readable_output,
        outputs=res
    )


def delete_secret_command():

    if 'kid' in demisto.args():
        kid = demisto.args()['kid']
    else:
        return_error('Secret cannot be deleted without a key ID')

    path = 'crypto/v1/keys/' + kid
    res = send_request(path, "delete")
    if res:
        raise ValueError('Secret was not deleted.')

    mapped_value = [{
        'Result': 'OK'
    }]
    readable_output = tableToMarkdown(f'Fortanix DSM Secret', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Secret.Result',
        readable_output=readable_output,
        outputs=mapped_value
    )


def invoke_plugin_command():

    if 'pid' in demisto.args():
        pid = demisto.args()['pid']
    else:
        raise ValueError('Plugin cannot be invoked without a Plugin UUID')

    plugin_input = '{}'
    if 'input' in demisto.args():
        args_input = demisto.args()['input']
        try:
            if isBase64(args_input):
                plugin_input = json.loads(b64decode(args_input))
            elif isJSON(args_input):
                plugin_input = json.loads(args_input)
            else:
                plugin_input = args_input
        except Exception:
            plugin_input = args_input

    # return_results(plugin_input)
    path = 'sys/v1/plugins/' + pid
    res = send_request(path, "post", plugin_input)
    value = ''
    if res and isinstance(res, dict):
        value = res
    elif res:
        value = [{
            'Output': res
        }]
    else:
        value = [{
            'Output': 'OK'
        }]

    readable_output = tableToMarkdown(f'Fortanix DSM Plugin', value)
    return CommandResults(
        outputs_prefix='Fortanix.Plugin.Output',
        readable_output=readable_output,
        outputs=value
    )


def encrypt_command():

    if 'data' in demisto.args():
        data = demisto.args()['data']
    else:
        return_error('Protection requires data')

    key_name = PROTECTION_KEY
    if 'key' in demisto.args():
        key_name = demisto.args()['key']

    mode = PROTECTION_MODE
    if 'mode' in demisto.args():
        mode = demisto.args()['mode']

    path = 'crypto/v1/encrypt'
    body = {
        'key': {"name": key_name},
        'plain': b64encode(bytes(data, encoding="raw_unicode_escape")).decode('ascii'),
        'alg': 'AES',
        'mode': mode
    }
    res = send_request(path, "post", body)
    value = ''
    try:
        if 'cipher' in res:
            res['mode'] = mode
            value = b64encode(json.dumps(res).encode('ascii')).decode('ascii')
        else:
            value = res
    except Exception:
        value = res

    mapped_value = [{
        'Cipher': value
    }]
    readable_output = tableToMarkdown(f'Fortanix DSM Encryption', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Data.Cipher',
        readable_output=readable_output,
        outputs=mapped_value
    )


def decrypt_command():

    payload_cipher = None
    if 'cipher' in demisto.args():
        raw_cipher = demisto.args()['cipher']
        try:
            if isBase64(raw_cipher):
                payload_cipher = json.loads(b64decode(raw_cipher))
            elif isJSON(raw_cipher):
                payload_cipher = json.loads(raw_cipher)
            else:
                payload_cipher = raw_cipher
        except Exception:
            payload_cipher = raw_cipher
    else:
        raise ValueError('Protection requires cipher')

    cipher = None
    key_name = None
    key_id = None
    iv = None
    mode = None
    if isinstance(payload_cipher, dict):
        if 'kid' in payload_cipher:
            key_id = payload_cipher['kid']
        if 'iv' in payload_cipher:
            iv = payload_cipher['iv']
        if 'mode' in payload_cipher:
            mode = payload_cipher['mode']
        cipher = payload_cipher['cipher']
    else:
        cipher = payload_cipher

    if not iv and 'iv' in demisto.args():
        iv = demisto.args()['iv']

    if not key_id:
        key_name = PROTECTION_KEY
        key_id = None
        if 'key' in demisto.args():
            key_id = demisto.args()['key']

    if not mode:
        mode = PROTECTION_MODE
        if 'mode' in demisto.args():
            mode = demisto.args()['mode']

    path = 'crypto/v1/decrypt'
    body = {
        'cipher': cipher,
        'alg': 'AES',
        'mode': mode,
        'key': {}
    }
    if key_name:
        body['key']['name'] = key_name
    else:
        body['key']['kid'] = key_id
    if iv:
        body['iv'] = iv

    res = send_request(path, "post", body)
    value = ''
    try:
        if 'plain' in res:
            if isBase64(res['plain']):
                value = b64decode(res['plain']).decode("utf-8")
            else:
                value = res['plain']
        else:
            value = res
    except Exception:
        value = res['plain']

    mapped_value = [{
        'Plain': value
    }]
    readable_output = tableToMarkdown(f'Fortanix DSM Decryption', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Data.Plain',
        readable_output=readable_output,
        outputs=mapped_value
    )


''' GLOBAL VARIABLES '''


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


USERNAME = None
PASSWORD = None
CREDENTIALS = demisto.params().get('credentials', {})
if CREDENTIALS:
    USERNAME = CREDENTIALS.get('identifier')
    PASSWORD = CREDENTIALS.get('password')

BEARER = None
TOKEN = demisto.params().get('token')
VERIFY_SSL = not demisto.params().get('tls_enforce', False)

BASE_URL = get_server_url()
SERVER_URL = BASE_URL  # + '/v1'

DEFAULT_STATUS_CODES = {999}

GROUP_IDS = demisto.params().get('group_ids', None)
if GROUP_IDS:
    GROUP_IDS = GROUP_IDS.strip()

PROTECTION_KEY = demisto.params().get('protection_key', None)
PROTECTION_MODE = demisto.params().get('protection_mode', None)


''' MAIN FUNCTION '''


def main() -> None:

    LOG('Executing command: ' + demisto.command())

    if (USERNAME and PASSWORD) or TOKEN:
        BEARER = login()
    elif not (BEARER or TOKEN):
        return_error('Either an API KEY or App/User credentials must be provided')

    try:
        if demisto.command() == 'test-module':
            test_command(demisto.command())
        if demisto.command() == 'fortanix-test':
            return_results(test_command(demisto.command()))
        elif demisto.command() == 'fortanix-list-secrets':
            return_results(list_secrets_command())
        elif demisto.command() == 'fortanix-get-secret-metadata':
            return_results(list_secrets_command())
        elif demisto.command() == 'fortanix-fetch-secret':
            return_results(fetch_secret_command())
        elif demisto.command() == 'fortanix-new-secret':
            return_results(import_secret_command(False))
        elif demisto.command() == 'fortanix-rotate-secret':
            return_results(import_secret_command(True))
        elif demisto.command() == 'fortanix-delete-secret':
            return_results(delete_secret_command())
        elif demisto.command() == 'fortanix-invoke-plugin':
            return_results(invoke_plugin_command())
        elif demisto.command() == 'fortanix-encrypt':
            return_results(encrypt_command())
        elif demisto.command() == 'fortanix-decrypt':
            return_results(decrypt_command())

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('Fortanix DSM', 'end', __line__())
