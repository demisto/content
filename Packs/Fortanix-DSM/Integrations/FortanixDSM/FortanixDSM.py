import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
from base64 import b64encode, b64decode


# Disable insecure warnings
urllib3.disable_warnings()

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


def getMetadata(strMeta):
    metadata = {}
    try:
        if strMeta:
            metadata = json.loads(strMeta)
        else:
            return None
    except Exception:
        demisto.debug('Metadata is null')
    if not metadata:
        if isinstance(strMeta, str):
            raw_meta = strMeta.strip().split(',')
            for attr in raw_meta:
                k_v = attr.strip().split('=')
                metadata[k_v[0]] = k_v[1]
        if isinstance(strMeta, dict):
            metadata = strMeta
    return metadata


def get_headers(username, password, apikey=None, bearer=None):
    headers = {'Content-Type': 'application/json'}

    if bearer:
        headers['Authorization'] = f'Bearer {bearer}'
    if username and password:
        if username.find('CERTIFICATE') < 0 and password.find('PRIVATE KEY') < 0:
            headers['Authorization'] = 'Basic ' + \
                b64encode(b":".join([username.encode("latin1"),
                                     password.encode("latin1")])).decode('ascii')
    elif apikey:
        headers['Authorization'] = f'Basic {apikey}'

    return headers


''' CLIENT CLASS '''


class Client(BaseClient):

    def send_request(self, path, method='get', body=None, params=None):
        data = json.dumps(body) if body is not None else None
        params = params if params is not None else {}

        return self._http_request(method=method, url_suffix=path, data=data, params=params)


''' COMMAND FUNCTIONS '''


def test_module(client):
    try:
        path = 'sys/v1/session/auth'
        res = client.send_request(path, 'post')
        if res:
            return 'ok'
    except Exception as e:
        raise DemistoException(f"Check the username/password or API Key. Error: {e}.")


def list_secrets_command(client, args, gids=None):
    name = args.get('name')
    kid = args.get('kid')
    if page := args.get('page'):
        page = int(args.get('page'))

    path = 'crypto/v1/keys'
    params = {'obj_type': 'SECRET', 'sort': 'name:asc'}
    if state := args.get('state'):
        if state == 'enabled':
            state = True
        elif state == 'disabled':
            state = False
        elif state == 'deleted':
            params['show_deleted'] = 'true'
        elif state == 'destroyed':
            params['show_destroyed'] = 'true'
        state = state.lower()

    if page and page > 1:
        params['offset'] = str((page - 1) * 100 + 1)
    if kid:
        path = f'{path}/{kid}'
    elif name:
        params['name'] = name
    else:
        if group_id := args.get('group_id'):
            params['group_id'] = group_id
        elif gids and len(gids) and gids.find(' ') < 0 and gids.find(',') < 0:
            params['group_id'] = gids

    res = client.send_request(path, 'get', params=params)
    if not res:
        readable_output = tableToMarkdown('Found 0 Fortanix DSM Secrets', {})
        return CommandResults(
            outputs_prefix='No secrets found',
            readable_output=readable_output,
            outputs={},
            raw_response={}
        )

    if kid and res:
        output = res
        if len(res) == 1:
            output = res[0]
        readable_output = tableToMarkdown('Fortanix DSM Secret', output)
        return CommandResults(
            outputs_prefix='Fortanix.Secret',
            readable_output=readable_output,
            outputs=res,
            raw_response=res
        )
    else:
        mapped_secrets = [{
            'Name': secret['name'],
            'ID': secret['kid'],
            'Group': secret['group_id']
        } for secret in res if state is None or (state == secret['state'].lower() or state == secret['enabled'])]

        readable_output = tableToMarkdown(f'Found {len(mapped_secrets)} Fortanix DSM Secrets', mapped_secrets)
        return CommandResults(
            outputs_prefix='Fortanix.Secret',
            outputs_key_field='Kid',
            readable_output=readable_output,
            outputs=mapped_secrets,
            raw_response=res
        )


def fetch_secret_command(client, args):
    if not (kid := args.get('kid')):
        raise DemistoException('Secret cannot be fetched without a key ID')

    path = 'crypto/v1/keys/export'
    body = {'kid': kid}

    res = client.send_request(path, "post", body)
    value = ''
    if not res:
        raise DemistoException('Secret cannot be fetched.')
    else:
        try:
            if 'value' in res:
                if isBase64(res['value']):
                    value = b64decode(res['value']).decode("utf-8")
                else:
                    value = res['value']
        except Exception:
            value = res['value']

    mapped_value = [{'Value': value}]
    readable_output = tableToMarkdown('Fortanix DSM Secret', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Secret.Value',
        readable_output=readable_output,
        outputs=mapped_value,
        raw_response=res
    )


def import_secret_command(client, args, gids=None, rotate=False):

    path = 'crypto/v1/keys'
    method = 'put'
    if rotate:
        path = path + '/rekey'
        method = 'post'

    if not (name := args.get('name')):
        raise DemistoException('Secret cannot be imported without a name')
    if not (value := args.get('value')):
        raise DemistoException('Secret cannot be imported without a value')
    body = {
        'name': name,
        'value': b64encode(value.encode("utf-8")).decode('ascii'),
        'obj_type': 'SECRET',
        'key_ops': ['EXPORT', 'APPMANAGEABLE']
    }
    if group_id := args.get('group_id'):
        body['group_id'] = group_id
    elif gids and len(gids) and gids.find(' ') < 0 and gids.find(',') < 0:
        body['group_id'] = gids

    if metadata := getMetadata(args.get('metadata')):
        body['custom_metadata'] = metadata

    res = client.send_request(path, method, body)
    if not res:
        msg = 'Secret cannot be '
        msg = msg + 'created.' if rotate else msg + 'rotated.'
        raise DemistoException(msg)

    readable_output = tableToMarkdown('Fortanix DSM Secret', res)
    return CommandResults(
        outputs_prefix='Fortanix.Secret',
        readable_output=readable_output,
        outputs=res,
        raw_response=res
    )


def delete_secret_command(client, args):

    if not (kid := args.get('kid')):
        raise DemistoException('Secret cannot be deleted without a key ID')

    path = 'crypto/v1/keys/' + kid
    res = client.send_request(path, "delete")
    if res:
        raise DemistoException('Secret was not deleted.')

    mapped_value = [{'Result': 'OK'}]
    readable_output = tableToMarkdown('Fortanix DSM Secret', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Secret.Result',
        readable_output=readable_output,
        outputs=mapped_value
    )


def invoke_plugin_command(client, args):

    if not (pid := args.get('pid')):
        raise DemistoException('Plugin cannot be invoked without a Plugin UUID')

    plugin_input = '{}'
    if 'input' in args:
        args_input = args.get('input')
        try:
            if isBase64(args_input):
                plugin_input = json.loads(b64decode(args_input))
            if isJSON(args_input):
                plugin_input = json.loads(args_input)
            else:
                plugin_input = args_input
        except Exception:
            plugin_input = args_input

    path = 'sys/v1/plugins/' + pid
    res = client.send_request(path, "post", plugin_input)
    value: List[Dict[Any, Any]]
    if res and isinstance(res, dict):
        value = [res]
    elif res and isinstance(res, str):
        value = [{'Output': res}]
    else:
        value = [{'Output': 'OK'}]

    readable_output = tableToMarkdown('Fortanix DSM Plugin', value)
    return CommandResults(
        outputs_prefix='Fortanix.Plugin.Output',
        readable_output=readable_output,
        outputs=value,
        raw_response=res
    )


def encrypt_command(client, args, pkey=None, pmode=None):

    if not (data := args.get('data')):
        raise DemistoException('Protection requires data')

    key_name = pkey
    if 'key' in args:
        key_name = args.get('key')

    mode = pmode
    if 'mode' in args:
        mode = args.get('mode')

    path = 'crypto/v1/encrypt'
    body = {
        'key': {"name": key_name},
        'plain': b64encode(bytes(data, encoding="raw_unicode_escape")).decode('ascii'),
        'alg': 'AES',
        'mode': mode
    }
    res = client.send_request(path, "post", body)
    value = ''
    try:
        if 'cipher' in res:
            res['mode'] = mode
            value = b64encode(json.dumps(res).encode('ascii')).decode('ascii')
        else:
            value = res
    except Exception:
        value = res

    mapped_value = [{'Cipher': value}]
    readable_output = tableToMarkdown('Fortanix DSM Encryption', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Data.Cipher',
        readable_output=readable_output,
        outputs=mapped_value,
        raw_response=res
    )


def decrypt_command(client, args, pkey=None, pmode=None):

    payload_cipher = None
    if raw_cipher := args.get('cipher'):
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
        raise DemistoException('Protection requires cipher')

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

    if not iv and 'iv' in args:
        iv = args.get('iv')

    if not key_id:
        key_name = pkey
        key_id = args.get('key')

    if not mode:
        mode = pmode
        if 'mode' in args:
            mode = args.get('mode')

    path = 'crypto/v1/decrypt'
    body = {'cipher': cipher, 'alg': 'AES', 'mode': mode, 'key': {}}
    if key_name:
        body['key']['name'] = key_name
    else:
        body['key']['kid'] = key_id
    if iv:
        body['iv'] = iv

    res = client.send_request(path, "post", body)
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
    readable_output = tableToMarkdown('Fortanix DSM Decryption', mapped_value)
    return CommandResults(
        outputs_prefix='Fortanix.Data.Plain',
        readable_output=readable_output,
        outputs=mapped_value,
        raw_response=res
    )


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    dparams = demisto.params()
    command = demisto.command()

    proxy = dparams.get('proxy', False)
    verify_ssl = not dparams.get('insecure', False)

    if endpoint := dparams.get('server'):
        # guardrails-disable-line
        endpoint = re.sub(r'/[\/]+$/', '', endpoint)
        endpoint = re.sub(r'\/$', '', endpoint)

    username = dparams.get('credentials', {}).get('identifier')
    password = dparams.get('credentials', {}).get('password')
    apikey = dparams.get('token', '')
    if not ((username and password) or (apikey)):
        return_results('Either an API Key or other App credentials must be provided')

    if group_ids := dparams.get('group_ids', ''):
        group_ids = group_ids.strip()

    pkey = dparams.get('protection_key', None)
    pmode = dparams.get('protection_mode', None)

    try:
        if username.find('CERTIFICATE') > 0 and password.find('PRIVATE KEY') > 0:
            return_results('Client certificate is currently not supported')

        demisto.debug(f'Executing command: {command}')
        client = Client(
            base_url=endpoint,
            verify=verify_ssl,
            headers=get_headers(username, password, apikey),
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fortanix-list-secrets':
            return_results(list_secrets_command(client, args, group_ids))

        elif command == 'fortanix-get-secret-metadata':
            return_results(list_secrets_command(client, args, group_ids))  # if kid in args or single secret in list

        elif command == 'fortanix-fetch-secret':
            return_results(fetch_secret_command(client, args))

        elif command == 'fortanix-new-secret':
            return_results(import_secret_command(client, args, group_ids, False))

        elif command == 'fortanix-rotate-secret':
            return_results(import_secret_command(client, args, group_ids, True))

        elif command == 'fortanix-delete-secret':
            return_results(delete_secret_command(client, args))

        elif command == 'fortanix-invoke-plugin':
            return_results(invoke_plugin_command(client, args))

        elif command == 'fortanix-encrypt':
            return_results(encrypt_command(client, args, pkey, pmode))

        elif command == 'fortanix-decrypt':
            return_results(decrypt_command(client, args, pkey, pmode))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
