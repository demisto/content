import demistomock as demisto  # noqa: F401
import hcl
from CommonServerPython import *  # noqa: F401

''' GLOBAL VARIABLES '''

CREDENTIALS = demisto.params().get('credentials', {})
USERNAME = None
PASSWORD = None
# Used to make sure we generate a new token before the old one expires, in seconds, only relevant to AWS
AWS_TOKEN_OVERLAP_TIME = 600
if CREDENTIALS:
    USERNAME = CREDENTIALS.get('identifier')
    PASSWORD = CREDENTIALS.get('password')
VERIFY_SSL = not demisto.params().get('unsecure', False)
TOKEN = demisto.params().get("credentials_token", {}).get('password') or demisto.params().get('token')
NAMESPACE = demisto.params().get('namespace')
USE_APPROLE_AUTH_METHOD = argToBoolean(demisto.params().get('use_approle', 'false') or 'false')
BASE_URL = demisto.params().get('server', '')
SERVER_URL = BASE_URL + '/v1'

DEFAULT_STATUS_CODES = {
    429,
    472,
    473
}

''' HELPER FUNCTIONS '''


def get_headers():
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Request': 'true'
    }

    if TOKEN:  # pragma: no cover
        headers['X-Vault-Token'] = TOKEN

    if NAMESPACE:  # pragma: no cover
        headers['X-Vault-Namespace'] = NAMESPACE

    return headers


def login():  # pragma: no cover
    if USE_APPROLE_AUTH_METHOD:
        path = 'auth/approle/login'  # type: ignore
        body = {
            'role_id': USERNAME,
            'secret_id': PASSWORD
        }
    else:
        path = 'auth/userpass/login/' + USERNAME  # type: ignore
        body = {
            'password': PASSWORD
        }

    url = urljoin(SERVER_URL, path)
    payload = json.dumps(body)
    headers = get_headers()
    res = requests.request("POST", url, headers=headers, data=payload, verify=VERIFY_SSL, allow_redirects=True)
    if (res.status_code < 200 or res.status_code >= 300) and res.status_code not in DEFAULT_STATUS_CODES:
        try:
            error_body = res.json()
            if 'errors' in error_body and isinstance(error_body['errors'], list):
                error_body = ';'.join(error_body['errors']) if len(error_body['errors']) > 0 else 'None'
        except Exception as ex:
            demisto.error(f"Error in login (parsing error msg): {ex}")
            error_body = res.content
        return_error(f'Login failed. Status code: {str(res.status_code)}, details: {error_body}')

    auth_res = res.json()
    if not auth_res or 'auth' not in auth_res or 'client_token' not in auth_res['auth']:
        return_error('Could not authenticate user')

    return auth_res['auth']['client_token']


def send_request(path, method='get', body=None, params=None, headers=None):
    body = body if body is not None else {}
    params = params if params is not None else {}

    url = urljoin(SERVER_URL, path)

    headers = headers if headers is not None else get_headers()
    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params, verify=VERIFY_SSL)
    if res.status_code < 200 or res.status_code >= 300:
        try:
            error_body = res.json()
            if 'errors' in error_body and isinstance(error_body['errors'], list):
                error_body = ';'.join(error_body['errors']) if len(error_body['errors']) > 0 else 'None'
        except Exception as ex:
            demisto.error(f"Error in send_request (parsing error msg): {ex}")
            error_body = res.content
        return_error(f'Request failed. Status code: {str(res.status_code)}, details: {error_body}')
    if res.content:
        return res.json()
    return ''


''' FUNCTIONS '''


def generate_role_secret_command():
    """
    Generate a secret ID for a specified AppRole in the authentication system.
    Args:
        args (dict): A dictionary containing the following keys:
            - 'role_name' (required): The name of the AppRole for which the secret ID is generated.
            - 'meta_data': Metadata associated with the secret ID.
            - 'cidr_list': Comma-separated list of CIDR blocks from which requests using the secret ID are allowed.
            - 'token_bound_cidrs': Comma-separated list of CIDR blocks to restrict tokens issued with this secret ID.
            - 'num_uses': Number of times the secret ID can be used before it expires.
            - 'ttl_seconds': Time duration in seconds for which the secret ID remains valid.
    Returns:
        CommandResults: The command results object containing the response from the Vault server as readable output.
    """
    args = demisto.args()
    role_name = args.get('role_name')
    meta_data = args.get('meta_data')
    cidr_list = argToList(args.get('cidr_list', ''))
    token_bound_cidrs = argToList(args.get('token_bound_cidrs', ''))
    num_uses = arg_to_number(args.get('num_uses', ''))
    ttl_seconds = arg_to_number(args.get('ttl_seconds', ''))

    path = f'/auth/approle/role/{role_name}/secret-id'
    body = {
        "metadata": meta_data,
        "cidr_list": cidr_list,
        "token_bound_cidrs": token_bound_cidrs,
        "ttl": ttl_seconds,
        "num_uses": num_uses
    }
    body = remove_empty_elements(body)

    response = send_request(path=path, method='post', body=body)
    return_results(CommandResults(readable_output=response))


def get_role_id_command():
    """
    Retrieve the Role ID associated with a specified AppRole from the authentication system.
    Args:
        args (dict): A dictionary containing the following keys:
            - 'role_name' (required): The name of the AppRole for which the Role ID is retrieved.
    Returns:
        CommandResults: The command results object containing the retrieved Role ID and role name as outputs.
    """
    args = demisto.args()
    role_name = args.get('role_name')
    path = f'/auth/approle/role/{role_name}/role-id'
    response = send_request(path=path, method='get', body={'role_name': role_name})
    role_id = response.get('data', {}).get('role_id', '') if response else ''

    if not role_id:
        raise DemistoException(f"Role ID not found for AppRole '{role_name}'. Please check the role name and try again.")

    return_results(CommandResults(outputs_prefix='HashiCorp.AppRole', outputs={"Id": role_id, "Name": role_name}))


def list_secrets_engines_command():  # pragma: no cover
    res = list_secrets_engines()

    if not res:
        return_error('No engines found')

    mapped_engines = [{
        'Path': k,
        'Type': v.get('type'),
        'Description': v.get('description'),
        'Accessor': v.get('accessor')
    } for k, v in res.get('data', {}).items()]

    headers = ['Path', 'Type', 'Description', 'Accessor']

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Secrets Engines', mapped_engines, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'HashiCorp.Engine(val.Path===obj.Path)': createContext(mapped_engines, removeNull=True)
        }
    })


def list_secrets_engines():
    path = 'sys/mounts'

    return send_request(path)


def list_secrets_command():  # pragma: no cover
    engine = demisto.args()['engine']
    version = demisto.args().get('version')

    res = list_secrets(engine, version)

    if not res or 'data' not in res:
        return_error('Secrets not found')

    mapped_secrets = [{
        'Path': k
    } for k in res['data'].get('keys', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Secrets in engine path: ' + engine, mapped_secrets,
                                         removeNull=True),
        'EntryContext': {
            'HashiCorp.Secret(val.Path===obj.Path)': createContext(mapped_secrets)
        }
    })


def list_secrets(engine_path, version, folder=None):
    path = engine_path

    if version == '2':
        path = urljoin(path, 'metadata')
        if folder:
            path += os.path.join('/', folder)

    params = {
        'list': 'true'
    }

    return send_request(path, 'get', params=params)


def get_secret_metadata_command():  # pragma: no cover
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']

    res = get_secret_metadata(engine_path, secret_path)

    if not res or 'data' not in res:
        return_error('Secret not found')

    data = res['data']

    secret_headers = ['Engine', 'Created', 'Updated', 'CurrentVersion']
    version_headers = ['Number', 'Created', 'Deleted', 'Destroyed']

    mapped_secret = {
        'Path': secret_path,
        'Engine': engine_path,
        'Created': data.get('created_time'),
        'Updated': data.get('updated_time'),
        'CurrentVersion': data.get('current_version')
    }

    mapped_versions = [{
        'Number': k,
        'Created': v['created_time'],
        'Deleted': v['deletion_time'],
        'Destroyed': v['destroyed']
    } for k, v in data.get('versions', {}).items()]

    hr = tableToMarkdown('Secret metadata', mapped_secret, headers=secret_headers, removeNull=True)
    if mapped_versions:
        hr += tableToMarkdown('Versions', mapped_versions, headers=version_headers, removeNull=True)
        mapped_secret['Version'] = mapped_versions

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': {
            'HashiCorp.Secret(val.Path===obj.Path)': createContext(mapped_secret, removeNull=True)
        }
    })


def get_secret_metadata(engine_path, secret_path):
    path = engine_path + '/metadata/' + secret_path

    return send_request(path, 'get')


def delete_secret_command():  # pragma: no cover
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    delete_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions deleted successfully')


def delete_secret(engine_path, secret_path, versions):
    path = urljoin(engine_path, urljoin('delete/', secret_path))

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def undelete_secret_command():  # pragma: no cover
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    undelete_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions undeleted successfully')


def undelete_secret(engine_path, secret_path, versions):
    path = urljoin(engine_path, urljoin('undelete/', secret_path))

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def destroy_secret_command():  # pragma: no cover
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    destroy_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions destroyed successfully')


def destroy_secret(engine_path, secret_path, versions):
    path = urljoin(engine_path, urljoin('destroy/', secret_path))

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def list_policies_command():  # pragma: no cover
    res = list_policies()

    if not res or 'policies' not in res:
        return_error('No policies found')

    mapped_policies = [{
        'Name': i
    } for i in res['policies']]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Policies', mapped_policies, removeNull=True),
        'EntryContext': {
            'HashiCorp.Policy(val.Name===obj.Name)': createContext(mapped_policies, removeNull=True)
        }
    })


def list_policies():
    path = '/sys/policy'

    return send_request(path, 'get')


def get_policy_command():  # pragma: no cover
    name = demisto.args()['name']

    res = get_policy(name)

    if not res or 'rules' not in res:
        return_error('Policy not found')

    rules = hcl.loads(res['rules'])

    mapped_rules = [{'Path': k, 'Capabilities': v['capabilities']} for k, v in rules.get('path', {}).items()]

    mapped_policy = {
        'Name': res['name'],
        'Rule': mapped_rules
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Policy - ' + name, mapped_rules, removeNull=True),
        'EntryContext': {
            'HashiCorp.Policy(val.Name===obj.Name)': createContext(mapped_policy, removeNull=True)
        }
    })


def get_policy(policy_name):
    path = 'sys/policy/' + policy_name

    return send_request(path, 'get')


def disable_engine_command():  # pragma: no cover
    path = demisto.args()['path']

    disable_engine(path)

    demisto.results('Engine disabled successfully')


def disable_engine(engine_path):
    path = 'sys/mounts/' + engine_path

    return send_request(path, 'delete')


def enable_engine_command():  # pragma: no cover
    path = demisto.args()['path']
    engine_type = demisto.args()['type']
    description = demisto.args().get('description')
    default_lease_ttl = demisto.args().get('default_lease_ttl')
    max_lease_ttl = demisto.args().get('max_lease_ttl')
    force_no_cache = demisto.args().get('force_no_cache')
    audit_non_hmac_request_keys = argToList(demisto.args().get('audit_non_hmac_request_keys', []))
    audit_non_hmac_response_keys = argToList(demisto.args().get('audit_non_hmac_response_keys', []))
    listing_visibility = demisto.args().get('listing_visibility')
    passthrough_request_headers = argToList(demisto.args().get('passthrough_request_headers', []))
    kv_version = demisto.args().get('kv_version')
    local = demisto.args().get('local')
    seal_wrap = demisto.args().get('seal_wrap')

    enable_engine(path, engine_type, description, default_lease_ttl, max_lease_ttl, force_no_cache,
                  audit_non_hmac_request_keys,
                  audit_non_hmac_response_keys, listing_visibility, passthrough_request_headers, kv_version, local,
                  seal_wrap)

    demisto.results('Engine enabled successfully')


def enable_engine(path, engine_type, description, default_lease_ttl, max_lease_ttl, force_no_cache,
                  audit_non_hmac_request_keys,
                  audit_non_hmac_response_keys, listing_visibility, passthrough_request_headers, kv_version, local,
                  seal_wrap):  # pragma: no cover
    path = 'sys/mounts/' + path

    body = {
        'type': engine_type,
        'config': {}
    }
    if description:
        body['description'] = description

    if default_lease_ttl:
        body['config']['default_lease_ttl'] = default_lease_ttl
    if max_lease_ttl:
        body['config']['max_lease_ttl'] = max_lease_ttl
    if force_no_cache:
        body['config']['force_no_cache'] = force_no_cache
    if audit_non_hmac_request_keys:
        body['config']['audit_non_hmac_request_keys'] = audit_non_hmac_request_keys
    if audit_non_hmac_response_keys:
        body['config']['audit_non_hmac_response_keys'] = audit_non_hmac_response_keys
    if listing_visibility:
        body['config']['listing_visibility'] = listing_visibility
    if passthrough_request_headers:
        body['config']['passthrough_request_headers'] = passthrough_request_headers
    if kv_version:
        body['options'] = {
            'version': kv_version
        }
    if local:
        body['local'] = local
    if seal_wrap:
        body['seal_wrap'] = seal_wrap

    if not body['config']:
        del body['config']

    return send_request(path, 'post', body=body)


def seal_vault_command():  # pragma: no cover
    seal_vault()

    demisto.results('Vault sealed successfully')


def seal_vault():
    path = 'sys/seal'

    return send_request(path, 'put')


def unseal_vault_command():  # pragma: no cover
    reset = demisto.args().get('reset')
    key = demisto.args().get('key')

    if not key and not reset:
        return_error('Either key or reset must be provided')

    res = unseal_vault(key, reset)

    if not res:
        return_error('Could not retrieve unseal state')

    mapped_unseal = {
        'Sealed': res.get('sealed'),
        'Threshold': res.get('t'),
        'Shares': res.get('n'),
        'Progress': res.get('progress')
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Unseal', mapped_unseal, removeNull=True),
    })


def unseal_vault(key, reset):
    path = 'sys/unseal'
    body = {}
    if reset:
        body['reset'] = reset
    elif key:
        body['key'] = key

    return send_request(path, 'put', body=body)


def create_token_command():  # pragma: no cover
    role_name = demisto.args().get('role_name')
    policies = argToList(demisto.args().get('policies', []))
    meta = demisto.args().get('meta')
    no_parent = demisto.args().get('no_parent')
    no_default_policy = demisto.args().get('no_default_policy')
    renewable = demisto.args().get('renewable')
    ttl = demisto.args().get('ttl')
    explicit_max_ttl = demisto.args().get('explicit_max_ttl')
    display_name = demisto.args().get('display_name')
    num_uses = demisto.args().get('num_uses')
    period = demisto.args().get('period')

    res = create_token(role_name, policies, meta, no_parent, no_default_policy, renewable, ttl, explicit_max_ttl,
                       display_name, num_uses, period)

    if not res or 'auth' not in res:
        return_error('Could not get authentication token')

    auth = res['auth']

    mapped_auth = {
        'Token': auth.get('client_token'),
        'Policy': auth.get('policies'),
        'LeaseDuration': auth.get('lease_duration')
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Token successfully created', mapped_auth, removeNull=True),
        'EntryContext': {
            'HashiCorp.Auth(val.Token===obj.Token)': createContext(mapped_auth, removeNull=True)
        }
    })


def create_token(role_name, policies, meta, no_parent, no_default_policy, renewable, ttl, explicit_max_ttl,
                 display_name, num_uses, period):  # pragma: no cover
    path = 'auth/token/create'
    body = {}
    if role_name:
        body['role_name'] = role_name
    if policies:
        body['policies'] = policies
    if meta:
        body['meta'] = meta
    if no_parent:
        body['no_parent'] = no_parent
    if no_default_policy:
        body['no_default_policy'] = no_default_policy
    if renewable:
        body['renewable'] = renewable
    if ttl:
        body['ttl'] = ttl
    if explicit_max_ttl:
        body['explicit_max_ttl'] = explicit_max_ttl
    if display_name:
        body['display_name'] = display_name
    if num_uses:
        body['num_uses'] = num_uses
    if period:
        body['period'] = period

    return send_request(path, 'post', body=body)


def configure_engine_command():  # pragma: no cover
    engine_path = demisto.args()['path']
    engine_type = demisto.args()['type']
    version = demisto.args().get('version')
    folder = demisto.args().get('folder')
    aws_roles_list = demisto.args().get('aws_roles_list')
    aws_method = demisto.args().get('aws_method')
    ttl = demisto.args().get('ttl')

    configure_engine(engine_path, engine_type, version, folder=folder, aws_roles_list=aws_roles_list,
                     aws_method=aws_method, ttl=ttl)

    demisto.results('Engine configured successfully')


def reset_config_command():  # pragma: no cover
    set_integration_context({'configs': []})

    demisto.results('Successfully reset the engines configuration')


def configure_engine(engine_path, engine_type, version, folder=None, ttl='3600', aws_roles_list=None,
                     aws_method=None):  # pragma: no cover
    engine_conf = {
        'type': engine_type,
        'path': engine_path,
        'ttl': ttl
    }
    if version:
        engine_conf['version'] = str(version)
    if folder:
        engine_conf['folder'] = folder
    if aws_roles_list:
        engine_conf['aws_roles_list'] = aws_roles_list
    if aws_method:
        engine_conf['aws_method'] = aws_method

    ENGINE_CONFIGS.append(engine_conf)  # pylint: disable=E0606

    set_integration_context({'configs': ENGINE_CONFIGS})  # pylint: disable=E0606


def fetch_credentials():  # pragma: no cover
    credentials = []
    engines_to_fetch_from = []
    engines = argToList(demisto.params().get('engines', []))
    identifier = demisto.args().get('identifier')
    concat_username_to_cred_name = argToBoolean(demisto.params().get('concat_username_to_cred_name') or 'false')
    if len(engines) == 0:
        return_error('No secrets engines specified')
    for engine_type in engines:
        engines_to_fetch = list(filter(lambda e: e['type'] == engine_type, ENGINE_CONFIGS))
        engines_to_fetch_from += engines_to_fetch
    if len(engines_to_fetch_from) == 0:
        return_error('Engine type not configured, Use the configure-engine command to configure a secrets engine.')

    for engine in engines_to_fetch_from:
        if engine['type'] == 'KV':
            if 'version' not in engine:
                return_error('Version not configured for KV engine, re-configure the engine')
            if engine['version'] == '1':
                credentials += get_kv1_secrets(engine['path'], concat_username_to_cred_name)
            elif engine['version'] == '2':
                credentials += get_kv2_secrets(engine['path'], concat_username_to_cred_name, engine.get('folder'))
        elif engine['type'] == 'Cubbyhole':
            credentials += get_ch_secrets(engine['path'], concat_username_to_cred_name)

        elif engine['type'] == 'AWS':
            aws_roles_list = []
            if engine.get('aws_roles_list'):
                aws_roles_list = engine.get('aws_roles_list').split(',')
            credentials += get_aws_secrets(engine['path'], concat_username_to_cred_name,
                                           aws_roles_list, engine.get('aws_method'))

    if identifier:
        credentials = list(filter(lambda c: c.get('name', '') == identifier, credentials))

    demisto.credentials(credentials)


def get_kv1_secrets(engine_path, concat_username_to_cred_name=False):  # pragma: no cover
    path = engine_path
    params = {
        'list': 'true'
    }

    res = send_request(path, 'get', params=params)

    secrets = []

    if not res or 'data' not in res:
        return []

    for secret in res['data'].get('keys', []):
        secret_data = get_kv1_secret(engine_path, secret)
        for k, v in secret_data.get('data', {}).items():
            if concat_username_to_cred_name:
                name = f'{secret}_{k}'
            else:
                name = secret
            secrets.append({
                'user': k,
                'password': v,
                'name': name
            })

    return secrets


def get_kv1_secret(engine_path, secret):
    path = engine_path + secret

    return send_request(path, 'get')


def get_kv2_secrets(engine_path, concat_username_to_cred_name=False, folder=None):  # pragma: no cover
    secrets = []
    res = list_secrets(engine_path, '2', folder)
    if not res or 'data' not in res:
        return []

    for secret in res['data'].get('keys', []):
        if str(secret).endswith('/') and secret.replace('/', '') != folder:
            demisto.debug(f'Could not get secrets from path: {secret}')
            continue

        secret_data = get_kv2_secret(engine_path, secret, folder)
        secret_info = secret_data.get('data', {}).get('data', {})
        for k in secret_data.get('data', {}).get('data', {}):
            if concat_username_to_cred_name:
                name = f'{secret}_{k}'
            else:
                name = secret
            secrets.append({
                'user': k,
                'password': secret_info[k],
                'name': name
            })

    return secrets


def get_kv2_secret(engine_path, secret, folder=None):
    path = urljoin(engine_path, 'data/')
    if folder:
        path += os.path.join(folder)
    path += secret

    return send_request(path, 'get')


def get_ch_secrets(engine_path, concat_username_to_cred_name=False):  # pragma: no cover
    path = engine_path

    params = {
        'list': 'true'
    }

    res = send_request(path, 'get', params=params)

    secrets = []

    if not res or 'data' not in res:
        return []

    for secret in res['data'].get('keys', []):
        secret_data = get_ch_secret(engine_path, secret)
        for k, v in secret_data.get('data', {}).items():
            if concat_username_to_cred_name:
                name = f'{secret}_{k}'
            else:
                name = secret
            secrets.append({
                'user': k,
                'password': v,
                'name': name
            })

    return secrets


def get_aws_secrets(engine_path, concat_username_to_cred_name, aws_roles_list, aws_method):
    secrets = []
    roles_list_url = engine_path + '/roles'
    demisto.debug(f'roles_list_url: {roles_list_url}')
    params = {'list': 'true'}
    res = send_request(roles_list_url, 'get', params=params)
    if not res or 'data' not in res:
        return []
    for role in res['data'].get('keys', []):
        if aws_roles_list and role not in aws_roles_list:
            continue
        role_url = urljoin(engine_path, urljoin('/roles/', role))
        demisto.debug(f'role_url: {role_url}')
        role_data = send_request(role_url, 'get')
        if not role_data or 'data' not in role_data:
            return []
        credential_type = role_data['data'].get('credential_type')
        if aws_method:
            if aws_method == 'POST':
                credential_type = 'sts'
            else:
                credential_type = 'iam_user'
        if credential_type != 'iam_user':
            method = 'POST'
            credential_type = 'sts'
        else:
            method = 'GET'
            credential_type = 'creds'
        generate_credentials_url = urljoin(engine_path + '/', urljoin(credential_type, '/' + role))
        demisto.debug(f'generate_credentials_url: {generate_credentials_url}')
        body = {}
        if 'role_arns' in role_data['data']:
            body['role_arns'] = role_data['data'].get('role_arns', [])
        aws_credentials = send_request(generate_credentials_url, method, body=body)
        if not aws_credentials or 'data' not in aws_credentials:
            return []
        access_key = aws_credentials['data'].get('access_key')
        secret_key = aws_credentials['data'].get('secret_key')
        if aws_credentials['data'].get('security_token'):
            secret_key = secret_key + '@@@' + aws_credentials["data"].get("security_token")
        if concat_username_to_cred_name:
            role = f'{role}_{access_key}'
        secrets.append({
            'user': access_key,
            'password': secret_key,
            'name': role
        })

    return secrets


def get_ch_secret(engine_path, secret):
    path = engine_path + secret

    return send_request(path, 'get')


''' EXECUTION CODE '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover

    handle_proxy()

    demisto.debug('Executing command: ' + demisto.command())
    if USERNAME and PASSWORD:
        if TOKEN:
            return_error(
                'You can only specify one login method, please choose username and password or authentication token')
        TOKEN = login()
    elif not TOKEN:
        return_error('Either an authentication token or user credentials must be provided')

    integration_context = get_integration_context()
    if not integration_context or 'configs' not in integration_context:
        integration_context['configs'] = []

    ENGINE_CONFIGS = integration_context['configs']

    try:
        command = demisto.command()
        if command == 'test-module':
            demisto.results('ok')
        elif command == 'fetch-credentials':
            fetch_credentials()
        elif command == 'hashicorp-list-secrets-engines':
            list_secrets_engines_command()
        elif command == 'hashicorp-list-secrets':
            list_secrets_command()
        elif command == 'hashicorp-list-policies':
            list_policies_command()
        elif command == 'hashicorp-get-policy':
            get_policy_command()
        elif command == 'hashicorp-get-secret-metadata':
            get_secret_metadata_command()
        elif command == 'hashicorp-delete-secret':
            delete_secret_command()
        elif command == 'hashicorp-undelete-secret':
            undelete_secret_command()
        elif command == 'hashicorp-destroy-secret':
            destroy_secret_command()
        elif command == 'hashicorp-disable-engine':
            disable_engine_command()
        elif command == 'hashicorp-enable-engine':
            enable_engine_command()
        elif command == 'hashicorp-seal-vault':
            seal_vault_command()
        elif command == 'hashicorp-unseal-vault':
            unseal_vault_command()
        elif command == 'hashicorp-create-token':
            create_token_command()
        elif command == 'hashicorp-configure-engine':
            configure_engine_command()
        elif command == 'hashicorp-reset-configuration':
            reset_config_command()
        elif command == 'hashicorp-generate-role-secret':
            generate_role_secret_command()
        elif command == 'hashicorp-get-role-id':
            get_role_id_command()

    except Exception as e:
        demisto.debug(f'An error occurred: {e}')
        return_error(f'An error occurred: {e}')
