import demistomock as demisto  # noqa: F401
import json
import hcl
import requests
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' GLOBAL VARIABLES '''

CREDENTIALS = demisto.params().get('credentials', {})
USERNAME = None
PASSWORD = None
if CREDENTIALS:
    USERNAME = CREDENTIALS.get('identifier')
    PASSWORD = CREDENTIALS.get('password')
VERIFY_SSL = not demisto.params().get('unsecure', False)
TOKEN = demisto.params().get('token')
USE_APPROLE_AUTH_METHOD = argToBoolean(demisto.params().get('use_approle', 'false') or 'false')


def get_server_url():
    url = demisto.params()['server']
    url = re.sub('/[\/]+$/', '', url)  # guardrails-disable-line
    url = re.sub('\/$', '', url)  # guardrails-disable-line
    return url


BASE_URL = get_server_url()
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
    }

    if TOKEN:
        headers['X-Vault-Token'] = TOKEN

    return headers


def login():
    if USE_APPROLE_AUTH_METHOD:
        path = 'auth/approle/login'
        body = {
            'role_id': USERNAME,
            'secret_id': PASSWORD,
        }
    else:
        path = 'auth/userpass/login/' + USERNAME  # type: ignore
        body = {
            'password': PASSWORD
        }

    url = '{}/{}'.format(SERVER_URL, path)
    res = requests.request('POST', url, headers=get_headers(), data=json.dumps(body), verify=VERIFY_SSL)
    if (res.status_code < 200 or res.status_code >= 300) and res.status_code not in DEFAULT_STATUS_CODES:
        try:
            error_body = res.json()
            if 'errors' in error_body and isinstance(error_body['errors'], list):
                error_body = ';'.join(error_body['errors']) if len(error_body['errors']) > 0 else 'None'
        except Exception as ex:
            demisto.error("Error in login (parsing error msg): {}".format(ex))
            error_body = res.content
        return_error('Login failed. Status code: {}, details: {}'.format(str(res.status_code), error_body))

    auth_res = res.json()
    if not auth_res or 'auth' not in auth_res or 'client_token' not in auth_res['auth']:
        return_error('Could not authenticate user')

    return auth_res['auth']['client_token']


def send_request(path, method='get', body=None, params=None, headers=None):
    body = body if body is not None else {}
    params = params if params is not None else {}

    url = '{}/{}'.format(SERVER_URL, path)

    headers = headers if headers is not None else get_headers()
    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params, verify=VERIFY_SSL)
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


''' FUNCTIONS '''


def list_secrets_engines_command():
    res = list_secrets_engines()

    if not res:
        return_error('No engines found')

    mapped_engines = [{
        'Path': k,
        'Type': v.get('type'),
        'Description': v.get('description'),
        'Accessor': v.get('accessor')
    } for k, v in res.get('data', {}).iteritems()]

    headers = ['Path', 'Type', 'Description', 'Accessor']

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('HashiCorp Vault Secrets Engines', mapped_engines, headers=headers, removeNull=True),
        'EntryContext': {
            'HashiCorp.Engine(val.Path===obj.Path)': createContext(mapped_engines, removeNull=True)
        }
    })


def list_secrets_engines():
    path = 'sys/mounts'

    return send_request(path)


def list_secrets_command():
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
        'HumanReadable': tableToMarkdown('HashiCorp Vault Secrets in engine path: ' + engine, mapped_secrets, removeNull=True),
        'EntryContext': {
            'HashiCorp.Secret(val.Path===obj.Path)': createContext(mapped_secrets)
        }
    })


def list_secrets(engine_path, version, folder=None):
    path = engine_path

    if version == '2':
        path += '/metadata'
        if folder:
            path += os.path.join('/', folder)

    params = {
        'list': 'true'
    }

    return send_request(path, 'get', params=params)


def get_secret_metadata_command():
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
    } for k, v in data.get('versions', {}).iteritems()]

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


def delete_secret_command():
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    delete_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions deleted successfully')


def delete_secret(engine_path, secret_path, versions):
    path = engine_path + 'delete/' + secret_path

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def undelete_secret_command():
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    undelete_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions undeleted successfully')


def undelete_secret(engine_path, secret_path, versions):
    path = engine_path + 'undelete/' + secret_path

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def destroy_secret_command():
    engine_path = demisto.args()['engine_path']
    secret_path = demisto.args()['secret_path']
    versions = argToList(demisto.args()['versions'])

    destroy_secret(engine_path, secret_path, versions)

    demisto.results('Secret versions destroyed successfully')


def destroy_secret(engine_path, secret_path, versions):
    path = engine_path + 'destroy/' + secret_path

    body = {
        'versions': versions
    }

    return send_request(path, 'post', body=body)


def list_policies_command():
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


def get_policy_command():
    name = demisto.args()['name']

    res = get_policy(name)

    if not res or 'rules' not in res:
        return_error('Policy not found')

    rules = hcl.loads(res['rules'])

    mapped_rules = [{'Path': k, 'Capabilities': v['capabilities']} for k, v in rules.get('path', {}).iteritems()]

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


def disable_engine_command():
    path = demisto.args()['path']

    disable_engine(path)

    demisto.results('Engine disabled successfully')


def disable_engine(engine_path):
    path = 'sys/mounts/' + engine_path

    return send_request(path, 'delete')


def enable_engine_command():
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

    enable_engine(path, engine_type, description, default_lease_ttl, max_lease_ttl, force_no_cache, audit_non_hmac_request_keys,
                  audit_non_hmac_response_keys, listing_visibility, passthrough_request_headers, kv_version, local, seal_wrap)

    demisto.results('Engine enabled successfully')


def enable_engine(path, engine_type, description, default_lease_ttl, max_lease_ttl, force_no_cache, audit_non_hmac_request_keys,
                  audit_non_hmac_response_keys, listing_visibility, passthrough_request_headers, kv_version, local, seal_wrap):
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


def seal_vault_command():
    seal_vault()

    demisto.results('Vault sealed successfully')


def seal_vault():
    path = 'sys/seal'

    return send_request(path, 'put')


def unseal_vault_command():
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


def create_token_command():
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
                 display_name, num_uses, period):
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


def configure_engine_command():
    engine_path = demisto.args()['path']
    engine_type = demisto.args()['type']
    version = demisto.args().get('version')
    folder = demisto.args().get('folder')

    configure_engine(engine_path, engine_type, version, folder)

    demisto.results('Engine configured successfully')


def reset_config_command():
    demisto.setIntegrationContext({'configs': []})

    demisto.results('Successfully reset the engines configuration')


def configure_engine(engine_path, engine_type, version, folder=None):
    engine_conf = {
        'type': engine_type,
        'path': engine_path
    }
    if version:
        engine_conf['version'] = str(version)
    if folder:
        engine_conf['folder'] = folder

    ENGINE_CONFIGS.append(engine_conf)

    demisto.setIntegrationContext({'configs': ENGINE_CONFIGS})


def fetch_credentials():
    credentials = []
    engines_to_fetch_from = []
    ENGINES = argToList(demisto.params().get('engines', []))
    identifier = demisto.args().get('identifier')
    concat_username_to_cred_name = argToBoolean(demisto.params().get('concat_username_to_cred_name') or 'false')

    if len(ENGINES) == 0:
        return_error('No secrets engines specified')

    for engine_type in ENGINES:
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

    if identifier:
        credentials = list(filter(lambda c: c.get('name', '') == identifier, credentials))

    demisto.credentials(credentials)


def get_kv1_secrets(engine_path, concat_username_to_cred_name=False):
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
        for k, v in secret_data.get('data', {}).iteritems():
            if concat_username_to_cred_name:
                name = '{0}_{1}'.format(secret, k)
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


def get_kv2_secrets(engine_path, concat_username_to_cred_name=False, folder=None):
    secrets = []
    res = list_secrets(engine_path, '2', folder)
    if not res or 'data' not in res:
        return []

    for secret in res['data'].get('keys', []):
        secret_data = get_kv2_secret(engine_path, secret, folder)
        for k, v in secret_data.get('data', {}).get('data', {}).iteritems():
            if concat_username_to_cred_name:
                name = '{0}_{1}'.format(secret, k)
            else:
                name = secret
            secrets.append({
                'user': k,
                'password': v,
                'name': name
            })

    return secrets


def get_kv2_secret(engine_path, secret, folder=None):
    path = engine_path + 'data/'
    if folder:
        path += os.path.join(folder)
    path += secret

    return send_request(path, 'get')


def get_ch_secrets(engine_path, concat_username_to_cred_name=False):
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
        for k, v in secret_data.get('data', {}).iteritems():
            if concat_username_to_cred_name:
                name = '{0}_{1}'.format(secret, k)
            else:
                name = secret
            secrets.append({
                'user': k,
                'password': v,
                'name': name
            })

    return secrets


def get_ch_secret(engine_path, secret):
    path = engine_path + secret

    return send_request(path, 'get')


''' EXECUTION CODE '''

LOG('Executing command: ' + demisto.command())

if USERNAME and PASSWORD:
    TOKEN = login()
elif not TOKEN:
    return_error('Either an authentication token or user credentials must be provided')

integ_context = demisto.getIntegrationContext()
if not integ_context or 'configs' not in integ_context:
    integ_context['configs'] = []

ENGINE_CONFIGS = integ_context['configs']

try:
    if demisto.command() == 'test-module':
        path = 'sys/health'
        send_request(path)
        demisto.results('ok')
    elif demisto.command() == 'fetch-credentials':
        fetch_credentials()
    elif demisto.command() == 'hashicorp-list-secrets-engines':
        list_secrets_engines_command()
    elif demisto.command() == 'hashicorp-list-secrets':
        list_secrets_command()
    elif demisto.command() == 'hashicorp-list-policies':
        list_policies_command()
    elif demisto.command() == 'hashicorp-get-policy':
        get_policy_command()
    elif demisto.command() == 'hashicorp-get-secret-metadata':
        get_secret_metadata_command()
    elif demisto.command() == 'hashicorp-delete-secret':
        delete_secret_command()
    elif demisto.command() == 'hashicorp-undelete-secret':
        undelete_secret_command()
    elif demisto.command() == 'hashicorp-destroy-secret':
        destroy_secret_command()
    elif demisto.command() == 'hashicorp-disable-engine':
        disable_engine_command()
    elif demisto.command() == 'hashicorp-enable-engine':
        enable_engine_command()
    elif demisto.command() == 'hashicorp-seal-vault':
        seal_vault_command()
    elif demisto.command() == 'hashicorp-unseal-vault':
        unseal_vault_command()
    elif demisto.command() == 'hashicorp-create-token':
        create_token_command()
    elif demisto.command() == 'hashicorp-configure-engine':
        configure_engine_command()
    elif demisto.command() == 'hashicorp-reset-configuration':
        reset_config_command()
except Exception as e:
    LOG(e)
    LOG.print_log()
    return_error(e.message)
