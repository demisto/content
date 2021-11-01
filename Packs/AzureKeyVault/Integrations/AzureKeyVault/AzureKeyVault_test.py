from CommonServerPython import *
from AzureKeyVault import KeyVaultClient, create_or_update_key_vault_command, list_key_vaults_command, \
    get_key_vault_command, delete_key_vault_command, update_access_policy_command, list_keys_command, get_key_command, \
    delete_key_command, list_secrets_command, get_secret_command, delete_secret_command, list_certificates_command, \
    get_certificate_command, get_certificate_policy_command, convert_attributes_to_readable, \
    convert_key_info_to_readable, convert_time_attributes_to_iso

'''MOCK PARAMETERS '''
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
TENANT_ID = "tenant_id"
SUBSCRIPTION_ID = "sub_id"
RESOURCE_GROUP_NAME = "group_name"

'''CONSTANTS'''
VAULT_NAME = "myvault"
KEY_NAME = "key_test"
SECRET_NAME = "sec_test"
SECRET_NAME_2 = "sec_test_2"
CERTIFICATE_NAME = "selfSignedCert01"
BASE_VAULT_URL = f'https://{VAULT_NAME}.vault.azure.net'
BASE_MANAGEMENT_URL = f'https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/' \
                      f'resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.KeyVault/vaults'
ACCESS_TOKEN_REQUEST_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/token'
API_MANAGEMENT_VERSION_PARAM = "?api-version=2019-09-01"
API_VAULT_VERSION_PARAM = "?api-version=7.2"
KEY_VAULT_PREFIX = "AzureKeyVault.KeyVault"
KEY_PREFIX = "AzureKeyVault.Key"
SECRET_PREFIX = "AzureKeyVault.Secret"
CERTIFICATE_PREFIX = "AzureKeyVault.Certificate"
OBJECT_ID = "00000000-0000-0000-0000-000000000000"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def mock_client():
    return KeyVaultClient(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                          subscription_id=SUBSCRIPTION_ID,
                          resource_group_name=RESOURCE_GROUP_NAME,
                          verify=False, proxy=False)


def test_azure_key_vault_key_vault_create_or_update_command(requests_mock):
    """
    Scenario: Create or Update Key Vault.
    Given:
     - User has provided valid credentials.
     - Key Vault name argument
    When:
     - azure-key-vault-key-vault-create-or-update command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('create_or_update_key_vault.json'))
    url = f'{BASE_MANAGEMENT_URL}/{VAULT_NAME}{API_MANAGEMENT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.put(url, json=mock_response)

    result = create_or_update_key_vault_command(mock_client(), {'vault_name': VAULT_NAME, 'storage': None,
                                                                'object_id': "00000000-0000-0000-0000-000000000000"})

    assert len(result.outputs) == 6
    assert result.outputs_prefix == KEY_VAULT_PREFIX
    assert result.outputs.get('name') == VAULT_NAME


def test_azure_key_vault_key_vault_list_command(requests_mock):
    """
    Scenario: list Key Vaults.
    Given:
     - User has provided valid credentials.
    When:
     - azure-key-vault-key-vault-list command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = json.loads(load_mock_response('list_key_vaults.json'))
    url = f'{BASE_MANAGEMENT_URL}{API_MANAGEMENT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    result = list_key_vaults_command(mock_client(), {})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == KEY_VAULT_PREFIX
    assert result.outputs[0].get('name') == VAULT_NAME
    assert result.outputs[0].get('type') == "Microsoft.KeyVault/vaults"
    assert result.outputs[0].get('properties').get('tenantId') == "00000000-0000-0000-0000-000000000000"


def test_azure_key_vault_key_vault_get_command(requests_mock):
    """
    Scenario: get Key Vault.
    Given:
     - User has provided valid credentials.
     - Key Vault name argument.
    When:
     - azure-key-vault-key-vault-get command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('get_key_vault.json'))
    url = f'{BASE_MANAGEMENT_URL}/{VAULT_NAME}{API_MANAGEMENT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    result = get_key_vault_command(mock_client(), {'vault_name': VAULT_NAME})

    assert len(result.outputs) == 6
    assert result.outputs_prefix == 'AzureKeyVault.KeyVault'
    assert result.outputs.get('name') == VAULT_NAME


def test_azure_key_vault_key_vault_delete_command(requests_mock):
    """
    Scenario: delete Key Vault.
    Given:
     - User has provided valid credentials.
     - Key Vault name
     - Key name
    When:
     - azure-key-vault-key-vault-delete command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    """

    mock_response = json.loads(load_mock_response('delete_key_vault.json'))
    url = f'{BASE_MANAGEMENT_URL}/{VAULT_NAME}{API_MANAGEMENT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.delete(url, json=mock_response)

    result = delete_key_vault_command(mock_client(), {'vault_name': VAULT_NAME})
    assert result.outputs is None


def test_azure_key_vault_key_vault_access_policy_update_command(requests_mock):
    """
    Scenario: update access policy of Key Vault.
    Given:
     - User has provided valid credentials.
     - Key Vault name argument
     - Operation kind argument
    When:
     - azure-key-vault-key-vault-access-policy-update command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    operation_kind = 'add'
    command_arguments = {'vault_name': VAULT_NAME, 'operation_kind': operation_kind,
                         'object_id': "00000000-0000-0000-0000-000000000000"}

    mock_response = json.loads(load_mock_response('update_access_policy.json'))

    url = f'{BASE_MANAGEMENT_URL}/{VAULT_NAME}/accessPolicies/{operation_kind}{API_MANAGEMENT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.put(url, json=mock_response)

    result = update_access_policy_command(mock_client(), command_arguments)
    assert len(result.outputs) == 1
    assert result.outputs.get('properties').get('accessPolicies')[0].get(
        'tenantId') == "00000000-0000-0000-0000-000000000000"
    assert result.outputs_prefix == 'AzureKeyVault.VaultAccessPolicy'


def test_azure_key_vault_key_list_command(requests_mock):
    """
    Scenario: list Keys.
    Given:
     - User has provided valid credentials.
     - vault_name argument
    When:
     - azure-key-vault-key-list command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('list_keys.json'))
    url = f'{BASE_VAULT_URL}/keys{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME}
    result = list_keys_command(mock_client(), command_arguments)
    assert len(result.outputs) == 1
    assert result.outputs_prefix == KEY_PREFIX
    assert result.outputs[0].get('kid') == "https://myvault.vault.azure.net/keys/sdktestkey"


def test_azure_key_vault_key_get_command(requests_mock):
    """
    Scenario: get Key.
    Given:
     - User has provided valid credentials.
    When:
     - azure-key-vault-key-get command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('get_key.json'))
    url = f'{BASE_VAULT_URL}/keys/{KEY_NAME}{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'key_name': KEY_NAME}
    result = get_key_command(mock_client(), command_arguments)
    assert len(result.outputs) == 4
    assert result.outputs_prefix == KEY_PREFIX
    assert result.outputs.get('key_vault_name') == VAULT_NAME
    assert result.outputs.get('key').get('e') == "AQAB"


def test_azure_key_vault_key_delete_command(requests_mock):
    """
    Scenario: delete Key.
    Given:
     - User has provided valid credentials.
     - Key Vault name
     - key name
    When:
     - azure-key-vault-key-delete command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('delete_key.json'))
    url = f'{BASE_VAULT_URL}/keys/{KEY_NAME}{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.delete(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'key_name': KEY_NAME}
    result = delete_key_command(mock_client(), command_arguments)
    assert len(result.outputs) == 7
    assert result.outputs_prefix == 'AzureKeyVault.Key'
    assert result.outputs.get('recoveryId') == "https://test.vault.azure.net/deletedkeys/key_test"
    assert result.outputs.get('deletedDate') == "2017-05-05T00:00:52"


def test_azure_key_vault_secret_list_command(requests_mock):
    """
    Scenario: list secrets.
    Given:
     - User has provided valid credentials.
     - Key Vault name
    When:
     - azure-key-vault-secret-list command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('list_secrets.json'))
    url = f'{BASE_VAULT_URL}/secrets{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME}
    result = list_secrets_command(mock_client(), command_arguments)
    assert len(result.outputs) == 1
    assert result.outputs_prefix == SECRET_PREFIX
    assert result.outputs[0].get('id') == "https://myvault.vault.azure.net/secrets/listsecrettest0"
    assert result.outputs[0].get('contentType') == "plainText"
    assert result.outputs[0].get('attributes').get('enabled') is True


def test_azure_key_vault_secret_get_command(requests_mock):
    """
    Scenario: get secret.
    Given:
     - User has provided valid credentials.
     - Key vault name
     - Secret name
    When:
     - azure-key-vault-secret-get command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('get_secret.json'))
    url = f'{BASE_VAULT_URL}/secrets/{SECRET_NAME}{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'secret_name': SECRET_NAME}
    result = get_secret_command(mock_client(), command_arguments)
    assert len(result.outputs) == 7
    assert result.outputs_prefix == SECRET_PREFIX
    assert result.outputs.get('value') == "mysecretvalue"
    assert result.outputs.get('kid') == "mykid"
    assert result.outputs.get('key_vault_name') == VAULT_NAME
    assert result.outputs.get('attributes').get('enabled') is True


def test_azure_key_vault_secret_delete_command(requests_mock):
    """
    Scenario: delete secret.
    Given:
     - User has provided valid credentials.
     - Key vault name
     - Secret name
    When:
     - azure-key-vault-secret-delete command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('delete_secret.json'))
    url = f'{BASE_VAULT_URL}/secrets/{SECRET_NAME}{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.delete(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'secret_name': SECRET_NAME}
    result = delete_secret_command(mock_client(), command_arguments)
    assert len(result.outputs) == 6
    assert result.outputs_prefix == 'AzureKeyVault.Secret'
    assert result.outputs.get('recoveryId') == "https://test.vault.azure.net/deletedsecrets/sec_test"
    assert result.outputs.get('key_vault_name') == VAULT_NAME
    assert result.outputs.get('deletedDate') == "2017-05-04T22:53:53"


def test_azure_key_vault_certificate_list_command(requests_mock):
    """
    Scenario: list certificates.
    Given:
     - User has provided valid credentials.
     - Key vault name
    When:
     - azure-key-vault-certificate-list command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('list_certificate.json'))
    url = f'{BASE_VAULT_URL}/certificates{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME}
    result = list_certificates_command(mock_client(), command_arguments)
    assert len(result.outputs) == 2
    assert result.outputs_prefix == CERTIFICATE_PREFIX
    assert result.outputs[0].get('x5t') == "fLi3U52HunIVNXubkEnf8tP6Wbo"
    assert result.outputs[0].get('attributes').get('enabled') is True


def test_azure_key_vault_certificate_get_command(requests_mock):
    """
    Scenario: get certificate.
    Given:
     - User has provided valid credentials.
     - Key vault name
     - Certificate name
    When:
     - azure-key-vault-certificate-get command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('get_certificate.json'))
    url = f'{BASE_VAULT_URL}/certificates/{CERTIFICATE_NAME}{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'certificate_name': CERTIFICATE_NAME}
    result = get_certificate_command(mock_client(), command_arguments)
    assert len(result.outputs) == 8
    assert result.outputs_prefix == CERTIFICATE_PREFIX
    assert result.outputs.get('x5t') == "fLi3U52HunIVNXubkEnf8tP6Wbo"
    assert result.outputs.get('key_vault_name') == VAULT_NAME
    assert result.outputs.get('attributes').get('enabled') is True


def test_azure_key_vault_certificate_policy_get_command(requests_mock):
    """
    Scenario: get certificate's policy.
    Given:
     - User has provided valid credentials.
     - Key vault name
     - Certificate name
    When:
     - azure-key-vault-certificate-policy-get command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    mock_response = json.loads(load_mock_response('get_certificate_policy.json'))
    url = f'{BASE_VAULT_URL}/certificates/{CERTIFICATE_NAME}/policy{API_VAULT_VERSION_PARAM}'

    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json=mock_response)
    requests_mock.get(url, json=mock_response)

    command_arguments = {'vault_name': VAULT_NAME,
                         'certificate_name': CERTIFICATE_NAME}
    result = get_certificate_policy_command(mock_client(), command_arguments)
    assert len(result.outputs) == 8
    assert result.outputs_prefix == 'AzureKeyVault.CertificatePolicy'
    assert result.outputs.get('id') == "https://myvault.vault.azure.net/certificates/selfSignedCert01/policy"
    assert result.outputs.get('attributes').get('enabled') is True


def test_config_vault_permission():
    """
     Scenario: configure Key Vault permission property.
     Given:
      - User has provided valid credentials.
      - List of keys permissions.
      - List of secrets permissions.
      - List of storage permissions.
     When:
      - azure-key-vault-create-update command called.
      - azure-key-vault-update-policy command called.
     Then:
      - Ensure number of items is correct.
      - Ensure that each permissions list contains the right values.
     """

    client = mock_client()
    keys = ['list', 'get', 'purge']
    secrets = keys
    certificates = []
    storage = ['delete', 'set', 'update']

    permissions = client.config_vault_permission(keys, secrets, certificates, storage)
    assert len(permissions) == 3
    assert permissions['keys'] == permissions['secrets']
    assert permissions['secrets'] == ['list', 'get', 'purge']
    assert permissions['storage'] == ['delete', 'set', 'update']


def test_config_vault_network_acls():
    """
     Scenario: configure Key Vault network acls property.
     Given:
      - User has provided valid credentials.
      - default action argument.
      - bypass argument.
      - virtual network subnet ID argument.
      - ignore missing vnet Service endpoint argument.
    When:
      - azure-key-vault-create-update command called.

     Then:
      - Ensure number of items is correct.
      - Ensure that each field contains the right values.
     """

    client = mock_client()
    default_action = 'Allow'
    bypass = 'None'
    subnet_id = 'subnet'
    ignore_missing_vnet = True
    ip_rules = []
    network_acl = client.config_vault_network_acls(default_action, bypass, subnet_id, ignore_missing_vnet, ip_rules)

    assert len(network_acl) == 3
    assert network_acl['defaultAction'] == default_action
    assert network_acl['virtualNetworkRules'][0]['id'] == subnet_id
    assert network_acl['virtualNetworkRules'][0]['ignoreMissingVnetServiceEndpoint'] == ignore_missing_vnet


def test_config_vault_properties():
    """
     Scenario: configure Key Vault properties.
     Given:
      - User has provided valid credentials.
      - Key Vault access policy.
      - Key Vault network acl.
    When:
      - azure-key-vault-create-update command called.
     Then:
      - Ensure number of items is correct.
      - Ensure that each field contains the right values.
     """

    client = mock_client()
    permissions = {
        'keys': ['list', 'get', 'purge'],
        'secrets': ['list', 'get', 'purge']
    }
    network_acl = {
        'defaultAction': 'Allow',
        'bypass': 'AzureServices'
    }

    properties = client.config_vault_properties(
        OBJECT_ID, TENANT_ID, True, True, True, 'standard',
        permissions, network_acl
    )

    assert len(properties) == 7
    assert properties['accessPolicies'][0]['objectId'] == OBJECT_ID
    assert properties['accessPolicies'][0]['tenantId'] == TENANT_ID
    assert properties['accessPolicies'][0]['permissions'] == permissions
    assert properties['sku']['name'] == 'standard'
    assert properties['networkAcls'] == network_acl


def test_convert_attributes_to_readable():
    """
      Scenario: convert entity's attributes to readable.
      Given:
        - Key Vault entities' attributes.
     When:
       - Preparing the readable output for the users in the commands.
      Then:
       - Ensure number of items is correct.
       - Ensure that each field contains the right values.
      """

    attributes = {
        "nbf": 1493938410,
        "exp": 1493938410,
        "created": 1493938410,
        "updated": 1493938410,
        "recoveryLevel": "Recoverable+Purgeable"
    }
    readable_attributes = convert_attributes_to_readable(attributes)

    assert len(attributes) == 5
    assert 'should_not_be_retrieved_Before' in readable_attributes
    assert 'expiry_time' in readable_attributes
    assert 'create_time' in readable_attributes
    assert 'update_time' in readable_attributes
    assert 'recovery_level' in readable_attributes
    assert readable_attributes['create_time'] == "2017-05-04T22:53:30"


def test_convert_key_info_to_readable():
    """
      Scenario: convert key info to readable.
      Given:
        - Key Vault entities' attributes.
     When:
       - Preparing the readable output for the users in the commands.
      Then:
       - Ensure number of items is correct.
       - Ensure that each field contains the right values.
      """

    key = {
        "kid": "https://test.vault.azure.net/keys/test/78deebed173b48e48f55abf87ed4cf71",
        "kty": "RSA",
        "key_ops": [
            "encrypt",
            "decrypt",
            "sign",
            "verify",
            "wrapKey",
            "unwrapKey"
        ],
        "n": "xxx",
        "e": "AQAB"
    }
    readable_key_info = convert_key_info_to_readable(key)
    assert len(readable_key_info) == 5
    assert 'key_id' in readable_key_info
    assert 'json_web_key_type' in readable_key_info
    assert 'key_operations' in readable_key_info
    assert 'RSA_modulus' in readable_key_info
    assert 'RSA_public_components' in readable_key_info


def test_convert_time_attributes_to_iso():
    attributes = {
        "exp": 1493938410,
        "created": 1493938410,
        "updated": 1493938410,
        "recoveryLevel": "Recoverable+Purgeable"
    }
    readable_time_attributes = convert_time_attributes_to_iso(attributes)

    assert len(attributes) == 4
    assert readable_time_attributes['exp'] == "2017-05-04T22:53:30"
    assert readable_time_attributes['created'] == "2017-05-04T22:53:30"
    assert readable_time_attributes['updated'] == "2017-05-04T22:53:30"
