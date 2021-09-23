from CommonServerPython import *
from AzureKeyVault import KeyVaultClient, create_or_update_key_vault_command, list_key_vaults_command, \
    get_key_vault_command, delete_key_vault_command, \
    update_access_policy_command, get_key_command, list_keys_command, delete_key_command, delete_secret_command, \
    get_secret_command, list_secrets_command, get_certificate_command, list_certificates_command, \
    get_certificate_policy_command

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
                          self_deployed=True, verify=False, proxy=False)


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
