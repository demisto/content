import json

CYBERARKPAS_URL = 'https://test.com'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_list_accounts(requests_mock):
    from CyberArkPAS import Client, list_accounts
    list_accounts_response = load_test_data('./test_data/cyberark-list-accounts.json')
    requests_mock.post(f'{CYBERARKPAS_URL}/PasswordVault/API/Auth/CyberArk/Logon', json="test")

    requests_mock.get(f'{CYBERARKPAS_URL}/PasswordVault/api/Accounts?offset=0', json=list_accounts_response)

    client = Client(
        base_url=f'{CYBERARKPAS_URL}',
        verify=False,
        proxy=False,
        ok_codes=(200, 201, 204),
        headers={'accept': "application/json"}
    )
    client.login(username="test", password="test")
    args = {
        "limit": "25",
        "offset": "0"
    }
    outputs = list_accounts(client, args).outputs
    expected_output = list_accounts_response
    assert outputs[0]['AccountName'] == expected_output.get('value')[0]['name']


def test_add_account(requests_mock):
    from CyberArkPAS import Client, add_account
    add_account_response = load_test_data('./test_data/cyberark-add-account.json')
    requests_mock.post(f'{CYBERARKPAS_URL}/PasswordVault/API/Auth/CyberArk/Logon', json="test")

    requests_mock.post(f'{CYBERARKPAS_URL}/PasswordVault/api/Accounts', json=add_account_response)

    client = Client(
        base_url=f'{CYBERARKPAS_URL}',
        verify=False,
        proxy=False,
        ok_codes=(200, 201, 204),
        headers={'accept': "application/json"}
    )
    client.login(username="test", password="test")
    args = {
        "name": "user3",
        "user-name": "user3",
        "platform-id": "WinDesktopLocal",
        "safe-name": "Labs",
        "address": "10.10.10.30",
        "platform-account-properties":
            {
                "LogonDomain": "string",
                "Location": "IT",
                "OwnerName": "MSSPAdmin"
            }
    }
    outputs = add_account(client, args).outputs
    expected_output = add_account_response
    assert outputs[0]['AccountName'] == expected_output.get('name')


def test_delete_account(requests_mock):
    from CyberArkPAS import Client, delete_account
    requests_mock.post(f'{CYBERARKPAS_URL}/PasswordVault/API/Auth/CyberArk/Logon', json="test")
    requests_mock.delete(f'{CYBERARKPAS_URL}/PasswordVault/api/Accounts/10_38')
    client = Client(
        base_url=f'{CYBERARKPAS_URL}',
        verify=False,
        proxy=False,
        ok_codes=(200, 201, 204),
        headers={'accept': "application/json"}
    )
    client.login(username="test", password="test")
    args = {
        "account_id": "10_38"
    }
    outputs = delete_account(client, args)
    expected_output = "Account is Deleted"
    assert outputs == expected_output
