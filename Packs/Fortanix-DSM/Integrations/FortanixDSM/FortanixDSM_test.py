"""Fortanix-DSM Integration for Cortex XSOAR - Unit Tests file

This Unit Tests in this file validate the FortanixDSM Integration based
on pytest as mandated by Cortex XSOAR contribution requirements. They verify
that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/Fortanix-DSM/Integrations/FortanixDSM

Coverage
--------

There could be one or more unit tests per command function and is executed with
specific parameters, wherein the output is checked against an expected result.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the Fortanix DSM API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_secrets(requests_mock):
    """
    Tests fortanix-list-secrets command function.

        Given:
            - requests_mock instance to generate the appropriate list_secrets API
              response when the correct list_secrets API request is performed.
            - group_id argument

        When:
            - Running the 'list-secrets-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, list_secrets_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys'
    name = 'secret 101'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    gid = '07f85883-adaf-4a6c-a040-ffed46dfd349'
    params = f'obj_type=SECRET&sort=name%3Aasc&group_id={gid}'

    mock_response = [
        {
            'Name': name,
            'ID': kid,
            'ID': kid,
            'Group': gid
        }
    ]
    requests_mock.get(f'{url}/{path}?{params}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'group_id': gid
    }

    response = list_secrets_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Secret'
    '''
    mocking a single secret response here, but;
    for a list of secrets, the response from the request
    needs to have each secret.state defined and the
    method response differs from the request response.
    '''
    assert response.outputs == mock_response[0]


def test_get_secret_metadata(requests_mock):
    """
    Tests fortanix-get-secret-metadata command function.

        Given:
            - requests_mock instance to generate the appropriate get_secret_metadata API
              response when the correct get_secret_metadata API request is performed.
            - kid argument

        When:
            - Running the 'get-secret-metadata-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, list_secrets_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys'
    name = 'secret 101'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    gid = '07f85883-adaf-4a6c-a040-ffed46dfd349'
    params = 'obj_type=SECRET&sort=name%3Aasc'

    mock_response = {
        'name': name,
        'kid': kid,
        'group_id': gid,
        'obj_type': 'SECRET'
    }

    requests_mock.get(f'{url}/{path}/{kid}?{params}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'kid': kid
    }

    response = list_secrets_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Secret'
    assert response.outputs == mock_response


def test_fetch_secret(requests_mock):
    """
    Tests fortanix-fetch-secret command function.

        Given:
            - requests_mock instance to generate the appropriate fetch_secret API
              response when the correct fetch_secret API request is performed.
            - name argument

        When:
            - Running the 'fetch-secret-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, fetch_secret_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys/export'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'

    mock_response = [
        {
            'Value': ''
        }
    ]
    requests_mock.post(f'{url}/{path}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'kid': kid
    }

    response = fetch_secret_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Secret.Value'
    assert response.outputs == mock_response


def test_new_secret(requests_mock):
    """
    Tests fortanix-new-secret command function.

        Given:
            - requests_mock instance to generate the appropriate import_secret API
              response when the correct import_secret API request is performed.
            - name argument
            - value argument

        When:
            - Running the 'new_secret_command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, import_secret_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    aid = '0a9bcbbe-1919-4c57-89e4-b521f4d9ff28'
    name = 'new secr3t'

    mock_response = {
        'kid': kid,
        'name': name,
        'acct_id': aid,
        'obj_type': 'SECRET',
        'never_exportable': False,
        'state': 'Active'
    }

    requests_mock.put(f'{url}/{path}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'name': name,
        'value': 'rand0m',
    }

    response = import_secret_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Secret'
    assert response.outputs == mock_response


def test_rotate_secret(requests_mock):
    """
    Tests fortanix-rotate-secret command function.

        Given:
            - requests_mock instance to generate the appropriate import_secret API
              response when the correct import_secret API request is performed.
            - name argument
            - value argument

        When:
            - Running the 'rotate_secret_command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, import_secret_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys/rekey'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    aid = '0a9bcbbe-1919-4c57-89e4-b521f4d9ff28'
    name = 'new secr3t'

    mock_response = {
        'kid': kid,
        'name': name,
        'acct_id': aid,
        'obj_type': 'SECRET',
        'never_exportable': False,
        'state': 'Active'
    }

    requests_mock.post(f'{url}/{path}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'name': name,
        'value': 'rand0m',
    }

    response = import_secret_command(client, args, None, True)

    assert response.outputs_prefix == 'Fortanix.Secret'
    assert response.outputs == mock_response


def test_delete_secret(requests_mock):
    """
    Tests fortanix-delete-secret command function.

        Given:
            - requests_mock instance to generate the appropriate delete_secret API
              response when the correct delete_secret API request is performed.
            - kid argument

        When:
            - Running the 'delete-secret-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, delete_secret_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/keys'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'

    mock_response = [{
        'Result': 'OK'
    }]

    requests_mock.delete(f'{url}/{path}/{kid}', json={})

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'kid': kid
    }

    response = delete_secret_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Secret.Result'
    assert response.outputs == mock_response


def test_invoke_plugin(requests_mock):
    """
    Tests fortanix-invoke-plugin command function.

        Given:
            - requests_mock instance to generate the appropriate invoke-plugin API
              response when the correct invoke-plugin API request is performed.
            - pid argument
            - input argument

        When:
            - Running the 'invoke-plugin-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, invoke_plugin_command
    url = 'https://fortanix.test'
    path = 'sys/v1/plugins'
    pid = '3599796b-7b18-49c3-aad8-9758af24fbf9'

    mock_response = {
        'plugin_output': 'Plugin_value',
        'another_key': True,
        'numeric_key': 90210
    }

    requests_mock.post(f'{url}/{path}/{pid}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'pid': pid,
        'input': 'random'
    }

    response = invoke_plugin_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Plugin.Output'
    assert response.outputs == [mock_response]


def test_encrypt(requests_mock):
    """
    Tests fortanix-encrypt command function.

        Given:
            - requests_mock instance to generate the appropriate encrypt API
              response when the correct encrypt API request is performed.
            - key argument
            - data argument
            - mode argument

        When:
            - Running the 'encrypt-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, encrypt_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/encrypt'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'

    mock_response = {
        'kid': kid,
        'cipher': 'u2KMcAUF1jsifJfh99uWqw==',
        'iv': 'r7HeHduHSZ1IrCC6s7MG0w=='
    }

    requests_mock.post(f'{url}/{path}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'key': 'key_name',
        'data': 'Hello World',
        'mode': 'CBC'
    }

    response = encrypt_command(client, args)

    cipher = ("eyJraWQiOiAiN2ExNjFhM2YtOGQ1My00MmRlLTgwY2QtOTJmYjAxN2M1YTEyIi"
              "wgImNpcGhlciI6ICJ1MktNY0FVRjFqc2lmSmZoOTl1V3F3PT0iLCAiaXYiOiAi"
              "cjdIZUhkdUhTWjFJckNDNnM3TUcwdz09IiwgIm1vZGUiOiAiQ0JDIn0=")
    assert response.outputs_prefix == 'Fortanix.Data.Cipher'
    assert response.outputs == [{
        'Cipher': cipher
    }]


def test_decrypt(requests_mock):
    """
    Tests fortanix-decrypt command function.

        Given:
            - requests_mock instance to generate the appropriate decrypt API
              response when the correct decrypt API request is performed.
            - cipher argument

        When:
            - Running the 'decrypt-command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from FortanixDSM import Client, decrypt_command
    url = 'https://fortanix.test'
    path = 'crypto/v1/decrypt'
    kid = '7a161a3f-8d53-42de-80cd-92fb017c5a12'

    cipher = ("eyJraWQiOiAiN2ExNjFhM2YtOGQ1My00MmRlLTgwY2QtOTJmYjAxN2M1YTEyIi"
              "wgImNpcGhlciI6ICJ1MktNY0FVRjFqc2lmSmZoOTl1V3F3PT0iLCAiaXYiOiAi"
              "cjdIZUhkdUhTWjFJckNDNnM3TUcwdz09IiwgIm1vZGUiOiAiQ0JDIn0=")
    mock_response = {
        'kid': kid,
        'plain': 'u2KMcAUF1jsifJfh99uWqw==',
    }

    requests_mock.post(f'{url}/{path}', json=mock_response)

    client = Client(
        base_url=url,
        verify=False,
        headers={
            'Authentication': 'Basic some_api_key'
        }
    )

    args = {
        'cipher': cipher
    }

    response = decrypt_command(client, args)

    assert response.outputs_prefix == 'Fortanix.Data.Plain'
    assert response.outputs == [{
        'Plain': 'u2KMcAUF1jsifJfh99uWqw=='
    }]
