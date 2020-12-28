import pytest

from CyberArkAIM_v2 import Client, list_credentials_command
from test_data.context import LIST_CREDENTIALS_CONTEXT
from test_data.http_resonses import LIST_CREDENTIALS_RAW


@pytest.mark.parametrize('command, http_response, context', [
    (list_credentials_command, LIST_CREDENTIALS_RAW, LIST_CREDENTIALS_CONTEXT)
])
def test_cyberark_aim_commands(command, http_response, context, mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - mock the http request result
    Then
    - create the context
    - validate the expected_result and the created context
    - make sure the key "Content" that contains the password doesn't appear in content or raw_response
    """
    client = Client(server_url="https://api.cyberark.com/", use_ssl=False, proxy=False, app_id="app", folder="Root",
                    safe="safe1", credentials_object="object1", username="", password="", cert_text="", key_text="")

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client)
    results = outputs.to_context()
    assert results.get("EntryContext") == context
    assert not results.get("EntryContext")['CyberArkAIM(val.Name == obj.Name)'].get("Content")
    assert not results.get("Contents").get("Content")
