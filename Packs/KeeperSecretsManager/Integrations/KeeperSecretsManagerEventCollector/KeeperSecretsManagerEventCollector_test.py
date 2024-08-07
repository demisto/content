import json
import io
import pytest
from pytest_mock import MockerFixture
from KeeperSecretsManagerEventCollector import DEFAULT_MAX_FETCH, Client, KeeperParams


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client_class():
    return Client(
        server_url="dummy_server_url",
        username="dummy_user",
        password="dummy_password",
    )


@pytest.mark.parametrize(
    "device_token, device_private_key, session_token, clone_code",
    (
        pytest.param("token1", "private_key1", "session1", "clone_code1"),
        pytest.param(None, None, None, None),
    ),
)
def test_load_integration_context_into_keeper_params(
    mocker: MockerFixture,
    device_token: str | None,
    device_private_key: str | None,
    session_token: str | None,
    clone_code: str | None,
):
    """
    Given
        - Data saved in the integration context that is used in the SDK to do requests.

    When
        - Loading the integration context into a KeeperParams instance.

    Then
        - Check the KeeperParams instance is instantiated correctly.
    """
    from KeeperSecretsManagerEventCollector import load_integration_context_into_keeper_params

    mocker.patch(
        "KeeperSecretsManagerEventCollector.get_integration_context",
        return_value={
            "device_token": device_token,
            "device_private_key": device_private_key,
            "session_token": session_token,
            "clone_code": clone_code,
        },
    )
    username = "dummy_username"
    password = "dummy_password"
    server_url = "dummy_server"
    keeper_params = load_integration_context_into_keeper_params(username=username, password=password, server_url=server_url)
    assert keeper_params.user == username
    assert keeper_params.password == password
    assert keeper_params.server == server_url
    assert keeper_params.rest_context.certificate_check is False
    assert keeper_params.device_token == device_token
    assert keeper_params.device_private_key == device_private_key
    assert keeper_params.session_token == session_token
    assert keeper_params.clone_code == clone_code


@pytest.mark.parametrize(
    "params_max_fetch, expected",
    [
        pytest.param(10, 10, id="param overrides default"),
        pytest.param("invalid", None, id="invalid params max fetch"),
        pytest.param("", DEFAULT_MAX_FETCH, id="empty param, using default"),
    ],
)
def test_get_max_events_to_fetch(params_max_fetch: str | int, expected: int):
    """
    Given: max_fetch parameters
    When: Setting the max events to fetch
    Then: Calculate the max events to fetch based on the parameter passed in
    """
    from KeeperSecretsManagerEventCollector import get_max_events_to_fetch

    if expected is None:
        with pytest.raises(ValueError):
            get_max_events_to_fetch(params_max_fetch)
    else:
        get_max_events_to_fetch(params_max_fetch)


def test_append_to_integration_context(mocker: MockerFixture):
    """
    Given: Data to append to the integration context
    When: Appending data to the integration context
    Then: Check that the newly appended data is saved
    """
    from KeeperSecretsManagerEventCollector import append_to_integration_context

    integration_context = {"key1": "val1", "key2": 12345}
    context_to_append = {"key3": "val3", "key1": "newValue1"}  # Notice that key1 will hold newValue1 in the end
    mocker.patch(
        "KeeperSecretsManagerEventCollector.get_integration_context",
        return_value=integration_context,
    )
    set_integration_context_mocker = mocker.patch(
        "KeeperSecretsManagerEventCollector.set_integration_context",
        return_value=None,
    )
    append_to_integration_context(context_to_append)
    assert set_integration_context_mocker.call_args[0][0] == integration_context | context_to_append


def test_save_device_tokens(
    mocker: MockerFixture,
    client_class: Client,
):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2, utils

    device_private_key = "private_key1"
    device_token = "device_token1"
    login_token = "1111111111111111"  # Length 16

    def startLoginMessage_side_effect(
        keeper_params: KeeperParams, encrypted_device_token: bytes, cloneCode: bytes | None = None, loginType="NORMAL"
    ):
        keeper_params.device_private_key = device_private_key  # type: ignore
        keeper_params.device_token = device_token  # type: ignore
        login_response = APIRequest_pb2.LoginResponse
        login_response.encryptedLoginToken = utils.base64_url_decode(login_token)  # type: ignore
        return login_response

    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.startLoginMessage",
        side_effect=startLoginMessage_side_effect,
    )
    set_integration_context_mocker = mocker.patch(
        "KeeperSecretsManagerEventCollector.set_integration_context",
        return_value=None,
    )
    client_class.save_device_tokens(b"encryptedDeviceToken")
    assert set_integration_context_mocker.call_args[0][0] == {
        "device_private_key": device_private_key,
        "device_token": device_token,
        "login_token": login_token,
    }


def test_start_registering_device(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import Client

    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.get_device_id",
        return_value=b"encryptedDeviceToken",
    )
    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.startLoginMessage",
        side_effect=startLoginMessage_side_effect,
    )
    client_class.start_registering_device(device_approval=Client.DeviceApproval())
