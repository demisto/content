import json
import pytest
from pytest_mock import MockerFixture
from CommonServerPython import DemistoException
from KeeperSecretsManagerEventCollector import DEFAULT_MAX_FETCH, Client, KeeperParams
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
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
def test_get_max_events_to_fetch(params_max_fetch: str | int, expected: None | int):
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
        login_response = APIRequest_pb2.LoginResponse()
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


def test_start_registering_device_success(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2

    device_approval = client_class.DeviceApproval()
    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.get_device_id",
        return_value=b"encryptedDeviceToken",
    )
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.DEVICE_APPROVAL_REQUIRED  # type: ignore
    mocker.patch.object(
        client_class,
        "save_device_tokens",
        return_value=login_resp,
    )
    device_approval_mocker = mocker.patch.object(device_approval, "send_push", return_value=None)
    client_class.start_registering_device(device_approval=device_approval)
    assert device_approval_mocker.call_count == 1


def test_start_registering_device_already_registered(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2, DEVICE_ALREADY_REGISTERED

    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.get_device_id",
        return_value=b"encryptedDeviceToken",
    )
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH  # type: ignore
    mocker.patch.object(
        client_class,
        "save_device_tokens",
        return_value=login_resp,
    )
    with pytest.raises(DemistoException) as e:
        client_class.start_registering_device(device_approval=client_class.DeviceApproval())
    assert DEVICE_ALREADY_REGISTERED in str(e)


def test_start_registering_device_unknown_state(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2

    mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.get_device_id",
        return_value=b"encryptedDeviceToken",
    )
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.INVALID_LOGINMETHOD  # type: ignore
    mocker.patch.object(
        client_class,
        "save_device_tokens",
        return_value=login_resp,
    )
    with pytest.raises(DemistoException, match="Unknown login state 0"):
        client_class.start_registering_device(device_approval=client_class.DeviceApproval())


def test_validate_device_registration_requires_auth_hash(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2

    # Arrange
    encrypted_device_token = b"encrypted_device_token"
    encrypted_login_token = b"encrypted_login_token"

    start_login_resp = APIRequest_pb2.LoginResponse()
    start_login_resp.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH  # type: ignore

    verify_password_response = APIRequest_pb2.LoginResponse()
    verify_password_response.loginState = APIRequest_pb2.LOGGED_IN  # type: ignore

    correct_salt_resp = mocker.Mock()
    correct_salt_resp.salt = [b"correct_salt"]

    mock_start_login = mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.startLoginMessage", return_value=start_login_resp
    )
    mock_get_salt = mocker.patch("KeeperSecretsManagerEventCollector.api.get_correct_salt", return_value=correct_salt_resp)
    mock_verify_password = mocker.patch.object(
        client_class.PasswordStep, "verify_password", return_value=verify_password_response
    )
    mock_post_login_processing = mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3Flow.post_login_processing", return_value=None
    )

    # Act
    client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)

    # Assert
    mock_start_login.assert_called_once_with(client_class.keeper_params, encrypted_device_token)
    mock_get_salt.assert_called_once_with(start_login_resp.salt)  # type: ignore
    mock_verify_password.assert_called_once_with(client_class.keeper_params, encrypted_login_token)
    mock_post_login_processing.assert_called_once_with(client_class.keeper_params, mock_verify_password.return_value)


def test_validate_device_registration_unknown_login_state_after_verify_password(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2

    # Arrange
    encrypted_device_token = b"encrypted_device_token"
    encrypted_login_token = b"encrypted_login_token"

    start_login_resp = APIRequest_pb2.LoginResponse()
    start_login_resp.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH  # type: ignore

    verify_password_response = APIRequest_pb2.LoginResponse()
    verify_password_response.loginState = APIRequest_pb2.INVALID_LOGINMETHOD  # type: ignore

    correct_salt_resp = mocker.Mock()
    correct_salt_resp.salt = [b"correct_salt"]

    mocker.patch("KeeperSecretsManagerEventCollector.LoginV3API.startLoginMessage", return_value=start_login_resp)
    mocker.patch("KeeperSecretsManagerEventCollector.api.get_correct_salt", return_value=correct_salt_resp)
    mocker.patch.object(client_class.PasswordStep, "verify_password", return_value=verify_password_response)

    # Act & Assert
    with pytest.raises(DemistoException, match="Unknown login state after verify password 0"):
        client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)


def test_validate_device_registration_unknown_login_state(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import APIRequest_pb2

    # Arrange
    encrypted_device_token = b"encrypted_device_token"
    encrypted_login_token = b"encrypted_login_token"

    start_login_resp = APIRequest_pb2.LoginResponse()
    start_login_resp.loginState = APIRequest_pb2.INVALID_LOGINMETHOD  # type: ignore

    mocker.patch("KeeperSecretsManagerEventCollector.LoginV3API.startLoginMessage", return_value=start_login_resp)

    # Act & Assert
    with pytest.raises(DemistoException, match="Unknown login state 0"):
        client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)


def test_start_registration_success(mocker: MockerFixture, client_class: Client):
    # Arrange
    device_approval_mock = client_class.DeviceApproval()

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mock_start_registering_device = mocker.patch.object(client_class, "start_registering_device")

    # Act
    client_class.start_registration()

    # Assert
    mock_start_registering_device.assert_called_once_with(device_approval_mock)


def test_start_registration_with_invalid_device_token(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import InvalidDeviceToken

    # Arrange
    device_approval_mock = client_class.DeviceApproval()

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mock_start_registering_device = mocker.patch.object(client_class, "start_registering_device")

    # Simulate raising InvalidDeviceToken on the first call
    mock_start_registering_device.side_effect = [InvalidDeviceToken, None]

    # Act
    client_class.start_registration()

    # Assert
    assert mock_start_registering_device.call_count == 2
    mock_start_registering_device.assert_any_call(device_approval_mock)
    mock_start_registering_device.assert_any_call(device_approval_mock, new_device=True)


def test_finish_registering_device_with_code(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import DeviceApprovalChannel

    # Arrange
    device_approval = mocker.Mock()
    encrypted_login_token = b"encrypted_login_token"
    code = "123456"

    mock_base64_url_decode = mocker.patch(
        "KeeperSecretsManagerEventCollector.utils.base64_url_decode", return_value=b"encrypted_device_token"
    )
    mock_send_code = mocker.patch.object(device_approval, "send_code")
    mock_validate_device_registration = mocker.patch.object(client_class, "validate_device_registration")

    # Act
    client_class.finish_registering_device(device_approval, encrypted_login_token, code)

    # Assert
    mock_base64_url_decode.assert_called_once_with(client_class.keeper_params.device_token)
    mock_send_code.assert_called_once_with(
        client_class.keeper_params,
        DeviceApprovalChannel.Email,
        b"encrypted_device_token",
        encrypted_login_token,
        code,
    )
    mock_validate_device_registration.assert_called_once_with(
        encrypted_device_token=b"encrypted_device_token",
        encrypted_login_token=encrypted_login_token,
    )


def test_finish_registering_device_without_code(mocker: MockerFixture, client_class: Client):
    # Arrange
    device_approval = mocker.Mock()
    encrypted_login_token = b"encrypted_login_token"
    code = ""

    mock_base64_url_decode = mocker.patch(
        "KeeperSecretsManagerEventCollector.utils.base64_url_decode", return_value=b"encrypted_device_token"
    )
    mock_send_code = mocker.patch.object(device_approval, "send_code")
    mock_validate_device_registration = mocker.patch.object(client_class, "validate_device_registration")

    # Act
    client_class.finish_registering_device(device_approval, encrypted_login_token, code)

    # Assert
    mock_base64_url_decode.assert_called_once_with(client_class.keeper_params.device_token)
    mock_send_code.assert_not_called()
    mock_validate_device_registration.assert_called_once_with(
        encrypted_device_token=b"encrypted_device_token",
        encrypted_login_token=encrypted_login_token,
    )


def test_complete_registration_success(mocker: MockerFixture, client_class: Client):
    # Arrange
    code = "123456"
    device_approval_mock = mocker.Mock()
    integration_context_mock = {"login_token": "mocked_login_token"}
    encrypted_login_token = b"mocked_encrypted_login_token"

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.utils.base64_url_decode", return_value=encrypted_login_token)
    mock_finish_registering_device = mocker.patch.object(client_class, "finish_registering_device")
    mock_save_session_token = mocker.patch.object(client_class, "save_session_token")

    # Mock a valid session token
    client_class.keeper_params.session_token = "mocked_session_token"  # type: ignore

    # Act
    client_class.complete_registration(code)

    # Assert
    mock_finish_registering_device.assert_called_once_with(device_approval_mock, encrypted_login_token, code)
    mock_save_session_token.assert_called_once()
    assert client_class.keeper_params.session_token == "mocked_session_token"


def test_complete_registration_no_session_token(mocker: MockerFixture, client_class: Client):
    # Arrange
    code = "123456"
    device_approval_mock = mocker.Mock()
    integration_context_mock = {"login_token": "mocked_login_token"}
    encrypted_login_token = b"mocked_encrypted_login_token"

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.utils.base64_url_decode", return_value=encrypted_login_token)
    mock_finish_registering_device = mocker.patch.object(client_class, "finish_registering_device")
    mock_save_session_token = mocker.patch.object(client_class, "save_session_token")

    # Mock an invalid (empty) session token
    client_class.keeper_params.session_token = ""  # type: ignore

    # Act & Assert
    with pytest.raises(DemistoException, match="Could not find session token"):
        client_class.complete_registration(code)

    mock_finish_registering_device.assert_called_once_with(device_approval_mock, encrypted_login_token, code)
    mock_save_session_token.assert_called_once()


@freeze_time("2024-01-01 00:00:00")
def test_save_session_token(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import get_current_time_in_seconds

    # Arrange
    session_token = "mocked_session_token"
    clone_code = "mocked_clone_code"
    current_time = get_current_time_in_seconds()  # This represents the freezed time, e.g., Jan 1, 2024, 00:00:00 UTC
    session_token_ttl = 3600  # Example TTL (1 hour)

    mock_append_to_integration_context = mocker.patch("KeeperSecretsManagerEventCollector.append_to_integration_context")

    client_class.keeper_params.session_token = session_token  # type: ignore
    client_class.keeper_params.clone_code = clone_code  # type: ignore

    # Act
    client_class.save_session_token()

    # Assert
    mock_append_to_integration_context.assert_called_once_with(
        {
            "session_token": session_token,
            "clone_code": clone_code,
            "valid_until": current_time + session_token_ttl,
        }
    )


def test_test_registration_no_session_token(mocker: MockerFixture, client_class: Client):
    from KeeperSecretsManagerEventCollector import REGISTRATION_FLOW_MESSAGE

    # Arrange
    client_class.keeper_params.session_token = ""  # type: ignore

    # Act & Assert
    with pytest.raises(DemistoException, match=REGISTRATION_FLOW_MESSAGE):
        client_class.test_registration()


def test_test_registration_with_session_token(mocker: MockerFixture, client_class: Client):
    # Arrange
    client_class.keeper_params.session_token = "mocked_session_token"  # type: ignore

    mock_query_audit_logs = mocker.patch.object(client_class, "query_audit_logs")

    # Act
    client_class.test_registration()

    # Assert
    mock_query_audit_logs.assert_called_once_with(limit=1, start_event_time=0)


def test_refresh_session_token_if_needed_refresh_needed(mocker: MockerFixture, client_class: Client):
    # Arrange
    integration_context_mock = {
        "valid_until": 1609459200  # Example timestamp for valid_until
    }
    current_time = 1609459195  # 5 seconds before valid_until

    mocker.patch("KeeperSecretsManagerEventCollector.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.get_current_time_in_seconds", return_value=current_time)
    mock_get_device_id = mocker.patch(
        "KeeperSecretsManagerEventCollector.LoginV3API.get_device_id", return_value=b"encrypted_device_token"
    )
    mock_save_device_tokens = mocker.patch.object(
        client_class, "save_device_tokens", return_value=mocker.Mock(encryptedLoginToken=b"encrypted_login_token")
    )
    mock_validate_device_registration = mocker.patch.object(client_class, "validate_device_registration")
    mock_save_session_token = mocker.patch.object(client_class, "save_session_token")

    client_class.keeper_params.session_token = "mocked_session_token"  # type: ignore

    # Act
    client_class.refresh_session_token_if_needed()

    # Assert
    mock_get_device_id.assert_called_once_with(client_class.keeper_params)
    mock_save_device_tokens.assert_called_once_with(encrypted_device_token=b"encrypted_device_token")
    mock_validate_device_registration.assert_called_once_with(
        encrypted_device_token=b"encrypted_device_token",
        encrypted_login_token=b"encrypted_login_token",
    )
    mock_save_session_token.assert_called_once()


def test_refresh_session_token_if_needed_no_refresh_needed(mocker: MockerFixture, client_class: Client):
    # Arrange
    integration_context_mock = {
        "valid_until": 1609459200  # Example timestamp for valid_until
    }
    current_time = 1609459100  # 100 seconds before valid_until

    mocker.patch("KeeperSecretsManagerEventCollector.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecretsManagerEventCollector.get_current_time_in_seconds", return_value=current_time)
    mock_get_device_id = mocker.patch("KeeperSecretsManagerEventCollector.LoginV3API.get_device_id")
    mock_save_device_tokens = mocker.patch.object(client_class, "save_device_tokens")
    mock_validate_device_registration = mocker.patch.object(client_class, "validate_device_registration")
    mock_save_session_token = mocker.patch.object(client_class, "save_session_token")

    client_class.keeper_params.session_token = "mocked_session_token" # type: ignore

    # Act
    client_class.refresh_session_token_if_needed()

    # Assert
    mock_get_device_id.assert_not_called()
    mock_save_device_tokens.assert_not_called()
    mock_validate_device_registration.assert_not_called()
    mock_save_session_token.assert_not_called()
