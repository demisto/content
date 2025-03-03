import json
import pytest
from pytest_mock import MockerFixture
from CommonServerPython import DemistoException
from KeeperSecurity import Client, KeeperParams
from freezegun import freeze_time
import demistomock as demisto


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
    from KeeperSecurity import load_integration_context_into_keeper_params

    mocker.patch(
        "KeeperSecurity.get_integration_context",
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


def test_append_to_integration_context(mocker: MockerFixture):
    """
    Given: Data to append to the integration context
    When: Appending data to the integration context
    Then: Check that the newly appended data is saved
    """
    from KeeperSecurity import append_to_integration_context

    integration_context = {"key1": "val1", "key2": 12345}
    context_to_append = {"key3": "val3", "key1": "newValue1"}  # Notice that key1 will hold newValue1 in the end
    mocker.patch(
        "KeeperSecurity.get_integration_context",
        return_value=integration_context,
    )
    set_integration_context_mocker = mocker.patch(
        "KeeperSecurity.set_integration_context",
        return_value=None,
    )
    append_to_integration_context(context_to_append)
    assert set_integration_context_mocker.call_args[0][0] == integration_context | context_to_append


def test_save_device_tokens(
    mocker: MockerFixture,
    client_class: Client,
):
    """
    Given
        - Mocked startLoginMessage function to simulate the device token saving process.
        - Mocked set_integration_context to verify its arguments.
    When
        - Running the save_device_tokens method.
    Then
        - The set_integration_context function should be called with the correct device private key, device token, and login
        token.
    """
    from KeeperSecurity import APIRequest_pb2, utils

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
        "KeeperSecurity.LoginV3API.startLoginMessage",
        side_effect=startLoginMessage_side_effect,
    )
    set_integration_context_mocker = mocker.patch(
        "KeeperSecurity.set_integration_context",
        return_value=None,
    )
    client_class.save_device_tokens(b"encryptedDeviceToken")
    assert set_integration_context_mocker.call_args[0][0] == {
        "device_private_key": device_private_key,
        "device_token": device_token,
        "login_token": login_token,
    }


def test_start_registering_device_success(mocker: MockerFixture, client_class: Client):
    """
    Given
        - A mock device approval object.
        - Mocked get_device_id to simulate fetching a device ID.
        - Mocked save_device_tokens to simulate saving device tokens.
    When
        - Running the start_registering_device method.
    Then
        - The device_approval's send_push method should be called once.
    """
    from KeeperSecurity import APIRequest_pb2

    device_approval = client_class.DeviceApproval()
    mocker.patch(
        "KeeperSecurity.LoginV3API.get_device_id",
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
    """
    Given
        - Mocked get_device_id to simulate fetching a device ID.
        - Mocked save_device_tokens to simulate returning a login state indicating the device is already registered.
    When
        - Running the start_registering_device method.
    Then
        - The function should raise a DemistoException with a message indicating the device is already registered.
    """
    from KeeperSecurity import APIRequest_pb2, DEVICE_ALREADY_REGISTERED

    mocker.patch(
        "KeeperSecurity.LoginV3API.get_device_id",
        return_value=b"encryptedDeviceToken",
    )
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH  # type: ignore
    mocker.patch.object(
        client_class,
        "save_device_tokens",
        return_value=login_resp,
    )
    with pytest.raises(DemistoException, match=DEVICE_ALREADY_REGISTERED):
        client_class.start_registering_device(device_approval=client_class.DeviceApproval())


def test_start_registering_device_unknown_state(mocker: MockerFixture, client_class: Client):
    """
    Given
        - Mocked get_device_id to simulate fetching a device ID.
        - Mocked save_device_tokens to simulate returning an unknown login state.
    When
        - Running the start_registering_device method.
    Then
        - The function should raise a DemistoException with a message indicating an unknown login state.
    """
    from KeeperSecurity import APIRequest_pb2

    mocker.patch(
        "KeeperSecurity.LoginV3API.get_device_id",
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
    """
    Given
        - Mocked startLoginMessage to simulate a login response requiring authentication hash.
        - Mocked get_correct_salt to simulate returning a correct salt.
        - Mocked verify_password to simulate a successful password verification.
        - Mocked post_login_processing to simulate post-login processing.
    When
        - Running the validate_device_registration method.
    Then
        - The function should call the appropriate methods to process the login and verify the password.
    """
    from KeeperSecurity import APIRequest_pb2

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
        "KeeperSecurity.LoginV3API.startLoginMessage", return_value=start_login_resp
    )
    mock_get_salt = mocker.patch("KeeperSecurity.api.get_correct_salt", return_value=correct_salt_resp)
    mock_verify_password = mocker.patch.object(
        client_class.PasswordStep, "verify_password", return_value=verify_password_response
    )
    mock_post_login_processing = mocker.patch(
        "KeeperSecurity.LoginV3Flow.post_login_processing", return_value=None
    )

    # Act
    client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)

    # Assert
    mock_start_login.assert_called_once_with(client_class.keeper_params, encrypted_device_token)
    mock_get_salt.assert_called_once_with(start_login_resp.salt)  # type: ignore
    mock_verify_password.assert_called_once_with(client_class.keeper_params, encrypted_login_token)
    mock_post_login_processing.assert_called_once_with(client_class.keeper_params, mock_verify_password.return_value)


def test_validate_device_registration_unknown_login_state_after_verify_password(mocker: MockerFixture, client_class: Client):
    """
    Given
        - Mocked startLoginMessage to simulate a login response requiring authentication hash.
        - Mocked verify_password to simulate an unknown login state after password verification.
    When
        - Running the validate_device_registration method.
    Then
        - The function should raise a DemistoException with a message indicating an unknown login state after
        password verification.
    """
    from KeeperSecurity import APIRequest_pb2

    # Arrange
    encrypted_device_token = b"encrypted_device_token"
    encrypted_login_token = b"encrypted_login_token"

    start_login_resp = APIRequest_pb2.LoginResponse()
    start_login_resp.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH  # type: ignore

    verify_password_response = APIRequest_pb2.LoginResponse()
    verify_password_response.loginState = APIRequest_pb2.INVALID_LOGINMETHOD  # type: ignore

    correct_salt_resp = mocker.Mock()
    correct_salt_resp.salt = [b"correct_salt"]

    mocker.patch("KeeperSecurity.LoginV3API.startLoginMessage", return_value=start_login_resp)
    mocker.patch("KeeperSecurity.api.get_correct_salt", return_value=correct_salt_resp)
    mocker.patch.object(client_class.PasswordStep, "verify_password", return_value=verify_password_response)

    # Act & Assert
    with pytest.raises(DemistoException, match="Unknown login state after verify password 0"):
        client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)


def test_validate_device_registration_unknown_login_state(mocker: MockerFixture, client_class: Client):
    """
    Given
        - Mocked startLoginMessage to simulate a login response with an unknown login state.
    When
        - Running the validate_device_registration method.
    Then
        - The function should raise a DemistoException with a message indicating an unknown login state.
    """
    from KeeperSecurity import APIRequest_pb2

    # Arrange
    encrypted_device_token = b"encrypted_device_token"
    encrypted_login_token = b"encrypted_login_token"

    start_login_resp = APIRequest_pb2.LoginResponse()
    start_login_resp.loginState = APIRequest_pb2.INVALID_LOGINMETHOD  # type: ignore

    mocker.patch("KeeperSecurity.LoginV3API.startLoginMessage", return_value=start_login_resp)

    # Act & Assert
    with pytest.raises(DemistoException, match="Unknown login state 0"):
        client_class.validate_device_registration(encrypted_device_token, encrypted_login_token)


def test_start_registration_success(mocker: MockerFixture, client_class: Client):
    """
    Given
        - A mock device approval object.
        - Mocked start_registering_device to simulate the registration process.
    When
        - Running the start_registration method.
    Then
        - The start_registering_device method should be called with the device approval object.
    """
    # Arrange
    device_approval_mock = client_class.DeviceApproval()

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mock_start_registering_device = mocker.patch.object(client_class, "start_registering_device")

    # Act
    client_class.start_registration()

    # Assert
    mock_start_registering_device.assert_called_once_with(device_approval_mock)


def test_start_registration_with_invalid_device_token(mocker: MockerFixture, client_class: Client):
    """
    Given
        - A mock device approval object.
        - Mocked start_registering_device to simulate an InvalidDeviceToken exception on the first call.
    When
        - Running the start_registration method.
    Then
        - The start_registering_device method should be called twice, once normally and once with new_device=True.
    """
    from KeeperSecurity import InvalidDeviceToken

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
    """
    Given
        - A mock device approval object.
        - Mocked base64_url_decode to simulate decoding a device token.
        - Mocked send_code to simulate sending a code.
        - Mocked validate_device_registration to simulate the device registration process.
    When
        - Running the finish_registering_device method with a code provided.
    Then
        - The send_code method should be called with the correct arguments.
        - The validate_device_registration method should be called with the decoded device token.
    """
    from KeeperSecurity import DeviceApprovalChannel

    # Arrange
    device_approval = mocker.Mock()
    encrypted_login_token = b"encrypted_login_token"
    code = "123456"

    mock_base64_url_decode = mocker.patch(
        "KeeperSecurity.utils.base64_url_decode", return_value=b"encrypted_device_token"
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
    """
    Given
        - A mock device approval object.
        - Mocked base64_url_decode to simulate decoding a device token.
        - Mocked validate_device_registration to simulate the device registration process.
    When
        - Running the finish_registering_device method without a code.
    Then
        - The send_code method should not be called.
        - The validate_device_registration method should be called with the decoded device token.
    """
    # Arrange
    device_approval = mocker.Mock()
    encrypted_login_token = b"encrypted_login_token"
    code = ""

    mock_base64_url_decode = mocker.patch(
        "KeeperSecurity.utils.base64_url_decode", return_value=b"encrypted_device_token"
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
    """
    Given
        - A mock device approval object.
        - Mocked get_integration_context to simulate fetching the integration context.
        - Mocked base64_url_decode to simulate decoding the login token.
        - Mocked finish_registering_device to simulate completing the registration process.
        - Mocked save_session_token to simulate saving the session token.
    When
        - Running the complete_registration method with a valid session token.
    Then
        - The finish_registering_device and save_session_token methods should be called with the correct arguments.
    """
    # Arrange
    code = "123456"
    device_approval_mock = mocker.Mock()
    integration_context_mock = {"login_token": "mocked_login_token"}
    encrypted_login_token = b"mocked_encrypted_login_token"

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mocker.patch("KeeperSecurity.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecurity.utils.base64_url_decode", return_value=encrypted_login_token)
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
    """
    Given
        - A mock device approval object.
        - Mocked get_integration_context to simulate fetching the integration context.
        - Mocked base64_url_decode to simulate decoding the login token.
        - Mocked finish_registering_device to simulate completing the registration process.
        - Mocked save_session_token to simulate saving the session token.
        - Simulating an empty session token.
    When
        - Running the complete_registration method.
    Then
        - The function should raise a DemistoException with a message indicating no session token was found.
    """
    # Arrange
    code = "123456"
    device_approval_mock = mocker.Mock()
    integration_context_mock = {"login_token": "mocked_login_token"}
    encrypted_login_token = b"mocked_encrypted_login_token"

    mocker.patch.object(client_class, "DeviceApproval", return_value=device_approval_mock)
    mocker.patch("KeeperSecurity.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecurity.utils.base64_url_decode", return_value=encrypted_login_token)
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
    """
    Given
        - Mocked append_to_integration_context to verify its arguments.
        - Simulated session_token and clone_code in keeper_params.
        - Freezing time to simulate the current time.
    When
        - Running the save_session_token method.
    Then
        - The append_to_integration_context function should be called with the correct session token, clone code, and calculated
        valid_until time.
    """
    from KeeperSecurity import get_current_time_in_seconds

    # Arrange
    session_token = "mocked_session_token"
    clone_code = "mocked_clone_code"
    current_time = get_current_time_in_seconds()  # This represents the freezed time, e.g., Jan 1, 2024, 00:00:00 UTC
    session_token_ttl = 3600  # Example TTL (1 hour)

    mock_append_to_integration_context = mocker.patch("KeeperSecurity.append_to_integration_context")

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


def test_test_registration_no_session_token(client_class: Client):
    """
    Given
        - Simulated an empty session token in keeper_params.
    When
        - Running the test_registration method.
    Then
        - The function should raise a DemistoException with the REGISTRATION_FLOW_MESSAGE.
    """
    from KeeperSecurity import REGISTRATION_FLOW_MESSAGE

    # Arrange
    client_class.keeper_params.session_token = ""  # type: ignore

    # Act & Assert
    with pytest.raises(DemistoException, match=REGISTRATION_FLOW_MESSAGE):
        client_class.test_registration()


def test_test_registration_with_session_token(mocker: MockerFixture, client_class: Client):
    """
    Given
        - Simulated a valid session token in keeper_params.
        - Mocked query_audit_logs to track its call.
    When
        - Running the test_registration method.
    Then
        - The query_audit_logs method should be called with the correct limit and start_event_time.
    """
    # Arrange
    client_class.keeper_params.session_token = "mocked_session_token"  # type: ignore

    mock_query_audit_logs = mocker.patch.object(client_class, "query_audit_logs")

    # Act
    client_class.test_registration()

    # Assert
    mock_query_audit_logs.assert_called_once_with(limit=1, start_event_time=0)


def test_refresh_session_token_if_needed_refresh_needed(mocker: MockerFixture, client_class: Client):
    """
    Given
        - Mocked get_integration_context to return a valid_until time close to the current time.
        - Mocked get_current_time_in_seconds to simulate the current time.
        - Mocked get_device_id to simulate fetching a device ID.
        - Mocked save_device_tokens to simulate saving device tokens.
        - Mocked validate_device_registration to simulate the registration process.
        - Mocked save_session_token to simulate saving the session token.
    When
        - Running the refresh_session_token_if_needed method.
    Then
        - The get_device_id, save_device_tokens, validate_device_registration, and save_session_token methods should be called
        with the correct arguments.
    """
    # Arrange
    integration_context_mock = {
        "valid_until": 1609459200  # Example timestamp for valid_until
    }
    current_time = 1609459195  # 5 seconds before valid_until

    mocker.patch("KeeperSecurity.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecurity.get_current_time_in_seconds", return_value=current_time)
    mock_get_device_id = mocker.patch(
        "KeeperSecurity.LoginV3API.get_device_id", return_value=b"encrypted_device_token"
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
    """
    Given
        - Mocked get_integration_context to return a valid_until time far from the current time.
        - Mocked get_current_time_in_seconds to simulate the current time.
    When
        - Running the refresh_session_token_if_needed method.
    Then
        - The get_device_id, save_device_tokens, validate_device_registration, and save_session_token methods
        should not be called.
    """
    # Arrange
    integration_context_mock = {
        "valid_until": 1609459200  # Example timestamp for valid_until
    }
    current_time = 1609459100  # 100 seconds before valid_until

    mocker.patch("KeeperSecurity.get_integration_context", return_value=integration_context_mock)
    mocker.patch("KeeperSecurity.get_current_time_in_seconds", return_value=current_time)
    mock_get_device_id = mocker.patch("KeeperSecurity.LoginV3API.get_device_id")
    mock_save_device_tokens = mocker.patch.object(client_class, "save_device_tokens")
    mock_validate_device_registration = mocker.patch.object(client_class, "validate_device_registration")
    mock_save_session_token = mocker.patch.object(client_class, "save_session_token")

    client_class.keeper_params.session_token = "mocked_session_token"  # type: ignore

    # Act
    client_class.refresh_session_token_if_needed()

    # Assert
    mock_get_device_id.assert_not_called()
    mock_save_device_tokens.assert_not_called()
    mock_validate_device_registration.assert_not_called()
    mock_save_session_token.assert_not_called()


@pytest.mark.parametrize(
    "last_run, expected_last_latest_event_time, expected_last_fetched_ids",
    [
        (
            {"last_fetch_epoch_time": "1672524000", "last_fetch_ids": ["id1", "id2"]},
            1672524000,  # 2023-01-01 00:00 UTC
            {"id1", "id2"},
        ),
        (
            {},  # No last_run data
            1704067200,  # Expected frozen timestamp for 2024-01-01 00:00:00 UTC
            set(),
        ),
    ],
)
@freeze_time("2024-01-01 00:00:00")
def test_fetch_events(mocker: MockerFixture, last_run, expected_last_latest_event_time, expected_last_fetched_ids):
    """
    Given
        - A mock client to fetch audit logs.
        - A last_run dictionary with different configurations for previous fetch times and fetched IDs.
        - A frozen time of 2024-01-01 00:00:00 UTC to ensure consistent timestamp handling.
    When
        - Running the fetch_events function.
    Then
        - The function should call get_audit_logs with the expected last_latest_event_time and last_fetched_ids based on the
        last_run input.
        - The result should match the mocked audit logs returned by get_audit_logs.
    """
    from KeeperSecurity import fetch_events

    # Arrange
    client_mock = mocker.Mock()
    max_fetch_limit = 10

    audit_log_mock = [{"event": "mocked_event"}]
    mock_get_audit_logs = mocker.patch("KeeperSecurity.get_audit_logs", return_value=audit_log_mock)

    # Act
    result = fetch_events(client=client_mock, last_run=last_run, max_fetch_limit=max_fetch_limit)

    # Assert
    mock_get_audit_logs.assert_called_once_with(
        client=client_mock,
        last_latest_event_time=expected_last_latest_event_time,
        max_fetch_limit=max_fetch_limit,
        last_fetched_ids=expected_last_fetched_ids,
    )
    assert result == audit_log_mock


@pytest.mark.parametrize(
    "audit_events, last_fetched_ids, expected_result",
    [
        (
            [{"id": "1", "event": "event1"}, {"id": "2", "event": "event2"}, {"id": "3", "event": "event3"}],
            {"4", "5"},
            [{"id": "1", "event": "event1"}, {"id": "2", "event": "event2"}, {"id": "3", "event": "event3"}],
        ),
        (
            [{"id": "1", "event": "event1"}, {"id": "2", "event": "event2"}, {"id": "3", "event": "event3"}],
            {"2", "3"},
            [{"id": "1", "event": "event1"}],
        ),
        (
            [{"id": "1", "event": "event1"}, {"id": "2", "event": "event2"}, {"id": "3", "event": "event3"}],
            {"1", "2", "3"},
            [],
        ),
        (
            [],
            {"1", "2", "3"},
            [],
        ),
    ],
)
def test_dedup_events(audit_events, last_fetched_ids, expected_result):
    """
    Given
        - A list of audit events and a set of last fetched IDs.
    When
        - Running the dedup_events function.
    Then
        - The function should correctly filter out events whose IDs are in last_fetched_ids.
        - The result should match the expected filtered list of audit events.
    """
    from KeeperSecurity import dedup_events

    # Act
    result = dedup_events(audit_events, last_fetched_ids)

    # Assert
    assert result == expected_result


def test_get_audit_logs_res_count_reaches_max_fetch_limit(mocker: MockerFixture):
    """
    Given
        - A mock client with two batches of audit events.
        - Mocking API_MAX_FETCH to dynamically limit the number of events fetched in each call.
        - Mocking demisto.setLastRun to verify its arguments.
    When
        - Running the get_audit_logs function with a max_fetch_limit smaller than the total number of available events.
    Then
        - The function should stop fetching after reaching the max_fetch_limit.
        - The client.query_audit_logs should be called twice, with the correct limits for each call.
        - The demisto.setLastRun should be called with the correct last fetch time and IDs.
    """
    from KeeperSecurity import get_audit_logs
    from unittest.mock import call

    # Arrange
    client_mock = mocker.Mock()
    audit_events_first_batch = [
        {"id": "1", "created": "1609459200"},
        {"id": "2", "created": "1609459200"},
    ]
    audit_events_second_batch = [
        {"id": "3", "created": "1609459300"},
    ]

    query_response_first = {"audit_event_overview_report_rows": audit_events_first_batch}
    query_response_second = {"audit_event_overview_report_rows": audit_events_second_batch}

    # Simulate two batches
    client_mock.query_audit_logs.side_effect = [query_response_first, query_response_second]

    # Mock API_MAX_FETCH to be 2
    mocker.patch("KeeperSecurity.API_MAX_FETCH", 2)
    mocker.patch("KeeperSecurity.demisto.setLastRun")

    # Act
    result = get_audit_logs(
        client=client_mock,
        last_latest_event_time=1609459100,
        max_fetch_limit=3,  # Set max_fetch_limit to 3
        last_fetched_ids=set(),
    )

    # Assert
    assert result == audit_events_first_batch + audit_events_second_batch  # Both batches should be returned
    assert client_mock.query_audit_logs.call_count == 2  # Two calls should be made

    # Check that the first call was made with a limit of 2 and the second with a limit of 1
    expected_calls = [
        call(limit=2, start_event_time=1609459100),
        call(limit=1, start_event_time=1609459200),
    ]
    assert client_mock.query_audit_logs.mock_calls == expected_calls

    demisto.setLastRun.assert_called_once_with({"last_fetch_epoch_time": "1609459300", "last_fetch_ids": ["3"]})


def test_get_audit_logs_no_audit_events(mocker: MockerFixture):
    """
    Given
        - A mock client that returns an empty list of audit events.
        - Mocking demisto.setLastRun to verify its arguments.
    When
        - Running the get_audit_logs function.
    Then
        - The result should be an empty list.
        - The client.query_audit_logs should be called once.
        - The demisto.setLastRun should be called with the initial last_latest_event_time and an empty list of IDs.
    """
    from KeeperSecurity import get_audit_logs

    # Arrange
    client_mock = mocker.Mock()
    query_response_mock = {"audit_event_overview_report_rows": []}
    client_mock.query_audit_logs.return_value = query_response_mock
    mocker.patch("KeeperSecurity.demisto.setLastRun")

    # Act
    result = get_audit_logs(
        client=client_mock,
        last_latest_event_time=1609459200,
        max_fetch_limit=10,
        last_fetched_ids=set(),
    )

    # Assert
    assert result == []
    client_mock.query_audit_logs.assert_called_once()
    demisto.setLastRun.assert_called_once_with({"last_fetch_epoch_time": "1609459200", "last_fetch_ids": []})


def test_get_audit_logs_deduplication_results_no_new_events(mocker: MockerFixture):
    """
    Given
        - A mock client that returns audit events already present in last_fetched_ids.
        - Mocking demisto.setLastRun to verify its arguments.
    When
        - Running the get_audit_logs function.
    Then
        - The result should be an empty list as no new events were found.
        - The client.query_audit_logs should be called once.
        - The demisto.setLastRun should be called with the same last_latest_event_time and the same set of fetched IDs.
    """
    from KeeperSecurity import get_audit_logs

    # Arrange
    client_mock = mocker.Mock()
    audit_events = [{"id": "1", "created": "1609459200"}, {"id": "2", "created": "1609459201"}]
    query_response_mock = {"audit_event_overview_report_rows": audit_events}
    client_mock.query_audit_logs.return_value = query_response_mock
    last_fetched_ids = {"1", "2"}
    mocker.patch("KeeperSecurity.demisto.setLastRun")

    # Act
    result = get_audit_logs(
        client=client_mock,
        last_latest_event_time=1609459200,
        max_fetch_limit=10,
        last_fetched_ids=last_fetched_ids,
    )

    # Assert
    assert result == []
    client_mock.query_audit_logs.assert_called_once()

    args, _ = demisto.setLastRun.call_args
    assert args[0]["last_fetch_epoch_time"] == "1609459200"
    assert sorted(args[0]["last_fetch_ids"]) == sorted(["1", "2"])


def test_get_audit_logs_pagination_stops_no_progress(mocker: MockerFixture):
    """
    Given
        - A mock client that returns audit events with the same creation time as the last_latest_event_time.
        - Mocking demisto.setLastRun to verify its arguments.
    When
        - Running the get_audit_logs function.
    Then
        - The result should contain the audit events returned by the client.
        - The client.query_audit_logs should be called once.
        - The demisto.setLastRun should be called with the same last_latest_event_time and the corresponding fetched IDs.
    """
    from KeeperSecurity import get_audit_logs

    # Arrange
    client_mock = mocker.Mock()
    audit_events = [
        {"id": "1", "created": "1609459200"},
        {"id": "2", "created": "1609459200"},
    ]
    query_response_mock = {"audit_event_overview_report_rows": audit_events}
    client_mock.query_audit_logs.return_value = query_response_mock
    mocker.patch("KeeperSecurity.demisto.setLastRun")

    # Act
    result = get_audit_logs(
        client=client_mock,
        last_latest_event_time=1609459200,
        max_fetch_limit=10,
        last_fetched_ids=set(),
    )

    # Assert
    assert result == audit_events
    client_mock.query_audit_logs.assert_called_once()
    # Assert that setLastRun was called with the correct parameters
    args, _ = demisto.setLastRun.call_args
    assert args[0]["last_fetch_epoch_time"] == "1609459200"
    assert sorted(args[0]["last_fetch_ids"]) == sorted(["1", "2"])


def test_get_audit_logs_successful_fetching(mocker: MockerFixture):
    """
    Given
        - A mock client with two batches of audit events.
        - Mocking API_MAX_FETCH to limit the number of events fetched in each call.
        - Mocking add_time_to_events to track its calls.
        - Mocking demisto.setLastRun to verify its arguments.
    When
        - Running the get_audit_logs function.
    Then
        - Both batches of events should be returned.
        - The client.query_audit_logs should be called twice with appropriate limits.
        - The demisto.setLastRun should be called with the correct parameters.
        - The add_time_to_events should be called twice, once for each batch of events.
    """

    from KeeperSecurity import get_audit_logs
    from unittest.mock import call

    # Arrange
    client_mock = mocker.Mock()
    audit_events_first_batch = [
        {"id": "1", "created": "1609459200"},
        {"id": "2", "created": "1609459200"},
    ]
    audit_events_second_batch = [
        {"id": "3", "created": "1609459300"},
        {"id": "4", "created": "1609459300"},
    ]
    query_response_first = {"audit_event_overview_report_rows": audit_events_first_batch}
    query_response_second = {"audit_event_overview_report_rows": audit_events_second_batch}
    client_mock.query_audit_logs.side_effect = [query_response_first, query_response_second]

    # Mock API_MAX_FETCH to be 2
    mocker.patch("KeeperSecurity.API_MAX_FETCH", 2)
    mocker.patch("KeeperSecurity.demisto.setLastRun")

    # Mock add_time_to_events to track calls
    mock_add_time_to_events = mocker.patch("KeeperSecurity.add_time_to_events")

    # Act
    result = get_audit_logs(
        client=client_mock,
        last_latest_event_time=1609459100,
        max_fetch_limit=4,
        last_fetched_ids=set(),
    )

    # Assert
    assert result == audit_events_first_batch + audit_events_second_batch  # Both batches should be returned
    assert client_mock.query_audit_logs.call_count == 2  # Two calls should be made

    # Check that the first call was made with a limit of 2 and the second with a limit of 2
    expected_calls = [
        call(limit=2, start_event_time=1609459100),
        call(limit=2, start_event_time=1609459200),
    ]
    assert client_mock.query_audit_logs.mock_calls == expected_calls

    args, _ = demisto.setLastRun.call_args
    assert args[0]["last_fetch_epoch_time"] == "1609459300"
    assert sorted(args[0]["last_fetch_ids"]) == sorted(["3", "4"])

    # Assert add_time_to_events was called twice, once for each batch
    assert mock_add_time_to_events.call_count == 2
    assert mock_add_time_to_events.mock_calls == [call(audit_events_first_batch), call(audit_events_second_batch)]


def test_add_time_to_events():
    """
    Given
        - A list of audit events with 'created' timestamps.
    When
        - Running the add_time_to_events function.
    Then
        - Each event in the list should have a '_time' key added, with the value matching the 'created' timestamp.
    """
    from KeeperSecurity import add_time_to_events

    # Arrange
    audit_events = [
        {"id": "1", "created": "1609459200"},
        {"id": "2", "created": "1609459300"},
        {"id": "3", "created": "1609459400"},
    ]
    expected_events = [
        {"id": "1", "created": "1609459200", "_time": "1609459200"},
        {"id": "2", "created": "1609459300", "_time": "1609459300"},
        {"id": "3", "created": "1609459400", "_time": "1609459400"},
    ]

    # Act
    add_time_to_events(audit_events)

    # Assert
    assert audit_events == expected_events
