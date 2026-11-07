import json

import demistomock as demisto
import duo_client
import pytest


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_client():
    from DuoAdminApi import create_api_call

    return create_api_call()


def test_modify_user(mocker):
    """
    Given
    - A user id and status.

    When
    - Calling modify_user method.

    Then
    - Validate that the user were successfully update.
    """
    from DuoAdminApi import modify_user

    args = {"user_id": "1", "status": "active"}
    user_id = args.get("user_id")
    client = mock_client()
    mocker.patch.object(duo_client.Admin, "update_user", return_value=None)
    result = modify_user(client, **args)
    assert result.readable_output == f"The user id {user_id} successfully updated"


def test_modify_admin_user(mocker):
    """
    Given
    - An admin id and name.

    When
    - Calling modify_admin_user method.

    Then
    - Validate that the admin were successfully update.
    """
    from DuoAdminApi import modify_admin_user

    args = {"admin_id": "1", "name": "test"}
    admin_id = args.get("admin_id")
    client = mock_client()
    mocker.patch.object(duo_client.Admin, "update_admin", return_value=None)
    result = modify_admin_user(client, **args)
    assert result.readable_output == f"The admin id {admin_id} successfully updated"


def test_get_users(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling get_all_users method.

    Then
    - Validate that all users were successfully retrieve.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    mock_res = util_load_json("test_data/get_users.json")
    mocker.patch.object(duo_client.Admin, "get_users", return_value=mock_res)
    mocker.patch.object(demisto, "results")

    get_all_users(client)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")
    assert content.get("alias1") == "test.1"
    assert content.get("email") == "test.1@test.com"
    assert content.get("status") == "active"


def _mock_user_list():
    return [util_load_json("test_data/get_users.json")]


def test_get_users_by_username_list(mocker):
    """
    Given
    - A username_list argument.

    When
    - Calling get_all_users method.

    Then
    - Validate only the by-usernames lookup is used and the user is returned.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    by_names = mocker.patch.object(duo_client.Admin, "get_users_by_names", return_value=iter(_mock_user_list()))
    all_users = mocker.patch.object(duo_client.Admin, "get_users")
    mocker.patch.object(demisto, "results")

    get_all_users(client, {"username_list": "test.1,test.2"})

    by_names.assert_called_once_with(["test.1", "test.2"])
    all_users.assert_not_called()
    entry = demisto.results.call_args[0][0]
    assert entry["Contents"][0]["email"] == "test.1@test.com"
    assert "DuoAdmin.UserDetails(val.username==obj.username)" in entry["EntryContext"]


def test_get_users_by_user_id_list(mocker):
    """
    Given
    - A user_id_list argument.

    When
    - Calling get_all_users method.

    Then
    - Validate only the by-ids lookup is used and the context shape is a list.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    by_ids = mocker.patch.object(duo_client.Admin, "get_users_by_ids", return_value=iter(_mock_user_list()))
    all_users = mocker.patch.object(duo_client.Admin, "get_users")
    mocker.patch.object(demisto, "results")

    get_all_users(client, {"user_id_list": "DUAB3CDEFG456HI7J8KL, DUCD4EFGHI567JK8L9MN"})

    by_ids.assert_called_once_with(["DUAB3CDEFG456HI7J8KL", "DUCD4EFGHI567JK8L9MN"])
    all_users.assert_not_called()
    entry = demisto.results.call_args[0][0]
    assert isinstance(entry["Contents"], list)
    assert entry["EntryContext"]["DuoAdmin.UserDetails(val.username==obj.username)"] == entry["Contents"]


def test_get_users_no_args_returns_all(mocker):
    """
    Given
    - No filter arguments.

    When
    - Calling get_all_users method.

    Then
    - Validate all users are fetched (backward compatible behavior).
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    all_users = mocker.patch.object(duo_client.Admin, "get_users", return_value=_mock_user_list())
    mocker.patch.object(demisto, "results")

    get_all_users(client, {})

    all_users.assert_called_once_with()
    assert len(demisto.results.call_args[0][0]["Contents"]) == 1


def test_get_users_both_args_raises(mocker):
    """
    Given
    - Both username_list and user_id_list arguments.

    When
    - Calling get_all_users method.

    Then
    - Validate a readable error is raised and no API call is made.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    all_users = mocker.patch.object(duo_client.Admin, "get_users")
    by_names = mocker.patch.object(duo_client.Admin, "get_users_by_names")
    by_ids = mocker.patch.object(duo_client.Admin, "get_users_by_ids")

    with pytest.raises(Exception, match="Provide only one of username_list or user_id_list."):
        get_all_users(client, {"username_list": "a", "user_id_list": "b"})

    all_users.assert_not_called()
    by_names.assert_not_called()
    by_ids.assert_not_called()


@pytest.mark.parametrize(
    "args, patched_method, expected_message",
    [
        ({"username_list": "ghost,casper"}, "get_users_by_names", "No user found matching the given username: ghost, casper."),
        ({"user_id_list": "DUMISSING"}, "get_users_by_ids", "No user found matching the given user ID: DUMISSING."),
    ],
)
def test_get_users_not_found_empty_list(mocker, args, patched_method, expected_message):
    """
    Given
    - A filter that matches no user (API returns an empty list).

    When
    - Calling get_all_users method.

    Then
    - Validate a readable "no user found" message is returned.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    mocker.patch.object(duo_client.Admin, patched_method, return_value=iter([]))
    mocker.patch.object(demisto, "results")

    get_all_users(client, args)

    entry = demisto.results.call_args[0][0]
    assert entry["HumanReadable"] == expected_message
    assert entry["Contents"] == []


def test_get_users_not_found_404(mocker):
    """
    Given
    - A user_id_list that makes the API return HTTP 404.

    When
    - Calling get_all_users method.

    Then
    - Validate a readable "no user found" message is returned instead of a raw error.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    error = RuntimeError("Received 404 Not Found")
    error.status = 404  # type: ignore[attr-defined]
    mocker.patch.object(duo_client.Admin, "get_users_by_ids", side_effect=error)
    mocker.patch.object(demisto, "results")

    get_all_users(client, {"user_id_list": "DUMISSING"})

    entry = demisto.results.call_args[0][0]
    assert entry["HumanReadable"] == "No user found matching the given user ID: DUMISSING."


def test_get_users_too_many_values_raises(mocker):
    """
    Given
    - A username_list with more than 100 values.

    When
    - Calling get_all_users method.

    Then
    - Validate a readable error is raised and no API call is made.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    by_names = mocker.patch.object(duo_client.Admin, "get_users_by_names")

    with pytest.raises(Exception, match="A maximum of 100 values can be provided, got 101."):
        get_all_users(client, {"username_list": ",".join(f"user{i}" for i in range(101))})

    by_names.assert_not_called()


def test_get_users_other_error_propagates(mocker):
    """
    Given
    - The lookup fails with a non-404 error.

    When
    - Calling get_all_users method.

    Then
    - Validate the original error is not swallowed.
    """
    from DuoAdminApi import get_all_users

    client = mock_client()
    error = RuntimeError("Received 500 Server Error")
    error.status = 500  # type: ignore[attr-defined]
    mocker.patch.object(duo_client.Admin, "get_users_by_names", side_effect=error)

    with pytest.raises(RuntimeError, match="500"):
        get_all_users(client, {"username_list": "DUX"})


def test_get_bypass_codes(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling get_all_bypass_codes method.

    Then
    - Validate that all bypass codes were successfully retrieve.
    """
    from DuoAdminApi import get_all_bypass_codes

    client = mock_client()
    mock_res = util_load_json("test_data/get_all_bypass_codes.json")
    mocker.patch.object(duo_client.Admin, "get_bypass_codes", return_value=mock_res)
    mocker.patch.object(demisto, "results")

    get_all_bypass_codes(client)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")
    assert content.get("bypass_code_id") == "1"


def test_get_authentication_logs_by_user(mocker):
    """
    Given
    - A duo admin client user name and from date time.

    When
    - Calling get_authentication_logs_by_user method.

    Then
    - Validate that all the logs were successfully retrieve.
    """
    from DuoAdminApi import get_authentication_logs_by_user

    client = mock_client()
    args = {"username": "test@demisto.com", "from": "10_years_ago"}
    mock_res = util_load_json("test_data/get_authentication_logs_by_user.json")

    mocker.patch.object(duo_client.Admin, "get_authentication_log", return_value=mock_res)
    mocker.patch.object(duo_client.Admin, "get_users_by_name", return_value=[{"user_id": "1"}])
    mocker.patch.object(demisto, "results")

    get_authentication_logs_by_user(client, args)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")[0]
    assert content.get("user").get("name") == args.get("username")
    assert content.get("auth_device").get("ip") == "1.1.1.1"
    assert content.get("auth_device").get("location").get("city") == "test_city"


def test_get_all_devices(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling get_all_devices method.

    Then
    - Validate that all the devices were successfully retrieve.
    """
    from DuoAdminApi import get_all_devices

    client = mock_client()
    mock_res = util_load_json("test_data/get_all_devices.json")

    mocker.patch.object(duo_client.Admin, "get_phones", return_value=mock_res)
    mocker.patch.object(demisto, "results")

    get_all_devices(client)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")
    assert content.get("activated")
    assert content.get("phone_id") == "1"
    assert content.get("type") == "Mobile"


def test_dissociate_device_by_user(mocker):
    """
    Given
    - A duo admin client user name and device id.

    When
    - Calling dissociate_device_by_user method.

    Then
    - Validate that the phone id was successfully dissociated.
    """
    from DuoAdminApi import dissociate_device_by_user

    client = mock_client()
    args = {"username": "test@demisto.com", "device_id": "1"}
    mock_res = util_load_json("test_data/get_authentication_logs_by_user.json")

    mocker.patch.object(duo_client.Admin, "delete_user_phone", return_value=mock_res)
    mocker.patch.object(duo_client.Admin, "get_users_by_name", return_value=[{"user_id": "1"}])
    mocker.patch.object(demisto, "results")

    dissociate_device_by_user(client, args)
    res = demisto.results
    hr = res.call_args[0][0]
    assert hr == f"Phone with ID {args.get('device_id')} was dissociated to user {args.get('username')}"


def test_associate_device_to_user(mocker):
    """
    Given
    - A duo admin client user name and device id.

    When
    - Calling associate_device_by_user method.

    Then
    - Validate that the phone id was successfully associated.
    """
    from DuoAdminApi import associate_device_to_user

    client = mock_client()
    args = {"username": "test@demisto.com", "device_id": "1"}
    mock_res = util_load_json("test_data/get_authentication_logs_by_user.json")

    mocker.patch.object(duo_client.Admin, "add_user_phone", return_value=mock_res)
    mocker.patch.object(duo_client.Admin, "get_users_by_name", return_value=[{"user_id": "1"}])
    mocker.patch.object(demisto, "results")

    associate_device_to_user(client, args)
    res = demisto.results
    hr = res.call_args[0][0]
    assert hr == f"Phone with ID {args.get('device_id')} was associated to user {args.get('username')}"


def test_get_all_admins(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling get_all_admins method.

    Then
    - Validate that all admins were successfully retrieve.
    """
    from DuoAdminApi import get_all_admins

    client = mock_client()
    mock_res = {
        "admin_id": "1",
        "created": None,
        "email": "test.1@test.com",
        "last_login": 1662468518,
        "name": "test1-Demisto",
        "phone": "+972111111111",
    }

    mocker.patch.object(duo_client.Admin, "get_admins", return_value=mock_res)
    mocker.patch.object(demisto, "results")

    get_all_admins(client)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")
    assert content.get("admin_id") == mock_res.get("admin_id")
    assert content.get("email") == mock_res.get("email")


def test_get_u2f_tokens_by_user(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling get_u2f_tokens_by_user method.

    Then
    - Validate that all u2f tokens were successfully retrieve.
    """
    from DuoAdminApi import get_u2f_tokens_by_user

    client = mock_client()
    mock_res = util_load_json("test_data/get_users.json")
    mock_res.update({"credential_name": "test_credential", "date_added": 1662468518, "label": "Security Key"})
    mock_res = [mock_res]
    args = {"username": "test1"}

    mocker.patch.object(duo_client.Admin, "get_user_u2ftokens", return_value=mock_res)
    mocker.patch.object(duo_client.Admin, "get_users_by_name", return_value=[{"user_id": "1"}])
    mocker.patch.object(demisto, "results")
    get_u2f_tokens_by_user(client, args)
    res = demisto.results
    content = res.call_args[0][0].get("Contents")[0]
    assert content.get("credential_name") == "test_credential"


def test_delete_u2f_token(mocker):
    """
    Given
    - A duo admin client.

    When
    - Calling delete_u2f_token method.

    Then
    - Validate that u2f token was successfully deleted.
    """
    from DuoAdminApi import delete_u2f_token

    client = mock_client()
    args = {"token_id": "test_token"}

    mocker.patch.object(duo_client.Admin, "delete_u2ftoken")
    mocker.patch.object(demisto, "results")
    delete_u2f_token(client, args)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == f"Token with ID {args.get('token_id')} deleted successfully"
