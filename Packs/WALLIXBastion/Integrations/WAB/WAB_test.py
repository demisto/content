from WAB import main, Client
import demistomock as demisto
from CommonServerPython import *
from typing import Any
import yaml
from os import path


class Settable:
    pass


def load_commands() -> List[str]:
    yml_path = path.join(path.dirname(__file__), "WAB.yml")

    with open(yml_path) as wab_yml:
        commands = yaml.safe_load(wab_yml)["script"]["commands"]

    assert len(commands) > 0

    return [cm["name"] for cm in commands]


command_names = load_commands()


class Counter:
    def __init__(self) -> None:
        self.count = 0


def test_timeout(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "timeout": "0"
        },
    )
    try:
        main()
    except ValueError:
        pass
    else:
        raise AssertionError("zero timeout should not be allowed")


def test_test_module(mocker):
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    results_mock = mocker.patch.object(demisto, "results")

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user"
        }
    )

    def mock_http_request(*args, **kwargs):
        assert args[0] == "get"
        assert args[1] == ""
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"

        mock: Any = Settable()

        mock.status_code = 204
        mock.headers = {}

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

    main()

    results_mock.assert_called_once_with("ok")


def test_login(mocker):
    mocker.patch.object(demisto, "command", return_value="wab-get-current-serial-configuration-number-of-bastion")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "results")

    params = {
        "url": "1.1.1.1",
        "verify_certificate": False,
        "api_version": "v3.12",
        "auth_key": "key",
        "auth_user": "user"
    }

    mocker.patch.object(
        demisto,
        "params",
        return_value=params
    )

    integration_context = {}

    def set_context(new_context, *args):
        integration_context.clear()
        integration_context.update(new_context)

    mocker.patch.object(demisto, "getIntegrationContextVersioned", return_value=integration_context)
    mocker.patch.object(demisto, "setIntegrationContextVersioned", side_effect=set_context)
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=set_context)

    c = Counter()

    def mock_http_request(*args, **kwargs):
        c.count += 1
        mock: Any = Settable()
        mock.headers = {}

        if c.count == 1:
            # API key auth
            assert kwargs["headers"].get("X-Auth-Key") == "key"
            assert kwargs["headers"].get("X-Auth-User") == "user"

            mock.status_code = 200
            mock.headers["Set-Cookie"] = "session=foobar"
            mock.json = lambda: {"configuration_number": "3615"}

        elif c.count == 2:
            # session token auth
            assert integration_context.get("session_token") == "session=foobar"
            assert integration_context.get("last_request_at") > 0

            assert kwargs["headers"].get("Cookies") == "session=foobar"
            assert kwargs["headers"].get("X-Auth-User") is None
            assert kwargs["headers"].get("X-Auth-Key") is None

            mock.status_code = 401

            kwargs["error_handler"](mock)

        elif c.count == 3:
            # password auth
            assert not integration_context
            assert kwargs.get("auth") == ("user", "key")
            assert kwargs["headers"].get("X-Auth-User") is None
            assert kwargs["headers"].get("X-Auth-Key") is None

            mock.status_code = 200
            mock.headers["Set-Cookie"] = "session=foobaz"
            mock.json = lambda: {"configuration_number": "3615"}

        else:
            raise ValueError("counter: " + str(c.count))

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

    main()
    assert c.count == 1

    params["is_password"] = True

    main()

    assert c.count == 3
    assert integration_context.get("session_token") == "session=foobaz"


def test_wab_get_device(mocker):
    mocker.patch.object(demisto, "args", return_value={"device_id": "012345"})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user",
            "timeout": "50"
        },
    )
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="wab-get-device")

    mock_result = mocker.patch("WAB.return_results")

    def mock_http_request(self: BaseClient, *args, **kwargs):
        assert args[0] == "get"
        assert args[1] == "/devices/012345"
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"
        assert self.timeout == 50

        mock: Any = Settable()

        mock.status_code = 200
        mock.headers = {}
        mock.json = lambda: {"device_name": "my device", "host": "1.2.3.4"}

        return mock

    mocker.patch.object(BaseClient, "_http_request", autospec=True, side_effect=mock_http_request)

    main()

    assert mock_result.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = mock_result.call_args[0]

    assert len(results) == 1

    result = results[0]

    assert result.outputs_prefix == "WAB.device_get"
    assert result.outputs_key_field == "id"

    assert result.outputs["device_name"] == "my device"
    assert result.outputs["host"] == "1.2.3.4"


def test_commands(mocker):
    """test that all commands names match an existing method."""
    mocker.patch.object(demisto, "args", return_value={
        "session_account_type": "account"  # required for add_session_target_to_target_group
    })
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user",
            "timeout": "50"
        },
    )

    mocker.patch.object(Client, "_http_request", return_value={})

    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_result = mocker.patch.object(demisto, "results")
    main()
    assert mock_result.call_count == 1

    for name in command_names:
        mocker.patch.object(demisto, "results")
        mocker.patch.object(demisto, "command", return_value=name)

        mock_result = mocker.patch("WAB.return_results")

        main()

        assert mock_result.call_count == 1
