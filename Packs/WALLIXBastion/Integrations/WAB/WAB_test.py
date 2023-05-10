import WAB
from WAB import main, Client
import demistomock as demisto
from CommonServerPython import BaseClient
from typing import Any


class Settable:
    pass


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
        },
    )
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="wab-get-device")

    mock_result = mocker.patch("WAB.return_results")

    def mock_http_request(*args, **kwargs):
        assert args[0] == "get"
        assert args[1] == "devices/012345"
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"

        mock: Any = Settable()

        mock.status_code = 200
        mock.headers = {}
        mock.json = lambda: {"device_name": "my device", "host": "1.2.3.4"}

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

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
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user",
        },
    )

    for name in WAB.__dict__.keys():
        if name.startswith("_"):
            continue
        if not name.endswith("_command"):
            continue

        command_name = "wab-" + name.removesuffix("_command").replace("_", "-")

        mocker.patch.object(demisto, "results")
        mocker.patch.object(demisto, "command", return_value=command_name)

        mocker.patch.object(Client, "_http_request", return_value={})

        mock_result = mocker.patch("WAB.return_results")

        main()

        assert mock_result.call_count == 1
