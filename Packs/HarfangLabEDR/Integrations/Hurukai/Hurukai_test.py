import unittest.mock
from pathlib import Path
from typing import TypeAlias
import inspect
import pytest
import requests_mock
import requests_mock.adapter

import Hurukai
from CommonServerPython import *


SERVER_URL = (
    "http://server-url.test"  # ".test" is a reserved tld and should not be registered
)

JSON_REPONSES_DIRECTORY = Path("test_data")

Client: TypeAlias = Hurukai.Client
RequestsMock: TypeAlias = requests_mock.Mocker
JSONData: TypeAlias = dict[str, Any]


def load_json(path: str) -> JSONData:
    json_file_to_load = JSON_REPONSES_DIRECTORY / (path + ".json")
    with json_file_to_load.open(mode="r", encoding="utf-8") as fd:
        return json.load(fd)


@pytest.fixture()
def client() -> Client:
    return Hurukai.Client(base_url=SERVER_URL)


def _full_url(path: str, query: Optional[str] = None) -> str:
    return f"{SERVER_URL}/api/{path}" + (f"?{query}" if query else "")


def _generic_last_run() -> Hurukai.LastRun:
    # always return a new copy
    # last_fetch will be set to 1970-01-01T00:00:00Z
    return Hurukai.LastRun(
        security_event=Hurukai.FetchHistory(last_fetch=1, already_fetched=[]),
        threat=Hurukai.FetchHistory(last_fetch=1, already_fetched=[]),
    )


def test_test_module_success(
    client: Client,
    requests_mock: RequestsMock,
) -> None:
    requests_mock.get(_full_url("version"), status_code=200, json=load_json("version"))
    assert Hurukai.test_module(client) == "ok"
    assert requests_mock.called_once


def test_test_module_fail_bad_api_return(
    client: Client,
    requests_mock: RequestsMock,
) -> None:
    requests_mock.get(_full_url("version"), status_code=200, json={})
    assert Hurukai.test_module(client) == "nope"
    assert requests_mock.called_once


@pytest.mark.parametrize(
    "status_code",
    [400, 500],
)
def test_test_module_fail_network_error(
    client: Client,
    requests_mock: RequestsMock,
    status_code: int,
) -> None:
    requests_mock.get(_full_url("version"), status_code=status_code)
    with pytest.raises(DemistoException, match="Error in API call"):
        Hurukai.test_module(client)
    assert requests_mock.called_once


def test_get_last_run() -> None:
    stored_last_run = {
        "security_event": {"last_fetch": 1, "already_fetched": [2]},
        "threat": {"last_fetch": 1, "already_fetched": [2]},
    }
    with unittest.mock.patch.object(
        demisto,
        "getLastRun",
        return_value=stored_last_run,
    ) as mock:
        last_run = Hurukai.get_last_run()
        mock.assert_called_once()

    assert isinstance(last_run, Hurukai.LastRun)

    for incident_type in last_run.security_event, last_run.threat:
        assert isinstance(incident_type, Hurukai.FetchHistory)
        assert incident_type.last_fetch == 1
        assert incident_type.already_fetched == [2]

    assert last_run.as_dict() == stored_last_run


def test_get_last_run_first_run() -> None:
    first_run = {
        "security_event": {"last_fetch": None, "already_fetched": []},
        "threat": {"last_fetch": None, "already_fetched": []},
    }
    with unittest.mock.patch.object(
        demisto,
        "getLastRun",
        return_value=None,
    ) as mock:
        last_run = Hurukai.get_last_run()
        mock.assert_called_once()

    assert isinstance(last_run, Hurukai.LastRun)

    for incident_type in last_run.security_event, last_run.threat:
        assert isinstance(incident_type, Hurukai.FetchHistory)
        assert incident_type.last_fetch is None
        assert incident_type.already_fetched == []

    assert last_run.as_dict() == first_run


def test_get_last_run_retro_compatibility() -> None:
    last_fetch = 1149573966123456
    already_fetched = []

    with unittest.mock.patch.object(
        demisto,
        "getLastRun",
        return_value={"last_fetch": last_fetch, "already_fetched": already_fetched},
    ) as mock:
        last_run = Hurukai.get_last_run()
        mock.assert_called_once()

    assert isinstance(last_run, Hurukai.LastRun)

    assert isinstance(last_run.security_event, Hurukai.FetchHistory)
    assert last_run.security_event.last_fetch == last_fetch // 1_000_000
    assert last_run.security_event.already_fetched is already_fetched

    assert isinstance(last_run.threat, Hurukai.FetchHistory)
    assert not last_run.threat.last_fetch
    assert not last_run.threat.already_fetched


def _generic_valid_fetch_incidents_argument() -> dict[str, Any]:
    return {
        "fetch_types": ["Security Events", "Threats"],
        "last_run": _generic_last_run(),
        "min_severity": "Low",
        "mirror_direction": "Incoming And Outgoing",
        "alert_status": None,
        "alert_type": None,
        "first_fetch": "5",
        "max_fetch": "200",
    }


@pytest.mark.parametrize(
    "fetch_types",
    (
        ["Security Events"],
        ["Threats"],
        ["Security Events", "Threats"],
    ),
)
def test_fetch_incidents(
    client: Client,
    requests_mock: RequestsMock,
    fetch_types: list[str],
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["fetch_types"] = fetch_types

    mock1 = requests_mock.get(
        _full_url(
            path="data/alert/alert/Alert/",
            query="ordering=alert_time"
            "&level=low,medium,high,critical"
            "&limit=25"
            "&offset=0"
            "&alert_time__gte=1970-01-01T00:00:00Z",
        ),
        status_code=200,
        json=load_json("data_alert_alert_Alert"),
    )

    mock2 = requests_mock.get(
        _full_url(
            path="data/alert/alert/Threat/",
            query="ordering=creation_date"
            "&level=low,medium,high,critical"
            "&limit=25"
            "&offset=0"
            "&creation_date__gte=1970-01-01T00:00:00Z"
            "&id__gt=0",
        ),
        status_code=200,
        json=load_json("data_alert_alert_Threat"),
    )

    mock3 = requests_mock.get(
        _full_url(
            path="data/alert/alert/Threat/1/",
        ),
        status_code=200,
        json=load_json("data_alert_alert_Threat_id"),
    )

    with unittest.mock.patch.object(Hurukai, "enrich_threat"):
        last_run, incidents = Hurukai.fetch_incidents(client, args)

    if "Security Events" in fetch_types:
        assert mock1.called_once
        assert last_run["security_event"]["last_fetch"] == 1
        assert len(last_run["security_event"]["already_fetched"]) == 1

    if "Threats" in fetch_types:
        assert mock2.called_once
        assert mock3.called_once
        assert last_run["threat"]["last_fetch"] == 1
        assert len(last_run["threat"]["already_fetched"]) == 1

    for incident in incidents:
        assert "name" in incident
        assert "occurred" in incident
        assert "rawJSON" in incident


def test_fetch_incidents_empty_fetch_types(
    client: Client,
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["fetch_types"] = []

    with pytest.raises(
        ValueError,
        match="Missing value for 'fetch_types' argument",
    ):
        Hurukai.fetch_incidents(client, args)


@pytest.mark.parametrize(
    "fetch_types",
    [
        ["---invalid---"],
        ["Security Events", "---invalid---"],
        ["Threats", "---invalid---"],
        ["Security Events", "Threats", "---invalid---"],
    ],
)
def test_fetch_incidents_invalid_fetch_types(
    client: Client,
    fetch_types: list[str],
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["fetch_types"] = fetch_types

    with pytest.raises(
        ValueError,
        match="Invalid value for 'fetch_types' argument:.*'---invalid---'",
    ):
        Hurukai.fetch_incidents(client, args)


@pytest.mark.parametrize(
    "min_severity",
    [
        "low",  # parameter is case-sensitive
        "---invalid---",
    ],
)
def test_fetch_incidents_invalid_min_severity(
    client: Client,
    min_severity: str,
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["min_severity"] = min_severity

    with pytest.raises(
        ValueError,
        match=f"Invalid value for 'min_severity' argument:.*'{min_severity}'",
    ):
        Hurukai.fetch_incidents(client, args)


@pytest.mark.parametrize(
    "mirror_direction",
    [
        "none",  # parameter is case-sensitive
        "---invalid---",
    ],
)
def test_fetch_incidents_invalid_mirror_direction(
    client: Client,
    mirror_direction: str,
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["mirror_direction"] = mirror_direction

    with pytest.raises(
        ValueError,
        match=f"Invalid value for 'mirror_direction' argument:.*'{mirror_direction}'",
    ):
        Hurukai.fetch_incidents(client, args)


@pytest.mark.parametrize(
    "alert_status",
    [
        "active",  # parameter is case-sensitive
        "---invalid---",
    ],
)
def test_fetch_incidents_invalid_alert_status(
    client: Client,
    alert_status: str,
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["alert_status"] = alert_status

    with pytest.raises(
        ValueError,
        match=f"Invalid value for 'alert_status' argument:.*'{alert_status}'",
    ):
        Hurukai.fetch_incidents(client, args)


@pytest.mark.parametrize(
    "max_fetch",
    [
        # 0,  # this an actual valid value
        -1,
    ],
)
def test_fetch_incidents_invalid_max_fetch(
    client: Client,
    max_fetch: int,
) -> None:

    args = _generic_valid_fetch_incidents_argument()
    args["max_fetch"] = max_fetch

    with pytest.raises(
        ValueError,
        match=f"Invalid value for 'max_fetch' argument:.*'{max_fetch}'",
    ):
        Hurukai.fetch_incidents(client, args)


def test_get_modified_remote_data(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "lastUpdate": "1970-01-01T00:00:00Z",
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/alert/alert/Alert/",
                query="ordering=last_update"
                "&level=low,medium,high,critical"
                "&limit=10000"
                "&offset=0"
                "&last_update__gte=1970-01-01T00:00:00Z"
                "&fields=id",
            ),
            status_code=200,
            json=load_json("data_alert_alert_Alert"),
        ),
        requests_mock.get(
            _full_url(
                path="data/alert/alert/Threat/",
                query="ordering=last_update"
                "&level=low,medium,high,critical"
                "&limit=10000"
                "&offset=0"
                "&last_update__gte=1970-01-01T00:00:00Z"
                "&fields=id",
            ),
            status_code=200,
            json=load_json("data_alert_alert_Threat"),
        ),
        requests_mock.get(
            _full_url(
                path="data/alert/alert/Threat/1/",
            ),
            status_code=200,
            json=load_json("data_alert_alert_Threat_id"),
        ),
    ]

    with unittest.mock.patch.object(Hurukai, "enrich_threat"):
        result = Hurukai.get_modified_remote_data(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)

    assert isinstance(result, GetModifiedRemoteDataResponse)
    assert len(result.modified_incident_ids) == 2


def test_get_function_from_command_name() -> None:

    for fn_name, expected_fn in inspect.getmembers(Hurukai, inspect.isfunction):
        command = f"harfanglab-{fn_name}".replace("_", "-")

        try:
            fn = Hurukai.get_function_from_command_name(command)
        except KeyError:
            pass
        else:
            assert fn is expected_fn

    # there are 53 correctly named functions (53/71)
    # here, the other one:

    # "harfanglab-job-persistencelist": job_linux_persistence_list,
    # "harfanglab-result-persistencelist": result_linux_persistence_list,

    # "harfanglab-job-artifact-filesystem": job_artifact_fs,
    # "harfanglab-result-artifact-filesystem": result_artifact_fs,

    # "harfanglab-telemetry-processes": TelemetryProcesses().telemetry,
    # "harfanglab-telemetry-network": TelemetryNetwork().telemetry,
    # "harfanglab-telemetry-eventlog": TelemetryEventLog().telemetry,
    # "harfanglab-telemetry-binary": TelemetryBinary().telemetry,
    # "harfanglab-telemetry-dns": TelemetryDNSResolution().telemetry,

    # "harfanglab-telemetry-authentication-windows": TelemetryWindowsAuthentication().telemetry,
    # "harfanglab-telemetry-authentication-linux": TelemetryLinuxAuthentication().telemetry,
    # "harfanglab-telemetry-authentication-macos": TelemetryMacosAuthentication().telemetry,
    # "harfanglab-telemetry-authentication-users": get_frequent_users,
    # "harfanglab-telemetry-process-graph": get_process_graph,

    # "harfanglab-whitelist-search": search_whitelist,
    # "harfanglab-whitelist-add": add_whitelist,
    # "harfanglab-whitelist-add-criterion": add_criterion_to_whitelist,
    # "harfanglab-whitelist-delete": delete_whitelist,

    threshold = 50

    assert Hurukai.get_function_from_command_name.cache_info().currsize >= threshold

    if Hurukai.get_function_from_command_name.cache_info().hits == 0:
        test_get_function_from_command_name()

    assert Hurukai.get_function_from_command_name.cache_info().hits >= threshold


def test_hunt_search_hash_single_digest(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "hash": "0" * 64,
    }

    requests_mock.get(
        _full_url(
            path="data/search/Search/explorer_with_list/",
            query=f"values={args['hash']}&type=hash",
        ),
        status_code=200,
        json=load_json("data_search_Search_explorer_with_list"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_hash(client, args)

    assert requests_mock.called_once


@pytest.mark.parametrize(
    "hashes",
    [
        ["0" * 64] * 4,
        ["1" * 64] * 6,
    ],
)
def test_hunt_search_hash_multiple_digests(
    client: Client,
    requests_mock: RequestsMock,
    hashes: list[str],
) -> None:

    args = {
        "hash": hashes,
    }

    requests_mock.get(
        _full_url(
            path="data/search/Search/explorer_with_list/",
            query=f"values={args['hash'][0]}&type=hash",
        ),
        status_code=200,
        json=load_json("data_search_Search_explorer_with_list"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_hash(client, args)

    assert requests_mock.call_count == len(hashes)


def test_hunt_search_hash_no_result(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "hash": "0" * 64,
    }

    requests_mock.get(
        _full_url(
            path="data/search/Search/explorer_with_list/",
            query=f"values={args['hash']}&type=hash",
        ),
        status_code=200,
        json={"data": []},
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_hash(client, args)

    assert requests_mock.called_once


def test_job_ioc(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "agent_id": "---unused---",
        "search_in_path": "---unused---",
        "filename": "---unused---",
        "filepath": "---unused---",
        "filepath_regex": "---unused---",
        "registry": "---unused---",
        "hash": "---unused---",
        "hash_filesize": 1,
        "filesize": 1,
    }

    requests_mock.post(
        _full_url(
            path="data/Job/",
        ),
        status_code=200,
        json=[{"id": "0"}],
    )

    result = Hurukai.job_ioc(client, args)

    assert requests_mock.called_once

    assert result.to_context()["Contents"]["ID"] == "0"
    assert result.to_context()["Contents"]["Action"] == "IOCScan"


def test_job_ioc_no_valid_args(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {}

    requests_mock.post(
        _full_url(
            path="data/Job/",
        ),
        status_code=200,
        json={},
    )

    Hurukai.job_ioc(client, args)

    assert not requests_mock.called


@pytest.mark.parametrize(
    "remote_id",
    [
        "sec:1",
        "thr:1",
    ],
)
def test_update_remote_system(
    client: Client,
    requests_mock: RequestsMock,
    remote_id: str,
) -> None:

    args = {
        "incidentChanged": True,
        "remoteId": remote_id,
        "delta": {"rule_name": "another rule name"},
        "status": 1,
    }

    mock1 = requests_mock.post(
        _full_url(
            path="data/alert/alert/Alert/tag/",
        ),
        status_code=200,
        json={},
    )

    mock2 = requests_mock.patch(
        _full_url(
            path="data/alert/alert/Threat/status/",
        ),
        status_code=200,
        json={},
    )

    result = Hurukai.update_remote_system(client, args)

    assert requests_mock.called_once

    if remote_id.startswith("sec"):
        assert mock1.called_once
    elif remote_id.startswith("thr"):
        assert mock2.called_once
    else:
        raise ValueError

    assert result == args["remoteId"]


@pytest.mark.parametrize(
    "remote_id",
    [
        "sec:1",
        "thr:1",
    ],
)
def test_update_remote_system_without_delta(
    client: Client,
    requests_mock: RequestsMock,
    remote_id: str,
) -> None:

    args = {
        "incidentChanged": True,
        "remoteId": remote_id,
    }

    with unittest.mock.patch.object(demisto, "error") as mock:
        result = Hurukai.update_remote_system(client, args)
        mock.assert_called_once()

    assert not requests_mock.called
    assert result == args["remoteId"]


@pytest.mark.parametrize(
    "remote_id",
    [
        "sec:1",
        "thr:1",
    ],
)
def test_update_remote_system_no_change(
    client: Client,
    requests_mock: RequestsMock,
    remote_id: str,
) -> None:

    args = {
        "incidentChanged": False,
        "remoteId": remote_id,
    }

    result = Hurukai.update_remote_system(client, args)

    assert not requests_mock.called
    assert result == args["remoteId"]


def test_global_result_artifact(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    artifact_type = "---unused---"

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/Job/1",
            ),
            status_code=200,
            json=load_json("data_Job_id"),
        ),
        requests_mock.get(
            _full_url(
                path="data/investigation/artefact/Artefact/",
                query="limit=10000&job_id=1",
            ),
            status_code=200,
            json=load_json("data_investigation_artefact_Artefact"),
        ),
        requests_mock.post(
            _full_url(
                path="user/api_token/",
            ),
            status_code=200,
            json={"api_token": "---unused---"},
        ),
    ]

    with unittest.mock.patch("time.sleep"):
        Hurukai.global_result_artifact(client, args, artifact_type)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_get_frequent_users(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {}

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/telemetry/authentication/AuthenticationWindows/",
                query="windows.logon_type=2",
            ),
            status_code=200,
            json=load_json("data_telemetry_authentication_AuthenticationWindows"),
        ),
        requests_mock.get(
            _full_url(
                path="data/telemetry/authentication/AuthenticationLinux/",
            ),
            status_code=200,
            json=load_json("data_telemetry_authentication_AuthenticationLinux"),
        ),
        requests_mock.get(
            _full_url(
                path="data/telemetry/authentication/AuthenticationMacos/",
            ),
            status_code=200,
            json=load_json("data_telemetry_authentication_AuthenticationMacos"),
        ),
    ]

    result = Hurukai.get_frequent_users(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)

    assert len(result.to_context()["Contents"]) == 3


def test_result_networkconnectionlist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Process/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Process"),
    )

    with unittest.mock.patch("time.sleep"):
        result = Hurukai.result_networkconnectionlist(client, args)

    assert requests_mock.called_once
    assert len(result.to_context()["Contents"]) == 1


@pytest.mark.parametrize(
    "remote_id",
    [
        "sec:1",
        "thr:1",
    ],
)
def test_get_remote_data(
    client: Client,
    requests_mock: RequestsMock,
    remote_id: str,
) -> None:

    args = {
        "id": remote_id,
        "lastUpdate": "1970-01-01T00:00:00Z",
    }

    mock1 = requests_mock.get(
        _full_url(
            path="data/alert/alert/Alert/1/details/",
        ),
        status_code=200,
        json=load_json("data_alert_alert_Alert_id_details"),
    )

    mock2 = requests_mock.get(
        _full_url(
            path="data/alert/alert/Threat/1/",
        ),
        status_code=200,
        json=load_json("data_alert_alert_Threat_id"),
    )

    with unittest.mock.patch.object(Hurukai, "enrich_threat"):
        result = Hurukai.get_remote_data(client, args)

    assert requests_mock.called_once

    if remote_id.startswith("sec"):
        assert mock1.called_once
        assert result.mirrored_object == {"incident_type": "Hurukai alert"}

    elif remote_id.startswith("thr"):
        assert mock2.called_once
        assert result.mirrored_object == {"incident_type": "Hurukai threat"}

    else:
        raise ValueError


def test_hunt_search_running_process_hash_single_digest(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "hash": "0" * 64,
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Process/",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Process"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_running_process_hash(client, args)

    assert requests_mock.called_once


@pytest.mark.parametrize(
    "hashes",
    [
        ["0" * 64] * 4,
        ["1" * 64] * 6,
    ],
)
def test_hunt_search_running_process_hash_multiple_digests(
    client: Client,
    requests_mock: RequestsMock,
    hashes: list[str],
) -> None:

    args = {
        "hash": hashes,
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Process/",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Process"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_running_process_hash(client, args)

    assert requests_mock.call_count == len(hashes)


def test_hunt_search_runned_process_hash_single_digest(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "hash": "0" * 64,
    }

    requests_mock.get(
        _full_url(
            path="data/telemetry/Processes/",
            query=f"hashes.sha256={args['hash']}",
        ),
        status_code=200,
        json=load_json("data_telemetry_Processes"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_runned_process_hash(client, args)

    assert requests_mock.called_once


@pytest.mark.parametrize(
    "hashes",
    [
        ["0" * 64] * 4,
        ["1" * 64] * 6,
    ],
)
def test_hunt_search_runned_process_hash_multiple_digests(
    client: Client,
    requests_mock: RequestsMock,
    hashes: list[str],
) -> None:

    args = {
        "hash": hashes,
    }

    requests_mock.get(
        _full_url(
            path="data/telemetry/Processes/",
            query=f"hashes.sha256={args['hash'][0]}",
        ),
        status_code=200,
        json=load_json("data_telemetry_Processes"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.hunt_search_runned_process_hash(client, args)

    assert requests_mock.call_count == len(hashes)


def test_result_processlist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Process/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Process"),
    )

    with unittest.mock.patch("time.sleep"):
        result = Hurukai.result_processlist(client, args)

    assert requests_mock.called_once
    assert len(result.to_context()["Contents"]) == 1


def test_add_whitelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {}

    requests_mock.post(
        _full_url(
            path="data/threat_intelligence/WhitelistRule/",
        ),
        status_code=200,
        json={"id": "1"},
    )

    Hurukai.add_whitelist(client, args)
    assert requests_mock.called_once


def test_add_whitelist_invalid_target(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "target": "---invalid---",
    }

    Hurukai.add_whitelist(client, args)
    assert not requests_mock.called


def test_add_whitelist_invalid_operator(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "operator": "---invalid---",
    }

    with pytest.raises(ValueError, match="Invalid operator"):
        Hurukai.add_whitelist(client, args)

    assert not requests_mock.called


def test_add_criterion_to_whitelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "id": "1",
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/WhitelistRule/1/",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_WhitelistRule_id"),
        ),
        requests_mock.put(
            _full_url(
                path="data/threat_intelligence/WhitelistRule/1/",
            ),
            status_code=200,
            json={},
        ),
    ]

    Hurukai.add_criterion_to_whitelist(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_add_criterion_to_whitelist_invalid_operator(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "id": "1",
        "operator": "---invalid---",
    }

    with pytest.raises(ValueError, match="Invalid operator"):
        Hurukai.add_criterion_to_whitelist(client, args)

    assert not requests_mock.called


def test_delete_whitelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "id": "1",
    }

    requests_mock.delete(
        _full_url(
            path="data/threat_intelligence/WhitelistRule/1/",
        ),
        status_code=200,
        json={},
    )

    Hurukai.delete_whitelist(client, args)
    assert requests_mock.called_once


def test_result_ioc(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/ioc/IOC/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_ioc_IOC"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_ioc(client, args)

    assert requests_mock.called_once


def test_result_networksharelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/NetworkShare/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_NetworkShare"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_networksharelist(client, args)

    assert requests_mock.called_once


def test_result_artifact_downloadfile(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/investigation/artefact/Artefact/",
                query="limit=10000&job_id=1&ordering=name",
            ),
            status_code=200,
            json=load_json("data_investigation_artefact_Artefact"),
        ),
        requests_mock.post(
            _full_url(
                path="user/api_token/",
            ),
            status_code=200,
            json={"api_token": "---unused---"},
        ),
    ]

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_artifact_downloadfile(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_result_artifact_ramdump(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/investigation/artefact/Artefact/",
                query="limit=10000&job_id=1&ordering=name",
            ),
            status_code=200,
            json=load_json("data_investigation_artefact_Artefact"),
        ),
        requests_mock.post(
            _full_url(
                path="user/api_token/",
            ),
            status_code=200,
            json={"api_token": "---unused---"},
        ),
    ]

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_artifact_ramdump(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_result_sessionlist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Session/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Session"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_sessionlist(client, args)

    assert requests_mock.called_once


def test_result_wmilist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Wmi/",
            query="limit=10000&job_id=1&ordering=filename",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Wmi"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_wmilist(client, args)

    assert requests_mock.called_once


def test_add_ioc_to_source(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    source_id = "id"
    source_name = "name"
    ioc_value = "ioc_value"

    args = {
        "source_name": source_name,
        "ioc_value": ioc_value,
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCSource/",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_IOCSource"),
        ),
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCRule/",
                query=f"source_id={source_id}&search={ioc_value}",
            ),
            status_code=200,
            json={"count": 0},
        ),
        requests_mock.post(
            _full_url(
                path="data/threat_intelligence/IOCRule/",
            ),
            status_code=200,
            json={},
        ),
    ]

    result = Hurukai.add_ioc_to_source(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)

    assert "added to source" in result.to_context()["Contents"]["Message"]


def test_add_ioc_to_source_already_exist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    source_id = "id"
    source_name = "name"
    ioc_value = "ioc_value"

    args = {
        "source_name": source_name,
        "ioc_value": ioc_value,
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCSource/",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_IOCSource"),
        ),
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCRule/",
                query=f"source_id={source_id}&search={ioc_value}",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_IOCSource"),
        ),
    ]

    result = Hurukai.add_ioc_to_source(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)

    assert "already exists" in result.to_context()["Contents"]["Message"]


def test_enrich_threat(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "id": "1",
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/endpoint/Agent/",
                query="offset=0"
                "&threat_id=1"
                "&fields=id,hostname,domainname,osproducttype,ostype"
                "&limit=10000",
            ),
            status_code=200,
            json=load_json("data_endpoint_Agent"),
        ),
        requests_mock.get(
            _full_url(
                path="data/host_properties/local_users/windows/",
                query="offset=0&threat_id=1&limit=10000",
            ),
            status_code=200,
            json=load_json("data_host_properties_local_users_windows"),
        ),
        requests_mock.get(
            _full_url(
                path="data/alert/alert/Threat/rules/",
                query="threat_id=1&fields=rule_level,rule_name,security_event_count",
            ),
            status_code=200,
            json=load_json("data_alert_alert_Threat_rules"),
        ),
    ]

    Hurukai.enrich_threat(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_search_whitelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "keyword": "foobar",
    }

    requests_mock.get(
        _full_url(
            path="data/threat_intelligence/WhitelistRule/",
            query="offset=0"
            "&limit=100"
            f"&search={args['keyword']}"
            "&ordering=-last_update"
            "&provided_by_hlab=False",
        ),
        status_code=200,
        json=load_json("data_threat_intelligence_WhitelistRule"),
    )

    Hurukai.search_whitelist(client, args)
    assert requests_mock.called_once


def test_result_startuplist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Startup/",
            query="limit=10000&job_id=1&ordering=filename",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Startup"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_startuplist(client, args)

    assert requests_mock.called_once


def test_result_servicelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Service/",
            query="limit=10000&job_id=1&ordering=service_name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Service"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_servicelist(client, args)

    assert requests_mock.called_once


def test_result_scheduledtasklist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/ScheduledTaskXML/",
            query="limit=10000&job_id=1&ordering=short_name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_ScheduledTaskXML"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_scheduledtasklist(client, args)

    assert requests_mock.called_once


def test_result_runkeylist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/RunKey/",
            query="limit=10000&job_id=1&ordering=-last_executed",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_RunKey"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_runkeylist(client, args)

    assert requests_mock.called_once


def test_result_pipelist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Pipe/",
            query="limit=10000&job_id=1&ordering=name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Pipe"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_pipelist(client, args)

    assert requests_mock.called_once


def test_result_prefetchlist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Prefetch/",
            query="limit=10000&job_id=1&ordering=-last_executed",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Prefetch"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_prefetchlist(client, args)

    assert requests_mock.called_once


def test_result_linux_persistence_list(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/PersistanceFile/",
            query="limit=10000&job_id=1&ordering=short_name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_PersistanceFile"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_linux_persistence_list(client, args)

    assert requests_mock.called_once


def test_result_driverlist(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    args = {
        "job_id": "1",
    }

    requests_mock.get(
        _full_url(
            path="data/investigation/hunting/Driver/",
            query="limit=10000&job_id=1&ordering=short_name",
        ),
        status_code=200,
        json=load_json("data_investigation_hunting_Driver"),
    )

    with unittest.mock.patch("time.sleep"):
        Hurukai.result_driverlist(client, args)

    assert requests_mock.called_once


def test_delete_ioc_from_source(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    source_id = "id"
    source_name = "name"
    ioc_value = "ioc_value"

    args = {
        "source_name": source_name,
        "ioc_value": ioc_value,
    }

    mocks = [
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCSource/",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_IOCSource"),
        ),
        requests_mock.get(
            _full_url(
                path="data/threat_intelligence/IOCRule/",
                query=f"source_id={source_id}&search={ioc_value}",
            ),
            status_code=200,
            json=load_json("data_threat_intelligence_IOCSource"),
        ),
        requests_mock.delete(
            _full_url(
                path=f"data/threat_intelligence/IOCRule/{source_id}/",
            ),
            status_code=200,
            json={},
        ),
    ]

    Hurukai.delete_ioc_from_source(client, args)

    assert requests_mock.call_count == len(mocks)
    assert all(m.called_once for m in mocks)


def test_api_call(
    client: Client,
    requests_mock: RequestsMock,
) -> None:

    api_endpoint = "non-existent-endpoint"

    args = {
        "api_endpoint": f"/api/{api_endpoint}",
    }

    requests_mock.get(
        _full_url(
            path=api_endpoint,
        ),
        status_code=200,
        json={},
    )

    Hurukai.api_call(client, args)
    assert requests_mock.called_once
