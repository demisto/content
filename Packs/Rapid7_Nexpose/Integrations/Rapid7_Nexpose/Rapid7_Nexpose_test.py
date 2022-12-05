import json
from pathlib import Path

import pytest

from Rapid7_Nexpose import *


@pytest.fixture
def mock_client():
    return Client(
        url="url",
        username="username",
        password="password",
        verify=False,
    )


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json", "r") as f:
        return json.load(f)


# --- Utility Functions Tests ---
@pytest.mark.parametrize("mock_files_prefix, pages",
                         [
                             ("get_vulnerabilities", 4)
                         ])
def test_paged_http_request(mocker, mock_client: Client, mock_files_prefix: str, pages: int):
    mock_data = [load_test_data("paged_http_request", mock_files_prefix + f"_{i}") for i in range(pages)]

    def pagination_side_effect(**kwargs):
        if kwargs.get("params") and kwargs["params"].get("page"):
            return mock_data[int(kwargs["params"]["page"])]

        return mock_data[0]

    mocker.patch.object(Client, "_http_request", side_effect=pagination_side_effect)
    assert mock_client._paged_http_request(page_size=3, limit=10) == \
           load_test_data("paged_http_request", f"{mock_files_prefix}_output")


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             (["risk-score is-greater-than 1000.5", "vulnerability-title contains 7zip"],
                              [
                                 {
                                     "field": "risk-score",
                                     "operator": "is-greater-than",
                                     "value": 1000.5
                                 },
                                 {
                                     "field": "vulnerability-title",
                                     "operator": "contains",
                                     "value": "7zip"
                                 }
                             ])
                         ])
def test_convert_asset_search_filters(test_input: list[str], expected_output: list[dict]):
    assert convert_asset_search_filters(test_input) == expected_output


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             (
                                 "2022-01-01T00:00:00Z",
                                 strptime("2022-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
                             ),
                             (
                                 "2022-01-01T00:00:00.000Z",
                                 strptime("2022-01-01T00:00:00.000Z", "%Y-%m-%dT%H:%M:%S.%fZ")
                             ),
                         ])
def test_convert_datetime_str(test_input: str, expected_output: struct_time):
    assert convert_datetime_str(test_input) == expected_output


# These (long) list of parameters assure that all possible function parameters are tested for this function.
@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({
                                 "service": CredentialService.CIFSHASH, "domain": "Test1", "username": "Test2",
                                 "password": "Test3", "ntlm_hash": "Test4"
                             },
                                 {
                                 "service": "cifshash", "username": "Test2", "password": "Test3", "domain": "Test1",
                                 "ntlmHash": "Test4"
                             }),
                             ({
                                 "service": CredentialService.HTTP, "http_realm": "Test1", "username": "Test2",
                                 "password": "Test3"
                             },
                                 {
                                 "service": "http", "username": "Test2", "password": "Test3", "realm": "Test1"
                             }),
                             ({
                                 "service": CredentialService.MS_SQL, "database_name": "Test1", "username": "Test2",
                                 "password": "Test3", "use_windows_authentication": True, "domain": "Test4"
                             },
                                 {
                                 "service": "ms-sql", "username": "Test2", "password": "Test3",
                                 "useWindowsAuthentication": True, "domain": "Test4", "database": "Test1"
                             }),
                             ({
                                 "service": CredentialService.NOTES, "notes_id_password": "Test1"
                             },
                                 {
                                 "service": "notes", "notesIDPassword": "Test1"
                             }),
                             ({
                                 "service": CredentialService.ORACLE, "oracle_sid": "Test1", "username": "Test2",
                                 "password": "Test3", "oracle_enumerate_sids": True,
                                 "oracle_listener_password": "Test4"
                             },
                                 {
                                 "service": "oracle", "username": "Test2", "password": "Test3", "sid": "Test1",
                                 "enumerateSids": True, "oracleListenerPassword": "Test4"
                             }),
                             ({
                                 "service": CredentialService.SNMP, "snmp_community_name": "Test1"
                             },
                                 {
                                 "service": "snmp", "community": "Test1"
                             }),
                             ({
                                 "service": CredentialService.SNMPV3,
                                 "snmpv3_authentication_type": SNMPv3AuthenticationType.SHA,
                                 "username": "Test1", "password": "Test2"
                             },
                                 {
                                 "service": "snmpv3", "username": "Test1", "authenticationType": "sha",
                                 "password": "Test2"
                             }),
                             ({
                                 "service": CredentialService.SSH, "username": "Test1", "password": "Test2",
                                 "ssh_permission_elevation": SSHElevationType.PRIVILEGED_EXEC,
                                 "ssh_permission_elevation_username": "Test3",
                                 "ssh_permission_elevation_password": "Test4"
                             },
                                 {
                                 "service": "ssh", "username": "Test1", "password": "Test2",
                                 "permissionElevation": "privileged-exec", "permissionElevationUsername": "Test3",
                                 "permissionElevationPassword": "Test4"
                             }),
                             ({
                                 "service": CredentialService.SSH_KEY, "ssh_key_pem": "Test1",
                                 "ssh_private_key_password": "Test2", "username": "Test3",
                                 "ssh_permission_elevation": SSHElevationType.SUDO,
                                 "ssh_permission_elevation_username": "Test4",
                                 "ssh_permission_elevation_password": "Test5"
                             },
                                 {
                                 "service": "ssh-key", "username": "Test3", "permissionElevation": "sudo",
                                 "permissionElevationUsername": "Test4", "permissionElevationPassword": "Test5",
                                 "pemKey": "Test1"
                             }),
                         ])
def test_create_credential_creation_body(test_input_kwargs: dict, expected_output: dict):
    assert create_credential_creation_body(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({"a": "test", "b": 1, "c": None, "d": 6.1}, {"a": "test", "b": 1, "d": 6.1}),
                             ({"a": None, "b": {}, "c": (1, "test")}, {"b": {}, "c": (1, "test")}),
                         ])
def test_find_valid_params(test_input_kwargs: dict, expected_output: dict):
    assert find_valid_params(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({"years": 1, "months": 8, "weeks": 2, "days": 6}, "P1Y8M2W6D"),
                             ({"hours": 16, "minutes": 26, "seconds": 53.4}, "PT16H26M53.4S"),
                             ({"years": 4, "months": 3, "weeks": 1, "days": 2,
                               "hours": 12, "minutes": 43, "seconds": 12.5}, "P4Y3M1W2DT12H43M12.5S"),
                         ])
def test_generate_duration_time(test_input_kwargs: dict, expected_output: str):
    assert generate_duration_time(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("PT2M16.481S", "2 minutes, 16.481 seconds"),
                             ("PT51.316S", "51.316 seconds"),
                             ("P3Y6M4DT12H30M5S", "3 years, 6 months, 4 days, 12 hours, 30 minutes, 5 seconds"),
                         ])
def test_readable_duration_time(test_input: str, expected_output: float):
    assert readable_duration_time(test_input) == expected_output


@pytest.mark.parametrize("test_input_data, test_input_key, expected_output",
                         [
                             ({"a": "b", "c": "d", "e": "f"}, "a", {"c": "d", "e": "f"}),
                             (("a", {1: "b"}), 1, ("a", {})),
                             ([1, 2, {"a": "b", "test": "test"}], "test", [1, 2, {"a": "b"}]),
                             ({"a": {"b": {"test": "x"}}}, "test", {'a': {'b': {}}}),
                         ])
def test_remove_dict_key(test_input_data: dict | list | tuple,
                         test_input_key: str, expected_output: dict | list | tuple):
    assert remove_dict_key(test_input_data, test_input_key) == expected_output


@pytest.mark.parametrize("test_input_data, name_mapping, include_none, expected_output",
                         [
                             ({"a": "b", "c": "d", "e": "f"}, {"a": "A", "e": "E"}, False, {"A": "b", "E": "f"}),
                             ({"a": {"b": {"test": "x"}}}, {"a": "A", "test": "TEST"}, True,
                              {"A": {"b": {"test": "x"}}, "TEST": None}),
                             ([(1, {"a": {"b": {"a": "a"}}}), 2], {"a": "A"}, False,
                              [(1, {"A": {"b": {"a": "a"}}}), 2]),
                             ({"a": {"b": {"test": "x"}}}, {"a.b": "A", "test": "TEST"}, False,
                              {"A": {"test": "x"}}),
                             ({}, {"a": "b"}, False, {})
                         ])
def test_generate_new_dict(test_input_data: dict | list, name_mapping: dict,
                           include_none: bool, expected_output: dict | list):
    result = generate_new_dict(test_input_data, name_mapping, include_none)
    assert result == expected_output


# --- Command & Client Functions Tests ---
@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("Test 1", "1"),
                             ("Test 2", "2"),
                             ("Test 3", "3"),
                             ("Site-That-Doesn't-Exist", None),
                         ])
def test_find_site_id(mocker, mock_client: Client, test_input: str, expected_output: Union[str, None]):
    mocker.patch.object(Client, "_paged_http_request", return_value=load_test_data("api_mock", "client_get_sites"))
    assert mock_client.find_site_id(test_input) == expected_output


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"site": Site(site_id="1"), "date": "2022-01-01T10:00:00Z", "ip_address": "192.0.2.0"},
                              {"id": 1}, {"id": 1})
                         ])
def test_create_asset_command(mocker, mock_client: Client, test_input_kwargs: dict,
                              api_mock_data: dict, expected_output_context: dict):
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)
    assert create_asset_command(client=mock_client, **test_input_kwargs).outputs == expected_output_context


@pytest.mark.parametrize("report_templates_mock_file, report_config_mock_data, report_mock_data, "
                         "expected_output_context_file",
                         [
                             ("client_get_report_templates", {"id": 1}, {"id": 2}, "create_report_commands")
                         ])
def test_create_report_commands(mocker, mock_client: Client, report_templates_mock_file: str,
                                report_config_mock_data: dict, report_mock_data: dict,
                                expected_output_context_file: str):
    report_templates_data = load_test_data("api_mock", report_templates_mock_file)
    mocker.patch.object(Client, "get_report_templates", return_value=report_templates_data)
    mocker.patch.object(Client, "create_report_config", return_value=report_config_mock_data)

    mocker.patch.object(Client, "_http_request", return_value=report_mock_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    assert create_assets_report_command(
        client=mock_client,
        asset_ids="1",
        report_name="Test Report",
        download_immediately="false").outputs == expected_output_context
    assert create_scan_report_command(
        client=mock_client,
        scan_id="1",
        report_name="Test Report",
        download_immediately="false").outputs == expected_output_context
    assert create_sites_report_command(
        client=mock_client,
        site_ids="1,2,3",
        report_name="Test Report",
        download_immediately="false").outputs == expected_output_context


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "FTP", "username": "Test1",
                               "password": "Test2"},
                              {"id": 1}, {"id": 1})
                         ])
def test_create_shared_credential_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                          api_mock_data: dict, expected_output_context: dict):
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)
    assert create_shared_credential_command(client=mock_client, **test_input_kwargs).outputs == expected_output_context


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"vulnerability_id": "7-zip-cve-2008-6536", "scope_type": "Global", "state": "Approved",
                               "reason": "Acceptable-Risk", "comment": "Comment"}, {"id": 1}, {"id": 1})
                         ])
def test_create_vulnerability_exception_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                                api_mock_data: dict, expected_output_context: dict):
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)
    assert create_vulnerability_exception_command(client=mock_client, **test_input_kwargs).outputs == \
        expected_output_context


@pytest.mark.parametrize("asset_mock_file, asset_vulnerability_api_mock_file, vulnerability_api_mock_file, "
                         "expected_output_context_file",
                         [
                             ("client_get_asset", "client_get_asset_vulnerabilities",
                              "client_get_vulnerability-certificate-common-name-mismatch", "get_asset_command")
                         ])
def test_get_asset_command(mocker, mock_client: Client, asset_mock_file: str, asset_vulnerability_api_mock_file: str,
                           vulnerability_api_mock_file: str, expected_output_context_file: str):
    asset_mock_data = load_test_data("api_mock", asset_mock_file)
    mocker.patch.object(Client, "get_asset", return_value=asset_mock_data)

    mocker.patch.object(Client, "find_asset_site", return_value=Site(site_id="1", site_name="Test"))

    asset_vulnerability_api_mock_data = load_test_data("api_mock", asset_vulnerability_api_mock_file)
    mocker.patch.object(Client, "get_asset_vulnerabilities", return_value=asset_vulnerability_api_mock_data)

    vulnerability_api_mock_data = load_test_data("api_mock", vulnerability_api_mock_file)
    mocker.patch.object(Client, "get_vulnerability", return_value=vulnerability_api_mock_data)

    result = get_asset_command(client=mock_client, asset_id="1")
    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    if isinstance(result, CommandResults):
        assert result.outputs == expected_output_context

    elif isinstance(result, list):
        assert result[-1].outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_assets", "get_assets_command")
                         ])
def test_get_assets_command(mocker, mock_client: Client, api_mock_file: str, expected_output_context_file: str):
    assets_mock_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "get_assets", return_value=assets_mock_data)

    mocker.patch.object(Client, "find_asset_site", return_value=Site(site_id="1", site_name="Test"))

    result = get_assets_command(client=mock_client)
    expected_output_context = load_test_data("expected_context", expected_output_context_file)
    assert [r.outputs for r in result] == expected_output_context


@pytest.mark.parametrize("vulnerability_id, asset_vulnerability_mock_file, vulnerability_mock_file, "
                         "asset_vulnerability_solution_mock_file, expected_output_context_file",
                         [
                             ("ssl-cve-2011-3389-beast", "client_get_asset_vulnerability-ssl-cve-2011-3389-beast",
                              "client_get_vulnerability-ssl-cve-2011-3389-beast",
                              "client_get_asset_vulnerability_solution-ssl-cve-2011-3389-beast",
                              "get_asset_vulnerability_command")
                         ])
def test_get_asset_vulnerability_command(mocker, mock_client: Client, vulnerability_id: str,
                                         asset_vulnerability_mock_file: str, vulnerability_mock_file: str,
                                         asset_vulnerability_solution_mock_file: str,
                                         expected_output_context_file: str):
    asset_vulnerability_data = load_test_data("api_mock", asset_vulnerability_mock_file)
    mocker.patch.object(Client, "get_asset_vulnerability", return_value=asset_vulnerability_data)

    vulnerability_data = load_test_data("api_mock", vulnerability_mock_file)
    mocker.patch.object(Client, "get_vulnerability", return_value=vulnerability_data)

    asset_vulnerability_solution_data = load_test_data("api_mock", asset_vulnerability_solution_mock_file)
    mocker.patch.object(Client, "get_asset_vulnerability_solution", return_value=asset_vulnerability_solution_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    results = get_asset_vulnerability_command(client=mock_client, asset_id="1", vulnerability_id=vulnerability_id)
    assert [result.outputs for result in results] == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_report_history", "get_generated_report_status_command")
                         ])
def test_get_generated_report_status_command(mocker, mock_client: Client, api_mock_file: str,
                                             expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = get_generated_report_status_command(client=mock_client, report_id="1", instance_id="latest")
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_report_templates", "get_report_templates_command")
                         ])
def test_get_report_templates_command(mocker, mock_client: Client, api_mock_file: str,
                                      expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = get_report_templates_command(client=mock_client)
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, ids_input, expected_output_context_file",
                         [
                             ("client_get_scan", "1", "get_scan_command")
                         ])
def test_get_scan_command(mocker, mock_client: Client, api_mock_file: str, ids_input: str,
                          expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    results = get_scan_command(client=mock_client, scan_ids=ids_input)
    assert [result.outputs for result in results] == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_scans", "get_scans_command")
                         ])
def test_get_scans_command(mocker, mock_client: Client, api_mock_file: str, expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = get_scans_command(client=mock_client, active="false")
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_sites", "get_sites_command")
                         ])
def test_get_sites_command(mocker, mock_client: Client, api_mock_file: str, expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = get_sites_command(client=mock_client)
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_shared_credentials", "list_shared_credential_command")
                         ])
def test_list_shared_credential_command(mocker, mock_client: Client, api_mock_file: str,
                                        expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_shared_credential_command(client=mock_client, limit="3")
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_assigned_shared_credentials", "list_assigned_shared_credential_command")
                         ])
def test_list_assigned_shared_credential_command(mocker, mock_client: Client, api_mock_file: str,
                                                 expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_assigned_shared_credential_command(client=mock_client, site=Site(site_id="1"), limit="3")
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_vulnerabilities", "list_vulnerability_command")
                         ])
def test_list_vulnerability_command(mocker, mock_client: Client, api_mock_file: str,
                                    expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_vulnerability_command(client=mock_client)
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_vulnerability_exceptions", "list_vulnerability_exceptions_command")
                         ])
def test_list_vulnerability_exceptions_command(mocker, mock_client: Client, api_mock_file: str,
                                               expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_vulnerability_exceptions_command(client=mock_client)
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_search_assets", "search_assets_command")
                         ])
def test_search_assets_command(mocker, mock_client: Client, api_mock_file: str,
                               expected_output_context_file: str):
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "search_assets", return_value=api_data,)
    mocker.patch.object(Client, "find_asset_site", return_value=Site(site_id="1", site_name="Test"))

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    results = search_assets_command(client=mock_client, risk_score="8000")

    assert isinstance(results, list)  # Assure a list of CommandResults has been received instead of a single one.
    # Using `sorted` to not fail test in case the order of CommandResults changes
    assert sorted([result.outputs for result in results], key=lambda d: d["AssetId"]) == \
           sorted(expected_output_context, key=lambda d: d["AssetId"])
