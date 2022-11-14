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


def load_test_data(file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / f"{file_name}.json", "r") as f:
        return json.load(f)


# --- Utility Functions Tests ---
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
                                  }])
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
                             ("PT2M17.976S", "2 minutes, 17.976 seconds"),
                             ("PT51.316S", "51.316 seconds")
                         ])
def test_readable_duration_time(test_input: str, expected_output: float):
    assert readable_duration_time(test_input) == expected_output


@pytest.mark.parametrize("test_input_data, test_input_key, expected_output",
                         [
                             ({"a": "b", "c": "d", "e": "f"}, "a", {"c": "d", "e": "f"}),
                             (("a", {1: "b"}), 1, ("a", {})),
                             ([1, 2, {"a": "b", "test": "test"}], "test", [1, 2, {"a": "b"}]),
                             ({"a": {"b": {"test": "x"}}}, "test", {"a": {"b": {"test": "x"}}}),
                         ])
def test_remove_dict_key(test_input_data: IterableCollection, test_input_key: str, expected_output: IterableCollection):
    assert remove_dict_key(test_input_data, test_input_key) == expected_output


@pytest.mark.parametrize("test_input_data, name_mapping, use_reference, expected_output",
                         [
                             ({"a": "b", "c": "d", "e": "f"}, {"a": "A", "e": "E"}, False,
                              {"A": "b", "c": "d", "E": "f"}),
                             ({"a": {"b": {"test": "x"}}}, {"a": "A", "test": "TEST"}, True,
                              {"A": {"b": {"test": "x"}}}),
                             ([(1, {"a": {"b": {"a": "a"}}}), 2], {"a": "A"}, True, [(1, {"A": {"b": {"a": "a"}}}), 2]),
                             ({"a": {"b": {"test": "x"}}}, {"a.b": "A", "test": "TEST"}, True,
                              {"A": {"test": "x"}, "a": {}}),
                             ({}, {"a": "b"}, False, {})
                         ])
def test_replace_key_names(test_input_data: IterableCollection, name_mapping: dict,
                           use_reference: bool, expected_output: IterableCollection):
    result = replace_key_names(test_input_data, name_mapping, use_reference)
    assert result == expected_output

    if use_reference:
        assert result is test_input_data


# --- Command & Client Functions Tests ---
@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("Test1", "1"),
                             ("Test2", "2"),
                             ("Test3", "3"),
                             ("Site-That-Doesn't-Exist", None),
                         ])
def test_find_site_id(mocker, mock_client: Client, test_input: str, expected_output: Union[str, None]):
    mocker.patch.object(Client, "_paged_http_request", return_value=load_test_data("client_get_sites"))
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
