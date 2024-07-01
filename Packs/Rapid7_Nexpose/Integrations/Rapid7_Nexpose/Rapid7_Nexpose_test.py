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
    with open(Path("test_data") / folder / f"{file_name}.json") as f:
        return json.load(f)


def test_connection_errors_recovers(mocker, mock_client):
    """
    Given:
     - Connection Error, ReadTimeout error and a success response

    When:
     - running the _http_request method

    Then:
     - Ensure that success message is printed and recovery for http request happens.
    """
    mocker.patch.object(demisto, "error")
    mocker.patch("Rapid7_Nexpose.time.sleep")
    mocker.patch.object(
        BaseClient,
        "_http_request",
        side_effect=[
            DemistoException(message="error", exception=requests.ConnectionError("error")),
            requests.ReadTimeout("error"),
            "success"
        ]
    )
    assert mock_client._http_request(method="GET", url_suffix="url") == "success"


def test_http_request_no_connection_errors(mocker, mock_client):
    """
    Given:
     - general Http error

    When:
     - running the _http_request method

    Then:
     - Ensure that the exception is raised without triggering the retry mechanism
    """
    mocker.patch.object(demisto, "error")
    sleep_mocker = mocker.patch("Rapid7_Nexpose.time.sleep")
    mocker.patch.object(
        BaseClient,
        "_http_request",
        side_effect=[DemistoException(message="error", exception=requests.exceptions.HTTPError("error"))]
    )
    with pytest.raises(DemistoException):
        assert mock_client._http_request(method="GET", url_suffix="url")

    assert not sleep_mocker.called


# --- Utility Functions Tests ---
@pytest.mark.parametrize("mock_files_prefix, pages, test_input_kwargs, expected_output_context_file",
                         [
                             ("get_vulnerabilities", 4, {"page_size": 3, "limit": 10}, "get_vulnerabilities_output"),
                             ("get_vulnerabilities", 4, {"page_size": 3, "page": 2},
                              "get_vulnerabilities_specific_page_output")
                         ])
def test_client_paged_http_request(mocker, mock_client: Client, mock_files_prefix: str, pages: int,
                                   test_input_kwargs: dict, expected_output_context_file: str):
    """
    Given: Valid pagination parameters.
    When: Calling the client_paged_http_request function.
    Then: Ensure the function returns the expected output, considering the pagination parameters.
    """
    mock_data = [load_test_data("paged_http_request", mock_files_prefix + f"_{i}") for i in range(pages)]

    def pagination_side_effect(**kwargs):
        if kwargs.get("params") and kwargs["params"].get("page"):
            return mock_data[int(kwargs["params"]["page"])]

        return mock_data[0]

    mocker.patch.object(BaseClient, "_http_request", side_effect=pagination_side_effect)
    assert mock_client._paged_http_request(**test_input_kwargs) == \
        load_test_data("paged_http_request", f"{expected_output_context_file}")


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
    """
    Given: A list of filters in a string format.
    When: Calling the convert_asset_search_filters function.
    Then: Ensure the function returns a list of valid dictionaries, where each dictionary represents a filter.
    """
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
    """
    Given: An ISO 8601 formatted date string.
    When: Calling the convert_datetime_str function.
    Then: Ensure the function returns a struct_time object matching the given date string.
    """
    assert convert_datetime_str(test_input) == expected_output


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
                                 "privateKeyPassword": "Test2", "pemKey": "Test1"
                             }),
                         ])
def test_create_credential_creation_body(test_input_kwargs: dict, expected_output: dict):
    """
    Given: A dictionary of valid keyword arguments for the create_credential_creation_body function.
    When: Calling the create_credential_creation_body function.
    Then: Ensure the function returns a dictionary representing a valid credential creation / update request body.
    """
    assert create_credential_creation_body(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input_kwargs",
                         [
                             ({
                                 "service": CredentialService.CIFSHASH, "domain": "Test1", "username": "Test2",
                                 "password": "Test3"
                             }),
                             ({
                                 "service": CredentialService.HTTP, "http_realm": "Test1", "username": "Test2",
                             }),
                             ({
                                 "service": CredentialService.MS_SQL, "database_name": "Test1", "password": "Test3",
                                 "use_windows_authentication": True, "domain": "Test4"
                             }),
                             ({
                                 "service": CredentialService.ORACLE, "oracle_sid": "Test1", "username": "Test2",
                                 "password": "Test3", "oracle_enumerate_sids": True,
                             }),
                             ({
                                 "service": CredentialService.SNMP
                             }),
                             ({
                                 "service": CredentialService.SNMPV3, "username": "Test1", "password": "Test2"
                             }),
                             ({
                                 "service": CredentialService.SNMPV3,
                                 "snmpv3_authentication_type": SNMPv3AuthenticationType.SHA, "username": "Test1"
                             }),
                             ({
                                 "service": CredentialService.SNMPV3,
                                 "snmpv3_authentication_type": SNMPv3AuthenticationType.SHA, "username": "Test1",
                                 "password": "Test2", "snmpv3_privacy_type": SNMPv3PrivacyType.AES_256
                             }),
                             ({
                                 "service": CredentialService.SSH, "username": "Test1", "password": "Test2",
                                 "ssh_permission_elevation": SSHElevationType.PRIVILEGED_EXEC,
                             }),
                             ({
                                 "service": CredentialService.SSH_KEY, "ssh_private_key_password": "Test2",
                                 "username": "Test3", "ssh_permission_elevation": SSHElevationType.SUDO,
                                 "ssh_permission_elevation_username": "Test4",
                                 "ssh_permission_elevation_password": "Test5"
                             }),
                         ])
def test_create_credential_creation_body_validations(test_input_kwargs: dict):
    """
    Given: A dictionary of invalid keyword arguments for the create_credential_creation_body function.
    When: Calling the create_credential_creation_body function.
    Then: Ensure validation errors are raised.
    """
    with pytest.raises(ValueError):
        create_credential_creation_body(**test_input_kwargs)


@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({"a": "test", "b": 1, "c": None, "d": 6.1}, {"a": "test", "b": 1, "d": 6.1}),
                             ({"a": None, "b": {}, "c": (1, "test")}, {"b": {}, "c": (1, "test")}),
                             ({"strict_mode": True, "a": False, "b": {}, "c": (1, "test"), "d": 1},
                              {"c": (1, "test"), "d": 1}),
                         ])
def test_find_valid_params(test_input_kwargs: dict, expected_output: dict):
    """
    Given: A dictionary of valid keyword arguments for the find_valid_params function.
    When: Calling the find_valid_params function.
    Then: Ensure the function returns a dictionary containing only the valid keyword arguments.
    """
    assert find_valid_params(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({"years": 1, "months": 8, "weeks": 2, "days": 6}, "P1Y8M2W6D"),
                             ({"hours": 16, "minutes": 26, "seconds": 53.4}, "PT16H26M53.4S"),
                             ({"years": 4, "months": 3, "weeks": 1, "days": 2,
                               "hours": 12, "minutes": 43, "seconds": 12.5}, "P4Y3M1W2DT12H43M12.5S"),
                         ])
def test_generate_duration_time(test_input_kwargs: dict, expected_output: str):
    """
    Given: A dictionary of valid keyword arguments for the generate_duration_time function.
    When: Calling the generate_duration_time function.
    Then: Ensure the function returns a string representing a valid duration time matching the given arguments.
    """
    assert generate_duration_time(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("PT2M16.481S", "2 minutes, 16.481 seconds"),
                             ("PT51.316S", "51.316 seconds"),
                             ("P3Y6M4DT12H30M5S", "3 years, 6 months, 4 days, 12 hours, 30 minutes, 5 seconds"),
                             ("Invalid", None),

                         ])
def test_readable_duration_time(test_input: str, expected_output: float | None):
    """
    Given: A string representing a valid duration time in ISO 8601 format.
    When: Calling the readable_duration_time function.
    Then: Ensure the function returns a string representing a valid and correct readable duration time.
    """
    if not re.fullmatch(r"P(?:[\d.]+[YMWD]){0,4}T(?:[\d.]+[HMS]){0,3}", test_input):
        with pytest.raises(ValueError):
            readable_duration_time(test_input)

    else:
        assert readable_duration_time(test_input) == expected_output


@pytest.mark.parametrize("test_input_data, test_input_key, expected_output",
                         [
                             ({"a": "b", "c": "d", "e": "f"}, "a", {"c": "d", "e": "f"}),
                             (("a", {1: "b"}), 1, ("a", {})),
                             ([1, 2, {"a": "b", "test": "test"}], "test", [1, 2, {"a": "b"}]),
                             ({"a": {"b": {"test": "x"}}}, "test", {'a': {'b': {}}}),
                         ])
def test_remove_dict_key(test_input_data: dict | list | tuple, test_input_key: str,
                         expected_output: dict | list | tuple):
    """
    Given: A dictionary, list or tuple and a key to remove.
    When: Calling the remove_dict_key function.
    Then: Ensure the function returns a dictionary, list or tuple without the given key.
    """
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
def test_generate_new_dict(test_input_data: dict | list, name_mapping: dict, include_none: bool,
                           expected_output: dict | list):
    """
    Given: A dictionary, list or tuple and a name-mapping dictionary.
    When: Calling the generate_new_dict function.
    Then: Ensure the function returns a dictionary, list or tuple with new keys
        according to the name-mapping dictionary.
    """
    result = generate_new_dict(test_input_data, name_mapping, include_none)
    assert result == expected_output


@pytest.mark.parametrize("sites_mock_file, site_id, site_name, send_client, expected_output_id",
                         [
                             ("client_get_sites", "1", "Test 1", True, "1"),
                             ("client_get_sites", "2", None, False, "2"),
                             ("client_get_sites", None, "Test 3", True, "3"),
                             ("client_get_sites", None, "Test 2", False, None),
                             ("client_get_sites", None, "This site does not exist", True, None),
                             ("client_get_sites", None, None, True, None),
                         ])
def test_site_init(mocker, mock_client: Client, sites_mock_file: str, send_client: bool, site_id: str | None,
                   site_name: str | None, expected_output_id: str | None):
    """
    Given: A site ID and a site name
    When: Calling the Site class constructor
    Then: If valid - ensure the class is initialized correctly. If not - ensure an exception is raised.
    """
    sites_api_data = load_test_data("api_mock", sites_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=sites_api_data)
    client = mock_client if send_client else None
    site_names = [site["name"] for site in sites_api_data]

    if site_id is None and site_name is None:
        # Assure an error is raised when neither site id nor site name are provided
        with pytest.raises(ValueError):
            Site(client=client, site_id=site_id, site_name=site_name)

    elif site_id is None and client is None:
        # Assure an error is raised when site name is provided without ID, but without a client
        with pytest.raises(ValueError):
            Site(client=client, site_id=site_id, site_name=site_name)

    elif site_id is None and site_name not in site_names:
        # Assure an error is raised when site name is provided without ID, and a site with that name does not exist
        with pytest.raises(DemistoException):
            Site(client=client, site_id=site_id, site_name=site_name)

    else:
        assert Site(client=client, site_id=site_id, site_name=site_name).id == expected_output_id


# --- Command & Client Functions Tests ---
@pytest.mark.parametrize("scope, template_id, report_name, report_format",
                         [
                             ({"sites": [1]}, "1", "Test", "pdf"),
                         ])
def test_client_create_report_config(mocker, mock_client: Client, scope: dict, template_id: str, report_name: str,
                                     report_format: str):
    """
    Given: Valid parameters for the create_report_config function.
    When: Calling the create_report_config function.
    Then: Ensure the API call is being called with the correct parameters.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request")
    mock_client.create_report_config(scope=scope,
                                     template_id=template_id,
                                     report_name=report_name,
                                     report_format=report_format)

    http_request.assert_called_with(
        url_suffix="/reports",
        method="POST",
        json_data={
            "scope": scope,
            "template": template_id,
            "name": report_name,
            "format": report_format.lower(),
        },
        resp_type="json",
    )


@pytest.mark.parametrize("api_mock_file, expected_output",
                         [
                             ("client_find_asset_site", Site(site_id="1", site_name="Test"))
                         ])
def test_client_find_asset_site(mocker, mock_client: Client, api_mock_file: str, expected_output: Site):
    """
    Given: A valid asset ID.
    When: Calling the find_asset_site function.
    Then: Ensure the function returns the correct site.
    """
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    returned_site = mock_client.find_asset_site(asset_id="1")
    assert returned_site.id == expected_output.id
    assert returned_site.name == expected_output.name


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("Test 1", "1"),
                             ("Test 2", "2"),
                             ("Test 3", "3"),
                             ("Site-That-Doesn't-Exist", None),
                         ])
def test_client_find_site_id(mocker, mock_client: Client, test_input: str, expected_output: Union[str, None]):
    """
    Given: A valid site name.
    When: Calling the find_site_id function.
    Then: Ensure the function returns the correct site ID.
    """
    mocker.patch.object(Client, "_paged_http_request", return_value=load_test_data("api_mock", "client_get_sites"))
    assert mock_client.find_site_id(test_input) == expected_output


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"site_id": "1", "date": "2022-01-01T10:00:00Z", "ip": "192.0.2.0"},
                              {"id": 1}, {"id": 1}),
                             ({"site_id": "1", "date": "2022-01-01T10:00:00Z", "host_name": "localhost",
                               "host_name_source": "LDAP"}, {"id": 1}, {"id": 1}),
                             ({"site_id": "1", "date": "2022-01-01T10:00:00Z"}, None, None),
                         ])
def test_create_asset_command(mocker, mock_client: Client, test_input_kwargs: dict, api_mock_data: dict | None,
                              expected_output_context: dict | None):
    """
    Given: Valid parameters for the create_asset_command function.
    When: Calling the create_asset_command function.
    Then: Ensure the API call is made with the correct parameters.
    """
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)
    if test_input_kwargs.get("ip") is not None or test_input_kwargs.get("host_name") is not None:
        assert create_asset_command(client=mock_client, **test_input_kwargs).outputs == expected_output_context

    else:
        # Assure an error is raised if neither of ip_address or hostname are provided
        with pytest.raises(ValueError):
            create_asset_command(client=mock_client, **test_input_kwargs)


@pytest.mark.parametrize("report_templates_mock_file, report_config_mock_data, report_mock_data, "
                         "expected_output_context_file",
                         [
                             ("client_get_report_templates", {"id": 1}, {"id": 2}, "create_report_commands")
                         ])
def test_create_report_commands(mocker, mock_client: Client, report_templates_mock_file: str,
                                report_config_mock_data: dict, report_mock_data: dict,
                                expected_output_context_file: str):
    """
    Given: Valid parameters for different report creation commands.
    When: Calling the create_report_command function.
    Then: Ensure a valid context output is returned.
    """
    report_templates_data = load_test_data("api_mock", report_templates_mock_file)
    mocker.patch.object(Client, "get_report_templates", return_value=report_templates_data)
    mocker.patch.object(Client, "create_report_config", return_value=report_config_mock_data)
    mocker.patch.object(Client, "_http_request", return_value=report_mock_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    assert create_assets_report_command(
        client=mock_client,
        assets="1",
        name="Test Report",
        download_immediately="false").outputs == expected_output_context
    assert create_scan_report_command(
        client=mock_client,
        scan="1",
        name="Test Report",
        download_immediately="false").outputs == expected_output_context
    assert create_sites_report_command(
        client=mock_client,
        sites="1,2,3",
        name="Test Report",
        download_immediately="false").outputs == expected_output_context


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_post_data, expected_output_context",
                         [
                             ({
                                 "site_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "week", "interval_time": "2",
                                 "duration_days": "1", "duration_hours": "1", "duration_minutes": "1",
                                 "scan_name": "Test", "enabled": "true", "included_targets": "192.0.2.0,192.0.2.1",
                                 "included_asset_groups": "1,2", "excluded_targets": "192.0.2.2,192.0.2.3",
                                 "excluded_asset_groups": "3,4",
                             }, {"id": 1},
                                 {
                                 "assets": {
                                     "excludedAssetGroups": {
                                         "assetGroupIDs": [3, 4]
                                     },
                                     "excludedTargets": {
                                         "addresses": [
                                             "192.0.2.2",
                                             "192.0.2.3"
                                         ]
                                     },
                                     "includedAssetGroups": {
                                         "assetGroupIDs": [1, 2]
                                     },
                                     "includedTargets": {
                                         "addresses": [
                                             "192.0.2.0",
                                             "192.0.2.1"
                                         ]
                                     }
                                 },
                                 "duration": "P1DT1H1M",
                                 "enabled": True,
                                 "onScanRepeat": "restart-scan",
                                 "repeat": {
                                     "every": "week",
                                     "interval": 2
                                 },
                                 "scanName": "Test",
                                 "start": "2050-01-01T10:00:00Z"
                             }, {"id": 1}),
                             ({
                                 "site_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z",
                             }, {"id": 1},
                                 {
                                 "enabled": True,
                                 "onScanRepeat": "restart-scan",
                                 "start": "2050-01-01T10:00:00Z"
                             }, {"id": 1}),
                             ({
                                 "site_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "week", "enabled": "true",
                             }, {"id": 1}, None, None),
                             ({
                                 "site_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "Date-of-month", "interval_time": "2",
                                 "duration_days": "1", "duration_hours": "1", "duration_minutes": "1",
                                 "scan_name": "Test", "enabled": "true", "included_targets": "192.0.2.0,192.0.2.1",
                                 "included_asset_groups": "1,2", "excluded_targets": "192.0.2.2,192.0.2.3",
                                 "excluded_asset_groups": "3,4",
                             }, {"id": 1}, None, None),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_create_scan_schedule_command(mocker, mock_client: Client, test_input_kwargs: dict, api_mock_data: dict,
                                      expected_post_data: dict | None, expected_output_context: dict):
    """
    Given: Valid or invalid parameters for the create_scan_schedule_command function.
    When: Calling the create_scan_schedule_command function.
    Then: If valid - ensure a valid API call is made and a valid context output is returned.
        If invalid - Ensure an  exception is raised.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value=api_mock_data)

    if test_input_kwargs.get("frequency") is not None and (test_input_kwargs.get("interval_time") is None
                                                           or (test_input_kwargs["frequency"] == "Date-of-month"
                                                               and test_input_kwargs.get("date_of_month") is None)):
        with pytest.raises(ValueError):
            create_scan_schedule_command(mock_client, **test_input_kwargs)

    else:
        assert create_scan_schedule_command(mock_client, **test_input_kwargs).outputs == \
            expected_output_context

        http_request.assert_called_with(
            method="POST",
            url_suffix=f"/sites/{test_input_kwargs['site_id']}/scan_schedules",
            json_data=expected_post_data,
            resp_type="json",
        )


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "FTP", "username": "Test1",
                               "password": "Test2", "host_restriction": "192.0.2.0", "port_restriction": "8080",
                               "sites": "1,2,3"},
                              {"id": 1}, {"id": 1}),
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "SNMPv3", "username": "Test1",
                               "password": "Test2", "authentication_type": "SHA", "privacy_type": "AES-256",
                               "privacy_password": "123"},
                              {"id": 1}, {"id": 1}),
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "Oracle", "username": "Test1",
                               "password": "Test2", "oracle_enumerate_sids": "false"},
                              {"id": 1}, {"id": 1}),
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "SSH", "username": "Test1",
                               "password": "Test2", "ssh_permission_elevation": "None"},
                              {"id": 1}, {"id": 1}),
                             ({"name": "Test", "site_assignment": "All-Sites", "service": "MS-SQL", "username": "Test1",
                               "password": "Test2", "use_windows_authentication": "false"},
                              {"id": 1}, {"id": 1}),
                         ])
def test_create_shared_credential_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                          api_mock_data: dict, expected_output_context: dict):
    """
    Given: valid parameters for the create_shared_credential_command function.
    When: Calling the create_shared_credential_command function.
    Then: Ensure a valid context output is returned.
    """
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)
    assert create_shared_credential_command(client=mock_client, **test_input_kwargs).outputs == expected_output_context


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_post_data, expected_output_context",
                         [
                             ({"name": "Test 1", "description": "Test 2", "assets": "1,2,3", "importance": "very_high"},
                              {"id": 1},
                              {
                                  "name": "Test 1",
                                  "description": "Test 2",
                                  "importance": "very_high",
                                  "scan": {
                                      "assets": {
                                          "includedTargets": {
                                              "addresses": [
                                                  "1",
                                                  "2",
                                                  "3"
                                              ]
                                          }
                                      }
                                  }
                             }, {"Id": 1}),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_create_site(mocker, mock_client: Client, test_input_kwargs: dict, api_mock_data: dict,
                     expected_post_data: dict, expected_output_context: dict):
    """
    Given: Valid parameters for the create_site function.
    When: Calling the create_site function.
    Then: Ensure a valid API call is made and a valid context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value=api_mock_data)

    assert create_site_command(client=mock_client, **test_input_kwargs).outputs == expected_output_context

    http_request.assert_called_with(
        url_suffix="/sites",
        method="POST",
        json_data=expected_post_data,
        resp_type="json"
    )


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_post_data, expected_output_context",
                         [
                             ({"site_id": "1", "name": "Test", "host_restriction": "192.0.2.0",
                                 "port_restriction": "8080", "service": "FTP", "username": "Test1", "password": "Test2"
                               }, {"id": 1},
                              {
                              "hostRestriction": "192.0.2.0",
                              "name": "Test",
                              "portRestriction": "8080",
                              "account": {
                                  "service": "ftp",
                                  "username": "Test1",
                                  "password": "Test2"
                              }
                              }, {"id": 1}),
                             ({"site_id": "2", "name": "Test", "service": "SNMPv3",
                                 "username": "Test1", "password": "Test2", "authentication_type": "SHA",
                                 "privacy_type": "AES-256", "privacy_password": "123"}, {"id": 1},
                              {
                              "name": "Test",
                              "account": {
                                  "service": "snmpv3",
                                  "username": "Test1",
                                  "authenticationType": "sha",
                                  "password": "Test2",
                                  "privacyType": "aes-256",
                                  "privacyPassword": "123"
                              }
                              }, {"id": 1}),
                             ({"site_id": "3", "name": "Test", "service": "Oracle",
                                 "username": "Test1", "password": "Test2", "oracle_enumerate_sids": "false"},
                              {"id": 1},
                              {
                              "name": "Test",
                              "account": {
                                  "service": "oracle",
                                  "username": "Test1",
                                  "password": "Test2",
                                  "enumerateSids": False,
                                  "oracleListenerPassword": None
                              }
                              }, {"id": 1},),
                             ({"site_id": "1", "name": "Test", "service": "SSH",
                                 "username": "Test1", "password": "Test2", "ssh_permission_elevation": "None"},
                              {"id": 1},
                              {
                              "name": "Test",
                              "account": {
                                  "service": "ssh",
                                  "username": "Test1",
                                  "password": "Test2",
                                  "permissionElevation": "none"
                              }
                              }, {"id": 1},),
                             ({"site_id": "2", "name": "Test", "service": "MS-SQL",
                                 "username": "Test1", "password": "Test2", "use_windows_authentication": "false"},
                              {"id": 1},
                              {
                              "name": "Test",
                              "account": {
                                  "service": "ms-sql",
                                  "username": "Test1",
                                  "password": "Test2",
                                  "useWindowsAuthentication": False
                              }
                              }, {"id": 1}),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_create_site_scan_credential_command(mocker, mock_client: Client, test_input_kwargs: dict, api_mock_data: dict,
                                             expected_post_data: dict, expected_output_context: dict):
    """
    Given: Valid parameters for the create_site_scan_credential_command function.
    When: Calling the create_site_scan_credential_command function.
    Then: Ensure a valid API call is made and a valid context output is returned.
    """
    site_id = test_input_kwargs.pop("site_id")
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value=api_mock_data)

    assert create_site_scan_credential_command(client=mock_client,
                                               site_id=site_id, **test_input_kwargs).outputs == expected_output_context

    http_request.assert_called_with(
        url_suffix=f"/sites/{site_id}/site_credentials",
        method="POST",
        json_data=expected_post_data,
        resp_type="json"
    )


@pytest.mark.parametrize("test_input_kwargs, api_mock_data, expected_output_context",
                         [
                             ({"vulnerability_id": "7-zip-cve-2008-6536", "scope_type": "Global", "state": "Approved",
                               "reason": "Acceptable-Risk", "comment": "Comment"}, {"id": 1}, {"id": 1}),
                             ({"vulnerability_id": "7-zip-cve-2008-6536", "scope_type": "Site", "state": "Approved",
                               "reason": "Acceptable-Risk", "comment": "Comment"}, None, None)
                         ])
def test_create_vulnerability_exception_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                                api_mock_data: dict | None, expected_output_context: dict | None):
    """
    Given: Valid  or invalid parameters for the create_vulnerability_exception_command function.
    When: Calling the create_vulnerability_exception_command function.
    Then: If valid - ensure a valid context output is returned. If invalid - Ensure an exception is raised.
    """
    mocker.patch.object(Client, "_http_request", return_value=api_mock_data)

    if test_input_kwargs["scope_type"] != "Global" and test_input_kwargs.get("scope_id") is None:
        with pytest.raises(ValueError):
            create_vulnerability_exception_command(client=mock_client, **test_input_kwargs)

    else:
        assert create_vulnerability_exception_command(client=mock_client, **test_input_kwargs).outputs == \
            expected_output_context


@pytest.mark.parametrize("asset_id",
                         [
                             ("1",),
                         ])
def test_delete_asset_command(mocker, mock_client: Client, asset_id: str):
    """
    Given: Valid parameters for the delete_asset_command function.
    When: Calling the delete_asset_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_asset_command(client=mock_client, asset_id=asset_id)

    http_request.assert_called_with(
        url_suffix=f"/assets/{asset_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("site_id, schedule_id",
                         [
                             ("1", "2"),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_delete_scheduled_scan_command(mocker, mock_client: Client, site_id: str, schedule_id: str):
    """
    Given: Valid parameters for the delete_scheduled_scan_command function.
    When: Calling the delete_scheduled_scan_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_scan_schedule_command(client=mock_client, site_id=site_id, schedule_id=schedule_id)

    http_request.assert_called_with(
        url_suffix=f"/sites/{site_id}/scan_schedules/{schedule_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("shared_credential_id",
                         [
                             ("1",),
                         ])
def test_delete_shared_credential_command(mocker, mock_client: Client, shared_credential_id: str):
    """
    Given: Valid parameters for the delete_shared_credential_command function.
    When: Calling the delete_shared_credential_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_shared_credential_command(client=mock_client, shared_credential_id=shared_credential_id)

    http_request.assert_called_with(
        url_suffix=f"/shared_credentials/{shared_credential_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("site_id",
                         [
                             ("1",),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_delete_site_command(mocker, mock_client: Client, site_id: str):
    """
    Given: Valid parameters for the delete_site_command function.
    When: Calling the delete_site_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_site_command(client=mock_client, site_id=site_id)

    http_request.assert_called_with(
        url_suffix=f"/sites/{site_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("site_id, credential_id",
                         [
                             ("1", "2"),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_delete_site_scan_credential_command(mocker, mock_client: Client, site_id: str, credential_id: str):
    """
    Given: Valid parameters for the delete_site_scan_credential_command function.
    When: Calling the delete_site_scan_credential_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_site_scan_credential_command(client=mock_client, site_id=site_id, credential_id=credential_id)

    http_request.assert_called_with(
        url_suffix=f"/sites/{site_id}/site_credentials/{credential_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("vulnerability_exception_id",
                         [
                             ("1",),
                         ])
def test_delete_vulnerability_exception_command(mocker, mock_client: Client, vulnerability_exception_id: str):
    """
    Given: Valid parameters for the delete_vulnerability_exception_command function.
    When: Calling the delete_vulnerability_exception_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = delete_vulnerability_exception_command(client=mock_client,
                                                    vulnerability_exception_id=vulnerability_exception_id)

    http_request.assert_called_with(
        url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}",
        method="DELETE",
        resp_type="json",
    )

    assert result.outputs is None


def test_download_report_command(mocker, mock_client: Client):
    """
    Given: Valid parameters for the download_report_command function.
    When: Calling the download_report_command function.
    Then: Ensure a valid dictionary is returned matching the expected output.
    """
    mocker.patch.object(Client, "download_report", return_value=b"Test")
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("uuid.uuid4", return_value="RandomUUID4")

    result = download_report_command(client=mock_client, report_id="1", instance_id="latest", name="Test")

    assert result == {
        "Contents": "",
        "ContentsFormat": "text",
        "Type": 9,
        "File": "Test.pdf",
        "FileID": "RandomUUID4"
    }


@pytest.mark.parametrize("asset_mock_file, asset_vulnerability_api_mock_file, vulnerability_api_mock_file, "
                         "expected_output_context_file",
                         [
                             ("client_get_asset", "client_get_asset_vulnerabilities",
                              "client_get_vulnerability-certificate-common-name-mismatch", "get_asset_command")
                         ])
def test_get_asset_command(mocker, mock_client: Client, asset_mock_file: str, asset_vulnerability_api_mock_file: str,
                           vulnerability_api_mock_file: str, expected_output_context_file: str):
    """
    Given: Valid parameters for the get_asset_command function.
    When: Calling the get_asset_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_assets_command function.
    When: Calling the get_assets_command function.
    Then: Ensure a valid context output is returned.
    """
    assets_mock_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "get_assets", return_value=assets_mock_data)

    mocker.patch.object(Client, "find_asset_site", return_value=Site(site_id="1", site_name="Test"))

    result = get_assets_command(client=mock_client)
    expected_output_context = load_test_data("expected_context", expected_output_context_file)
    assert [r.outputs for r in result] == expected_output_context


@pytest.mark.parametrize("asset_mock_file, expected_output_context_file",
                         [
                             ("client_get_asset_tags", "get_asset_tags_command")
                         ])
def test_get_asset_tags_command(mocker, mock_client: Client, asset_mock_file: str, expected_output_context_file: str):
    """
    Given: Valid parameters for the get_asset_tags_command function.
    When: Calling the get_asset_tags_command function.
    Then: Ensure a valid context output is returned.
    """
    asset_mock_data = load_test_data("api_mock", asset_mock_file)
    mocker.patch.object(Client, "get_asset_tags", return_value=asset_mock_data)

    result = get_asset_tags_command(client=mock_client, asset_id="1")
    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    if isinstance(result, CommandResults):
        assert result.outputs == expected_output_context

    elif isinstance(result, list):
        assert result[-1].outputs == expected_output_context


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
    """
    Given: Valid parameters for the get_asset_vulnerability_command function.
    When: Calling the get_asset_vulnerability_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_generated_report_status_command function.
    When: Calling the get_generated_report_status_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_report_templates_command function.
    When: Calling the get_report_templates_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_scan_command function.
    When: Calling the get_scan_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_scans_command function.
    When: Calling the get_scans_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the get_sites_command function.
    When: Calling the get_sites_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the list_shared_credential_command function.
    When: Calling the list_shared_credential_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the list_assigned_shared_credential_command function.
    When: Calling the list_assigned_shared_credential_command function.
    Then: Ensure a valid context output is returned.
    """
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_assigned_shared_credential_command(client=mock_client, site_id="1", limit="3")
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_get_vulnerabilities", "list_vulnerability_command")
                         ])
def test_list_vulnerability_command(mocker, mock_client: Client, api_mock_file: str,
                                    expected_output_context_file: str):
    """
    Given: Valid parameters for the list_vulnerability_command function.
    When: Calling the list_vulnerability_command function.
    Then: Ensure a valid context output is returned.
    """
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
    """
    Given: Valid parameters for the list_vulnerability_exceptions_command function.
    When: Calling the list_vulnerability_exceptions_command function.
    Then: Ensure a valid context output is returned.
    """
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data)

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    result = list_vulnerability_exceptions_command(client=mock_client)
    assert result.outputs == expected_output_context


@pytest.mark.parametrize("api_mock_file, expected_output_context_file",
                         [
                             ("client_search_assets", "search_assets_command")
                         ])
def test_search_assets_command(mocker, mock_client: Client, api_mock_file: str, expected_output_context_file: str):
    """
    Given: Valid parameters for the search_assets_command function.
    When: Calling the search_assets_command function.
    Then: Ensure a valid context output is returned.
    """
    api_data = load_test_data("api_mock", api_mock_file)
    mocker.patch.object(Client, "_paged_http_request", return_value=api_data,)
    mocker.patch.object(Client, "find_asset_site", return_value=Site(site_id="1", site_name="Test"))

    expected_output_context = load_test_data("expected_context", expected_output_context_file)

    results = search_assets_command(client=mock_client, risk_score_higher_than="8000")

    assert isinstance(results, list)  # Assure a list of CommandResults has been received instead of a single one.
    # Using `sorted` to not fail test in case the order of CommandResults changes
    assert sorted([result.outputs for result in results], key=lambda d: d["AssetId"]) == \
        sorted(expected_output_context, key=lambda d: d["AssetId"])


@pytest.mark.parametrize("site_id, credential_id, enabled",
                         [
                             ("1", "1", True),
                             ("1", "1", False),
                         ])
def test_set_assigned_shared_credential_status_command(mocker, mock_client: Client, site_id: str, credential_id: str,
                                                       enabled: bool):
    """
    Given: Valid parameters for the set_assigned_shared_credential_status_command function.
    When: Calling the set_assigned_shared_credential_status_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(Client, "_http_request", return_value={})
    result = set_assigned_shared_credential_status_command(client=mock_client, credential_id=credential_id,
                                                           enabled=enabled, site_id=site_id)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"/sites/{site_id}/shared_credentials/{credential_id}/enabled",
        data=json.dumps(enabled),
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("scan_id, scan_status",
                         [
                             ("1", ScanStatus.PAUSE),
                             ("2", ScanStatus.RESUME),
                             ("3", ScanStatus.STOP),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_update_scan_command(mocker, mock_client: Client, scan_id: str, scan_status: ScanStatus):
    """
    Given: Valid parameters for the update_scan_command function.
    When: Calling the update_scan_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(Client, "_http_request", return_value={})
    result = update_scan_command(mock_client, scan_id=scan_id, scan_status=scan_status)

    http_request.assert_called_with(
        method="POST",
        url_suffix=f"/scans/{scan_id}/{scan_status.value}",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("test_input_kwargs, expected_post_data",
                         [
                             ({
                                 "site_id": "1", "schedule_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "week", "interval": "2",
                                 "duration_days": "1", "duration_hours": "1", "duration_minutes": "1",
                                 "scan_name": "Test", "enabled": "true", "included_targets": "192.0.2.0,192.0.2.1",
                                 "included_asset_groups": "1,2", "excluded_targets": "192.0.2.2,192.0.2.3",
                                 "excluded_asset_groups": "3,4",
                             },
                                 {
                                 "assets": {
                                     "excludedAssetGroups": {
                                         "assetGroupIDs": [3, 4]
                                     },
                                     "excludedTargets": {
                                         "addresses": [
                                             "192.0.2.2",
                                             "192.0.2.3"
                                         ]
                                     },
                                     "includedAssetGroups": {
                                         "assetGroupIDs": [1, 2]
                                     },
                                     "includedTargets": {
                                         "addresses": [
                                             "192.0.2.0",
                                             "192.0.2.1"
                                         ]
                                     }
                                 },
                                 "duration": "P1DT1H1M",
                                 "enabled": True,
                                 "onScanRepeat": "restart-scan",
                                 "repeat": {
                                     "every": "week",
                                     "interval": 2
                                 },
                                 "scanName": "Test",
                                 "start": "2050-01-01T10:00:00Z"
                             }),
                             ({
                                 "site_id": "1", "schedule_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z",
                             },
                                 {
                                 "enabled": True,
                                 "onScanRepeat": "restart-scan",
                                 "start": "2050-01-01T10:00:00Z"
                             }),
                             ({
                                 "site_id": "1", "schedule_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "week", "enabled": "true",
                             },
                                 None),
                             ({
                                 "site_id": "1", "schedule_id": "1", "on_scan_repeat": "Restart-Scan",
                                 "start": "2050-01-01T10:00:00Z", "frequency": "Date-of-month", "interval": "2",
                                 "duration_days": "1", "duration_hours": "1", "duration_minutes": "1",
                                 "scan_name": "Test", "enabled": "true", "included_targets": "192.0.2.0,192.0.2.1",
                                 "included_asset_groups": "1,2", "excluded_targets": "192.0.2.2,192.0.2.3",
                                 "excluded_asset_groups": "3,4",
                             },
                                 None),
                         ])
def test_update_scan_schedule_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                      expected_post_data: dict | None):
    """
    Given: Valid or invalid parameters for the update_scan_schedule_command function.
    When: Calling the update_scan_schedule_command function.
    Then: If valid - ensure a valid API call is made and no context output is returned.
        If invalid - ensure an exception is raised.


    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    if test_input_kwargs.get("frequency") is not None and (test_input_kwargs.get("interval") is None
                                                           or (test_input_kwargs["frequency"] == "Date-of-month"
                                                               and test_input_kwargs.get("date_of_month") is None)):
        with pytest.raises(ValueError):
            update_scan_schedule_command(mock_client, **test_input_kwargs)

    else:
        result = update_scan_schedule_command(mock_client, **test_input_kwargs)

        http_request.assert_called_with(
            method="PUT",
            url_suffix=f"/sites/{test_input_kwargs['site_id']}/scan_schedules/{test_input_kwargs['schedule_id']}",
            json_data=expected_post_data,
            resp_type="json",
        )

        assert result.outputs is None


@pytest.mark.parametrize("test_input_kwargs, expected_post_data",
                         [
                             ({"shared_credential_id": "1", "name": "Test", "site_assignment": "Specific-Sites",
                               "host_restriction": "192.0.2.0", "port_restriction": "8080", "service": "FTP",
                               "username": "Test1", "password": "Test2", "sites": "1,2,3",
                               },
                              {
                                  "hostRestriction": "192.0.2.0",
                                  "name": "Test",
                                  "siteAssignment": "specific-sites",
                                  "portRestriction": "8080",
                                  "sites": [1, 2, 3],
                                  "account": {
                                      "service": "ftp",
                                      "username": "Test1",
                                      "password": "Test2"
                                  }
                             }),
                             ({"shared_credential_id": "1", "name": "Test", "site_assignment": "All-Sites",
                               "service": "SNMPv3", "username": "Test1", "password": "Test2",
                               "authentication_type": "SHA", "privacy_type": "AES-256",
                               "privacy_password": "123"},
                              {
                                  "name": "Test",
                                  "siteAssignment": "all-sites",
                                  "account": {
                                      "service": "snmpv3",
                                      "username": "Test1",
                                      "authenticationType": "sha",
                                      "password": "Test2",
                                      "privacyType": "aes-256",
                                      "privacyPassword": "123"
                                  }
                             }),
                             ({"shared_credential_id": "1", "name": "Test", "site_assignment": "All-Sites",
                               "service": "Oracle", "username": "Test1", "password": "Test2",
                               "oracle_enumerate_sids": "false"},
                              {
                                  "name": "Test",
                                  "siteAssignment": "all-sites",
                                  "account": {
                                      "service": "oracle",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "enumerateSids": False,
                                      "oracleListenerPassword": None
                                  }
                             }),
                             ({"shared_credential_id": "1", "name": "Test", "site_assignment": "All-Sites",
                               "service": "SSH", "username": "Test1", "password": "Test2",
                               "ssh_permission_elevation": "None"},
                              {
                                  "name": "Test",
                                  "siteAssignment": "all-sites",
                                  "account": {
                                      "service": "ssh",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "permissionElevation": "none"
                                  }
                             }),
                             ({"shared_credential_id": "1", "name": "Test", "site_assignment": "All-Sites",
                               "service": "MS-SQL", "username": "Test1", "password": "Test2",
                               "use_windows_authentication": "false"},
                              {
                                  "name": "Test",
                                  "siteAssignment": "all-sites",
                                  "account": {
                                      "service": "ms-sql",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "useWindowsAuthentication": False
                                  }
                             }),
                         ])
def test_update_shared_credential_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                          expected_post_data: dict):
    """
    Given: Valid parameters for the update_shared_credential_command function.
    When: Calling the update_shared_credential_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = update_shared_credential_command(client=mock_client, **test_input_kwargs)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"/shared_credentials/{test_input_kwargs['shared_credential_id']}",
        json_data=expected_post_data,
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("test_input_kwargs, expected_post_data",
                         [
                             ({"site_id": "1", "credential_id": "1", "name": "Test", "host_restriction": "192.0.2.0",
                               "port_restriction": "8080", "service": "FTP", "username": "Test1", "password": "Test2"
                               },
                              {
                                  "hostRestriction": "192.0.2.0",
                                  "name": "Test",
                                  "id": "1",
                                  "portRestriction": "8080",
                                  "account": {
                                      "service": "ftp",
                                      "username": "Test1",
                                      "password": "Test2"
                                  }
                             }),
                             ({"site_id": "2", "credential_id": "1", "name": "Test", "service": "SNMPv3",
                               "username": "Test1", "password": "Test2", "authentication_type": "SHA",
                               "privacy_type": "AES-256", "privacy_password": "123"},
                              {
                                  "name": "Test",
                                  "id": "1",
                                  "account": {
                                      "service": "snmpv3",
                                      "username": "Test1",
                                      "authenticationType": "sha",
                                      "password": "Test2",
                                      "privacyType": "aes-256",
                                      "privacyPassword": "123"
                                  }
                             }),
                             ({"site_id": "3", "credential_id": "1", "name": "Test", "service": "Oracle",
                               "username": "Test1", "password": "Test2", "oracle_enumerate_sids": "false"},
                              {
                                  "name": "Test",
                                  "id": "1",
                                  "account": {
                                      "service": "oracle",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "enumerateSids": False,
                                      "oracleListenerPassword": None
                                  }
                             }),
                             ({"site_id": "1", "credential_id": "1", "name": "Test", "service": "SSH",
                               "username": "Test1", "password": "Test2", "ssh_permission_elevation": "None"},
                              {
                                  "name": "Test",
                                  "id": "1",
                                  "account": {
                                      "service": "ssh",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "permissionElevation": "none"
                                  }
                             }),
                             ({"site_id": "2", "credential_id": "1", "name": "Test", "service": "MS-SQL",
                               "username": "Test1", "password": "Test2", "use_windows_authentication": "false"},
                              {
                                  "name": "Test",
                                  "id": "1",
                                  "account": {
                                      "service": "ms-sql",
                                      "username": "Test1",
                                      "password": "Test2",
                                      "useWindowsAuthentication": False
                                  }
                             }),
                         ])
# Note: This command hasn't been tested on an actual Nexpose instance
def test_update_site_scan_credential_command(mocker, mock_client: Client, test_input_kwargs: dict,
                                             expected_post_data: dict):
    """
    Given: Valid parameters for the update_site_scan_credential_command function.
    When: Calling the update_site_scan_credential_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = update_site_scan_credential_command(client=mock_client, **test_input_kwargs)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"/sites/{test_input_kwargs['site_id']}/site_credentials/{test_input_kwargs['credential_id']}",
        json_data=expected_post_data,
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("vulnerability_exception_id, expiration",
                         [
                             ("1", "2050-01-01T10:00:00Z"),
                         ])
def test_update_vulnerability_exception_expiration_command(mocker, mock_client: Client,
                                                           vulnerability_exception_id: str, expiration: str):
    """
    Given: Valid parameters for the update_vulnerability_exception_expiration_command function.
    When: Calling the update_vulnerability_exception_expiration_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = update_vulnerability_exception_expiration_command(client=mock_client,
                                                               vulnerability_exception_id=vulnerability_exception_id,
                                                               expiration=expiration)

    http_request.assert_called_with(
        url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/expires",
        method="PUT",
        data=json.dumps(expiration),
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("vulnerability_exception_id, status",
                         [
                             ("1", "Approve"),
                             ("2", "Reject"),
                         ])
def test_update_vulnerability_exception_status_command(mocker, mock_client: Client,
                                                       vulnerability_exception_id: str, status: str):
    """
    Given: Valid parameters for the update_vulnerability_exception_status_command function.
    When: Calling the update_vulnerability_exception_status_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    result = update_vulnerability_exception_status_command(client=mock_client,
                                                           vulnerability_exception_id=vulnerability_exception_id,
                                                           status=status)

    http_request.assert_called_with(
        url_suffix=f"/vulnerability_exceptions/{vulnerability_exception_id}/{status.lower()}",
        method="POST",
        resp_type="json",
    )

    assert result.outputs is None


@pytest.mark.parametrize("site_id, hosts, expected_post_data",
                         [
                             ("1", None, {"name": "Test Scan"}),
                             ("1", ["192.0.2.0"], {"hosts": ["192.0.2.0"], "name": "Test Scan"})
                         ])
def test_start_site_scan_command(mocker, mock_client: Client, site_id: str, hosts: list[str] | None,
                                 expected_post_data: dict):
    """
    Given: Valid parameters for the start_site_scan_command function.
    When: Calling the start_site_scan_command function.
    Then: Ensure a valid API call is made and no context output is returned.
    """
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    start_site_scan_command(client=mock_client, site_id=site_id, name="Test Scan", hosts=hosts)

    http_request.assert_called_with(
        url_suffix=f"/sites/{site_id}/scans",
        method="POST",
        resp_type="json",
        json_data=expected_post_data,
    )


@pytest.mark.parametrize(
    "name, type, color, ip_address_is, match, expected_post_data",
    [
        ("test", "custom", "red", "3.3.3.3", "Any",
            {
                "name": "test",
                "type": "custom",
                "color": "red",
                "searchCriteria": {
                    "filters": [
                        {"field": "ip-address", "operator": "is", "value": "3.3.3.3"}
                    ],
                    "match": "Any",
                },
            },
         )
    ],
)
def test_create_tag_command(
    mocker, mock_client, name, type, color, ip_address_is, match, expected_post_data
):
    http_request = mocker.patch.object(
        BaseClient, "_http_request", return_value={"id": 1}
    )
    result = create_tag_command(
        client=mock_client,
        name=name,
        type=type,
        color=color,
        ip_address_is=ip_address_is,
        match=match,
    )

    http_request.assert_called_with(
        url_suffix="/tags",
        method="POST",
        resp_type="json",
        json_data=expected_post_data,
    )
    assert result.outputs == {"id": 1}


@pytest.mark.parametrize("tag_id", [(1)])
def test_delete_tag_command(mocker, mock_client, tag_id):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    delete_tag_command(client=mock_client, id=tag_id)

    http_request.assert_called_with(
        url_suffix=f"/tags/{tag_id}",
        method="DELETE",
        resp_type="json",
    )


@pytest.mark.parametrize("name, type, tag_id, page_size, api_mock_file", [
    ("test", "owner", None, "2", "client_get_list_tag"),
    (None, None, "1", None, "client_get_list_tag")
])
def test_get_list_tag_command(mocker, mock_client, name, type, tag_id, page_size, api_mock_file):
    api_data = load_test_data("api_mock", api_mock_file)
    paged_http_request = mocker.patch.object(Client, "_paged_http_request", return_value=api_data)
    http_request = mocker.patch.object(Client, "_http_request", return_value=api_data["resources"][0])
    get_list_tag_command(client=mock_client, name=name, type=type, id=tag_id, page_size=page_size)

    if tag_id is None:
        paged_http_request.assert_called_with(
            url_suffix="/tags",
            method="GET",
            resp_type="json",
            params={"name": "test", "type": "owner"},
            page_size=2,
            page=None,
            limit=None
        )
    else:
        http_request.assert_called_with(
            url_suffix=f"/tags/{tag_id}",
            method="GET",
            resp_type="json"
        )


@pytest.mark.parametrize("tag_id, risk_score_higher_than, match, overwrite", [("1", "8000", "all", "no")])
def test_update_tag_search_criteria(mocker, mock_client, tag_id, risk_score_higher_than, match, overwrite):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    update_tag_search_criteria_command(client=mock_client, overwrite=overwrite,
                                       tag_id=tag_id, risk_score_higher_than=risk_score_higher_than, match=match)

    expected_calls = [
        mocker.call(
            method="GET",
            url_suffix=f"/tags/{tag_id}",
            resp_type="json"
        ),
        mocker.call(
            method="PUT",
            url_suffix=f"/tags/{tag_id}/search_criteria",
            json_data={"filters": [{"field": "risk-score", "operator": "is-greater-than", "value": 8000.0}], "match": "all"},
            resp_type="json"
        )
    ]

    http_request.assert_has_calls(expected_calls)


@pytest.mark.parametrize("tag_id", [(1)])
def test_get_list_tag_asset_group_command(mocker, mock_client, tag_id):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={"resources": [1, 2, 5]})
    get_list_tag_asset_group_command(client=mock_client, tag_id=tag_id)

    http_request.assert_called_with(
        method="GET",
        url_suffix=f"/tags/{tag_id}/asset_groups",
        resp_type="json"
    )


@pytest.mark.parametrize("tag_id, asset_group_ids", [("1", "2,3,4"),])
def test_add_tag_asset_group_command(mocker, mock_client, tag_id, asset_group_ids):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={"resources": [1, 2, 3]})

    add_tag_asset_group_command(client=mock_client, tag_id=tag_id, asset_group_ids=asset_group_ids)

    expected_calls = [
        mocker.call(
            method="GET",
            url_suffix=f"/tags/{tag_id}/asset_groups",
            resp_type="json"
        ),
        mocker.call(
            method="PUT",
            url_suffix=f"/tags/{tag_id}/asset_groups",
            json_data=[1, 2, 3, 4],
            resp_type="json"
        )
    ]
    http_request.assert_has_calls(expected_calls)


@pytest.mark.parametrize("tag_id, asset_group_id", [("1", "5")])
def test_remove_tag_asset_group_command(mocker, mock_client, tag_id, asset_group_id,):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    remove_tag_asset_group_command(client=mock_client, tag_id=tag_id, asset_group_id=asset_group_id)

    http_request.assert_called_with(
        method="DELETE",
        url_suffix=f"/tags/{tag_id}/asset_groups/{asset_group_id}",
        resp_type="json"
    )


@pytest.mark.parametrize("tag_id, expected_output", [("1", {"resources": [{"id": 12, "sources": ["asset-group"]}]})])
def test_get_list_tag_asset_command(mocker, mock_client, tag_id, expected_output):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value=expected_output)

    result = get_list_tag_asset_command(client=mock_client, tag_id=tag_id)

    http_request.assert_called_with(
        method="GET",
        url_suffix=f"/tags/{tag_id}/assets",
        resp_type="json"
    )

    assert result.outputs == expected_output.get("resources")


@pytest.mark.parametrize("tag_id, asset_id", [("1", "123")])
def test_add_tag_asset_command(mocker, mock_client, tag_id, asset_id):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    add_tag_asset_command(client=mock_client, tag_id=tag_id, asset_id=asset_id)

    http_request.assert_called_with(
        method="PUT",
        url_suffix=f"/tags/{tag_id}/assets/{asset_id}",
        resp_type="json"
    )


@pytest.mark.parametrize("tag_id, asset_id", [("1", "123")])
def test_remove_tag_asset_command(mocker, mock_client, tag_id, asset_id):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    remove_tag_asset_command(client=mock_client, tag_id=tag_id, asset_id=asset_id)

    http_request.assert_called_with(
        method="DELETE",
        url_suffix=f"/tags/{tag_id}/assets/{asset_id}",
        resp_type="json"
    )


@pytest.mark.parametrize("target_type, site_id, assets, asset_group_ids", [
    ("included", "1", "8.8.8.8,www", None),  # test add included asset
    ("included", "2", None, "789,612"),  # test add included asset group
    ("excluded", "1", "8.8.8.8,www", None),  # test add excluded asset
    ("excluded", "2", None, "789,612")  # test add excluded asset group
])
def test_add_site_asset_command(mocker, mock_client, site_id, target_type, assets, asset_group_ids):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    add_site_asset_command(client=mock_client, target_type=target_type, site_id=site_id,
                           assets=assets, asset_group_ids=asset_group_ids)

    if assets is not None:
        http_request.assert_called_with(
            method="POST",
            url_suffix=f"/sites/{site_id}/{target_type}_targets",
            json_data=["8.8.8.8", "www"],
            resp_type='json'
        )
    else:
        http_request.assert_called_with(
            method="PUT",
            url_suffix=f"/sites/{site_id}/{target_type}_asset_groups",
            json_data=[789, 612],
            resp_type='json',
        )


@pytest.mark.parametrize("target_type, site_id, assets, asset_group_ids", [
    ("included", "1", "8.8.8.8,www", None),  # test remove included asset
    ("included", "2", None, "789,612"),  # test remove included asset group
    ("excluded", "1", "8.8.8.8,www", None),  # test remove excluded asset
    ("excluded", "2", None, "789,612")  # test remove excluded asset group
])
def test_remove_site_asset_command(mocker, mock_client, target_type, site_id, assets, asset_group_ids):
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})

    remove_site_asset_command(client=mock_client, target_type=target_type, site_id=site_id,
                              assets=assets, asset_group_ids=asset_group_ids)

    if assets:
        http_request.assert_called_with(
            method="DELETE",
            url_suffix=f"/sites/{site_id}/{target_type}_targets",
            json_data=["8.8.8.8", "www"],
            resp_type='json'
        )
    else:
        http_request.assert_called_with(
            method="DELETE",
            url_suffix=f"/sites/{site_id}/{target_type}_asset_groups",
            json_data=[789, 612],
            resp_type='json'
        )


@pytest.mark.parametrize("site_id, asset_type, target_type, expected_url_suffix", [
    ("1", "assets", "included", "/sites/1/included_targets"),
    ("1", "asset_groups", "included", "/sites/1/included_asset_groups"),
    ("1", "assets", "excluded", "/sites/1/excluded_targets"),
    ("1", "asset_groups", "excluded", "/sites/1/excluded_asset_groups")
])
def test_list_site_assets_command(mocker, mock_client, site_id, asset_type, target_type, expected_url_suffix):
    response_data = (
        {"addresses": ["1.1.1.1", "www"]}
        if asset_type == "assets"
        else {"resources": [{
            "assets": 768,
            "description": "Assets with unacceptable high risk required immediate remediation.",
            "id": 61,
            "links": [],
            "name": "High Risk Assets",
            "riskScore": 4457823.78,
            "searchCriteria": {},
            "type": "dynamic",
            "vulnerabilities": {},
        }]}
    )
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value=response_data)

    list_site_assets_command(client=mock_client, site_id=site_id, asset_type=asset_type, target_type=target_type)

    http_request.assert_called_with(
        method="GET",
        url_suffix=expected_url_suffix,
        resp_type="json"
    )


@pytest.mark.parametrize("kwargs, expected_output", [
    ({
        "ip_address_is": "192.168.1.1",
        "host_name_is": "hostname1",
        "risk_score_higher_than": "70",
        "vulnerability_title_contains": "vuln-title",
        "query": "ip-address in-range 192.0.2.0,192.0.2.1;host-name is myhost",
        "site_id_in": "1,2",
        "site_name_in": "site1"
    }, [
        "ip-address is 192.168.1.1",
        "host-name is hostname1",
        "risk-score is-greater-than 70",
        "vulnerability-title contains vuln-title",
        "ip-address in-range 192.0.2.0,192.0.2.1",
        "host-name is myhost",
        "site-id in 1,2,site1_Id"
    ])])
def test_parse_filters(mocker, mock_client, kwargs, expected_output):
    mocker.patch.object(BaseClient, "_http_request", return_value={"resources": [{"name": "site1", "id": "site1_Id"}]})

    result = parse_asset_filters(client=mock_client, **kwargs)

    assert result == expected_output


@pytest.mark.parametrize(
    "name, type, description, ip_address_is, match, expected_post_data",
    [
        ("test", "dynamic", "description test", "1.1.1.1", "Any",
            {
                "name": "test",
                "type": "dynamic",
                "description": "description test",
                "searchCriteria": {
                    "filters": [
                        {"field": "ip-address", "operator": "is", "value": "1.1.1.1"}
                    ],
                    "match": "Any",
                },
            },
         )
    ],
)
def test_create_asset_group_command(mocker, mock_client, name, type, description, ip_address_is, match, expected_post_data):
    http_request = mocker.patch.object(
        BaseClient, "_http_request", return_value={"id": 1}
    )
    result = create_asset_group_command(
        client=mock_client,
        name=name,
        type=type,
        description=description,
        ip_address_is=ip_address_is,
        match=match,
    )
    http_request.assert_called_with(
        url_suffix="/asset_groups",
        method="POST",
        resp_type="json",
        json_data=expected_post_data,
    )
    assert result.outputs == {"id": 1}


@pytest.mark.parametrize("name, type, group_id, limit, api_mock_file", [
    ("test", "dynamic", None, "2", "client_get_asset_groups"),
    (None, None, "1", None, "client_get_asset_groups")
])
def test_get_asset_group_command(mocker, mock_client, name, type, group_id, limit, api_mock_file):
    api_data = load_test_data("api_mock", api_mock_file)
    paged_http_request = mocker.patch.object(Client, "_paged_http_request", return_value=api_data)
    http_request = mocker.patch.object(Client, "_http_request", return_value=api_data[0])
    get_list_asset_group_command(client=mock_client, group_name=name, type=type, group_id=group_id, limit=limit)

    if group_id is None:
        paged_http_request.assert_called_with(
            url_suffix="/asset_groups",
            method="GET",
            resp_type="json",
            params={"name": "test", "type": "dynamic"},
            page_size=None,
            page=None,
            limit=2,
            sort=None
        )
    else:
        http_request.assert_called_with(
            url_suffix=f"/asset_groups/{group_id}",
            method="GET",
            resp_type="json"
        )
