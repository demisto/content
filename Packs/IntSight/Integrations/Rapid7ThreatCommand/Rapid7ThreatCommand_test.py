import json
import os
from http import HTTPStatus
from collections.abc import Callable
from urllib.parse import urljoin

import pytest
from CommonServerPython import *
from Rapid7ThreatCommand import (
    Client,
    ReadableOutputs,
    ReadableErrors,
    ArgumentValues,
    file_reputation_handler,
    domain_reputation_handler,
    ip_reputation_handler,
    url_reputation_handler,
)
from requests.models import PreparedRequest


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """Create a test client for Threat Command.

    Returns:
        Client: Threat Command Client.
    """
    return Client(
        base_url="http://1.1.1.1/",
        account_id="usn",
        api_key="pwd",
        reliability="A - Completely reliable",
        proxy=True,
        verify=False,
        mssp_sub_account=None,
    )


@pytest.mark.parametrize(
    ("args", "jsonpath"),
    (
        (
            {"cyber_term_id": "617e67d488191a0007954c4d"},
            "cyber_term/cyber_term_cve.json",
        ),
        (
            {"cyber_term_id": "617e67d488191a0007954c4d"},
            "cyber_term/cyber_term_cve_empty.json",
        ),
    ),
)
def test_list_cyber_term_cve_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: List cyber term CVE.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cyber-term-cve-list called.
    Then:
     - Ensure that cyber term CVE listed.
    """
    from Rapid7ThreatCommand import list_cyber_term_cve_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(
        mock_client._base_url,
        "/v1/threat-library/cyber-terms/617e67d488191a0007954c4d/cves",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_cyber_term_cve_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.CVE"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) <= 50 if result.outputs else True


@pytest.mark.parametrize(
    ("args"),
    (
        {"cyber_term_id": "617e67d488191a0007954c4d"},
        {"cyber_term_id": "617e67d488191a0007954c4d", "ioc_type": "Ip Adressses"},
    ),
)
def test_list_cyber_term_ioc_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List cyber term IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cyber-term-ioc-list called.
    Then:
     - Ensure that cyber term IOC listed.
    """
    from Rapid7ThreatCommand import list_cyber_term_ioc_command

    json_response = load_mock_response("cyber_term/cyber_term_ioc.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/threat-library/cyber-terms/617e67d488191a0007954c4d/iocs",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_cyber_term_ioc_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.IOC"
    assert result.outputs_key_field == "id"


@pytest.mark.parametrize(
    ("status_code", "content", "error"),
    (
        (
            HTTPStatus.INTERNAL_SERVER_ERROR,
            b"GeneralError",
            f"Status Code: {HTTPStatus.INTERNAL_SERVER_ERROR}, {ReadableErrors.GENERAL.value}",
        ),
        (
            HTTPStatus.NOT_FOUND,
            None,
            f"Status Code: {HTTPStatus.NOT_FOUND}, {ReadableErrors.NOT_FOUND.value}"
        ),
    ),
)
def test_fail_list_cyber_term_ioc_command(
    requests_mock,
    mock_client: Client,
    status_code: str,
    content: str,
    error: str,
):
    """
    Scenario: List cyber term IOC.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-cyber-term-ioc-list called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import list_cyber_term_ioc_command

    url = urljoin(
        mock_client._base_url,
        "/v1/threat-library/cyber-terms/617e67d488191a0007954c4d/iocs",
    )
    requests_mock.get(url=url, content=content, status_code=status_code)
    args = {"cyber_term_id": "617e67d488191a0007954c4d"}
    with pytest.raises(DemistoException) as error_info:
        list_cyber_term_ioc_command(mock_client, args)
    assert error == str(error_info.value)


@pytest.mark.parametrize(
    ("args", "params"),
    (
        (
            {},
            [
                ({"limit": 50}, "cyber_term/cyber_term.json"),
            ],
        ),
        (
            {"page": 1, "page_size": 50},
            [
                ({"limit": 50}, "cyber_term/cyber_term.json"),
            ],
        ),
        (
            {"page": 2, "page_size": 2},
            [
                ({"limit": 2}, "cyber_term/cyber_term_ioc_limit2.json"),
                (
                    {
                        "limit": 2,
                        "offset": "2022-03-13T13:48:12.159Z::6220ea495c879c2c4d36c124",
                    },
                    "cyber_term/cyber_term_ioc_limit_offset.json",
                ),
            ],
        ),
    ),
)
def test_list_cyber_term_command(
    requests_mock, mock_client: Client, args: dict[str, Any], params: List[tuple]
):
    """
    Scenario: List cyber terms.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cyber-term called.
    Then:
     - Ensure that cyber terms listed.
    """
    from Rapid7ThreatCommand import list_cyber_term_command

    url = urljoin(mock_client._base_url, "/v1/threat-library/cyber-terms")
    for param, json_path in params:
        req = PreparedRequest()
        req.prepare_url(url, param)
        json_response = load_mock_response(json_path)
        requests_mock.get(url=req.url, json=json_response, status_code=HTTPStatus.OK)
    result = list_cyber_term_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.CyberTerm"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)
    assert {"type", "id"}.issubset(list(result.outputs[0].keys()))


@pytest.mark.parametrize(
    ("args"),
    (
        {},
        {"limit": 2},
        {"all_results": True},
    ),
)
def test_list_source_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List sources.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-source-list called.
    Then:
     - Ensure that sources listed.
    """
    from Rapid7ThreatCommand import list_source_command

    json_response = load_mock_response("source/source_list.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/sources")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_source_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Source"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) <= args.get("limit", 50)


@pytest.mark.parametrize(
    ("args"),
    (
        {
            "name": "test",
            "confidence_level": 1,
            "description": "test",
            "domains": "test.com",
        },
        {
            "name": "test",
            "confidence_level": 1,
            "description": "test",
            "domains": ["test.com", "test1"],
        },
        {
            "name": "test",
            "confidence_level": 1,
            "description": "test",
            "domains": ["test.com", "test1"],
            "emails": ["test@test.com"],
        },
    ),
)
def test_create_source_document_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: Create source document.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-source-document-create called.
    Then:
     - Ensure that source document was created.
    """
    from Rapid7ThreatCommand import create_source_document_command

    json_response = load_mock_response("source/create_document.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/add-source")
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = create_source_document_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Source"
    assert result.outputs_key_field == "id"


@pytest.mark.parametrize(
    ("args", "error"),
    (
        (
            {"name": "test", "confidence_level": 1, "description": "test"},
            ReadableErrors.NO_IOCS.value,
        ),
        (
            {
                "name": "test",
                "confidence_level": 1,
                "description": "test",
                "hashes": "test",
            },
            ReadableErrors.HASH.value.format("test"),
        ),
        (
            {
                "name": "test",
                "confidence_level": 1,
                "description": "test",
                "ips": ["test"],
            },
            ReadableErrors.IP.value.format("test"),
        ),
        (
            {
                "name": "test",
                "confidence_level": 1,
                "description": "test",
                "emails": ["test"],
            },
            ReadableErrors.EMAIL.value.format("test"),
        ),
        (
            {
                "name": "test",
                "confidence_level": 1,
                "description": "test",
                "urls": ["test"],
            },
            ReadableErrors.URL.value.format("test"),
        ),
        (
            {
                "name": "test",
                "confidence_level": -1,
                "description": "test",
                "emails": ["test@test.com"],
            },
            ReadableErrors.CONFIDENCE_LEVEL.value,
        ),
        (
            {
                "name": "test",
                "confidence_level": -1,
                "description": "test",
                "emails": ["test@test.com"],
                "share": "test",
            },
            ReadableErrors.ARGUMENT.value.format("share", ArgumentValues.BOOLEAN.value),
        ),
    ),
)
def test_fail_create_source_document_command(
    requests_mock, mock_client: Client, args: dict[str, Any], error: str
):
    """
    Scenario: Create source document.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-source-document-create called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import create_source_document_command

    json_response = load_mock_response("source/create_document.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/add-source")
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    with pytest.raises(ValueError) as error_info:
        create_source_document_command(mock_client, args)
    assert error == str(error_info.value)


def test_fail_api_create_source_document_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Create source document.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-source-document-create called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import create_source_document_command

    json_response = load_mock_response("source/create_document_exist.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/add-source")
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    with pytest.raises(DemistoException) as error_info:
        create_source_document_command(
            mock_client,
            {
                "name": "test",
                "confidence_level": 1,
                "description": "test",
                "domains": "test.com",
            },
        )
    assert ReadableErrors.SOURCE_ALREADY_EXIST.value == str(error_info.value)


def test_delete_source_document_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Delete source document.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-source-document-delete called.
    Then:
     - Ensure that the source document was deleted.
    """
    from Rapid7ThreatCommand import delete_source_document_command

    url = urljoin(mock_client._base_url, "/v1/iocs/delete-source/test")
    requests_mock.delete(url=url, status_code=HTTPStatus.OK)
    result = delete_source_document_command(mock_client, {"source_id": "test"})
    assert result.readable_output == ReadableOutputs.DOCUMENT_DELETE.value.format(
        "test"
    )


def test_fail_delete_source_document_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Delete source document.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-source-document-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import delete_source_document_command

    url = urljoin(mock_client._base_url, "/v1/iocs/delete-source/test")
    requests_mock.delete(
        url=url, content=b"SourceDoesNotExist", status_code=HTTPStatus.NOT_FOUND
    )
    with pytest.raises(DemistoException) as error_info:
        delete_source_document_command(mock_client, {"source_id": "test"})
    assert ReadableErrors.SOURCE_NOT_EXIST.value == str(error_info.value)


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"source_id": "test", "domains": "test.com"},
            ReadableOutputs.CREATE_IOC.value.format(["test.com"], "test"),
        ),
        (
            {"source_id": "test", "domains": ["test.com"], "emails": ["test@test.com"]},
            ReadableOutputs.CREATE_IOC.value.format(
                ["test.com", "test@test.com"], "test"
            ),
        ),
    ),
)
def test_create_source_document_ioc_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: Create IOCs to source document.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-source-document-ioc-create called.
    Then:
     - Ensure that the IOCs was created.
    """
    from Rapid7ThreatCommand import create_source_document_ioc_command

    url = urljoin(mock_client._base_url, "/v1/iocs/add-iocs-to-source/test")
    requests_mock.post(url=url, status_code=HTTPStatus.OK)
    result = create_source_document_ioc_command(mock_client, args)
    assert result.readable_output == message


def test_list_system_modules_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List system modules.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-account-system-modules-list called.
    Then:
     - Ensure that system modules listed.
    """
    from Rapid7ThreatCommand import list_system_modules_command

    json_response = load_mock_response("system_modules.json")
    url = urljoin(mock_client._base_url, "/v1/account/system-modules")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_system_modules_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.SystemModule"
    assert result.outputs_key_field == "module_name"


def test_add_asset_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add asset.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-asset-add called.
    Then:
     - Ensure that asset added.
    """
    from Rapid7ThreatCommand import add_asset_command

    url = urljoin(mock_client._base_url, "/v1/data/assets/add-asset")
    requests_mock.put(url=url, status_code=HTTPStatus.OK)
    result = add_asset_command(
        mock_client, {"asset_type": "test", "asset_value": "test"}
    )
    assert result.outputs_prefix == "ThreatCommand.Asset"


@pytest.mark.parametrize(
    ("args", "message", "content", "status_code"),
    (
        (
            {"asset_value": "test", "asset_type": "test"},
            ReadableErrors.ASSET_TYPE.value,
            b"InvalidAssetType",
            HTTPStatus.BAD_REQUEST,
        ),
        (
            {"asset_value": "test", "asset_type": "test"},
            ReadableErrors.ASSET_COUNTRY.value,
            b"InvalidCountryOfActivityAsset",
            HTTPStatus.FORBIDDEN,
        ),
        (
            {"asset_value": "test", "asset_type": "test"},
            ReadableErrors.ASSET_SECTOR.value,
            b"InvalidSectorAsset",
            HTTPStatus.FORBIDDEN,
        ),
        (
            {"asset_value": "test", "asset_type": "test"},
            ReadableErrors.ASSET_DOMAIN.value,
            b"InvalidDomainAsset",
            HTTPStatus.FORBIDDEN,
        ),
    ),
)
def test_fail_add_asset_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
    content: str,
    status_code: int,
):
    """
    Scenario: Add asset.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-asset-add called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import add_asset_command

    url = urljoin(mock_client._base_url, "/v1/data/assets/add-asset")
    requests_mock.put(url=url, content=content, status_code=status_code)
    with pytest.raises(DemistoException) as error_info:
        add_asset_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_delete_asset_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Delete asset.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-asset-delete called.
    Then:
     - Ensure that asset deleted.
    """
    from Rapid7ThreatCommand import delete_asset_command

    url = urljoin(mock_client._base_url, "/v1/data/assets/delete-asset")
    requests_mock.delete(url=url, status_code=HTTPStatus.OK)
    result = delete_asset_command(
        mock_client, {"asset_type": "test", "asset_value": "test"}
    )
    assert result.readable_output == ReadableOutputs.DELETE_ASSET.value.format(
        "test", "test"
    )


@pytest.mark.parametrize(
    ("args", "message", "content", "status_code"),
    (
        (
            {"asset_value": "test", "asset_type": "test"},
            ReadableErrors.ASSET_TYPE.value,
            b"InvalidAssetType",
            HTTPStatus.BAD_REQUEST,
        ),
    ),
)
def test_fail_delete_asset_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
    content: str,
    status_code: int,
):
    """
    Scenario: Delete asset.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-asset-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import delete_asset_command

    url = urljoin(mock_client._base_url, "/v1/data/assets/delete-asset")
    requests_mock.delete(url=url, content=content, status_code=status_code)
    with pytest.raises(DemistoException) as error_info:
        delete_asset_command(mock_client, args)
    assert str(message) == str(error_info.value)


@pytest.mark.parametrize(
    ("args"),
    (
        {},
        {"limit": 2},
        {"all_results": True},
    ),
)
def test_list_assets_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List assets.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-asset-list called.
    Then:
     - Ensure that assets listed.
    """
    from Rapid7ThreatCommand import list_assets_command

    json_response = load_mock_response("asset/list_assets.json")
    url = urljoin(mock_client._base_url, "/v1/data/assets/account-assets")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_assets_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Asset"
    assert result.outputs_key_field == "value"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) <= args.get("limit", 50)


@pytest.mark.parametrize(
    ("args"),
    (
        {},
        {"limit": 2},
        {"all_results": True},
    ),
)
def test_list_asset_types_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List asset types.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-asset-types-list called.
    Then:
     - Ensure that assset types listed.
    """
    from Rapid7ThreatCommand import list_asset_types_command

    json_response = load_mock_response("asset/list_types.json")
    url = urljoin(mock_client._base_url, "/v1/data/assets/assets-types")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_asset_types_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.AssetType"
    assert result.outputs_key_field == "value"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) <= args.get("limit", 50)


@pytest.mark.parametrize(
    ("args"),
    (
        {},
        {"limit": 2},
        {"all_results": True},
    ),
)
def test_list_cve_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List account CVEs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cve-list called.
    Then:
     - Ensure that CVEs listed.
    """
    from Rapid7ThreatCommand import list_cve_command

    json_response = load_mock_response("cve/cve_list.json")
    url = urljoin(mock_client._base_url, "/v1/cves/get-cves-list")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = list_cve_command(mock_client, args)
    assert result[0].outputs_prefix == "ThreatCommand.CVE"
    assert result[0].outputs_key_field == "id"
    assert isinstance(result[0].outputs, list)
    assert len(result[0].outputs) <= args.get("limit", 50)


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"severity_list": "test"},
            ReadableErrors.ARGUMENT.value.format(
                "severity_list", ArgumentValues.CVE_SEVERITY.value
            ),
        ),
        (
            {"severity_list": "High,test"},
            ReadableErrors.ARGUMENT.value.format(
                "severity_list", ArgumentValues.CVE_SEVERITY.value
            ),
        ),
    ),
)
def test_fail_list_cve_command(
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: List account CVEs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cve-list called.
    Then:
     - Ensure that CVEs listed.
    """
    from Rapid7ThreatCommand import list_cve_command

    with pytest.raises(ValueError) as error_info:
        list_cve_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_add_cve_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add CVEs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cve-add called.
    Then:
     - Ensure that CVEs added.
    """
    from Rapid7ThreatCommand import add_cve_command

    json_response = load_mock_response("cve/add_cve.json")
    url = urljoin(mock_client._base_url, "/v1/cves/add-cves")
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = add_cve_command(mock_client, {"cve_ids": "CVE-5555-0001,CVE-5555-0003"})
    assert result[0].readable_output == ReadableOutputs.ADD_CVE_SUCCESS.value.format(
        "CVE-5555-0001"
    )
    assert result[1].readable_output == ReadableOutputs.ADD_CVE_FAIL.value.format(
        "CVE-5555-0003 (Unsupported CVE by Intsights)"
    )


def test_delete_cve_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Delete CVEs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-cve-delete called.
    Then:
     - Ensure that the CVEs deleted.
    """
    from Rapid7ThreatCommand import delete_cve_command

    json_response = load_mock_response("cve/delete_cve.json")
    url = urljoin(mock_client._base_url, "/v1/cves/delete-cves")
    requests_mock.delete(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = delete_cve_command(mock_client, {"cve_ids": "CVE-1999-0003,CVE-5555-0003"})
    assert result[0].readable_output == ReadableOutputs.DELETE_CVE_SUCCESS.value.format(
        "CVE-5555-0003"
    )
    assert result[1].readable_output == ReadableOutputs.DELETE_CVE_FAIL.value.format(
        "CVE-1999-0003 (CVEs are not associated to account)"
    )


@pytest.mark.parametrize(
    ("args"),
    (
        {"retrieve_ids_only": "true"},
        {"retrieve_ids_only": "false", "limit": 3},
        {"retrieve_ids_only": "false", "alert_id": "59490dabe57c281391e11ceb"},
    ),
)
def test_list_alert_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: List alerts.
    Given:
     - User has provided correct parameters.
     - User provided single alert_id.
     - User has provided filters.
    When:
     - threat-command-alert-list called.
    Then:
     - Ensure that alert listed.
    """
    from Rapid7ThreatCommand import list_alert_handler_command

    json_response = load_mock_response("alert/list50.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/update-alerts?limit=50")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response("alert/list3.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/update-alerts?limit=3")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response("alert/complete1.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/59490dabe57c281391e11ceb",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response("alert/complete2.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/59490d7ae57c281391e11cba",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response("alert/complete3.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/59490d9be57c281391e11cdb",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_handler_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"
    if not args.get("alert_id"):
        assert isinstance(result.outputs, list)
        assert len(result.outputs) == args.get("limit", 50)
    if not args.get("retrieve_ids_only") or args.get("retrieve_ids_only") is False:
        assert isinstance(result.outputs, list)
        assert result.outputs[0].get("id")
        assert result.outputs[0].get("type")
        assert result.outputs[0].get("found_date")


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"retrieve_ids_only": True, "alert_id": "test"},
            ReadableErrors.ALERT_LIST.value,
        ),
    ),
)
def test_fail_list_alert_command(
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: List alerts.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-list called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import list_alert_handler_command

    with pytest.raises(ValueError) as error_info:
        list_alert_handler_command(mock_client, args)
    assert str(message) == str(error_info.value)


@pytest.mark.parametrize(
    ("args"),
    (
        {
            "description": "test",
            "severity": "High",
            "source_network_type": "Clear Web",
            "source_type": "Application Store",
            "title": "test",
            "scenario": "test",
        },
        {
            "description": "test",
            "severity": "High",
            "source_network_type": "Clear Web",
            "source_type": "Application Store",
            "title": "test",
            "type": "Attack Indication",
            "sub_type": "test",
        },
        # {"all_results": True},
    ),
)
def test_create_alert_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: Create alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-create called.
    Then:
     - Ensure that alert created.
    """
    from Rapid7ThreatCommand import create_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/add-alert")
    requests_mock.put(
        url=url, content=b"59490dabe57c281391e11ceb", status_code=HTTPStatus.OK
    )

    result = create_alert_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"


@pytest.mark.parametrize(
    ("args", "error"),
    (
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
            },
            ReadableErrors.SCENARIO_TYPES.value,
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "type": "test",
            },
            ReadableErrors.ALERT_SUB_TYPE.value,
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "sub_type": "test",
                "scenario": "test",
            },
            ReadableErrors.SCENARIO_TYPES.value,
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "sub_type": "test",
            },
            ReadableErrors.ALERT_TYPE.value,
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "type": "test",
                "sub_type": "test",
            },
            ReadableErrors.ARGUMENT.value.format(
                "type", ArgumentValues.ALERT_TYPE.value
            ),
        ),
        (
            {
                "description": "test",
                "severity": "test",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "type": "Phishing",
                "sub_type": "test",
            },
            ReadableErrors.ARGUMENT.value.format(
                "severity", ArgumentValues.ALERT_IOC_AND_DOCUMENT_SEVERITY.value
            ),
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "test",
                "source_type": "Application Store",
                "title": "test",
                "type": "Phishing",
                "sub_type": "test",
            },
            ReadableErrors.ARGUMENT.value.format(
                "source_network_type", ArgumentValues.ALERT_SOURCE_NETWORK.value
            ),
        ),
        (
            {
                "description": "test",
                "severity": "High",
                "source_network_type": "Clear Web",
                "source_type": "Application Store",
                "title": "test",
                "type": "test",
                "sub_type": "test",
                "scenario": "test",
            },
            ReadableErrors.SCENARIO_TYPES.value,
        ),
        # {"all_results": True},
    ),
)
def test_fail_create_alert_command(
    requests_mock, mock_client: Client, args: dict[str, Any], error: str
):
    """
    Scenario: Create alert.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-create called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import create_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/add-alert")
    requests_mock.put(
        url=url, content=b"59490dabe57c281391e11ceb", status_code=HTTPStatus.OK
    )

    with pytest.raises(ValueError) as error_info:
        create_alert_command(mock_client, args)

    assert str(error) == str(error_info.value)


def test_close_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Close alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-close called.
    Then:
     - Ensure that alert closed.
    """
    from Rapid7ThreatCommand import close_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/close-alert/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = close_alert_command(
        mock_client,
        {"alert_id": "123", "reason": "Problem Solved", "is_hidden": "false"},
    )
    assert result.outputs_prefix == "ThreatCommand.Alert"


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {
                "alert_id": "test",
                "rate": 6,
                "reason": "Problem Solved",
                "is_hidden": "true",
            },
            ReadableErrors.IS_HIDDEN.value,
        ),
        (
            {
                "alert_id": "test",
                "rate": 6,
                "reason": "Problem Solved",
                "is_hidden": "false",
            },
            ReadableErrors.RATE.value,
        ),
        (
            {
                "alert_id": "test",
                "rate": -1,
                "reason": "Problem Solved",
                "is_hidden": "false",
            },
            ReadableErrors.RATE.value,
        ),
        (
            {"alert_id": "test", "rate": 3, "reason": "test", "is_hidden": "false"},
            ReadableErrors.ARGUMENT.value.format(
                "reason", ArgumentValues.ALERT_CLOSE_REASON.value
            ),
        ),
        (
            {
                "alert_id": "test",
                "rate": 3,
                "reason": "Problem Solved",
                "is_hidden": "test",
            },
            ReadableErrors.ARGUMENT.value.format(
                "is_hidden", ArgumentValues.BOOLEAN.value
            ),
        ),
    ),
)
def test_fail_close_alert_command(
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: Close alert.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-close called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import close_alert_command

    with pytest.raises(ValueError) as error_info:
        close_alert_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_update_alert_severity_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Update alert severity.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-severity-update called.
    Then:
     - Ensure that severity updated.
    """
    from Rapid7ThreatCommand import update_alert_severity_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/change-severity/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = update_alert_severity_command(
        mock_client, {"alert_id": "123", "severity": "High"}
    )
    assert result.outputs_prefix == "ThreatCommand.Alert"


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"alert_id": "test", "severity": "test"},
            ReadableErrors.ARGUMENT.value.format(
                "severity", ArgumentValues.ALERT_IOC_AND_DOCUMENT_SEVERITY.value
            ),
        ),
    ),
)
def test_fail_update_alert_severity_command(
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: Update alert severity.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-severity-update called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import update_alert_severity_command

    with pytest.raises(ValueError) as error_info:
        update_alert_severity_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_assign_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Assign alert to user.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-assign called.
    Then:
     - Ensure that alert assigned to user.
    """
    from Rapid7ThreatCommand import assign_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/assign-alert/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = assign_alert_command(
        mock_client, {"alert_id": "123", "user_id": "123456789", "is_mssp": "false"}
    )
    assert result.outputs_prefix == "ThreatCommand.Alert"


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"is_mssp": "test"},
            ReadableErrors.ARGUMENT.value.format(
                "is_mssp", ArgumentValues.BOOLEAN.value
            ),
        ),
    ),
)
def test_fail_assign_alert_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: Assign alert to user.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-assign called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import assign_alert_command

    with pytest.raises(ValueError) as error_info:
        assign_alert_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_unassign_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Unassign alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-unassign called.
    Then:
     - Ensure that alert unassigned.
    """
    from Rapid7ThreatCommand import unassign_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/unassign-alert/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = unassign_alert_command(mock_client, {"alert_id": "123"})
    assert result.outputs_prefix == "ThreatCommand.Alert"


def test_reopen_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Re-open alert..
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-reopen called.
    Then:
     - Ensure that alert re-opened.
    """
    from Rapid7ThreatCommand import reopen_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/reopen-alert/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = reopen_alert_command(mock_client, {"alert_id": "123"})
    assert result.readable_output == ReadableOutputs.ALERT_REOPEN.value.format("123")


def test_add_tag_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add tag to alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-tag-add called.
    Then:
     - Ensure that the tag added.
    """
    from Rapid7ThreatCommand import tag_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/add-tag/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = tag_alert_command(mock_client, {"alert_id": "123", "tag_name": "test"})
    assert result.readable_output == ReadableOutputs.ALERT_TAG_ADD.value.format(
        "123", "test"
    )


def test_remove_tag_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Remove tag from alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-tag-remove called.
    Then:
     - Ensure that the tag removed.
    """
    from Rapid7ThreatCommand import untag_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/remove-tag/123")
    requests_mock.patch(url=url, content=b"", status_code=HTTPStatus.OK)

    result = untag_alert_command(mock_client, {"alert_id": "123", "tag_id": "123123"})
    assert result.readable_output == ReadableOutputs.ALERT_TAG_REMOVE.value.format(
        "123", "123123"
    )


def test_send_mail_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Send mail with alert details.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-send-mail called.
    Then:
     - Ensure that the mail sent.
    """
    from Rapid7ThreatCommand import send_mail_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/send-mail/123")
    requests_mock.post(url=url, content=b"", status_code=HTTPStatus.OK)

    result = send_mail_alert_command(
        mock_client,
        {"alert_id": "123", "email_addresses": "test@test.com", "content": "example"},
    )
    assert result.readable_output == ReadableOutputs.ALERT_MAIL.value.format(
        "123", "['test@test.com']"
    )


def test_ask_analyst_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Ask the analyst with question.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-analyst-ask called.
    Then:
     - Ensure that the question sent to analyst.
    """
    from Rapid7ThreatCommand import analyst_ask_alert_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/ask-the-analyst/123")
    requests_mock.post(url=url, content=b"", status_code=HTTPStatus.OK)

    result = analyst_ask_alert_command(
        mock_client, {"alert_id": "123", "question": "example"}
    )
    assert result.readable_output == ReadableOutputs.ALERT_ANALYST.value.format("123")


def test_list_alert_conversation_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert conversation with analyst.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-analyst-conversation-list called.
    Then:
     - Ensure that the conversation listed.
    """
    from Rapid7ThreatCommand import list_alert_conversation_command

    json_response = load_mock_response("alert/conversation.json")
    url = urljoin(
        mock_client._base_url, "/v1/data/alerts/ask-the-analyst-conversation/123"
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_conversation_command(
        mock_client, {"alert_id": "123", "question": "example"}
    )
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"


def test_list_alert_activity_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert activity log.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-activity-log-get called.
    Then:
     - Ensure that activity log listed.
    """
    from Rapid7ThreatCommand import list_alert_activity_command

    json_response = load_mock_response("alert/activity_log.json")
    url = urljoin(
        mock_client._base_url, "/v1/data/alerts/activity-log/59490da8e57c281391e11ce9"
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_activity_command(
        mock_client, {"alert_id": "59490da8e57c281391e11ce9"}
    )
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"


def test_add_alert_note_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add alert note.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-note-add called.
    Then:
     - Ensure that the note added.
    """
    from Rapid7ThreatCommand import add_alert_note_command

    url = urljoin(mock_client._base_url, "/v1/data/alerts/add-note/123")
    requests_mock.post(url=url, content=b"", status_code=HTTPStatus.OK)

    result = add_alert_note_command(mock_client, {"alert_id": "123", "note": "example"})
    assert result.readable_output == ReadableOutputs.ALERT_ADD_NOTE.value.format("123")


def test_get_alert_blocklist_status_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Get alert blocklist status.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-blocklist-get called.
    Then:
     - Ensure that the alert blocklist status got.
    """
    from Rapid7ThreatCommand import get_alert_blocklist_status_command

    json_response = load_mock_response("alert/conversation.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/blocklist-status/123")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = get_alert_blocklist_status_command(mock_client, {"alert_id": "123"})
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, dict)
    assert "BlockList" in list(result.outputs.keys())


def test_update_alert_blocklist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Update alert blocklist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-blocklist-update called.
    Then:
     - Ensure that the alert blocklist updated.
    """
    from Rapid7ThreatCommand import update_alert_blocklist_command

    json_response = load_mock_response("alert/conversation.json")
    url = urljoin(
        mock_client._base_url, "/v1/data/alerts/change-iocs-blocklist-status/123"
    )
    requests_mock.patch(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = update_alert_blocklist_command(
        mock_client,
        {"alert_id": "123", "blocklist_status": "Sent", "domains": "test.com"},
    )
    assert (
        result.readable_output
        == ReadableOutputs.ALERT_BLOCKLIST_UPDATE.value.format("Sent")
    )


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"alert_id": "test", "blocklist_status": "test", "domains": "test.com"},
            ReadableErrors.ARGUMENT.value.format(
                "blocklist_status", ArgumentValues.ALERT_BLOCKLIST.value
            ),
        ),
    ),
)
def test_fail_update_alert_blocklist_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: Update alert blocklist.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-alert-blocklist-update called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import update_alert_blocklist_command

    with pytest.raises(ValueError) as error_info:
        update_alert_blocklist_command(mock_client, args)
    assert str(message) == str(error_info.value)


def test_list_alert_image_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert images.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-image-list called.
    Then:
     - Ensure that alert images listed.
    """
    from Rapid7ThreatCommand import list_alert_image_command

    json_response = load_mock_response("alert/complete2.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/59490dabe57c281391e11ceb",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    with open("test_data/alert/alert_image.png", "rb") as img1:
        url = urljoin(
            mock_client._base_url,
            "/v1/data/alerts/alert-image/59490d78e57c281391e11cb9",
        )
        requests_mock.get(url=url, content=img1.read(), status_code=HTTPStatus.OK)

    result = list_alert_image_command(
        mock_client, {"alert_id": "59490dabe57c281391e11ceb"}
    )
    assert isinstance(result, list)
    assert isinstance(result[0], CommandResults)
    assert result[0].readable_output == ReadableOutputs.ALERT_IMAGES.value.format(
        "59490dabe57c281391e11ceb"
    )
    assert isinstance(result[1], list)


def test_takedown_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Send takedown request for alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-takedown-request called.
    Then:
     - Ensure that the takedown request was sent.
    """
    from Rapid7ThreatCommand import takedown_alert_command

    json_response = load_mock_response("alert/conversation.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/takedown-request/123")
    requests_mock.patch(url=url, json=json_response, status_code=HTTPStatus.OK)
    args = {"alert_id": "123", "target": "Domain", "close_alert_after_success": "true"}
    result = takedown_alert_command(mock_client, args)
    assert result.readable_output == ReadableOutputs.ALERT_TAKEDOWN.value.format(
        args["alert_id"]
    )


def test_get_takedown_alert_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Get takedown status for alert.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-takedown-request-status-get called.
    Then:
     - Ensure that the takedown status got.
    """
    from Rapid7ThreatCommand import get_takedown_alert_command

    json_response = load_mock_response("alert/conversation.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/takedown-status/123")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    args = {"alert_id": "123"}
    result = get_takedown_alert_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.Alert"
    assert result.outputs_key_field == "id"


def test_list_alert_type_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert types.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-type-list called.
    Then:
     - Ensure that alert types listed.
    """
    from Rapid7ThreatCommand import list_alert_type_command

    json_response = load_mock_response("alert/list_type.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/types-subtypes-relations")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_type_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.AlertType"
    assert result.outputs_key_field == "sub_type"


def test_list_alert_source_type_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert source types.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-source-type-list called.
    Then:
     - Ensure that alert source types listed.
    """
    from Rapid7ThreatCommand import list_alert_source_type_command

    json_response = load_mock_response("alert/list_source_type.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/source-types")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_source_type_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.AlertSourceType"


def test_list_alert_scenario_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List alert scenario.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-scenario-list called.
    Then:
     - Ensure that scenarios listed.
    """
    from Rapid7ThreatCommand import list_alert_scenario_command

    json_response = load_mock_response("alert/list_scenario.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/scenario-relations")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_alert_scenario_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.Scenario"


# def test_report_alert_ioc_command(
#     requests_mock,
#     mock_client: Client,
# ):
#     """
#     Scenario: Report alert IOC.
#     Given:
#      - User has provided correct parameters.
#     When:
#      - threat-command-alert-ioc-report called.
#     Then:
#      - Ensure that the IOC reported.
#     """
#     from Rapid7ThreatCommand import report_alert_ioc_command

#     json_response = load_mock_response("alert/conversation.json")
#     url = urljoin(mock_client._base_url, "/v1/data/alerts/report-iocs/123")
#     requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
#     args = {"alert_id": "123", "external_sources": "test"}
#     result = report_alert_ioc_command(mock_client, args)
#     assert result.readable_output == ReadableOutputs.ALERT_REPORT.value.format(
#         args["alert_id"]
#     )


def test_list_account_user_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List account users.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-account-user-list.
    Then:
     - Ensure that CVaccount users listed.
    """
    from Rapid7ThreatCommand import list_account_user_command

    json_response = load_mock_response("account_user_list.json")
    url = urljoin(mock_client._base_url, "/v1/account/users-details")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = list_account_user_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.AccountUser"


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (
            {"user_type": "test"},
            ReadableErrors.ARGUMENT.value.format(
                "user_type", ArgumentValues.USER_TYPE.value
            ),
        ),
    ),
)
def test_fail_list_account_user_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    message: str,
):
    """
    Scenario: List account users.
    Given:
     - User has provided wrong parameters.
    When:
     - threat-command-account-user-list.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import list_account_user_command

    with pytest.raises(ValueError) as error_info:
        list_account_user_command(mock_client, args)
    assert str(message) == str(error_info.value)


@pytest.mark.parametrize(
    ("args", "endpoints"),
    (
        (
            {"limit": 3, "last_updated_from": "2022-12-13T06:25:33.163Z"},
            [
                (
                    "ioc/filter_list.json",
                    "/v3/iocs?lastUpdatedFrom=2022-12-13T06%3A25%3A33.163Z&limit=3",
                )
            ],
        ),
        (
            {"ioc_value": "example.com"},
            [("ioc/get.json", "/v3/iocs/ioc-by-value?iocValue=example.com")],
        ),
    ),
)
def search_ioc_handler_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    endpoints: List[tuple],
):
    """
    Scenario: Search IOCs.
    Given:
     - User has provided single IOC.
     - User has provided filter arguments.
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search called.
    Then:
     - Ensure that IOCs listed.
    """
    from Rapid7ThreatCommand import search_ioc_handler_command

    for json_path, endpoint in endpoints:
        json_response = load_mock_response(json_path)
        url = urljoin(mock_client._base_url, endpoint)
        requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)

    result = search_ioc_handler_command(mock_client, args)
    assert result.outputs_prefix == "ThreatCommand.IOC"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == args["limit"]


def test_add_tags_ioc_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add tag to IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-tags-add called.
    Then:
     - Ensure that tag was added.
    """
    from Rapid7ThreatCommand import add_tags_ioc_command

    url = urljoin(mock_client._base_url, "/v1/iocs/tags")
    requests_mock.post(url=url, json={"success": True}, status_code=HTTPStatus.OK)

    result = add_tags_ioc_command(
        mock_client, {"ioc_value": "test.com", "tag_values": "test"}
    )
    assert result.readable_output == ReadableOutputs.IOC_TAG_ADD.value.format(
        "test.com", "['test']"
    )


def test_fail_add_tags_ioc_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add tag to IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-tags-add called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import add_tags_ioc_command

    json_response = load_mock_response("ioc/tag_fail.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/tags")
    requests_mock.post(
        url=url, json=json_response, status_code=HTTPStatus.UNPROCESSABLE_ENTITY
    )

    with pytest.raises(DemistoException) as error_info:
        add_tags_ioc_command(
            mock_client, {"ioc_value": "test.com", "tag_values": "test"}
        )
    assert f"Status Code: {HTTPStatus.UNPROCESSABLE_ENTITY}, {ReadableErrors.WRONG_PARAMETERS.value}" == str(
        error_info.value)


def test_update_ioc_severity_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Update severity to IOCs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-severity-update was called.
    Then:
     - Ensure that IOC severity was updated.
    """
    from Rapid7ThreatCommand import update_ioc_severity_command

    json_response = load_mock_response("ioc/severity_update.json")
    url = urljoin(mock_client._base_url, "/v2/iocs/severity")
    requests_mock.patch(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = update_ioc_severity_command(
        mock_client, {"domains": "test.com", "severity": "High"}
    )
    assert result.readable_output == ReadableOutputs.UPDATE_IOC_SEVERITY.value.format(
        "['test.com']", "High"
    )


def test_fail_update_ioc_severity_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Update severity to IOCs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-severity-update was called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import update_ioc_severity_command

    json_response = load_mock_response("ioc/severity_fail.json")
    url = urljoin(mock_client._base_url, "/v2/iocs/severity")
    requests_mock.patch(url=url, json=json_response, status_code=HTTPStatus.OK)
    with pytest.raises(DemistoException):
        update_ioc_severity_command(
            mock_client, {"domains": "test.com", "severity": "High"}
        )


def test_add_ioc_comment_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add comment to IOCs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-comment-add was called.
    Then:
     - Ensure that comment added.
    """
    from Rapid7ThreatCommand import add_ioc_comment_command

    url = urljoin(mock_client._base_url, "/v1/iocs/comments")
    requests_mock.post(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    result = add_ioc_comment_command(
        mock_client, {"domains": "test.com", "comment": "test"}
    )
    assert result.readable_output == ReadableOutputs.ADD_IOC_COMMENT.value.format(
        "['test.com']", "test"
    )


def test_fail_add_ioc_comment_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add comment to IOCs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-comment-add was called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import add_ioc_comment_command

    json_response = load_mock_response("ioc/tag_fail.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/comments")
    requests_mock.post(
        url=url, json=json_response, status_code=HTTPStatus.UNPROCESSABLE_ENTITY
    )

    with pytest.raises(DemistoException) as error_info:
        add_ioc_comment_command(mock_client, {"domains": "test.com", "comment": "test"})
    assert f"Status Code: {HTTPStatus.UNPROCESSABLE_ENTITY}, {ReadableErrors.WRONG_PARAMETERS.value}" == str(
        error_info.value)


@pytest.mark.parametrize(
    ("args"),
    (
        ({"domains": "google.com", "is_whitelisted": "Add to the user whitelist"}),
        ({"domains": "google.com", "is_whitelisted": "Do not whitelist"}),
    ),
)
def test_update_account_whitelist_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
):
    """
    Scenario: Update account whitelist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-account-whitelist-update called.
    Then:
     - Ensure that account whitelist updated.
    """
    from Rapid7ThreatCommand import update_account_whitelist_command

    url = urljoin(mock_client._base_url, "/v2/iocs/user-whitelist")
    requests_mock.post(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    result = update_account_whitelist_command(mock_client, args)
    assert (
        result.readable_output
        == ReadableOutputs.UPDATE_ACCOUNT_WHITELIST.value.format(
            argToList(args["domains"]), args["is_whitelisted"]
        )
    )


def test_fail_update_account_whitelist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Update account whitelist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-account-whitelist-update called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import update_account_whitelist_command

    args = {"domains": "google.com", "is_whitelisted": "test"}
    url = urljoin(mock_client._base_url, "/v2/iocs/user-whitelist")
    requests_mock.post(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    with pytest.raises(ValueError) as error_info:
        update_account_whitelist_command(mock_client, args)
    assert ReadableErrors.ARGUMENT.value.format(
        "is_whitelisted", ArgumentValues.WHITELIST_STATUS.value
    ) == str(error_info.value)


def test_remove_account_whitelist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Remove from IOCs account whitelist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-account-whitelist-remove called.
    Then:
     - Ensure that IOCs removed from account whitelist.
    """
    from Rapid7ThreatCommand import remove_account_whitelist_command

    url = urljoin(mock_client._base_url, "/v2/iocs/user-whitelist")
    requests_mock.delete(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    args = {"domains": "test.com"}
    result = remove_account_whitelist_command(mock_client, args)
    assert (
        result.readable_output
        == ReadableOutputs.REMOVE_ACCOUNT_WHITELIST.value.format(
            argToList(args["domains"])
        )
    )


def test_add_ioc_blocklist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add IOCs to blocklist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-blocklist-add called.
    Then:
     - Ensure that IOCs was added to blocklist.
    """
    from Rapid7ThreatCommand import add_ioc_blocklist_command

    url = urljoin(mock_client._base_url, "/v1/iocs/blocklist")
    requests_mock.post(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    result = add_ioc_blocklist_command(mock_client, {"domains": "test.com"})
    assert result.readable_output == ReadableOutputs.ADD_IOC_BLOCKLIST.value.format(
        "['test.com']"
    )


def test_fail_add_ioc_blocklist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Add IOCs to blocklist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-blocklist-add called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import add_ioc_blocklist_command

    json_response = load_mock_response("ioc/add_blocklist_fail.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/blocklist")
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.BAD_REQUEST)
    with pytest.raises(DemistoException):
        add_ioc_blocklist_command(mock_client, {"domains": "test.test"})


def test_remove_ioc_blocklist_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Remove IOCs from blocklist.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-blocklist-remove called.
    Then:
     - Ensure that IOCs was removed from blocklist.
    """
    from Rapid7ThreatCommand import remove_ioc_blocklist_command

    url = urljoin(mock_client._base_url, "/v1/iocs/blocklist")
    requests_mock.delete(url=url, json={"success": True}, status_code=HTTPStatus.OK)
    result = remove_ioc_blocklist_command(mock_client, {"domains": "test.com"})
    assert result.readable_output == ReadableOutputs.REMOVE_IOC_BLOCKLIST.value.format(
        "['test.com']"
    )


def test_search_mention_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Search mentions.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-mention-search called.
    Then:
     - Ensure that the mentions sent to XSOAR.
    """
    from Rapid7ThreatCommand import search_mention_command

    json_response = load_mock_response("search_mentions.json")
    url = urljoin(
        mock_client._base_url,
        "/v2/intellifind?search=test.com&page-number=1&only-dark-web=True&highlight-tags=True",
    )
    requests_mock.get(url=url, json=json_response)
    result = search_mention_command(
        mock_client,
        {
            "search": "test.com",
            "page_number": 1,
            "only_dark_web": "true",
            "highlight_tags": "true",
        },
    )
    assert result.outputs_prefix == "ThreatCommand.Mentions"


def test_usage_quota_enrichment_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Get enrichment quota.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-enrichment-quota-usage called.
    Then:
     - Ensure that the quota sent to XSOAR.
    """
    from Rapid7ThreatCommand import usage_quota_enrichment_command

    json_response = load_mock_response("ioc/quota.json")
    url = urljoin(mock_client._base_url, "/v1/iocs/quota")
    requests_mock.get(url=url, json=json_response)
    result = usage_quota_enrichment_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.IOCsQuota"


def test_list_mssp_user_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List MSSP users.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-mssp-user-list called.
    Then:
     - Ensure that MSSP users listed.
    """
    from Rapid7ThreatCommand import list_mssp_user_command

    json_response = load_mock_response("mssp/mssp_user.json")
    url = urljoin(mock_client._base_url, "/v1/mssp/users-details")
    requests_mock.get(url=url, json=json_response)
    result = list_mssp_user_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.MsspUser"


def test_list_mssp_customer_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List MSSP customers.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-mssp-customer-list called.
    Then:
     - Ensure that MSSP customers listed.
    """
    from Rapid7ThreatCommand import list_mssp_customer_command

    json_response = load_mock_response("mssp/mssp_customer.json")
    url = urljoin(mock_client._base_url, "/v1/mssp/customers")
    requests_mock.get(url=url, json=json_response)
    result = list_mssp_customer_command(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.MsspCustomer"


def test_get_alert_csv_command_with_comma_separated_content(
        requests_mock,
        mock_client: Client,
):
    """
    Scenario: Get alert CSV file with comma separated content.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-csv-get called.
    Then:
     - Ensure that CSV sent to XSOAR.
    """
    from Rapid7ThreatCommand import get_alert_csv_command

    with open("test_data/alert/alert_csv.csv", "rb") as csv:
        url = urljoin(
            mock_client._base_url,
            "/v1/data/alerts/csv-file/59490dabe57c281391e11ceb",
        )
        requests_mock.get(url=url, content=csv.read())

    result = get_alert_csv_command(
        mock_client, {"alert_id": "59490dabe57c281391e11ceb"}
    )
    assert isinstance(result, list)
    assert isinstance(result[0], CommandResults)
    assert result[0].raw_response == load_mock_response("alert/alert_csv_response.json")
    assert result[0].readable_output == ReadableOutputs.ALERT_CSV.value.format(
        "59490dabe57c281391e11ceb"
    )
    assert isinstance(result[1], dict)


def test_get_alert_csv_command_with_tab_separated_content(
        requests_mock,
        mock_client: Client,
):
    """
    Scenario: Get alert CSV file with tab separated content.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-alert-csv-get called.
    Then:
     - Ensure that CSV sent to XSOAR.
    """
    from Rapid7ThreatCommand import get_alert_csv_command

    with open("test_data/alert/alert_csv_2.csv", "rb") as csv:
        url = urljoin(
            mock_client._base_url,
            "/v1/data/alerts/csv-file/59490dabe57c281391e11ceb",
        )
        requests_mock.get(url=url, content=csv.read())

    result = get_alert_csv_command(
        mock_client, {"alert_id": "59490dabe57c281391e11ceb"}
    )
    assert isinstance(result, list)
    assert isinstance(result[0], CommandResults)
    assert result[0].raw_response == load_mock_response("alert/alert_csv_response_2.json")
    assert result[0].readable_output == ReadableOutputs.ALERT_CSV.value.format(
        "59490dabe57c281391e11ceb"
    )
    assert isinstance(result[1], dict)


@pytest.mark.parametrize(
    ("handler_command", "key", "response_path"),
    (
        (file_reputation_handler, "file", "ioc/enrich_file.json"),
        (file_reputation_handler, "file", "ioc/enrich_file_2.json"),
        (file_reputation_handler, "file", "ioc/enrich_file_3.json"),
        (file_reputation_handler, "file", "ioc/enrich_file_4.json"),
        (
            domain_reputation_handler,
            "domain",
            "ioc/enrich_domain.json",
        ),
        (
            domain_reputation_handler,
            "domain",
            "ioc/enrich_domain_2.json",
        ),
        (
            domain_reputation_handler,
            "domain",
            "ioc/enrich_domain_3.json",
        ),
        (
            domain_reputation_handler,
            "domain",
            "ioc/enrich_domain_4.json",
        ),
        (ip_reputation_handler, "ip", "ioc/enrich_ip.json"),
        (ip_reputation_handler, "ip", "ioc/enrich_ip_2.json"),
        (ip_reputation_handler, "ip", "ioc/enrich_ip_3.json"),
        (ip_reputation_handler, "ip", "ioc/enrich_ip_4.json"),
        (url_reputation_handler, "url", "ioc/enrich_url.json"),
        (url_reputation_handler, "url", "ioc/enrich_url_2.json"),
        (url_reputation_handler, "url", "ioc/enrich_url_3.json"),
        (url_reputation_handler, "url", "ioc/enrich_url_4.json"),
    ),
)
def test_finish_reputation_handler(
    requests_mock,
    mock_client: Client,
    handler_command: Callable,
    key: str,
    response_path: str,
):
    """
    Scenario: Reputation commands.
    Given:
     - User has provided correct parameters.
    When:
     - reputation command called.
    Then:
     - Ensure that the command finished.
    """
    from Rapid7ThreatCommand import reputation_handler
    execution_metrics = ExecutionMetrics()
    json_response = load_mock_response(response_path)
    url = urljoin(mock_client._base_url, "/v1/iocs/enrich/test")
    requests_mock.get(url=url, json=json_response)
    result = reputation_handler(
        args={key: "test", 'unfinished_enriches': -1},
        client=mock_client,
        handler_command=handler_command,
        key=key,
        execution_metrics=execution_metrics
    )
    assert not result.continue_to_poll


@pytest.mark.parametrize(
    ("handler_command", "key", "status"),
    (
        (file_reputation_handler, "file", "InProggress"),
        (url_reputation_handler, "url", "Queued"),
        (domain_reputation_handler, "domain", "QuotaExceeded"),
    ),
)
def test_continue_reputation_handler(
    requests_mock,
    mock_client: Client,
    handler_command: Callable,
    key: str,
    status: str,
):
    """
    Scenario: Reputation commands.
    Given:
     - User has provided correct parameters.
    When:
     - reputation command called.
    Then:
     - Ensure that the command called again.
    """
    from Rapid7ThreatCommand import reputation_handler
    execution_metrics = ExecutionMetrics()
    url = urljoin(mock_client._base_url, "/v1/iocs/enrich/test")
    requests_mock.get(url=url, json={"OriginalValue": "test", "Status": status})

    result = reputation_handler(
        args={key: "test", 'unfinished_enriches': -1},
        client=mock_client,
        handler_command=handler_command,
        key=key,
        execution_metrics=execution_metrics
    )
    if status == "QuotaExceeded":
        assert not result.continue_to_poll
    else:
        assert result.continue_to_poll


def test_get_ioc_handler(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Get IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search called.
    Then:
     - Ensure that the IOC sent to the user.
    """
    from Rapid7ThreatCommand import get_ioc_handler

    json_response = load_mock_response("ioc/get.json")
    url = urljoin(mock_client._base_url, "/v3/iocs/ioc-by-value?iocValue=test")
    requests_mock.get(url=url, json=json_response)
    result = get_ioc_handler(client=mock_client, ioc_value="test")
    assert result.outputs_prefix == "ThreatCommand.IOC"


def test_list_ioc_handler(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: List IOCs.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search.
    Then:
     - Ensure that IOCs listed.
    """
    from Rapid7ThreatCommand import list_ioc_handler

    json_response = load_mock_response("ioc/filter_list.json")
    url = urljoin(mock_client._base_url, "/v3/iocs?limit=50")
    requests_mock.get(url=url, json=json_response)
    result = list_ioc_handler(mock_client, {})
    assert result.outputs_prefix == "ThreatCommand.IOC"


@pytest.mark.parametrize(
    ("response_path"),
    (
        ("ioc/enrich_file.json"),
        ("ioc/enrich_domain.json"),
        ("ioc/enrich_ip.json"),
        ("ioc/enrich_url.json"),
    ),
)
def test_enrich_ioc_handler(
    requests_mock,
    mock_client: Client,
    response_path: str,
):
    """
    Scenario: Enrich IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search called with enrichment flag.
    Then:
     - Ensure that the command stop from running.
    """
    from Rapid7ThreatCommand import enrich_ioc_handler
    execution_metrics = ExecutionMetrics()
    json_response = load_mock_response(response_path)
    url = urljoin(mock_client._base_url, "/v1/iocs/enrich/test")
    requests_mock.get(url=url, json=json_response)
    result = enrich_ioc_handler(mock_client, {"ioc_value": "test"}, execution_metrics=execution_metrics)
    assert not result.continue_to_poll


@pytest.mark.parametrize(
    ("status"),
    (
        ("QuotaExceeded"),
        ("Failed"),
    ),
)
def test_fail_enrich_ioc_handler(
    requests_mock,
    mock_client: Client,
    status: str,
):
    """
    Scenario: Enrich IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search called with enrichment flag.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import enrich_ioc_handler
    execution_metrics = ExecutionMetrics()
    url = urljoin(mock_client._base_url, "/v1/iocs/enrich/test")
    requests_mock.get(url=url, json={"Status": status})
    result = enrich_ioc_handler(mock_client, {"ioc_value": "test"}, execution_metrics=execution_metrics)
    assert not result.continue_to_poll


@pytest.mark.parametrize(
    ("status"),
    (
        ("InProgress"),
        ("Quoted"),
    ),
)
def test_continue_enrich_ioc_handler(
    requests_mock,
    mock_client: Client,
    status: str,
):
    """
    Scenario: Enrich IOC.
    Given:
     - User has provided correct parameters.
    When:
     - threat-command-ioc-search called with enrichment flag.
    Then:
     - Ensure that polling command called again.
    """
    from Rapid7ThreatCommand import enrich_ioc_handler
    execution_metrics = ExecutionMetrics()
    url = urljoin(mock_client._base_url, "/v1/iocs/enrich/test")
    requests_mock.get(url=url, json={"Status": status})
    result = enrich_ioc_handler(mock_client, {"ioc_value": "test"}, execution_metrics=execution_metrics)
    assert result.continue_to_poll


def test_test_module_with_fetch_success(requests_mock, mock_client: Client):
    """
    Scenario: Test module with fetch enabled and success.
    Given:
     - User has provided correct parameters.
    When:
     - test-module called.
    Then:
     - Ensure that test module gets success.
    """
    from Rapid7ThreatCommand import test_module

    json_response = load_mock_response("system_modules.json")
    url = urljoin(mock_client._base_url, "/v1/account/system-modules")
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = test_module(mock_client, {'isFetch': True, 'max_fetch': '200', 'first_fetch': '1 day'})
    assert result == "ok"


@pytest.mark.parametrize(
    ("args", "error_msg"),
    (
        ({"isFetch": True, "first_fetch": "1 day", "max_fetch": "201.5"}, ReadableErrors.MAX_FETCH_INVALID.value),
        ({"isFetch": True, "first_fetch": "1 day", "max_fetch": "0"}, ReadableErrors.MAX_FETCH_INVALID.value),
        ({"isFetch": True, "first_fetch": "1 day", "max_fetch": "-1"}, ReadableErrors.MAX_FETCH_INVALID.value)
    ),
)
def test_test_module_with_fetch_invalid_args(mock_client, args, error_msg):
    """
    Scenario: Test module with fetch enabled and invalid arguments.
    Given:
     - User has provided correct parameters.
    When:
     - test-module called.
    Then:
     - Ensure that test module gets failed.
    """
    from Rapid7ThreatCommand import test_module

    result = test_module(mock_client, args)
    assert str(error_msg) in result


def test_fetch_incidents(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Fetch 2 incidents.
    Given:
     - User has provided correct parameters.
    When:
     - fetch-incidents called.
    Then:
     - Ensure that the incidents created successfully.
    """
    from Rapid7ThreatCommand import fetch_incidents

    json_response = load_mock_response("alert/fetch_alert_list.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/update-alerts")
    requests_mock.get(url=url, json=json_response)
    json_response = load_mock_response("alert/complete1.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/641cbbdfb6a71e6aa08b8e53",
    )
    requests_mock.get(url=url, json=json_response)
    json_response = load_mock_response("alert/complete2.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/640f00172c908c0307cbf91e",
    )
    requests_mock.get(url=url, json=json_response)

    next_run, incidents = fetch_incidents(
        client=mock_client,
        last_run={"time": "2023-01-14T08:32:35.478Z", "last_id": "1"},
        alert_severities=None,
        alert_types=None,
        network_types=None,
        fetch_attachments=True,
        fetch_csv=True,
        first_fetch="3 Days",
        is_closed=False,
        max_fetch=None,
        source_types=None,
    )
    assert next_run.get("time")
    assert next_run.get("last_id")
    assert len(incidents) == 2


def test_fetch_incidents_with_invalid_offset_time(
        requests_mock,
        mock_client: Client,
):
    """
    Scenario: Fetch 2 incidents with invalid last run time.
    Given:
     - User has provided correct parameters.
    When:
     - fetch-incidents called.
    Then:
     - Ensure that the incidents created successfully.
    """
    from Rapid7ThreatCommand import fetch_incidents

    json_response = load_mock_response("alert/fetch_alert_list.json")
    url = urljoin(mock_client._base_url, "/v1/data/alerts/update-alerts")
    requests_mock.get(url=url, json=json_response)
    json_response = load_mock_response("alert/complete1.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/641cbbdfb6a71e6aa08b8e53",
    )
    requests_mock.get(url=url, json=json_response)
    json_response = load_mock_response("alert/complete2.json")
    url = urljoin(
        mock_client._base_url,
        "/v1/data/alerts/get-complete-alert/640f00172c908c0307cbf91e",
    )
    requests_mock.get(url=url, json=json_response)

    next_run, incidents = fetch_incidents(
        client=mock_client,
        last_run={"time": "2023-01--14T08:32:35.478Z", "last_id": "1"},
        alert_severities=None,
        alert_types=None,
        network_types=None,
        fetch_attachments=True,
        fetch_csv=True,
        first_fetch="3 Days",
        is_closed=False,
        max_fetch=None,
        source_types=None,
    )
    assert next_run.get("time")
    assert next_run.get("last_id")
    assert len(incidents) == 2


def test_fetch_incidents_with_empty_alert_list_response(
        requests_mock,
        mock_client: Client,
):
    """
    Scenario: Fetch 2 incidents when alert list response is empty list.
    Given:
     - User has provided correct parameters.
    When:
     - fetch-incidents called.
    Then:
     - Ensure that the incidents created successfully.
    """
    from Rapid7ThreatCommand import fetch_incidents

    url = urljoin(mock_client._base_url, "/v1/data/alerts/update-alerts")
    requests_mock.get(url=url, json={"content": []})
    last_run = {"time": "2023-01-14T08:32:35.478Z", "last_id": "1"}
    next_run, incidents = fetch_incidents(
        client=mock_client,
        last_run=last_run,
        alert_severities=None,
        alert_types=None,
        network_types=None,
        fetch_attachments=True,
        fetch_csv=True,
        first_fetch="3 Days",
        is_closed=False,
        max_fetch=None,
        source_types=None,
    )
    assert next_run == last_run
    assert len(incidents) == 0


@pytest.mark.parametrize(
    ("response", "args", "result"),
    (
        (list(range(10)), {}, 10),
        (list(range(70)), {}, 50),
        (list(range(70)), {"limit": 3}, 3),
        (list(range(70)), {"all_results": True}, 70),
    ),
)
def test_manual_pagination(
    response: List[Any],
    args: dict[str, Any],
    result: int,
):
    """
    Scenario: Paginate a list of objects.
    Given:
     - User has provided correct parameters.
    When:
     - manual_pagination called.
    Then:
     - Ensure that the list paginated.
    """
    from Rapid7ThreatCommand import manual_pagination

    paginated_data = manual_pagination(response, args)
    assert len(paginated_data) == result
    assert paginated_data == response[:result]


def test_fail_manual_pagination():
    """
    Scenario: Paginate a list of objects.
    Given:
     - User has provided correct parameters.
    When:
     - manual_pagination called.
    Then:
     - Ensure relevant error raised.
    """
    from Rapid7ThreatCommand import manual_pagination

    with pytest.raises(ValueError) as error_info:
        manual_pagination(["test"], {"limit": -1})
    assert str(error_info.value) == ReadableErrors.LIMIT.value
