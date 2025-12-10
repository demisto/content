import json
from unittest.mock import MagicMock

import pytest
from CommonServerPython import *
from CortexCoreIR import (
    core_execute_command_reformat_args,
    core_add_indicator_rule_command,
    core_block_ip_command,
    polling_block_ip_status,
    Client,
    core_get_contributing_event_command,
)
from freezegun import freeze_time

Core_URL = "https://api.xdrurl.com"
STATUS_AMOUNT = 6


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_report_incorrect_wildfire_command(mocker):
    """
    Given:
        - FilterObject and name to get by exclisions.
    When
        - A user desires to get exclusions.
    Then
        - returns markdown, context data and raw response.
    """
    from CortexCoreIR import Client, report_incorrect_wildfire_command

    wildfire_response = load_test_data("./test_data/wildfire_response.json")
    mock_client = Client(base_url=f"{Core_URL}/public_api/v1", headers={})
    mocker.patch.object(mock_client, "report_incorrect_wildfire", return_value=wildfire_response)
    file_hash = "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
    args = {
        "email": "a@a.gmail.com",
        "file_hash": file_hash,
        "new_verdict": 0,
        "reason": "test1",
    }
    res = report_incorrect_wildfire_command(client=mock_client, args=args)
    assert res.readable_output == f"Reported incorrect WildFire on {file_hash}"


class TestPrevalenceCommands:
    def test_get_domain_analytics(self, mocker):
        """
        Given:
            - A domain name.
        When:
            - Calling handle_prevalence_command as part of core-get-domain-analytics-prevalence command.
        Then:
            - Verify response is as expected.
        """
        from CortexCoreIR import Client, handle_prevalence_command

        mock_client = Client(base_url=f"{Core_URL}/xsiam/", headers={})
        mock_res = load_test_data("./test_data/prevalence_response.json")
        mocker.patch.object(mock_client, "get_prevalence", return_value=mock_res.get("domain"))
        res = handle_prevalence_command(mock_client, "core-get-domain-analytics-prevalence", {"domain": "some_name"})
        assert res.outputs[0].get("value") is True
        assert res.outputs[0].get("domain_name") == "some_name"

    def test_get_ip_analytics(self, mocker):
        """
        Given:
            - An Ip address.
        When:
            - Calling handle_prevalence_command as part of core-get-IP-analytics-prevalence command.
        Then:
            - Verify response is as expected.
        """
        from CortexCoreIR import Client, handle_prevalence_command

        mock_client = Client(base_url=f"{Core_URL}/xsiam/", headers={})
        mock_res = load_test_data("./test_data/prevalence_response.json")
        mocker.patch.object(mock_client, "get_prevalence", return_value=mock_res.get("ip"))
        res = handle_prevalence_command(mock_client, "core-get-IP-analytics-prevalence", {"ip": "some ip"})
        assert res.outputs[0].get("value") is True
        assert res.outputs[0].get("ip_address") == "some_ip"

    def test_get_registry_analytics(self, mocker):
        """
        Given:
            - A registry name.
        When:
            - Calling handle_prevalence_command as part of core-get-registry-analytics-prevalence command.
        Then:
            - Verify response is as expected.
        """
        from CortexCoreIR import Client, handle_prevalence_command

        mock_client = Client(base_url=f"{Core_URL}/xsiam/", headers={})
        mock_res = load_test_data("./test_data/prevalence_response.json")
        mocker.patch.object(mock_client, "get_prevalence", return_value=mock_res.get("registry"))
        res = handle_prevalence_command(
            mock_client,
            "core-get-registry-analytics-prevalence",
            {"key_name": "some key", "value_name": "some value"},
        )
        assert res.outputs[0].get("value") is True
        assert res.outputs[0].get("key_name") == "some key"

    def test_blocklist_files_command(self, mocker):
        """
        Given:
            - An hash list and incident ID.
        When:
            - Calling blocklist_files_command.
        Then:
            - Verify response is as expected.
        """
        from CortexCoreIR import Client, blocklist_files_command

        mock_client = Client(base_url=f"{Core_URL}/xsiam/", headers={})
        args = {"incident_id": "1", "hash_list": ["hash"]}

        error_message = (
            "[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:"
            "request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: "
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": '
            '"All hashes have already been added to the allow or block list"}}\n'
        )
        mocker.patch.object(mock_client, "_http_request", side_effect=Exception(error_message))
        mocker.patch("CoreIRApiModule.validate_sha256_hashes", return_value="")

        res = blocklist_files_command(mock_client, args)
        assert res.readable_output == "All hashes have already been added to the block list."

    def test_allowlist_files_command(self, mocker):
        """
        Given:
            - An hash list and incident ID.
        When:
            - Calling allowlist_files_command.
        Then:
            - Verify response is as expected.
        """
        from CortexCoreIR import Client, allowlist_files_command

        mock_client = Client(base_url=f"{Core_URL}/xsiam/", headers={})
        args = {"incident_id": "1", "hash_list": ["hash"]}

        error_message = (
            "[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:"
            "request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: "
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": '
            '"All hashes have already been added to the allow or block list"}}\n'
        )
        mocker.patch.object(mock_client, "_http_request", side_effect=Exception(error_message))
        mocker.patch("CoreIRApiModule.validate_sha256_hashes", return_value="")

        res = allowlist_files_command(mock_client, args)
        assert res.readable_output == "All hashes have already been added to the allow list."


class TestPollingCommand:
    @staticmethod
    def create_mocked_responses():
        response_queue = [{"reply": {"action_id": 1, "status": 1, "endpoints_count": 1}}]

        for i in range(STATUS_AMOUNT):
            if i == STATUS_AMOUNT - 1:
                general_status = "COMPLETED_SUCCESSFULLY"
            elif i < 2:
                general_status = "PENDING"
            else:
                general_status = "IN_PROGRESS"

            response_queue.append(
                {
                    "reply": {  # get script status response
                        "general_status": general_status,
                        "endpoints_pending": 1 if i < 2 else 0,
                        "endpoints_in_progress": 0 if i < 2 else 1,
                    }
                }
            )
            response_queue.append(
                {
                    "reply": {  # get script execution result response
                        "script_name": "snippet script",
                        "error_message": "",
                        "results": [
                            {
                                "endpoint_name": "test endpoint",
                                "endpoint_ip_address": ["1.1.1.1"],
                                "endpoint_status": "STATUS_010_CONNECTED",
                                "domain": "aaaa",
                                "endpoint_id": "1",
                                "execution_status": "COMPLETED_SUCCESSFULLY",
                                "failed_files": 0,
                            }
                        ],
                    }
                }
            )

        return response_queue

    def test_script_run_command(self, mocker):
        """
        Given -
            core-script-run command arguments including polling true and is_core is true where each time a different amount of
            response is returned.

        When -
            Running the core-script-run

        Then
            - Make sure the readable output is returned to war-room only once indicating on polling.
            - Make sure the correct context output is returned once the command finished polling
            - Make sure context output is returned only at the end of polling.
            - Make sure the readable output is returned only in the first run.
            - Make sure the correct output prefix is returned.
        """
        from CommonServerPython import ScheduledCommand
        from CoreIRApiModule import CoreClient, script_run_polling_command

        client = CoreClient(base_url="https://test_api.com/public_api/v1", headers={})

        mocker.patch.object(client, "_http_request", side_effect=self.create_mocked_responses())
        mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

        command_result = script_run_polling_command(args={"endpoint_ids": "1", "script_uid": "1"}, client=client)

        assert command_result.readable_output == "Waiting for the script to finish running on the following endpoints: ['1']..."
        assert command_result.outputs == {
            "action_id": 1,
            "endpoints_count": 1,
            "status": 1,
        }

        polling_args = {
            "endpoint_ids": "1",
            "script_uid": "1",
            "action_id": "1",
            "hide_polling_output": True,
            "is_core": "true",
        }

        command_result = script_run_polling_command(args=polling_args, client=client)
        # if scheduled_command is set, it means that command should still poll
        while not isinstance(command_result, list) and command_result.scheduled_command:
            # if command result is a list, it means command execution finished
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            # make sure no context output is being returned to war-room during polling
            assert not command_result.outputs
            command_result = script_run_polling_command(polling_args, client)

        assert command_result[0].outputs == {
            "action_id": 1,
            "results": [
                {
                    "endpoint_name": "test endpoint",
                    "endpoint_ip_address": ["1.1.1.1"],
                    "endpoint_status": "STATUS_010_CONNECTED",
                    "domain": "aaaa",
                    "endpoint_id": "1",
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                    "failed_files": 0,
                }
            ],
        }
        assert command_result[0].outputs_prefix == "Core.ScriptResult"


def test_get_asset_details_command_success(mocker):
    """
    GIVEN:
        A mocked client and valid arguments with an asset ID.
    WHEN:
        The get_asset_details_command function is called.
    THEN:
        The response is parsed, formatted, and returned correctly.
    """
    from CortexCoreIR import Client, get_asset_details_command

    mock_client = Client(base_url="", headers={})
    mock_get_asset_details = mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={"reply": {"id": "1234", "name": "Test Asset"}},
    )

    args = {"asset_id": "1234"}

    result = get_asset_details_command(mock_client, args)

    assert result.outputs == {"id": "1234", "name": "Test Asset"}
    assert "Test Asset" in result.readable_output
    assert mock_get_asset_details.call_count == 1


def test_get_distribution_url_command_without_download():
    """
    Given:
        - `download_package` argument set to False.
    When:
        - Calling `get_distribution_url_command` without downloading the package.
    Then:
        - Should return a CommandResults object with the distribution URL and no file download.
    """
    from CoreIRApiModule import get_distribution_url_command

    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")

    args = {
        "distribution_id": "12345",
        "package_type": "x64",
        "download_package": "false",
        "integration_context_brand": "CoreIR",
    }

    result = get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "x64")
    assert isinstance(result, CommandResults)
    assert result.outputs == {"id": "12345", "url": "https://example.com/distribution"}
    assert result.outputs_prefix == "CoreIR.Distribution"
    assert result.outputs_key_field == "id"
    assert "[Distribution URL](https://example.com/distribution)" in result.readable_output


def test_get_distribution_url_command_with_download(mocker):
    """
    Given:
        - `download_package` set to True.
    When:
        - Calling `get_distribution_url_command` with downloading the package.
    Then:
        - Should return a list with CommandResults for the distribution URL and the downloaded file information.
    """
    from CoreIRApiModule import get_distribution_url_command

    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")
    client._http_request = MagicMock(return_value=b"mock_binary_data")

    args = {
        "distribution_id": "12345",
        "package_type": "x64",
        "download_package": "true",
        "integration_context_brand": "CortexCoreIR",
    }
    mocker.patch(
        "CortexCoreIR.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 3,
            "File": "xdr-agent-install-package.msi",
            "FileID": "11111",
        },
    )
    result = get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "x64")
    client._http_request.assert_called_once_with(method="GET", full_url="https://example.com/distribution", resp_type="content")
    assert isinstance(result, list)
    assert len(result) == 2
    command_result = result[1]
    assert isinstance(command_result, CommandResults)
    assert command_result.outputs == {
        "id": "12345",
        "url": "https://example.com/distribution",
    }
    assert command_result.outputs_prefix == "CortexCoreIR.Distribution"
    assert command_result.outputs_key_field == "id"
    assert "Installation package downloaded successfully." in command_result.readable_output


def test_get_distribution_url_command_without_download_not_supported_type():
    """
    Given:
        - `download_package` argument set to True but package_type is not x64 or x86.
    When:
        - Calling `get_distribution_url_command` without downloading the package.
    Then:
        - Should raise a demisto error.
    """
    from CommonServerPython import DemistoException
    from CoreIRApiModule import get_distribution_url_command

    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")

    args = {
        "distribution_id": "12345",
        "package_type": "sh",
        "download_package": "true",
        "integration_context_brand": "PaloAltoNetworksXDR",
    }
    with pytest.raises(DemistoException) as e:
        get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "sh")
    assert e.value.message == "`download_package` argument can be used only for package_type 'x64' or 'x86'."


# tests for core_execute_command_command


def test_reformat_args_missing_command_raises():
    """
    Given:
        - args set to empty dict.
    When:
        - Calling `reformate_args` with no args.
    Then:
        - Should raise a DemistoException.
    """
    from CommonServerPython import DemistoException

    args = {}
    with pytest.raises(DemistoException, match="'command' is a required argument."):
        core_execute_command_reformat_args(args)


def test_reformat_args_is_raw_command_true():
    """
    Given:
        - is_raw_command argument set to True.
    When:
        - Calling `reformate_args` with is_raw_command=True.
    Then:
        - Verify that commands_list has only one element.
    """
    args = {"command": "dir, hostname", "is_raw_command": True}
    reformatted_args = core_execute_command_reformat_args(args)
    params = json.loads(reformatted_args["parameters"])
    assert params["commands_list"] == ["dir, hostname"]
    assert reformatted_args["is_core"] is True
    assert reformatted_args["script_uid"] == "a6f7683c8e217d85bd3c398f0d3fb6bf"


@pytest.mark.parametrize("separator", [",", "/", "|"])
def test_reformat_args_separators(separator):
    """
    Given:
        - is_raw_command argument set to False (default) and a chosen separator.
    When:
        - Calling `reformate_args` with each of the separators options.
    Then:
        - Verify that commands_list split by the chosen separator.
    """
    args = {
        "command": f"dir{separator}hostname",
        "is_raw_command": False,
        "command_separator": separator,
    }
    reformatted_args = core_execute_command_reformat_args(args)
    params = json.loads(reformatted_args["parameters"])
    assert params["commands_list"] == ["dir", "hostname"]


def test_reformat_args_powershell_command_formatting():
    """
    Given:
        - command_type argument set to powershell.
    When:
        - Calling `reformate_args` with command_type=powershell.
    Then:
        - Verify command at commands_list reformated from 'command' to 'powershell -Command "command"'.
    """
    args = {
        "command": "Get-Process",
        "command_type": "powershell",
        "is_raw_command": True,
    }
    reformatted_args = core_execute_command_reformat_args(args)
    params = json.loads(reformatted_args["parameters"])
    assert params["commands_list"] == ['powershell -Command "Get-Process"']


def test_reformat_output():
    """
    Given:
        - Response from polling command.
    When:
        - Calling `reformat_output` with response.
    Then:
        - Verify output unify all duplicated data.
        Instead of a list with element for each commmand, we'll have an element for each endpoint.
    """
    from CortexCoreIR import core_execute_command_reformat_outputs

    mock_res = CommandResults(
        outputs_prefix="val",
        outputs=load_test_data("./test_data/execute_command_response.json"),
    )
    reformatted_outputs = core_execute_command_reformat_outputs([mock_res])
    excepted_output = [
        {
            "endpoint_name": "name",
            "endpoint_ip_address": ["2.2.2.2"],
            "endpoint_status": "STATUS_010_CONNECTED",
            "domain": "domain.name",
            "endpoint_id": "dummy_id",
            "executed_command": [
                {
                    "command": "echo",
                    "failed_files": 0,
                    "retention_date": None,
                    "retrieved_files": 0,
                    "standard_output": "output",
                    "command_output": [],
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                },
                {
                    "command": "echo hello",
                    "failed_files": 0,
                    "retention_date": None,
                    "retrieved_files": 0,
                    "standard_output": "outputs",
                    "command_output": ["hello"],
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                },
            ],
        },
        {
            "endpoint_name": "name2",
            "endpoint_ip_address": ["11.11.11.11"],
            "endpoint_status": "STATUS_010_CONNECTED",
            "domain": "",
            "endpoint_id": "dummy_id2",
            "executed_command": [
                {
                    "command": "echo",
                    "failed_files": 0,
                    "retention_date": None,
                    "retrieved_files": 0,
                    "standard_output": "out",
                    "command_output": [],
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                },
                {
                    "command": "echo hello",
                    "failed_files": 0,
                    "retention_date": None,
                    "retrieved_files": 0,
                    "standard_output": "output",
                    "command_output": ["hello"],
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                },
            ],
        },
        {
            "endpoint_name": "name3",
            "endpoint_ip_address": ["11.11.11.11"],
            "endpoint_status": "STATUS_020_CONNECTED",
            "domain": "",
            "endpoint_id": "dummy_id3",
            "executed_command": [
                {
                    "failed_files": 0,
                    "retention_date": None,
                    "retrieved_files": 0,
                    "standard_output": "output",
                    "execution_status": "COMPLETED_SUCCESSFULLY",
                    "command_output": None,
                    "command": None,
                }
            ],
        },
    ]
    assert reformatted_outputs == excepted_output


def test_reformat_readable():
    """
    Given:
        - Response from polling command.
    When:
        - Calling `reformat_readable_output` with response.
    Then:
        - Verify readable_output show the relevant data.
        Instead of a row for each endpoint, we'll have a row for each command.
    """
    from CortexCoreIR import core_execute_command_reformat_readable_output

    mock_res = CommandResults(
        outputs_prefix="val",
        outputs=load_test_data("./test_data/execute_command_response.json"),
    )
    reformatted_readable_output = core_execute_command_reformat_readable_output([mock_res])
    excepted_output = """### Script Execution Results for Action ID: 1
|Endpoint Id|Command|Command Output|Endpoint Ip Address|Endpoint Name|Endpoint Status|
|---|---|---|---|---|---|
| dummy_id | echo |  | 2.2.2.2 | name | STATUS_010_CONNECTED |
| dummy_id | echo hello | hello | 2.2.2.2 | name | STATUS_010_CONNECTED |
| dummy_id2 | echo |  | 11.11.11.11 | name2 | STATUS_010_CONNECTED |
| dummy_id2 | echo hello | hello | 11.11.11.11 | name2 | STATUS_010_CONNECTED |
| dummy_id3 |  |  | 11.11.11.11 | name3 | STATUS_020_CONNECTED |
"""
    assert reformatted_readable_output == excepted_output


@pytest.mark.parametrize("result", load_test_data("./test_data/execute_command_response.json")["results"])
def test_reformat_command_data(result):
    """
    Given:
        - Response from polling command.
    When:
        - Calling `core_execute_command_reformat_command_data` with response.
    Then:
        - Verify function output removes the underscore prefix from the command name.
    """
    from CortexCoreIR import core_execute_command_reformat_command_data

    reformatted_command_data = core_execute_command_reformat_command_data(result)

    assert not str(reformatted_command_data["command"]).startswith("_")


@freeze_time("2024-01-01T12:00:00Z")
def test_parse_expiration_date():
    """
    Given:
        - an expiration to representing a date be parsed.
    When:
        - Calling `parse_expiration_date`.
    Then:
        - Verify that parsed date comes back as expected.
    """
    from CortexCoreIR import parse_expiration_date

    def get_epoch_millis(dt: datetime) -> int:
        """Convert datetime to epoch milliseconds."""
        return int(dt.timestamp() * 1000)

    fixed_now = datetime(2024, 1, 1, 12, 0, 0)
    fixed_now_epoch_milli = get_epoch_millis(fixed_now)

    # Case 1: Epoch time in the past
    epoch_past = fixed_now_epoch_milli - 100000
    result = parse_expiration_date(str(epoch_past))
    assert result == epoch_past

    # Case 2: Epoch time in the future
    epoch_future = fixed_now_epoch_milli + 100000
    result = parse_expiration_date(str(epoch_future))
    assert result == epoch_future

    # Case 3: Relative time: "3 days"
    result = parse_expiration_date("3 days")
    expected = get_epoch_millis(fixed_now + timedelta(days=3))
    assert result == expected  # Tolerance of a few seconds

    # Case 4: ISO time in the past
    iso_past = "2023-12-31T12:00:00"
    iso_past_epoch = get_epoch_millis(datetime(2023, 12, 31, 12, 0, 0))
    result = parse_expiration_date(iso_past)
    assert result == iso_past_epoch

    # Case 5: ISO time in the future
    iso_future = "2024-01-03T12:00:00"
    iso_future_epoch = get_epoch_millis(datetime(2024, 1, 3, 12, 0, 0))
    result = parse_expiration_date(iso_future)
    assert result == iso_future_epoch

    # Case 6: "Never"
    result = parse_expiration_date("Never")
    assert result == "Never"

    # Case 7: "Broken Never"
    result = parse_expiration_date("never")
    assert result == "Never"

    # Case 8: "Broken String"
    result = parse_expiration_date("brokenstring")
    assert result == "brokenstring"

    # Case 9: None
    result = parse_expiration_date(None)
    assert result is None


def test_prepare_ioc_to_output():
    """
    Given:
        - an ioc params that had been sent to XSIAM create IOC API.
    When:
        - Calling `prepare_ioc_to_output`.
    Then:
        - Verify that parsed data come back as dictionary to be sent to XSIAM Context.
    """

    from CortexCoreIR import prepare_ioc_to_output

    # Case 1: input_format is JSON → return as-is
    json_input = {"indicator": "1.2.3.4", "type": "IP", "severity": "HIGH"}
    assert prepare_ioc_to_output(json_input, "JSON") == json_input

    # Case 2: input_format is CSV → single vendor, return as dict
    csv_input_single_vendor = (
        "indicator,type,severity,expiration_date,comment,reputation,reliability,vendor.name,vendor.reliability,vendor.reputation,class\n"
        "1.2.3.4,IP,HIGH,1794894791000,test,SUSPICIOUS,D,VirusTotal,A,GOOD,Malware"
    )
    expected_output_single = {
        "indicator": "1.2.3.4",
        "type": "IP",
        "severity": "HIGH",
        "expiration_date": 1794894791000,
        "comment": "test",
        "reputation": "SUSPICIOUS",
        "reliability": "D",
        "class": "Malware",
        "vendors": [{"vendor_name": "VirusTotal", "reliability": "A", "reputation": "GOOD"}],
    }
    assert prepare_ioc_to_output(csv_input_single_vendor, "CSV") == expected_output_single

    # Case 3: input_format is CSV → multiple vendors, only last one taken
    csv_input_multi_vendor = (
        "indicator,type,severity,expiration_date,comment,reputation,reliability,"
        "vendor.name,vendor.reliability,vendor.reputation,"
        "vendor.name,vendor.reliability,vendor.reputation,class\n"
        "1.2.3.4,IP,HIGH,1794894791000,test,SUSPICIOUS,D,"
        "VirusTotalV3,A,GOOD,"
        "VirusTotalV5,B,SUSPICIOUS,Malware"
    )
    expected_output_multi = {
        "indicator": "1.2.3.4",
        "type": "IP",
        "severity": "HIGH",
        "expiration_date": 1794894791000,
        "comment": "test",
        "reputation": "SUSPICIOUS",
        "reliability": "D",
        "class": "Malware",
        "vendors": [
            {
                "vendor_name": "VirusTotalV5",
                "reliability": "B",
                "reputation": "SUSPICIOUS",
            }
        ],
    }
    assert prepare_ioc_to_output(csv_input_multi_vendor, "CSV") == expected_output_multi


def get_mock_client():
    return Client(
        base_url="https://example.com",
        proxy=False,
        verify=False,
        headers={"Authorization": "Bearer dummy"},
        timeout=10,
    )


class TestCoreAddIndicator:
    def test_core_add_indicator_rule_json(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command.
        When:
            - Calling `core_add_indicator_rule`.
            - Receiving successful response.
        Then:
            - Verify that results were correctly parsed.
            - Verify that the API call was sent with the correct params.
        """

        client = get_mock_client()
        mock_post = mocker.patch.object(
            client,
            "create_indicator_rule_request",
            return_value={"reply": {"success": True, "validation_errors": []}},
        )

        args = {
            "indicator": "1.2.3.4",
            "type": "IP",
            "severity": "HIGH",
            "expiration_date": "3 days",
            "comment": "test comment",
            "reputation": "SUSPICIOUS",
            "reliability": "A",
            "class": "Malware",
            "vendor_name": "VirusTotal",
            "vendor_reliability": "A",
            "vendor_reputation": "GOOD",
            "input_format": "JSON",
        }

        result = core_add_indicator_rule_command(client, args)

        assert isinstance(result, CommandResults)
        assert "1.2.3.4" in result.readable_output
        assert result.outputs["indicator"] == "1.2.3.4"
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        assert kwargs["suffix"] == "indicators/insert_jsons"

    def test_core_add_indicator_rule_success_minimal_args(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command - the minimal required arguments.
        When:
            - Calling `core_add_indicator_rule`.
            - Receiving successful response.
        Then:
            - Verify that results were correctly parsed.
        """
        client = get_mock_client()
        mocker.patch.object(
            client,
            "create_indicator_rule_request",
            return_value={"reply": {"success": True, "validation_errors": []}},
        )

        args = {"indicator": "example.com", "type": "DOMAIN_NAME", "severity": "LOW"}

        result = core_add_indicator_rule_command(client, args)
        assert isinstance(result, CommandResults)
        assert "example.com" in result.readable_output

    def test_core_add_indicator_rule_csv(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command.
            - IOC object argument
        When:
            - Calling `core_add_indicator_rule`.
            - Receiving successful response.
        Then:
            - Verify that results were correctly parsed.
            - Verify that the API call was sent with the correct params.
        """
        client = get_mock_client()
        mock_post = mocker.patch.object(
            client,
            "create_indicator_rule_request",
            return_value={"reply": {"success": True, "validation_errors": []}},
        )

        csv_payload = (
            "indicator,type,severity,expiration_date,comment,reputation,reliability,vendor.name,vendor.reliability,vendor.reputation"
            ",class\\n"
            "1.2.3.4,IP,HIGH,1794894791000,test,SUSPICIOUS,D,VirusTotal,A,GOOD,Malware"
        )

        args = {
            "ioc_object": csv_payload,
            "input_format": "CSV",
            "indicator": "ignored",
            "type": "ignored",
            "severity": "ignored",
        }

        result = core_add_indicator_rule_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["indicator"] == "1.2.3.4"
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        assert kwargs["suffix"] == "indicators/insert_csv"

    def test_core_add_indicator_rule_ioc_object_precedence(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command.
            - IOC object argument
        When:
            - Calling `core_add_indicator_rule`.
            - Receiving successful response.
        Then:
            - Verify that results were correctly parsed.
            - Verify that the API call was sent with the correct params.
        """
        client = get_mock_client()
        mock_post = mocker.patch.object(
            client,
            "create_indicator_rule_request",
            return_value={"reply": {"success": True, "validation_errors": []}},
        )

        args = {
            "ioc_object": '{"indicator": "5.5.5.5", "type": "IP", "severity": "LOW"}',
            "input_format": "JSON",
            "indicator": "should_not_use_this",
            "type": "should_not_use_this",
            "severity": "should_not_use_this",
        }

        result = core_add_indicator_rule_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["indicator"] == "5.5.5.5"
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        assert kwargs["suffix"] == "indicators/insert_jsons"

    def test_core_add_indicator_rule_invalid_ioc_object_raises_error(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command.
            - IOC object argument malformed
        When:
            - Calling `core_add_indicator_rule`.
        Then:
            - Verify an error has been raised and that the error message is correct.
        """
        client = get_mock_client()
        args = {"ioc_object": "not a json or csv string"}
        with pytest.raises(
            DemistoException,
            match="Core Add Indicator Rule Command: The IOC object provided isn't in a valid JSON format.",
        ):
            core_add_indicator_rule_command(client, args)

    def test_core_add_indicator_rule_failure_response(self, mocker):
        """
        Given:
            - A mock Client to make API calls.
            - Arguments for the command.
        When:
            - Calling `core_add_indicator_rule`.
            - Receiving bad response.
        Then:
            - Verify an error has been raised and that the error message is correct.
        """
        client = get_mock_client()
        mock_post = mocker.patch.object(
            client,
            "create_indicator_rule_request",
            return_value={
                "reply": {
                    "success": False,
                    "validation_errors": [
                        {"indicator": "dummy", "error": "error1"},
                        {"indicator": "dummy", "error": "error2"},
                    ],
                }
            },
        )

        args = {"indicator": "dummy", "type": "IP", "severity": "HIGH"}

        with pytest.raises(DemistoException) as exc_info:
            core_add_indicator_rule_command(client, args)

        assert "Core Add Indicator Rule Command: post of IOC rule failed: error1, error2" in str(exc_info.value)
        mock_post.assert_called_once()


class TestClientBlockIP:
    @pytest.fixture
    def client(self):
        return Client(base_url="", headers={})

    def test_block_ip_request_disconnected(self, mocker, client):
        """
        Given:
            - client.block_ip_request called with all args.
        When:
            - No endpoint exists with that id.
        Then:
            - group_id of the actions are None
        """
        mocker.patch.object(client, "get_endpoints", return_value=[])

        ips = ["1.1.1.1", "2.2.2.2"]
        results = client.block_ip_request("endpoint_id", ips, 300)

        assert results == [
            {"ip_address": "1.1.1.1", "group_id": None, "endpoint_id": "endpoint_id"},
            {"ip_address": "2.2.2.2", "group_id": None, "endpoint_id": "endpoint_id"},
        ]

    def test_block_ip_request_success(self, mocker, client):
        """
        Given:
            - client.block_ip_request called with all args.
        When:
            - Endpoint exists and running.
        Then:
            - the appropriate list returned.
        """
        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "_http_request",
            return_value={"reply": {"group_action_id": "gid-123"}},
        )

        results = client.block_ip_request("endpoint_id", ["3.3.3.3", "4.4.4.4"], 123)
        assert results == [
            {
                "ip_address": "3.3.3.3",
                "group_id": "gid-123",
                "endpoint_id": "endpoint_id",
            },
            {
                "ip_address": "4.4.4.4",
                "group_id": "gid-123",
                "endpoint_id": "endpoint_id",
            },
        ]

    def test_fetch_block_status_disconnected(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - Endpoint disconnected.
        Then:
            - The status returned is Failure with Endpoint Disconnected message.
        """
        mocker.patch.object(client, "get_endpoints", return_value=[])

        status, msg = client.fetch_block_status("gid123", "endpoint_id")

        assert status == "Failure"
        assert msg == "Endpoint Disconnected"

    def test_fetch_block_status_group_id_none(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - group_id is none.
        Then:
            - The status returned is Failure with Endpoint Disconnected message.
        """
        mocker.patch.object(client, "get_endpoints", return_value=[])

        status, msg = client.fetch_block_status(None, "endpoint_id")

        assert status == "Failure"
        assert msg == "Endpoint Disconnected"

    def test_fetch_block_status_failed_with_errorText(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - Action failed due to internal error and returned FAILED.
        Then:
            - The status returned is Failure with the returned message.
        """
        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "action_status_get",
            return_value={
                "data": {"endpoint_id": "FAILED"},
                "errorReasons": {"endpoint_id": {"errorText": "Error Message"}},
            },
        )

        status, msg = client.fetch_block_status(100, "endpoint_id")

        assert status == "Failure"
        assert msg == "Error Message"

    def test_fetch_block_status_failed_without_errorText(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - Action failed due to internal error and returned FAILED.
            - No message in errorText.
        Then:
            - The status returned is Failure with the "Unknown error" message.
        """
        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "action_status_get",
            return_value={
                "data": {"endpoint_id": "FAILED"},
                "errorReasons": {"endpoint_id": {}},
            },
        )
        status, msg = client.fetch_block_status(100, "endpoint_id")
        assert status == "Failure"
        assert msg == "Unknown error"

    def test_fetch_block_status_success(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - Action Success.
        Then:
            - The status returned is Success without message.
        """
        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "action_status_get",
            return_value={"data": {"endpoint_id": "COMPLETED_SUCCESSFULLY"}},
        )
        status, msg = client.fetch_block_status(100, "endpoint_id")
        assert status == "Success"
        assert msg == ""

    def test_fetch_block_status_unknown(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - Action in progress.
        Then:
            - The status returned is IN_PROGRESS without message.
        """
        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "action_status_get",
            return_value={"data": {"endpoint_id": "IN_PROGRESS"}},
        )
        status, msg = client.fetch_block_status(100, "endpoint_id")
        assert status == "IN_PROGRESS"
        assert msg == ""

    def test_fetch_block_error_code_message(self, mocker, client):
        """
        Given:
            - client.fetch_block_status called.
        When:
            - ip address already blocked and server return error code -197
        Then:
            - The status returned is Failure with the right message.
        """
        from CortexCoreIR import ERROR_CODE_MAP

        mocker.patch.object(client, "get_endpoints", return_value="Connected")
        mocker.patch.object(
            client,
            "_http_request",
            return_value={
                "reply": {
                    "data": {"endpoint_id": "FAILED"},
                    "errorReasons": {
                        "endpoint_id": {
                            "errorData": '{"reportIds":["11"],"errorText":"Failed blocking IP address with error code -197\\n"}'
                        }
                    },
                }
            },
        )
        status, msg = client.fetch_block_status(100, "endpoint_id")
        assert status == "Failure"
        assert msg == ERROR_CODE_MAP[-197]


class DummyClient:
    """
    Test-double for the Integration Client.
    Initialized with:
      - status_map: dict mapping (group_id, endpoint_id) to (status, message)
      - block_map: dict mapping endpoint_id to list of action dicts
    fetch_block_status and block_ip_request delegate to those maps.
    """

    def __init__(self, status_map=None, block_map=None):
        self.status_map = status_map or {}
        self.block_map = block_map or {}

    def fetch_block_status(self, group_id, endpoint_id):
        return self.status_map.get((group_id, endpoint_id), ("Unknown", ""))

    def block_ip_request(self, endpoint_id, ip_list, duration):
        return self.block_map.get(endpoint_id, [])


class TestBlockIp:
    def test_polling_all_success(self):
        """
        Given:
            - A blocked_list with one action (gid1 on endpoint_id1).
        When:
            - polling_block_ip_status returns Success for that action.
        Then:
            - polling stops and outputs include the success reason.
        """
        args = {
            "blocked_list": [
                {
                    "endpoint_id": "endpoint1",
                    "group_id": "gid1",
                    "ip_address": "1.1.1.1",
                }
            ]
        }
        client = DummyClient(status_map={("gid1", "endpoint1"): ("Success", "")})

        pollRequest: PollResult = polling_block_ip_status(args, client)

        assert pollRequest.continue_to_poll is False
        assert isinstance(pollRequest.response, CommandResults)
        assert pollRequest.response.outputs == [{"ip_address": "1.1.1.1", "endpoint_id": "endpoint1", "reason": "Success"}]
        assert pollRequest.args_for_next_run == args

    def test_polling_failure(self):
        """
        Given:
            - A blocked_list with one action (gid1 on endpoint1).
        When:
            - polling_block_ip_status returns Failure with a message.
        Then:
            - polling stops and outputs include the failure reason and message.
        """
        args = {
            "blocked_list": [
                {
                    "endpoint_id": "endpoint1",
                    "group_id": "gid1",
                    "ip_address": "1.1.1.1",
                }
            ]
        }
        client = DummyClient(status_map={("gid1", "endpoint1"): ("Failure", "Network unreachable")})

        pollRequest = polling_block_ip_status(args, client)

        assert pollRequest.continue_to_poll is False
        assert pollRequest.response.outputs == [
            {
                "ip_address": "1.1.1.1",
                "endpoint_id": "endpoint1",
                "reason": "Failure: Network unreachable",
            }
        ]
        assert pollRequest.args_for_next_run == args

    def test_polling_continue(self):
        """
        Given:
            - A blocked_list with one action.
        When:
            - polling_block_ip_status returns a non-terminal status.
        Then:
            - polling continues with partial results.
        """
        args = {
            "blocked_list": [
                {
                    "endpoint_id": "endpoint1",
                    "group_id": "gid1",
                    "ip_address": "1.1.1.1",
                }
            ]
        }
        client = DummyClient(status_map={("gid1", "endpoint1"): ("PENDING", "Still working")})

        pollRequest = polling_block_ip_status(args, client)

        assert pollRequest.continue_to_poll is True
        assert pollRequest.response is None
        assert isinstance(pollRequest.partial_result, CommandResults)
        assert pollRequest.args_for_next_run == args

    def test_polling_empty_queue(self):
        """
        Given:
            - An empty blocked_list.
        When:
            - polling_block_ip_status is invoked.
        Then:
            - polling stops immediately with empty outputs.
        """
        args = {"blocked_list": []}
        client = DummyClient()

        pollRequest = polling_block_ip_status(args, client)

        assert pollRequest.continue_to_poll is False
        assert isinstance(pollRequest.response, CommandResults)
        assert pollRequest.response.outputs == []
        assert pollRequest.args_for_next_run == args

    def test_core_block_ip_initial_call(self, mocker):
        """
        Given:
            - The command_block_ip function is being called first time.
            - block_ip_request will work for endpoint1 ip 1.1.1.1.
        When:
            - core_block_ip_command is called.
        Then:
            - client.block_ip_request is invoked exactly once.
            - results are passed to polling_block_ip_status.
        """
        calls = {}

        fake_poll_result = PollResult(
            response="Polling",
            continue_to_poll=False,
            args_for_next_run=None,
            partial_result=None,
        )

        def fake_poll(args, client):
            calls["args"] = args
            return fake_poll_result

        mocker.patch("CortexCoreIR.polling_block_ip_status", side_effect=fake_poll)

        block_map = {
            "endpoint1": [
                {
                    "endpoint_id": "endpoint1",
                    "group_id": "gid1",
                    "ip_address": "1.1.1.1",
                }
            ]
        }
        client = DummyClient(block_map=block_map)
        spy = mocker.spy(client, "block_ip_request")

        args = {
            "addresses": ["1.1.1.1"],
            "endpoint_list": "endpoint1",
            "duration": "123",
        }

        result = core_block_ip_command(args, client)

        assert result == "Polling"

        # polling_block_ip_status should see the merged blocked_list + original args
        expected_args = {"blocked_list": block_map["endpoint1"], **args}
        assert calls["args"] == expected_args

        spy.assert_called_once_with("endpoint1", ["1.1.1.1"], 123)

    def test_core_block_ip_subsequent_call(self, mocker):
        """
        Given:
            - The command_block_ip function is being called second time after the blocking requests.
        When:
            - core_block_ip_command was called adn the block requests worked and returned group id.
        Then:
            - client.block_ip_request is not being called.
            - The args are not being changed.
        """
        calls = {}

        fake_poll_result = PollResult(
            response="Polling",
            continue_to_poll=False,
            args_for_next_run=None,
            partial_result=None,
        )

        def fake_poll(a, c):
            calls["args"] = a
            return fake_poll_result

        mocker.patch("CortexCoreIR.polling_block_ip_status", side_effect=fake_poll)

        client = DummyClient()
        spy = mocker.spy(client, "block_ip_request")
        args = {
            "blocked_list": [
                {
                    "endpoint_id": "endpoint1",
                    "group_id": "gid1",
                    "ip_address": "1.1.1.1",
                }
            ],
        }

        result = core_block_ip_command(args, client)

        assert result == "Polling"
        # we get exactly the same args dict back
        assert calls["args"] == args
        assert spy.call_count == 0


def test_core_get_contributing_event(mocker):
    """
    Given:
        - A mock Client and alert ID
    When:
        - Calling `core-get-contributing-event`.
    Then:
        - Verify that results were correctly parsed.
    """
    client = get_mock_client()
    mocker.patch.object(
        client,
        "_http_request",
        return_value={
            "reply": {
                "events": [
                    {
                        "Logon_Type": "1",
                        "User_Name": "example",
                        "Domain": "domain",
                        "Source_IP": "1.1.1.1",
                        "Process_Name": "C:\\Windows\\System32\\example.exe",
                        "Host_Name": "WIN10X64",
                        "Raw_Message": "An account was successfully logged on.",
                        "_time": 1652982800000,
                        "aaaaaa": "111111",
                        "bbbbbb": 1652982800000,
                        "cccccc": "222222",
                        "dddddd": 2,
                        "eeeeee": 1,
                        "insert_timestamp": 1652982800001,
                        "_vendor": "PANW",
                        "_product": "XDR agent",
                    }
                ]
            }
        },
    )

    args = {
        "alert_ids": "1",
    }

    result = core_get_contributing_event_command(client, args)

    assert isinstance(result, CommandResults)
    assert "Contributing events" in result.readable_output
    assert result.outputs[0]["alertID"] == "1"


def test_update_endpoints_tags_command_with_both_add_and_remove():
    """
    Given:
        - A client with mock add_tag_endpoint and remove_tag_endpoint methods
        - Endpoint IDs and both tags to add and tags to remove
    When:
        - update_endpoints_tags_command is called
    Then:
        - Tags are successfully added and removed
        - Results contain success message with added and removed tags
    """
    from unittest.mock import Mock, patch

    client = Mock()
    client.add_tag_endpoint.return_value = {"reply": "true"}
    client.remove_tag_endpoint.return_value = {"reply": "true"}

    args = {
        "endpoint_ids": ["endpoint1", "endpoint2"],
        "tags_to_add": ["tag1", "tag2"],
        "tags_to_remove": ["tag3", "tag4"],
    }

    with patch("CoreIRApiModule.filter_invalid_tags", return_value=[]):
        from CortexCoreIR import update_endpoints_tags_command

        results = update_endpoints_tags_command(client, args)

    assert len(results) == 1
    assert "Successfully updated tags for endpoint(s)" in results[0].readable_output
    assert "Added tags: ['tag1', 'tag2']" in results[0].readable_output
    assert "Removed tags: ['tag3', 'tag4']" in results[0].readable_output

    client.add_tag_endpoint.assert_any_call(endpoint_ids=["endpoint1", "endpoint2"], tag="tag1", args=args)
    client.add_tag_endpoint.assert_any_call(endpoint_ids=["endpoint1", "endpoint2"], tag="tag2", args=args)
    client.remove_tag_endpoint.assert_any_call(endpoint_ids=["endpoint1", "endpoint2"], tag="tag3", args=args)
    client.remove_tag_endpoint.assert_any_call(endpoint_ids=["endpoint1", "endpoint2"], tag="tag4", args=args)


def test_update_endpoints_tags_command_with_invalid_tags():
    """
    Given:
        - A client with mock add_tag_endpoint method
        - Endpoint IDs and tags including invalid ones
    When:
        - update_endpoints_tags_command is called
    Then:
        - Valid tags are processed successfully
        - Invalid tags are detected and reported
    """
    from unittest.mock import Mock, patch

    client = Mock()
    client.add_tag_endpoint.return_value = {"reply": "true"}

    args = {
        "endpoint_ids": ["endpoint1"],
        "tags_to_add": ["valid_tag", "invalid_tag_that_is_too_long"],
        "tags_to_remove": [],
    }

    with patch(
        "CoreIRApiModule.filter_invalid_tags",
        side_effect=[["invalid_tag_that_is_too_long"], []],
    ):
        from CortexCoreIR import update_endpoints_tags_command

        results = update_endpoints_tags_command(client, args)

    assert len(results) == 2
    assert "Successfully updated tags" in results[0].readable_output
    assert "Invalid tags detected: invalid_tag_that_is_too_long" in results[1].readable_output
    assert results[1].entry_type == 4


def test_update_endpoints_tags_command_no_tags_provided():
    """
    Given:
        - A client and endpoint IDs
        - No tags to add or remove
    When:
        - update_endpoints_tags_command is called
    Then:
        - A DemistoException is raised indicating tags must be specified
    """
    from unittest.mock import Mock

    client = Mock()

    args = {"endpoint_ids": ["endpoint1"], "tags_to_add": [], "tags_to_remove": []}

    from CortexCoreIR import update_endpoints_tags_command

    with pytest.raises(DemistoException) as exc_info:
        update_endpoints_tags_command(client, args)

    assert "At least one tag to add or remove must be specified" in str(exc_info.value)
