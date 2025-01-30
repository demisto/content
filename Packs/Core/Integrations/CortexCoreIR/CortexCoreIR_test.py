import json
from unittest.mock import MagicMock

import pytest

from CommonServerPython import CommandResults

Core_URL = 'https://api.xdrurl.com'


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
    from CortexCoreIR import report_incorrect_wildfire_command, Client
    wildfire_response = load_test_data('./test_data/wildfire_response.json')
    mock_client = Client(base_url=f'{Core_URL}/public_api/v1', headers={})
    mocker.patch.object(mock_client, 'report_incorrect_wildfire', return_value=wildfire_response)
    file_hash = "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
    args = {
        "email": "a@a.gmail.com",
        "file_hash": file_hash,
        "new_verdict": 0,
        "reason": "test1"
    }
    res = report_incorrect_wildfire_command(client=mock_client, args=args)
    assert res.readable_output == f'Reported incorrect WildFire on {file_hash}'


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
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('domain'))
        res = handle_prevalence_command(mock_client, 'core-get-domain-analytics-prevalence',
                                        {'domain': 'some_name'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('domain_name') == 'some_name'

    def test_get_ip_analytics(self, mocker):
        """
            Given:
                - An Ip address.
            When:
                - Calling handle_prevalence_command as part of core-get-IP-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('ip'))
        res = handle_prevalence_command(mock_client, 'core-get-IP-analytics-prevalence',
                                        {'ip': 'some ip'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('ip_address') == 'some_ip'

    def test_get_registry_analytics(self, mocker):
        """
            Given:
                - A registry name.
            When:
                - Calling handle_prevalence_command as part of core-get-registry-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('registry'))
        res = handle_prevalence_command(mock_client, 'core-get-registry-analytics-prevalence',
                                        {'key_name': 'some key', 'value_name': 'some value'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('key_name') == 'some key'

    def test_blocklist_files_command(self, mocker):
        """
            Given:
                - An hash list and incident ID.
            When:
                - Calling blocklist_files_command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import blocklist_files_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        args = {'incident_id': '1', 'hash_list': ['hash']}

        error_message = '[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:' \
            'request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: ' \
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": ' \
            '"All hashes have already been added to the allow or block list"}}\n'
        mocker.patch.object(mock_client, '_http_request', side_effect=Exception(error_message))
        mocker.patch('CoreIRApiModule.validate_sha256_hashes', return_value='')

        res = blocklist_files_command(mock_client, args)
        assert res.readable_output == 'All hashes have already been added to the block list.'

    def test_allowlist_files_command(self, mocker):
        """
            Given:
                - An hash list and incident ID.
            When:
                - Calling allowlist_files_command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import allowlist_files_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        args = {'incident_id': '1', 'hash_list': ['hash']}

        error_message = '[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:' \
            'request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: ' \
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": ' \
            '"All hashes have already been added to the allow or block list"}}\n'
        mocker.patch.object(mock_client, '_http_request', side_effect=Exception(error_message))
        mocker.patch('CoreIRApiModule.validate_sha256_hashes', return_value='')

        res = allowlist_files_command(mock_client, args)
        assert res.readable_output == 'All hashes have already been added to the allow list.'


class TestPollingCommand:
    @staticmethod
    def create_mocked_responses(status_count):

        response_queue = [
            {
                "reply": {
                    "action_id": 1,
                    "status": 1,
                    "endpoints_count": 1
                }
            }
        ]

        for i in range(status_count):
            if i == status_count - 1:
                general_status = 'COMPLETED_SUCCESSFULLY'
            elif i < 2:
                general_status = 'PENDING'
            else:
                general_status = 'IN_PROGRESS'

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
                                "endpoint_ip_address": [
                                    "1.1.1.1"
                                ],
                                "endpoint_status": "STATUS_010_CONNECTED",
                                "domain": "aaaa",
                                "endpoint_id": "1",
                                "execution_status": "COMPLETED_SUCCESSFULLY",
                                "failed_files": 0,
                            }
                        ]
                    }
                }
            )

        return response_queue

    @pytest.mark.parametrize(argnames='status_count', argvalues=[1, 3, 7, 9, 12, 15])
    def test_script_run_command(self, mocker, status_count):
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
        from CoreIRApiModule import script_run_polling_command, CoreClient
        from CommonServerPython import ScheduledCommand

        client = CoreClient(base_url='https://test_api.com/public_api/v1', headers={})

        mocker.patch.object(client, '_http_request', side_effect=self.create_mocked_responses(status_count))
        mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

        command_result = script_run_polling_command(args={'endpoint_ids': '1', 'script_uid': '1'}, client=client)

        assert command_result.readable_output == "Waiting for the script to " \
                                                 "finish running on the following endpoints: ['1']..."
        assert command_result.outputs == {'action_id': 1, 'endpoints_count': 1, 'status': 1}

        polling_args = {
            'endpoint_ids': '1', 'script_uid': '1', 'action_id': '1', 'hide_polling_output': True, 'is_core': 'true'
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
            'action_id': 1,
            'results': [
                {
                    'endpoint_name': 'test endpoint',
                    'endpoint_ip_address': ['1.1.1.1'],
                    'endpoint_status': 'STATUS_010_CONNECTED',
                    'domain': 'aaaa',
                    'endpoint_id': '1',
                    'execution_status': 'COMPLETED_SUCCESSFULLY',
                    'failed_files': 0
                }
            ]
        }
        assert command_result[0].outputs_prefix == 'Core.ScriptResult'


def test_get_asset_details_command_success(mocker):
    """
    GIVEN:
        A mocked client and valid arguments with an asset ID.
    WHEN:
        The get_asset_details_command function is called.
    THEN:
        The response is parsed, formatted, and returned correctly.
    """
    from CortexCoreIR import get_asset_details_command, Client
    mock_client = Client(base_url="", headers={})
    mock_get_asset_details = mocker.patch.object(mock_client, '_http_request',
                                                 return_value={
                                                     "reply":
                                                     {"id": "1234", "name": "Test Asset"}})

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
        "integration_context_brand": "CoreIR"
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
        "integration_context_brand": "CortexCoreIR"
    }
    mocker.patch('CortexCoreIR.fileResult', return_value={
        'Contents': '',
        'ContentsFormat': 'text',
        'Type': 3,
        'File': 'xdr-agent-install-package.msi',
        'FileID': '11111'
    })
    result = get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "x64")
    client._http_request.assert_called_once_with(
        method="GET", full_url="https://example.com/distribution", resp_type="content"
    )
    assert isinstance(result, list)
    assert len(result) == 2
    command_result = result[1]
    assert isinstance(command_result, CommandResults)
    assert command_result.outputs == {"id": "12345", "url": "https://example.com/distribution"}
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
    from CoreIRApiModule import get_distribution_url_command
    from CommonServerPython import DemistoException
    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")

    args = {
        "distribution_id": "12345",
        "package_type": "sh",
        "download_package": "true",
        "integration_context_brand": "PaloAltoNetworksXDR"
    }
    with pytest.raises(DemistoException) as e:
        get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "sh")
    assert e.value.message == "`download_package` argument can be used only for package_type 'x64' or 'x86'."
