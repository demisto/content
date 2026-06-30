"""Sanity tests for the MicrosoftGraphFilesStandardConnector shim integration.

Full behavioural coverage lives in the MicrosoftGraphFilesApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""
import pytest

import MicrosoftGraphFilesStandardConnector as integration_module


def test_shim_imports_run_entry_point():
    assert hasattr(integration_module, "run_microsoft_graph_files_integration"), \
        "MicrosoftGraphFilesApiModule.run_microsoft_graph_files_integration must be importable via the shim"


def test_shim_imports_client_class():
    assert hasattr(integration_module, "MsGraphClient")


def test_shim_imports_command_functions():
    for name in (
        "list_sharepoint_sites_command",
        "list_drive_content_command",
        "download_file_command",
        "upload_new_file_command",
    ):
        assert hasattr(integration_module, name), f"Command {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("MicrosoftGraphFilesStandardConnector.run_microsoft_graph_files_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch(
        "MicrosoftGraphFilesStandardConnector.run_microsoft_graph_files_integration",
        side_effect=RuntimeError("boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
