"""Sanity tests for the MicrosoftGraphFiles shim integration.

Full behavioural coverage lives in the MicrosoftGraphFilesApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""
import pytest

import MicrosoftGraphFiles


def test_shim_imports_run_entry_point():
    assert hasattr(MicrosoftGraphFiles, "run_microsoft_graph_files_integration"), \
        "MicrosoftGraphFilesApiModule.run_microsoft_graph_files_integration must be importable via the shim"


def test_shim_imports_client_class():
    assert hasattr(MicrosoftGraphFiles, "MsGraphClient")


def test_shim_imports_command_functions():
    for name in (
        "list_sharepoint_sites_command",
        "list_drive_content_command",
        "download_file_command",
        "upload_new_file_command",
    ):
        assert hasattr(MicrosoftGraphFiles, name), f"Command {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("MicrosoftGraphFiles.run_microsoft_graph_files_integration")
    MicrosoftGraphFiles.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch(
        "MicrosoftGraphFiles.run_microsoft_graph_files_integration",
        side_effect=RuntimeError("boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        MicrosoftGraphFiles.main()
