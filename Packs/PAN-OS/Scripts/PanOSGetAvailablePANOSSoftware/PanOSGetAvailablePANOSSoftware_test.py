from PanOSGetAvailablePANOSSoftware import run_command, get_current_version_and_base_version, get_available_software
from CommonServerPython import *

sample_output = {
    "Summary": [
        {
            "current": False,
            "downloaded": False,
            "filename": "PanOS_vm-11.1.0",
            "hostid": "11111111111111111",
            "latest": False,
            "release_notes": "https://www.paloaltonetworks.com/documentation/11-1/pan-os/pan-os-release-notes",
            "size": "750",
            "size_kb": "768000",
            "uploaded": False,
            "version": "11.1.0",
        },
        {
            "current": False,
            "downloaded": False,
            "filename": "PanOS_vm-11.2.0",
            "hostid": "11111111111111111",
            "latest": False,
            "release_notes": "https://www.paloaltonetworks.com/documentation/11-2/pan-os/pan-os-release-notes",
            "size": "755",
            "size_kb": "773000",
            "uploaded": False,
            "version": "11.2.0",
        },
        {
            "current": True,
            "downloaded": True,
            "filename": "PanOS_vm-11.2.6",
            "hostid": "11111111111111111",
            "latest": False,
            "release_notes": "https://www.paloaltonetworks.com/documentation/11-2/pan-os/pan-os-release-notes",
            "size": "755",
            "size_kb": "773254",
            "uploaded": False,
            "version": "11.2.6",
        },
        {
            "current": False,
            "downloaded": False,
            "filename": "PanOS_vm-11.2.7",
            "hostid": "11111111111111111",
            "latest": True,
            "release_notes": "https://www.paloaltonetworks.com/documentation/11-2/pan-os/pan-os-release-notes",
            "size": "758",
            "size_kb": "777082",
            "uploaded": False,
            "version": "11.2.7",
        },
        {
            "current": False,
            "downloaded": False,
            "filename": "PanOS_vm-11.3.0",
            "hostid": "11111111111111111",
            "latest": False,
            "release_notes": "https://www.paloaltonetworks.com/documentation/11-3/pan-os/pan-os-release-notes",
            "size": "760",
            "size_kb": "778000",
            "uploaded": False,
            "version": "11.3.0",
        },
    ]
}

sample_command_result = CommandResults(
    outputs_prefix="PANOS.SoftwareVersions",
    outputs=sample_output,
    readable_output=tableToMarkdown("PAN-OS Available Software Versions", sample_output),
)


def test_run_command(mocker):
    """
    Test that the function correctly constructs function call to get available software
    and handles panos_instance_name argument conversion to 'using'
    """

    # Mock the demisto.executeCommand to return a sample response
    mock_execute_command = mocker.patch(
        "PanOSGetAvailablePANOSSoftware.demisto.executeCommand", return_value=sample_command_result
    )

    # Mock is_error to return False (no error)
    mocker.patch("PanOSGetAvailablePANOSSoftware.is_error", return_value=False)

    # Test with 'target', 'device_filter_string', and 'panos_instance_name' arguments set
    args = {"target": "device1", "device_filter_string": "filter123", "panos_instance_name": "PAN-OS_instance"}

    result = run_command(args)

    # Verify the command was called with correct arguments
    mock_execute_command.assert_called_once_with(
        "pan-os-platform-get-available-software",
        {"target": "device1", "device_filter_string": "filter123", "using": "PAN-OS_instance"},
    )

    # Assert return type is CommandResults
    assert isinstance(result, CommandResults)
    assert result.outputs == sample_output


def test_get_current_version_and_base_version():
    """
    Test that the function correctly identifies the current version and calculates its base version
    (e.g., if current version is 11.1.4, base version should be 11.1.0)
    """

    # Mock versions list with different scenarios
    versions = [
        {"version": "10.2.0", "current": False},
        {"version": "11.0.0", "current": False},
        {"version": "11.1.0", "current": False},
        {"version": "11.1.4", "current": True},  # Current version
        {"version": "11.2.0", "current": False},
    ]

    current_version, base_version = get_current_version_and_base_version(versions)

    # Assert current version is correctly identified
    assert current_version["version"] == "11.1.4"
    assert current_version["current"] == True  # noqa: E712

    # Assert base version is correctly calculated (11.1.4 -> 11.1.0)
    assert base_version["version"] == "11.1.0"
    assert base_version["current"] == False  # noqa: E712


def test_get_current_version_and_base_version_already_base():
    """
    Test that when current version is already a base version (ends with .0),
    it returns itself as the base version
    """

    # Mock versions list where current version is already a base version
    versions = [
        {"version": "10.2.0", "current": False},
        {"version": "11.0.0", "current": False},
        {"version": "11.1.0", "current": True},  # Current version is base version
        {"version": "11.2.0", "current": False},
    ]

    current_version, base_version = get_current_version_and_base_version(versions)

    # Assert current version is correctly identified
    assert current_version["version"] == "11.1.0"
    assert current_version["current"] == True  # noqa: E712

    # Assert base version is the same as current (11.1.0 -> 11.1.0)
    assert base_version["version"] == "11.1.0"
    assert base_version["current"] == True  # noqa: E712


def test_get_available_software_with_newer_images_only(mocker):
    """
    Test that when newer_images_only argument is passed as 'yes',
    the function correctly filters to show only newer versions than current
    """

    # Extended mock data with more versions including older and newer ones

    # Mock command result structure
    mock_command_result = [
        {
            "Contents": {"Summary": sample_output["Summary"]},
            "EntryContext": {"PANOS.SoftwareVersions": {"Summary": sample_output["Summary"]}},
        }
    ]

    # Mock the run_command function to return our extended sample
    mocker.patch("PanOSGetAvailablePANOSSoftware.run_command", return_value=mock_command_result)

    # Test with newer_images_only set to "yes"
    args = {"target": "device1", "newer_images_only": "yes"}

    result = get_available_software(args)

    # Extract the filtered versions from result
    filtered_versions = result[0]["Contents"]["Summary"]

    # Should include: current version (11.2.6), base version (11.2.0), and newer versions (11.2.7, 11.3.0)
    # Should exclude: older versions (11.1.0)
    expected_versions = ["11.2.6", "11.2.0", "11.2.7", "11.3.0"]
    actual_versions = [v["version"] for v in filtered_versions]

    # Assert that only expected versions are included
    assert len(filtered_versions) == 4
    assert all(version in actual_versions for version in expected_versions)
    assert "11.1.0" not in actual_versions  # Older version should be filtered out

    # Assert that current version is still marked as current
    current_version_in_result = next(v for v in filtered_versions if v["current"])
    assert current_version_in_result["version"] == "11.2.6"


def test_get_available_software_without_newer_images_only(mocker):
    """
    Test that when newer_images_only is not set to 'yes',
    all versions are returned without filtering
    """

    # Use the original sample output
    mock_command_result = [
        {
            "Contents": {"Summary": sample_output["Summary"]},
            "EntryContext": {"PANOS.SoftwareVersions": {"Summary": sample_output["Summary"]}},
        }
    ]

    # Mock the run_command function
    mocker.patch("PanOSGetAvailablePANOSSoftware.run_command", return_value=mock_command_result)

    # Test with newer_images_only set to "no" (or not set)
    args = {"target": "device1", "newer_images_only": "no"}

    result = get_available_software(args)

    # Should return unfiltered results
    assert result == mock_command_result
    assert len(result[0]["Contents"]["Summary"]) == 5
