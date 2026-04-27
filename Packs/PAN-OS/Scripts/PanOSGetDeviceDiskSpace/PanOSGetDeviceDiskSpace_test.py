import pytest
from CommonServerPython import CommandResults

sample_response: list[dict] = [
    {
        "Category": "Builtin",
        "Type": 1,
        "ContentsFormat": "json",
        "Brand": "Builtin",
        "HumanReadable": "Command was executed successfully.",
        "Contents": {
            "response": {
                "@status": "success",
                "result": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/root       6.9G  5.0G  1.5G  78% /\n"
                "none             16G   76K   16G   1% /dev\n/dev/nvme0n1p5   16G  7.3G  7.8G  49% /opt/pancfg\n"
                "/dev/nvme0n1p6  7.9G  3.9G  3.6G  53% /opt/panrepo\ntmpfs           3.5G  2.9G  587M  84% /dev/shm\n"
                "cgroup_root      16G     0   16G   0% /cgroup\n/dev/nvme0n1p8   21G  1.4G   19G   7% /opt/panlogs",
            }
        },
    }
]


def test_show_disk_space_command(mocker):
    """
    Test that the function correctly constructs function call to get disk space
    """
    from PanOSGetDeviceDiskSpace import show_disk_space_command

    mock_execute_command = mocker.patch("PanOSGetDeviceDiskSpace.demisto.executeCommand", return_value=True)

    mocker.patch("PanOSGetDeviceDiskSpace.is_error", return_value=False)

    # Test with 'target' and 'panos_instance_name' arguments set
    args = {"target": "device1", "panos_instance_name": "PAN-OS_instance"}
    show_disk_space_command(args)
    command_call_args = mock_execute_command.call_args[0][1]
    assert command_call_args == {
        "target": "device1",
        "cmd": "<show><system><disk-space></disk-space></system></show>",
        "type": "op",
        "using": "PAN-OS_instance",
    }

    # Test with 'target' set but not 'panos_instance_name'
    args = {"target": "device1"}
    show_disk_space_command(args)
    command_call_args = mock_execute_command.call_args[0][1]
    assert command_call_args == {
        "target": "device1",
        "cmd": "<show><system><disk-space></disk-space></system></show>",
        "type": "op",
    }


@pytest.mark.parametrize(
    ("original_value", "desired_units", "expected_result"),
    [
        ("5G", "M", 5120.0),
        ("5.5T", "T", 5.5),
        ("1024M", "G", 1.0),
    ],
)
def test_convert_space_units(original_value, desired_units, expected_result, mocker):
    """
    Test that the function correctly converts disk space units correctly
    """
    from PanOSGetDeviceDiskSpace import convert_space_units

    result = convert_space_units(original_value, desired_units)
    assert result == pytest.approx(expected_result, rel=1e-6)


def test_parse_disk_space_output(mocker):
    """
    Test that the function correctly parses details from a sample disk space string and formats the result correctly.
    """
    from PanOSGetDeviceDiskSpace import parse_disk_space_output

    result = parse_disk_space_output(sample_response[0]["Contents"]["response"]["result"], "M")

    expected_result = [
        {
            "FileSystem": "/dev/root",
            "Size": 7065.6,
            "Used": 5120.0,
            "Avail": 1536.0,
            "Use%": "78%",
            "MountedOn": "/",
            "Units": "M",
        },
        {"FileSystem": "none", "Size": 16384.0, "Used": 0.1, "Avail": 16384.0, "Use%": "1%", "MountedOn": "/dev", "Units": "M"},
        {
            "FileSystem": "/dev/nvme0n1p5",
            "Size": 16384.0,
            "Used": 7475.2,
            "Avail": 7987.2,
            "Use%": "49%",
            "MountedOn": "/opt/pancfg",
            "Units": "M",
        },
        {
            "FileSystem": "/dev/nvme0n1p6",
            "Size": 8089.6,
            "Used": 3993.6,
            "Avail": 3686.4,
            "Use%": "53%",
            "MountedOn": "/opt/panrepo",
            "Units": "M",
        },
        {
            "FileSystem": "tmpfs",
            "Size": 3584.0,
            "Used": 2969.6,
            "Avail": 587.0,
            "Use%": "84%",
            "MountedOn": "/dev/shm",
            "Units": "M",
        },
        {
            "FileSystem": "cgroup_root",
            "Size": 16384.0,
            "Used": 0,
            "Avail": 16384.0,
            "Use%": "0%",
            "MountedOn": "/cgroup",
            "Units": "M",
        },
        {
            "FileSystem": "/dev/nvme0n1p8",
            "Size": 21504.0,
            "Used": 1433.6,
            "Avail": 19456.0,
            "Use%": "7%",
            "MountedOn": "/opt/panlogs",
            "Units": "M",
        },
    ]

    assert result == expected_result


def test_get_disk_space(mocker):
    """Test the main get_disk_space function"""
    from PanOSGetDeviceDiskSpace import get_disk_space

    # Mock the show_disk_space_command function
    mocker.patch("PanOSGetDeviceDiskSpace.show_disk_space_command", return_value=sample_response)

    args = {"target": "device1", "disk_space_units": "G"}
    result = get_disk_space(args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "PANOS.DiskSpace"
    assert isinstance(result.outputs, dict)
    assert result.outputs["hostid"] == "device1"
    assert "FileSystems" in result.outputs


def test_show_disk_space_command_error_handling(mocker):
    """Test error handling in show_disk_space_command"""
    from PanOSGetDeviceDiskSpace import show_disk_space_command

    mocker.patch("PanOSGetDeviceDiskSpace.demisto.executeCommand", return_value=True)
    mocker.patch("PanOSGetDeviceDiskSpace.is_error", return_value=True)
    mocker.patch("PanOSGetDeviceDiskSpace.get_error", return_value="Test error")

    args = {"target": "device1"}

    with pytest.raises(Exception, match="Error executing pan-os: Test error"):
        show_disk_space_command(args)
