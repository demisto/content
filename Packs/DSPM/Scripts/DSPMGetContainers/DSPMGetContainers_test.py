from DSPMGetContainers import get_containers
from CommonServerPython import CommandResults


def test_get_containers():
    args = {
        "asset_files": {
            "files": [
                {"path": "folder1/file1.txt"},
                {"path": "folder2/file2.txt"},
                {"path": "folder3/subfolder/file3.txt"},
            ]
        }
    }
    result = get_containers(args)

    # Assert
    expected_containers = ["folder1", "folder2", "folder3"]
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "containers"
    assert result.outputs == expected_containers
