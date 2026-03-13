import os
from unittest.mock import patch

from PrintEnvironmentDetails import get_environment_details


def test_get_environment_details():
    """Test that get_environment_details returns correct UID, GID, and PWD."""
    with patch.object(os, "getuid", return_value=4321), \
         patch.object(os, "getgid", return_value=8765), \
         patch.object(os, "getcwd", return_value="/home/demisto"):

        result = get_environment_details()

        assert result.outputs["UID"] == 4321
        assert result.outputs["GID"] == 8765
        assert result.outputs["PWD"] == "/home/demisto"
        assert "Environment Details" in result.readable_output
        assert "4321" in result.readable_output
        assert "8765" in result.readable_output
        assert "/home/demisto" in result.readable_output
