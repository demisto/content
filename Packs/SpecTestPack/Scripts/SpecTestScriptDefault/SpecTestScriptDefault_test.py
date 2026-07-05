import pytest
from SpecTestScriptDefault import process_data

from CommonServerPython import DemistoException


class TestProcessData:
    def test_echo(self):
        result = process_data("hello world", "echo")
        assert result["Status"] == "completed"
        assert result["Data"] == "hello world"

    def test_reverse(self):
        result = process_data("hello", "reverse")
        assert result["Status"] == "completed"
        assert result["Data"] == "olleh"

    def test_count(self):
        result = process_data("hello world", "count")
        assert result["Status"] == "completed"
        assert "characters=11" in result["Data"]
        assert "words=2" in result["Data"]

    def test_unknown_operation(self):
        with pytest.raises(DemistoException, match="Unknown operation"):
            process_data("data", "invalid_op")
