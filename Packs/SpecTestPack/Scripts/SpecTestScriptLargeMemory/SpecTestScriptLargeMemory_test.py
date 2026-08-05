import pytest
from SpecTestScriptLargeMemory import process_data

from CommonServerPython import DemistoException


class TestProcessData:
    def test_transform(self):
        result = process_data("hello world", "transform")
        assert result["Status"] == "completed"
        assert result["Data"] == "HELLO WORLD"
        assert result["OutputSize"] == 11

    def test_analyze(self):
        result = process_data("hello world", "analyze")
        assert result["Status"] == "completed"
        assert "length=11" in result["Data"]
        assert "words=2" in result["Data"]

    def test_aggregate(self):
        result = process_data("test data", "aggregate")
        assert result["Status"] == "completed"
        assert result["Data"] == "Aggregated: test data"

    def test_unknown_operation(self):
        with pytest.raises(DemistoException, match="Unknown operation"):
            process_data("data", "invalid_op")
