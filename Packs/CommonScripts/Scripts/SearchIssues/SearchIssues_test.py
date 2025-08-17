from CommonServerPython import *
import pytest
import demistomock as demisto
from SearchIssues import *
from datetime import datetime
import dateparser
def test_prepare_start_end_time_end_time_without_start_time():
    """Test that providing end_time without start_time raises DemistoException."""
    args = {"end_time": "2023-01-01T12:00:00"}
    with pytest.raises(DemistoException, match="When end time is provided start_time must be provided as well."):
        prepare_start_end_time(args)

def test_prepare_start_end_time_valid_start_and_end_time():
    """Test that providing both valid start_time and end_time sets time_frame to custom."""
    args = {"start_time": "2023-01-01T10:00:00", "end_time": "2023-01-01T12:00:00"}
    prepare_start_end_time(args)
    assert args["time_frame"] == "custom"
    assert args["start_time"] == "2023-01-01T10:00:00"
    assert args["end_time"] == "2023-01-01T12:00:00"

def test_prepare_start_end_time_only_start_time_provided(mocker):
    """Test that providing only start_time sets end_time to current time."""
    args = {"start_time": "2023-01-01T10:00:00"}
    mock_datetime = mocker.patch('SearchIssues.datetime')
    mock_datetime.now.return_value = dateparser.parse("2023-01-01T15:00:00")
    prepare_start_end_time(args)
    assert args["time_frame"] == "custom"
    assert args["start_time"] == "2023-01-01T10:00:00"
    assert args["end_time"] == "2023-01-01T15:00:00"

def test_prepare_start_end_time_empty_strings():
    """Test that empty string values for start_time and end_time don't modify args."""
    args = {"start_time": "", "end_time": ""}
    original_args = args.copy()
    prepare_start_end_time(args)
    assert args == original_args

def test_prepare_start_end_time_no_time_parameters():
    """Test that missing start_time and end_time parameters don't modify args."""
    args = {"other_param": "value"}
    original_args = args.copy()
    prepare_start_end_time(args)
    assert args == original_args

def test_prepare_start_end_time_preserves_existing_args():
    """Test that existing arguments are preserved when setting time parameters."""
    args = {
        "start_time": "2023-01-01T10:00:00",
        "end_time": "2023-01-01T12:00:00",
        "existing_param": "existing_value",
        "another_param": 123
    }
    prepare_start_end_time(args)
    assert args["time_frame"] == "custom"
    assert args["start_time"] == "2023-01-01T10:00:00"
    assert args["end_time"] == "2023-01-01T12:00:00"
    assert args["existing_param"] == "existing_value"
    assert args["another_param"] == 123
