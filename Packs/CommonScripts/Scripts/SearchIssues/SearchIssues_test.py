from CommonServerPython import *
import pytest
from SearchIssues import *
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
    mock_datetime = mocker.patch("SearchIssues.datetime")
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
        "another_param": 123,
    }
    prepare_start_end_time(args)
    assert args["time_frame"] == "custom"
    assert args["start_time"] == "2023-01-01T10:00:00"
    assert args["end_time"] == "2023-01-01T12:00:00"
    assert args["existing_param"] == "existing_value"
    assert args["another_param"] == 123


def test_create_sha_search_field_query_single_value():
    result = create_sha_search_field_query("actor_process_image_sha256", EQ, ["abc123"])
    expected = {
        "AND": [{
            "OR": [
                {
                    "SEARCH_FIELD": "actor_process_image_sha256",
                    "SEARCH_TYPE": "EQ",
                    "SEARCH_VALUE": "abc123"
                }
            ]
        }]
    }
    assert result == expected


def test_create_sha_search_field_query_multiple_values():
    result = create_sha_search_field_query("actor_process_image_sha256", EQ, ["abc123", "def456"])
    expected = {
        "AND": [{
            "OR": [
                {
                    "SEARCH_FIELD": "actor_process_image_sha256",
                    "SEARCH_TYPE": "EQ",
                    "SEARCH_VALUE": "abc123"
                },
                {
                    "SEARCH_FIELD": "actor_process_image_sha256",
                    "SEARCH_TYPE": "EQ",
                    "SEARCH_VALUE": "def456"
                }
            ]
        }]
    }


def test_create_sha_search_field_query_empty_list():
    result = create_sha_search_field_query("actor_process_image_sha256", EQ, [])
    assert result is None


def test_prepare_sha256_custom_field_populates_custom_filter():
    args = {"sha256": ["hash1", "hash2"]}
    prepare_sha256_custom_field(args)
    assert "custom_filter" in args
    filter_obj = json.loads(args["custom_filter"])
    assert "OR" in filter_obj
    # Should contain queries for 2 equal fields + 3 contains fields = 5 queries
    assert len(filter_obj["OR"]) == 5


def test_prepare_sha256_custom_field_empty_input():
    args = {"sha256": None}
    result = prepare_sha256_custom_field(args)
    assert result is None
    assert "custom_filter" not in args


def test_prepare_sha256_custom_field_single_value_str():
    args = {"sha256": "onlyonehash"}
    prepare_sha256_custom_field(args)
    assert "custom_filter" in args
    filter_obj = json.loads(args["custom_filter"])
    assert len(filter_obj["OR"]) == 5


def test_prepare_sha256_custom_field_empty_list():
    args = {"sha256": ""}
    prepare_sha256_custom_field(args)
    assert "custom_filter" not in args
