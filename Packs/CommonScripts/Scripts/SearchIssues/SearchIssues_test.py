from unittest.mock import MagicMock

from CommonServerPython import *
import pytest

from Packs.CommonScripts.Scripts.SearchIssues import SearchIssues
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
    expected = {"AND": [{"OR": [{"SEARCH_FIELD": "actor_process_image_sha256", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "abc123"}]}]}
    assert result == expected


def test_create_sha_search_field_query_multiple_values():
    result = create_sha_search_field_query("actor_process_image_sha256", EQ, ["abc123", "def456"])
    expected = {
        "AND": [
            {
                "OR": [
                    {"SEARCH_FIELD": "actor_process_image_sha256", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "abc123"},
                    {"SEARCH_FIELD": "actor_process_image_sha256", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "def456"},
                ]
            }
        ]
    }
    assert result == expected


def test_create_sha_search_field_query_empty_list():
    result = create_sha_search_field_query("actor_process_image_sha256", EQ, [])
    assert result is None


def test_prepare_sha256_custom_field_empty_input():
    args = {"sha256": None}
    result = prepare_sha256_custom_field(args)
    assert result is None


@pytest.mark.parametrize("sha_values", [["abc123", "xyz456"]])
def test_main_with_sha256_filter(monkeypatch, sha_values):
    expected_custom_filter = """{
  "OR": [
    {
      "AND": [
        {
          "OR": [
            {
              "SEARCH_FIELD": "actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "abc123"
            },
            {
              "SEARCH_FIELD": "actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "xyz456"
            }
          ]
        }
      ]
    },
    {
      "AND": [
        {
          "OR": [
            {
              "SEARCH_FIELD": "causality_actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "abc123"
            },
            {
              "SEARCH_FIELD": "causality_actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "xyz456"
            }
          ]
        }
      ]
    },
    {
      "AND": [
        {
          "OR": [
            {
              "SEARCH_FIELD": "action_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "abc123"
            },
            {
              "SEARCH_FIELD": "action_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "xyz456"
            }
          ]
        }
      ]
    },
    {
      "AND": [
        {
          "OR": [
            {
              "SEARCH_FIELD": "os_actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "abc123"
            },
            {
              "SEARCH_FIELD": "os_actor_process_image_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "xyz456"
            }
          ]
        }
      ]
    },
    {
      "AND": [
        {
          "OR": [
            {
              "SEARCH_FIELD": "action_file_macro_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "abc123"
            },
            {
              "SEARCH_FIELD": "action_file_macro_sha256",
              "SEARCH_TYPE": "EQ",
              "SEARCH_VALUE": "xyz456"
            }
          ]
        }
      ]
    }
  ]
}"""

    # Mock demisto.args()
    monkeypatch.setattr(
        SearchIssues.demisto,
        "args",
        lambda: {"sha256": ",".join(sha_values), "start_time": "2024-01-01", "end_time": "2024-01-02"},
    )

    # Mock demisto.executeCommand()
    fake_response = {
        "EntryContext": {
            "Core.Issue(val.internal_id && val.internal_id == obj.internal_id)": [{"internal_id": "test123", "severity": "high"}]
        },
        "HumanReadable": "Sample Issue Result",
        "Type": 1,
    }

    execute_command_mock = MagicMock(return_value=[fake_response])
    monkeypatch.setattr(SearchIssues.demisto, "executeCommand", execute_command_mock)

    # Mock demisto.debug and return_results
    monkeypatch.setattr(SearchIssues, "return_results", lambda x: x)
    monkeypatch.setattr(SearchIssues.demisto, "debug", lambda x: None)

    SearchIssues.main()

    # Ensure core-get-issues was called
    assert execute_command_mock.called, "core-get-issues was not called"

    # Get the actual args passed to core-get-issues
    called_args = execute_command_mock.call_args[0][1]  # [0] is args tuple, [1] is the args dict

    assert "custom_filter" in called_args, "custom_filter not found in args"

    expected_dict = json.loads(expected_custom_filter)
    actual_dict = json.loads(called_args["custom_filter"])

    assert actual_dict == expected_dict, "custom_filter structure does not match expected"
