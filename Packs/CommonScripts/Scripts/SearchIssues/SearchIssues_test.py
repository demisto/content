from unittest.mock import MagicMock

from CommonServerPython import *
import pytest

from Packs.CommonScripts.Scripts.SearchIssues import SearchIssues
from SearchIssues import *


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


@pytest.mark.parametrize(
    "args, expected",
    [
        # empty string values are dropped
        ({"status": "", "severity": "high"}, {"severity": "high"}),
        # all empty → empty result
        ({"status": "", "page": ""}, {}),
        # empty input dict
        ({}, {}),
        # non-empty regular args are kept as-is
        ({"status": "active", "severity": "low"}, {"status": "active", "severity": "low"}),
    ],
)
def test_remove_empty_string_values_general(args, expected):
    assert remove_empty_string_values(args) == expected


@pytest.mark.parametrize(
    "key, value, should_keep",
    [
        ("page", "1", True),
        ("page", "0", True),
        ("page_size", "100", True),
        ("page", " 3 ", True),
        ("page_size", " 10 ", True),
        ("page", "n/a", False),
        ("page", "invalid_offset", False),
        ("page", "1.5", False),
        ("page", "-1", False),
        ("page", "abc", False),
        ("page_size", "bad", False),
        ("page", "", False),
        ("page_size", "", False),
    ],
)
def test_remove_empty_string_values_numeric_args(key, value, should_keep):
    result = remove_empty_string_values({key: value})
    if should_keep:
        assert result == {key: value}
    else:
        assert result == {}


@pytest.mark.parametrize(
    "value, should_keep",
    [
        ("42", True),
        ("1,2,3", True),
        (["10", "20"], True),
        ("n/a", False),
        ("abc", False),
        ("1,abc,3", False),
        (["10", "n/a"], False),
        ("", False),
    ],
)
def test_remove_empty_string_values_numeric_list_args(value, should_keep):
    result = remove_empty_string_values({"issue_id": value})
    if should_keep:
        assert result == {"issue_id": value}
    else:
        assert result == {}


@pytest.mark.parametrize(
    "args, expected",
    [
        (
            # valid regular + valid numeric + valid list
            {"status": "active", "page": "2", "issue_id": "7,8"},
            {"status": "active", "page": "2", "issue_id": "7,8"},
        ),
        (
            # empty string dropped, invalid numeric dropped, valid list kept
            {"severity": "", "page_size": "bad", "issue_id": "1,2"},
            {"issue_id": "1,2"},
        ),
        (
            # all three categories invalid → empty result
            {"severity": "", "page": "n/a", "issue_id": "abc"},
            {},
        ),
        (
            # numeric arg valid, list arg invalid, regular arg kept
            {"page": "5", "issue_id": "x,y", "status": "closed"},
            {"page": "5", "status": "closed"},
        ),
    ],
)
def test_remove_empty_string_values_mixed(args, expected):
    assert remove_empty_string_values(args) == expected
