import pytest
from unittest.mock import MagicMock
from Cspresentpolicyactions import convert_json_to_markdown_table, main
import demistomock as demisto


def test_convert_json_to_markdown_table_basic():
    input_data = {"Action1": "Value1", "Action2": "Value2"}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action2 | Value2 |\n| Action1 | Value1 |\n"  # noqa: E501
    assert convert_json_to_markdown_table(input_data) == expected_output


def test_convert_json_to_markdown_table_with_dict():
    input_data = {"Action1": {"subkey": "subvalue"}}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action1 | ```json\n{\n    \"subkey\": \"subvalue\"\n}\n``` |\n"  # noqa: E501
    assert convert_json_to_markdown_table(input_data) == expected_output


def test_convert_json_to_markdown_table_with_list():
    input_data = {"Action1": ["item1", "item2"]}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action1 | item1, item2 |\n"
    assert convert_json_to_markdown_table(input_data) == expected_output


def test_convert_json_to_markdown_table_with_boolean():
    input_data = {"Action1": True, "Action2": False}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action1 | ✅ |\n| Action2 | ❌ |\n"
    assert convert_json_to_markdown_table(input_data) == expected_output


def test_convert_json_to_markdown_table_invalid_input():
    with pytest.raises(ValueError):
        convert_json_to_markdown_table("Not a dict")


def test_convert_json_to_markdown_table_sort_options():
    input_data = {"B": 2, "A": 1, "C": 3}
    assert "| C | 3 |" in convert_json_to_markdown_table(input_data, sort_by_value=True, descending=True)
    assert "| A | 1 |" in convert_json_to_markdown_table(input_data, sort_by_value=True, descending=False)
    assert "| A | 1 |" in convert_json_to_markdown_table(input_data, sort_by_value=False, descending=True)


@pytest.mark.parametrize("context_value, expected_output, expected_calls", [
    ([{"policyactions": {"Action1": "Value1"}}], "| Action1 | Value1 |", 1),
    ([], "### No policyactions data available.", 2),
    ([{"no_policyactions": {}}], "### No policyactions data available.", 2),
])
def test_main_with_data(monkeypatch, context_value, expected_output, expected_calls):
    def mock_context():
        return {"CrowdStrike": {"Detection": context_value}}
    monkeypatch.setattr(demisto, "context", mock_context)
    mock_results = MagicMock()
    monkeypatch.setattr(demisto, "results", mock_results)
    main()
    assert mock_results.call_count == expected_calls
    if isinstance(mock_results.call_args_list[0][0][0], dict):
        assert expected_output in mock_results.call_args_list[0][0][0]['Contents']
    else:
        assert expected_output in mock_results.call_args_list[0][0][0]
    if expected_calls == 2:
        assert "No Policy Actions were found" in mock_results.call_args_list[1][0][0]


def test_main_exception(monkeypatch):
    def mock_context():
        return {}
    monkeypatch.setattr(demisto, "context", mock_context)
    mock_results = MagicMock()
    monkeypatch.setattr(demisto, "results", mock_results)
    main()
    mock_results.assert_called_once_with("No Policy Actions were found on CrowdStrike.Detection context key")


def test_main_exception_no_context(monkeypatch):
    monkeypatch.setattr(demisto, "context", lambda: None)
    mock_results = MagicMock()
    monkeypatch.setattr(demisto, "results", mock_results)
    main()
    assert mock_results.call_count == 1
    assert "No Policy Actions were found" in mock_results.call_args[0][0]


def test_main_exception_raised(monkeypatch):
    def mock_context():
        raise Exception("Test exception")
    monkeypatch.setattr(demisto, "context", mock_context)
    mock_results = MagicMock()
    monkeypatch.setattr(demisto, "results", mock_results)
    main()
    assert mock_results.call_count == 1
    assert "No Policy Actions were found" in mock_results.call_args[0][0]
