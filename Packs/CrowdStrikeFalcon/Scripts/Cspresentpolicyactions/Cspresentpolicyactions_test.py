import pytest
from Cspresentpolicyactions import convert_json_to_markdown_table, main
import demistomock as demisto

def test_convert_json_to_markdown_table_basic():
    input_data = {"Action1": "Value1", "Action2": "Value2"}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action2 | Value2 |\n| Action1 | Value1 |\n"
    assert convert_json_to_markdown_table(input_data) == expected_output

def test_convert_json_to_markdown_table_with_dict():
    input_data = {"Action1": {"subkey": "subvalue"}}
    expected_output = "| ***Policy Action*** | ***Opration Executed*** |\n| --- | ----- |\n| Action1 | ```json\n{\n    \"subkey\": \"subvalue\"\n}\n``` |\n"
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

@pytest.mark.parametrize("context_value, expected_output", [
    ([{"policyactions": {"Action1": "Value1"}}], "| Action1 | Value1 |"),
    ([], "### No policyactions data available."),
    ([{"no_policyactions": {}}], "### No policyactions data available."),
])
def test_main_with_data(monkeypatch, context_value, expected_output):
    def mock_context():
        return {"CrowdStrike": {"Detection": context_value}}
    monkeypatch.setattr(demisto, "context", mock_context)
    monkeypatch.setattr(demisto, "results", lambda x: None)
    main()
    assert demisto.results.call_count == 1
    assert expected_output in demisto.results.call_args[0][0]['Contents']

def test_main_exception(monkeypatch):
    def mock_context():
        return {}
    monkeypatch.setattr(demisto, "context", mock_context)
    monkeypatch.setattr(demisto, "results", lambda x: None)
    main()
    assert demisto.results.call_count == 1
    assert "No Policy Actions were found" in demisto.results.call_args[0][0]
