from SearchSimilarIssues import (
    update_args,
    delete_keys_recursively,
    replace_keys_recursively_multi,
    replace_fields,
    handle_results,
)


def test_update_args():
    """Tests the update_args function

    Given:
    - A dictionary with issue-based argument keys

    When:
    - Running the 'update_args' function

    Then:
    - Validates that issue-based keys are renamed to incident-based equivalents
    - Validates that unmapped keys remain unchanged
    """
    args = {
        "issue_id": "123",
        "min_similarity": "0.8",
        "max_issues_to_display": "10",
        "text_similarity_fields": "title,description",
        "unmapped_key": "value",
        "another_unmapped": "test",
    }

    result = update_args(args)

    expected = {
        "incidentId": "123",
        "minimunIncidentSimilarity": "0.8",
        "maxIncidentsToDisplay": "10",
        "similarTextField": "title,description",
        "unmapped_key": "value",
        "another_unmapped": "test",
    }

    assert result == expected


def test_update_args_empty_dict():
    """Tests the update_args function with empty dictionary

    Given:
    - An empty dictionary

    When:
    - Running the 'update_args' function

    Then:
    - Validates that an empty dictionary is returned
    """
    args = {}
    result = update_args(args)
    assert result == {}


def test_delete_keys_recursively_dict():
    """Tests the delete_keys_recursively function with dictionary input

    Given:
    - A nested dictionary with keys to delete

    When:
    - Running the 'delete_keys_recursively' function

    Then:
    - Validates that specified keys are deleted at all levels
    - Validates that other keys remain unchanged
    """
    obj = {
        "keep_this": "value1",
        "delete_this": "value2",
        "nested": {
            "keep_nested": "value3",
            "delete_this": "value4",
            "deep_nested": {"delete_this": "value5", "keep_deep": "value6"},
        },
    }

    keys_to_delete = ["delete_this"]
    result = delete_keys_recursively(obj, keys_to_delete)

    expected = {"keep_this": "value1", "nested": {"keep_nested": "value3", "deep_nested": {"keep_deep": "value6"}}}

    assert result == expected


def test_delete_keys_recursively_list():
    """Tests the delete_keys_recursively function with list input

    Given:
    - A list containing dictionaries with keys to delete

    When:
    - Running the 'delete_keys_recursively' function

    Then:
    - Validates that specified keys are deleted from all dictionaries in the list
    """
    obj = [{"keep": "value1", "delete": "value2"}, {"keep": "value3", "delete": "value4"}, "string_item"]

    keys_to_delete = ["delete"]
    result = delete_keys_recursively(obj, keys_to_delete)

    expected = [{"keep": "value1"}, {"keep": "value3"}, "string_item"]

    assert result == expected


def test_delete_keys_recursively_primitive():
    """Tests the delete_keys_recursively function with primitive input

    Given:
    - A primitive value (string, int, etc.)

    When:
    - Running the 'delete_keys_recursively' function

    Then:
    - Validates that the primitive value is returned unchanged
    """
    obj = "test_string"
    keys_to_delete = ["delete"]
    result = delete_keys_recursively(obj, keys_to_delete)
    assert result == "test_string"


def test_replace_keys_recursively_multi_dict():
    """Tests the replace_keys_recursively_multi function with dictionary input

    Given:
    - A nested dictionary with keys and values to replace

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that keys and string values are replaced according to replacements dict
    - Validates that nested structures are handled correctly
    """
    obj = {"incident_key": "incident_value", "alert_data": {"incident_nested": "alert_text", "number_value": 123}}

    replacements = {"incident": "issue", "alert": "notification"}
    result = replace_keys_recursively_multi(obj, replacements)

    expected = {"issue_key": "issue_value", "notification_data": {"issue_nested": "notification_text", "number_value": 123}}

    assert result == expected


def test_replace_keys_recursively_multi_list():
    """Tests the replace_keys_recursively_multi function with list input

    Given:
    - A list containing dictionaries and strings with values to replace

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that replacements are applied to all items in the list
    """
    obj = [{"incident_key": "incident_value"}, "alert_string", 123]

    replacements = {"incident": "issue", "alert": "notification"}
    result = replace_keys_recursively_multi(obj, replacements)

    expected = [{"issue_key": "issue_value"}, "notification_string", 123]

    assert result == expected


def test_replace_keys_recursively_multi_string():
    """Tests the replace_keys_recursively_multi function with string input

    Given:
    - A string with substrings to replace

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that all specified substrings are replaced
    """
    obj = "This is an incident alert message"
    replacements = {"incident": "issue", "alert": "notification"}
    result = replace_keys_recursively_multi(obj, replacements)
    assert result == "This is an issue notification message"


def test_replace_keys_recursively_multi_primitive():
    """Tests the replace_keys_recursively_multi function with primitive input

    Given:
    - A non-string primitive value

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that the primitive value is returned unchanged
    """
    obj = 123
    replacements = {"incident": "issue"}
    result = replace_keys_recursively_multi(obj, replacements)
    assert result == 123


def test_replace_fields_string_values():
    """Tests the replace_fields function with string field values

    Given:
    - Arguments dictionary with comma-separated field strings

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that field names are replaced according to replacements mapping
    - Validates that comma-separated strings are handled correctly
    """
    args = {
        "text_similarity_fields": "status, domain, category",
        "filter_equal_fields": "status,url",
        "discrete_match_fields": "category, domain",
        "other_field": "unchanged",
    }

    replacements = {"status": "status.progress", "domain": "alert_domain", "category": "categoryname", "url": "alerturl"}

    result = replace_fields(args, replacements)

    expected = {
        "text_similarity_fields": "status.progress,alert_domain,categoryname",
        "filter_equal_fields": "status.progress,alerturl",
        "discrete_match_fields": "categoryname,alert_domain",
        "other_field": "unchanged",
    }

    assert result == expected


def test_replace_fields_list_values():
    """Tests the replace_fields function with list field values

    Given:
    - Arguments dictionary with list field values

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that field names in lists are replaced correctly
    """
    args = {
        "text_similarity_fields": "status, domain",
        "filter_equal_fields": ["category", "url"],
        "other_field": "unchanged",
    }

    replacements = {"status": "status.progress", "domain": "alert_domain", "category": "categoryname", "url": "alerturl"}

    result = replace_fields(args, replacements)

    expected = {
        "text_similarity_fields": "status.progress,alert_domain",
        "filter_equal_fields": "categoryname,alerturl",
        "other_field": "unchanged",
    }

    assert result == expected


def test_replace_fields_empty_values():
    """Tests the replace_fields function with empty or None field values

    Given:
    - Arguments dictionary with empty or None field values

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that empty/None values are skipped without error
    """
    args = {
        "text_similarity_fields": "",
        "filter_equal_fields": None,
        "discrete_match_fields": "status",
        "other_field": "unchanged",
    }

    replacements = {"status": "status.progress"}
    result = replace_fields(args, replacements)

    expected = {
        "text_similarity_fields": "",
        "filter_equal_fields": None,
        "discrete_match_fields": "status.progress",
        "other_field": "unchanged",
    }

    assert result == expected


def test_handle_results_with_context():
    """Tests the handle_results function with valid context data

    Given:
    - Results list with HumanReadable and EntryContext data

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that human readable output is combined correctly
    - Validates that context data is transformed with proper key replacements
    - Validates that final outputs structure is correct
    """
    results = [
        {
            "HumanReadable": "Found 2 similar alerts",
            "EntryContext": {
                "DBotFindSimilarIncidents": {
                    "similarIncident": [
                        {"incident": {"id": "123", "similarity alert": "high"}, "alert ID": "alert_123"},
                        {"incident": {"id": "456", "similarity alert": "medium"}, "alert ID": "alert_456"},
                    ]
                }
            },
        }
    ]

    human_readable, outputs = handle_results(results)

    assert "Found 2 similar issues" in human_readable
    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is True
    assert outputs["SimilarIssues"]["excutionSummary"] == "Success"
    assert len(outputs["SimilarIssues"]["similarIssueList"]) == 2
    assert "alert ID" not in str(outputs["SimilarIssues"]["similarIssueList"])
    assert "similarityIssue" in str(outputs["SimilarIssues"]["similarIssueList"])


def test_handle_results_empty_context():
    """Tests the handle_results function with empty context

    Given:
    - Results list with HumanReadable but no valid EntryContext

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that default outputs are returned
    - Validates that isSimilarIssueFound is False
    """
    results = [{"HumanReadable": "No similar alerts found"}]

    human_readable, outputs = handle_results(results)

    assert "No similar issues found" in human_readable
    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is False
    assert outputs["SimilarIssues"]["similarIssueList"] == {}
    assert "No similar issues found" in outputs["SimilarIssues"]["excutionSummary"]


def test_handle_results_multiple_entries():
    """Tests the handle_results function with multiple result entries

    Given:
    - Results list with multiple entries containing HumanReadable content

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that all HumanReadable content is combined
    """
    results = [{"HumanReadable": "First alert message"}, {"HumanReadable": "Second alert message"}]

    human_readable, outputs = handle_results(results)

    assert "First issue message" in human_readable
    assert "Second issue message" in human_readable
    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is False


def test_handle_results_no_similar_incidents():
    """Tests the handle_results function when no similar incidents are found

    Given:
    - Results with EntryContext but empty similarIncident list

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that isSimilarIssueFound is False when no incidents found
    - Validates that similarIssueList is empty
    """
    results = [
        {"HumanReadable": "No similar alerts found", "EntryContext": {"DBotFindSimilarIncidents": {"similarIncident": []}}}
    ]

    human_readable, outputs = handle_results(results)

    assert "No similar issues found" in human_readable
    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is False
    assert outputs["SimilarIssues"]["similarIssueList"] == []
    assert outputs["SimilarIssues"]["excutionSummary"] == "Success"


def test_handle_results_missing_dbotfindsimilarincidents():
    """Tests the handle_results function when DBotFindSimilarIncidents key is missing

    Given:
    - Results with EntryContext but missing DBotFindSimilarIncidents key

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that default empty dict is used for similarIncident
    """
    results = [{"HumanReadable": "Processing completed", "EntryContext": {"SomeOtherKey": {"data": "value"}}}]

    human_readable, outputs = handle_results(results)

    assert "Processing completed" in human_readable
    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is False
    assert outputs["SimilarIssues"]["similarIssueList"] == {}


def test_replace_fields_mixed_types():
    """Tests the replace_fields function with mixed field value types

    Given:
    - Arguments dictionary with different value types for field keys

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that different value types are handled correctly
    - Validates that invalid types are skipped
    """
    args = {
        "text_similarity_fields": "status,domain",
        "filter_equal_fields": ["category", "url"],
        "discrete_match_fields": 123,  # Invalid type
        "json_similarity_fields": {"invalid": "dict"},  # Invalid type
        "other_field": "unchanged",
    }

    replacements = {"status": "status.progress", "domain": "alert_domain", "category": "categoryname", "url": "alerturl"}

    result = replace_fields(args, replacements)

    expected = {
        "text_similarity_fields": "status.progress,alert_domain",
        "filter_equal_fields": "categoryname,alerturl",
        "discrete_match_fields": 123,  # Unchanged due to invalid type
        "json_similarity_fields": {"invalid": "dict"},  # Unchanged due to invalid type
        "other_field": "unchanged",
    }

    assert result == expected


def test_replace_fields_no_matching_fields():
    """Tests the replace_fields function when no field names match replacements

    Given:
    - Arguments with field values that don't match any replacements

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that field values remain unchanged
    """
    args = {"text_similarity_fields": "field1,field2", "filter_equal_fields": "field3,field4"}

    replacements = {"other_field": "replacement"}

    result = replace_fields(args, replacements)

    expected = {"text_similarity_fields": "field1,field2", "filter_equal_fields": "field3,field4"}

    assert result == expected


def test_replace_fields_with_whitespace():
    """Tests the replace_fields function with whitespace in field values

    Given:
    - Arguments with field values containing extra whitespace

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that whitespace is properly handled and trimmed
    """
    args = {"text_similarity_fields": " status , domain , category ", "filter_equal_fields": ["  url  ", " status "]}

    replacements = {"status": "status.progress", "domain": "alert_domain", "category": "categoryname", "url": "alerturl"}

    result = replace_fields(args, replacements)

    expected = {
        "text_similarity_fields": "status.progress,alert_domain,categoryname",
        "filter_equal_fields": "alerturl,status.progress",
    }

    assert result == expected


def test_delete_keys_recursively_nested_lists():
    """Tests the delete_keys_recursively function with deeply nested lists and dicts

    Given:
    - Complex nested structure with lists containing dictionaries

    When:
    - Running the 'delete_keys_recursively' function

    Then:
    - Validates that keys are deleted at all nesting levels
    """
    obj = {
        "top_level": [
            {"keep": "value1", "delete": "value2", "nested_list": [{"keep": "value3", "delete": "value4"}, {"keep": "value5"}]}
        ],
        "delete": "top_level_delete",
    }

    keys_to_delete = ["delete"]
    result = delete_keys_recursively(obj, keys_to_delete)

    expected = {"top_level": [{"keep": "value1", "nested_list": [{"keep": "value3"}, {"keep": "value5"}]}]}

    assert result == expected


def test_replace_keys_recursively_multi_complex_nested():
    """Tests the replace_keys_recursively_multi function with complex nested structure

    Given:
    - Complex nested structure with multiple levels and types

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that all replacements are applied at all levels
    """
    obj = {
        "incident_data": {
            "alert_list": [
                {"incident_id": "123", "alert_message": "incident occurred", "metadata": {"alert_type": "incident_type"}}
            ],
            "incident_count": 1,
        }
    }

    replacements = {"incident": "issue", "alert": "notification"}
    result = replace_keys_recursively_multi(obj, replacements)

    expected = {
        "issue_data": {
            "notification_list": [
                {"issue_id": "123", "notification_message": "issue occurred", "metadata": {"notification_type": "issue_type"}}
            ],
            "issue_count": 1,
        }
    }

    assert result == expected


def test_update_args_all_mappings():
    """Tests the update_args function with all possible argument mappings

    Given:
    - Dictionary containing all mappable argument keys

    When:
    - Running the 'update_args' function

    Then:
    - Validates that all keys are correctly mapped to their incident equivalents
    """
    args = {
        "issue_id": "123",
        "min_similarity": "0.8",
        "max_issues_to_display": "10",
        "max_issues_in_indicators_for_white_list": "5",
        "filter_equal_fields": "field1",
        "text_similarity_fields": "field2",
        "json_similarity_fields": "field3",
        "discrete_match_fields": "field4",
        "fields_to_display": "field5",
        "use_all_fields": "true",
        "from_date": "2023-01-01",
        "to_date": "2023-12-31",
        "aggregate_issues_different_date": "true",
        "include_indicators_similarity": "true",
        "min_number_of_indicators": "3",
        "indicators_types": "type1,type2",
    }

    result = update_args(args)

    expected = {
        "incidentId": "123",
        "minimunIncidentSimilarity": "0.8",
        "maxIncidentsToDisplay": "10",
        "maxIncidentsInIndicatorsForWhiteList": "5",
        "fieldExactMatch": "field1",
        "similarTextField": "field2",
        "similarJsonField": "field3",
        "similarCategoricalField": "field4",
        "fieldsToDisplay": "field5",
        "useAllFields": "true",
        "fromDate": "2023-01-01",
        "toDate": "2023-12-31",
        "aggreagateIncidentsDifferentDate": "true",
        "includeIndicatorsSimilarity": "true",
        "minNumberOfIndicators": "3",
        "indicatorsTypes": "type1,type2",
    }

    assert result == expected


def test_handle_results_with_boolean_context():
    """Tests the handle_results function with boolean similarIncident value

    Given:
    - Results with EntryContext containing boolean similarIncident

    When:
    - Running the 'handle_results' function

    Then:
    - Validates that boolean values are handled correctly for isSimilarIssueFound
    """
    results = [{"HumanReadable": "Search completed", "EntryContext": {"DBotFindSimilarIncidents": {"similarIncident": False}}}]

    human_readable, outputs = handle_results(results)

    assert outputs["SimilarIssues"]["isSimilarIssueFound"] is False
    assert outputs["SimilarIssues"]["similarIssueList"] is False


def test_replace_fields_empty_args():
    """Tests the replace_fields function with empty arguments dictionary

    Given:
    - Empty arguments dictionary

    When:
    - Running the 'replace_fields' function

    Then:
    - Validates that empty dictionary is returned unchanged
    """
    args = {}
    replacements = {"status": "status.progress"}
    result = replace_fields(args, replacements)
    assert result == {}


def test_replace_keys_recursively_multi_empty_replacements():
    """Tests the replace_keys_recursively_multi function with empty replacements

    Given:
    - Object with data and empty replacements dictionary

    When:
    - Running the 'replace_keys_recursively_multi' function

    Then:
    - Validates that object is returned unchanged
    """
    obj = {"incident": "test", "alert": ["data"]}
    replacements = {}
    result = replace_keys_recursively_multi(obj, replacements)
    assert result == obj


def test_delete_keys_recursively_empty_keys():
    """Tests the delete_keys_recursively function with empty keys_to_delete

    Given:
    - Object with data and empty keys_to_delete list

    When:
    - Running the 'delete_keys_recursively' function

    Then:
    - Validates that object is returned unchanged
    """
    obj = {"keep": "value", "also_keep": "value2"}
    keys_to_delete = []
    result = delete_keys_recursively(obj, keys_to_delete)
    assert result == obj
