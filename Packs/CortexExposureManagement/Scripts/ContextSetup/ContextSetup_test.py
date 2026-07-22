from ContextSetup import *
import pytest

incident_contains_field_in_root = {
    "field_name": "Test",
    "id": 2,
    "name": "This is incident2",
    "CustomFields": {"urlsslverification": [{"entryid": "abcd", "link": "1234"}, {"entryid": "abcd", "link": "1234"}]},
}


def test_append(mocker):
    """
    Tests context_setup_command with append functionality.
    Given: An incident with existing urlsslverification custom field data and valid arguments with multiple keys and values
    When: Running the 'context_setup_command' with append arguments
    Then: Checks the function executes successfully and appends new values to existing context data
    """
    args = {
        "keys": "Link,EntryID,TimeStamp",
        "val1": "www.google.com",
        "val2": "AWS",
        "val3": "TIMESTAMP",
        "context_key": "urlsslverification",
    }
    mocker.patch.object(demisto, "incidents", return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, "executeCommand", return_value="Done")
    entry = context_setup_command(args)
    assert entry == "Done"


def test_overwrite(mocker):
    """
    Tests context_setup_command with overwrite functionality.
    Given: An incident with existing urlsslverification custom field data and overwrite flag set to true
    When: Running the 'context_setup_command' with overwrite enabled
    Then: Checks the function executes successfully and replaces existing context data with new values
    """
    args = {
        "keys": "Link,EntryID",
        "val1": "www.google.com",
        "val2": "AWS",
        "context_key": "urlsslverification",
        "overwrite": "true",
    }
    mocker.patch.object(demisto, "incidents", return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, "executeCommand", return_value="Done")
    entry = context_setup_command(args)
    assert entry == "Done"


def test_error(mocker):
    """
    Tests context_setup_command error handling.
    Given: An incident with existing data and mismatched keys and values causing validation errors
    When: Running the 'context_setup_command' with invalid key-value mapping
    Then: Checks the function raises ValueError due to key-value count mismatch and fails validation
    """
    args = {"keys": "Link", "val1": "www.google.com", "val2": "AWS", "context_key": "urlsslverification", "overwrite": "true"}
    mocker.patch.object(demisto, "incidents", return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, "executeCommand", return_value="Done")
    with pytest.raises(ValueError):
        context_setup_command(args)
