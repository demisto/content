from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import *

from GetUserData import (
    create_account,
    merge_accounts,
)


def test_create_account_with_all_fields():
    """
    Given:
        All fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with all the provided information.
    """
    account = create_account(
        id="123",
        username="johndoe",
        display_name="John Doe",
        email_address="john@example.com",
        groups=["Group1", "Group2"],
        type="AD",
        job_title="Developer",
        office="New York",
        telephone_number="123-456-7890",
        is_enabled=True,
        manager_email="manager@example.com",
        manager_display_name="Manager Name",
        risk_level="LOW",
    )

    assert account == {
        "id": "123",
        "username": "johndoe",
        "display_name": "John Doe",
        "email_address": "john@example.com",
        "groups": ["Group1", "Group2"],
        "type": "AD",
        "job_title": "Developer",
        "office": "New York",
        "telephone_number": "123-456-7890",
        "is_enabled": True,
        "manager_email": "manager@example.com",
        "manager_display_name": "Manager Name",
        "risk_level": "LOW",
    }


def test_create_account_with_partial_fields():
    """
    Given:
        Only some fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with only the provided information.
    """
    account = create_account(
        id="456", username="janedoe", email_address="jane@example.com", is_enabled=False
    )

    assert account == {
        "id": "456",
        "username": "janedoe",
        "email_address": "jane@example.com",
        "is_enabled": False,
    }


def test_create_account_with_single_item_list():
    """
    Given:
        A field is provided as a single-item list.

    When:
        create_account is called with this field.

    Then:
        It should return a dictionary with the field value extracted from the list.
    """
    account = create_account(id="789", username="bobsmith", groups=["SingleGroup"])

    assert account == {"id": "789", "username": "bobsmith", "groups": "SingleGroup"}


def test_create_account_with_empty_fields():
    """
    Given:
        All fields are provided as None or empty lists.

    When:
        create_account is called with these fields.

    Then:
        It should return an empty dictionary.
    """
    account = create_account(
        id=None,
        username=None,
        display_name=None,
        email_address=None,
        groups=[],
        type=None,
        job_title=None,
        office=None,
        telephone_number=None,
        is_enabled=None,
        manager_email=None,
        manager_display_name=None,
        risk_level=None,
    )

    assert account == {}


def test_merge_accounts_with_no_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with no conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with all unique key-value pairs.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123"}, {"name": "John Doe"}, {"email": "john@example.com"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}


def test_merge_accounts_with_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with the first encountered value
        for conflicting keys and log debug messages for conflicts.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")
    mock_debug = mocker.patch.object(demisto, "debug")

    accounts = [
        {"id": "123", "name": "John Doe"},
        {"id": "456", "email": "john@example.com"},
        {"name": "Jane Doe"},
    ]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}
    mock_debug.assert_any_call("Conflicting values for key 'id': '123' vs '456'")
    mock_debug.assert_any_call(
        "Conflicting values for key 'name': 'John Doe' vs 'Jane Doe'"
    )


def test_merge_accounts_with_empty_list(mocker):
    """
    Given:
        An empty list of account dictionaries.

    When:
        merge_accounts is called with this empty list.

    Then:
        It should return an empty dictionary.
    """
    result = merge_accounts([])

    assert result == {}


def test_merge_accounts_with_single_account(mocker):
    """
    Given:
        A list containing a single account dictionary.

    When:
        merge_accounts is called with this list.

    Then:
        It should return a dictionary with the same key-value pairs as the input account.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123", "name": "John Doe"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe"}
