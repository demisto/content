def test_count_dict_multiple_users():
    """
    Given:
      - A comma-separated string of multiple users.
    When:
      - Running the MS365DefenderUserListToTable transformer.
    Then:
      - Ensure every user is returned as its own row (not collapsed into a single row).
    """
    from MS365DefenderUserListToTable import count_dict

    input_value = "username@domain (BOQDEVUSER.LOCAL),admin@contoso.com (CONTOSO)"
    expected_output = [
        {"User": "username@domain (BOQDEVUSER.LOCAL)"},
        {"User": "admin@contoso.com (CONTOSO)"},
    ]
    assert count_dict(input_value) == expected_output


def test_count_dict_single_user():
    """
    Given:
      - A single user string.
    When:
      - Running the MS365DefenderUserListToTable transformer.
    Then:
      - Ensure a single row is returned.
    """
    from MS365DefenderUserListToTable import count_dict

    assert count_dict("username@domain (BOQDEVUSER.LOCAL)") == [{"User": "username@domain (BOQDEVUSER.LOCAL)"}]


def test_count_dict_non_string_passthrough():
    """
    Given:
      - A non-string value.
    When:
      - Running the MS365DefenderUserListToTable transformer.
    Then:
      - Ensure the value is returned unchanged.
    """
    from MS365DefenderUserListToTable import count_dict

    value = [{"User": "already-a-table"}]
    assert count_dict(value) == value
