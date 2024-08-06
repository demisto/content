def test_format_comment():
    """
    Given:
        - A comment
    When:
         - calling format_comment function
    Then:
        - Validate the comment is formatted correctly
    """
    comment = {
        "kind": "test_kind",
        "properties": {
            "message": "test_message",
            "createdTimeUtc": "2024-08-05T14:19:49.3176516Z",
            "author": {"name": "test", "userPrincipalName": "test_user"},
        },
    }
    expected = {
        "name": "test",
        "message": "test_message",
        "createdTimeUtc": "05/08/2024, 14:19",
    }

    from MicrosoftSentinelConvertCommentsToTable import format_comment
    result = format_comment(comment)

    assert result == expected


CONTEXT_RESULTS = (
    '[{"kind": "test_kind", "properties": {"message": "test_message", '
    '"createdTimeUtc": "2024-08-05T14:19:49.3176516Z", "author": {"name": "test", "userPrincipalName": "test_user"}}},'
    '{"kind": "test_kind2", "properties": {"message": "test_message2", '
    '"createdTimeUtc": "2024-08-05T14:19:49.3176516Z", "author": {"name": "test2", "userPrincipalName": "test_user2"}}}]'
)

EXPECTED_TABLE = "|Name|Message|Created Time Utc|\n" \
                 "|---|---|---|\n" \
                 "| test | test_message | test_time |\n" \
                 "| test2 | test_message2 | test_time2 |\n"


def test_convert_to_table():
    """
    Given:
        - A list of comments in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertCommentsToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
