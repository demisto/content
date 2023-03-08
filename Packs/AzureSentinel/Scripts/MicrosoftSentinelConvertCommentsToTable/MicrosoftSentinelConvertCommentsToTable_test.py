def test_format_comment():
    """
    Given:
        - A comment
    When:
         - calling format_comment function
    Then:
        - Validate the comment is formatted correctly
    """
    comment = {'name': 'test', 'kind': 'test_kind', 'properties':
               {'message': 'test_message', 'createdTimeUtc': 'test_time', 'author': {'userPrincipalName': 'test_user'}}}
    expected = {'name': 'test', 'message': 'test_message', 'createdTimeUtc': 'test_time', 'userPrincipalName': 'test_user'}

    from MicrosoftSentinelConvertCommentsToTable import format_comment
    result = format_comment(comment)

    assert result == expected


CONTEXT_RESULTS = ('[{"name": "test", "kind": "test_kind", "properties": {"message": "test_message", '
                   '"createdTimeUtc": "test_time", "author": {"userPrincipalName": "test_user"}}}, '
                   '{"name": "test2", "kind": "test_kind2", "properties": {"message": "test_message2", '
                   '"createdTimeUtc": "test_time2", "author": {"userPrincipalName": "test_user2"}}}]')

EXPECTED_TABLE = "|Name|Message|Created Time Utc|User Principal Name|\n" \
                 "|---|---|---|---|\n" \
                 "| test | test_message | test_time | test_user |\n" \
                 "| test2 | test_message2 | test_time2 | test_user2 |\n"


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
