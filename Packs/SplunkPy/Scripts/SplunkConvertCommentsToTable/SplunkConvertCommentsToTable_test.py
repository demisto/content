import SplunkConvertCommentsToTable

EXPECTED_TABLE = ('|Comment|\n'
                  '|---|\n'
                  '| new comment |\n')


def test_convert_to_table(mocker):
    """
    Given:
        - A list of comments of a Jira issue in string format
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    incident = {'CustomFields': {'splunkcomments': [
        '{"Comment":"new comment"}']}}
    mocker.patch('demistomock.incident', return_value=incident)
    result = SplunkConvertCommentsToTable.main()

    assert result.readable_output == EXPECTED_TABLE
