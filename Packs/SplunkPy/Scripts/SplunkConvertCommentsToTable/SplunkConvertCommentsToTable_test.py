import SplunkConvertCommentsToTable

EXPECTED_TABLE = ('|Comment|Comment time|Reviewer|\n'
                  '|---|---|---|\n'
                  '| new comment | 1688548665.512371 | admin |\n')


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
        '{"Comment":"new comment","Comment time":"1688548665.512371","Reviewer":"admin"}']}}
    mocker.patch('demistomock.incident', return_value=incident)
    result = SplunkConvertCommentsToTable.main()

    assert result.readable_output == EXPECTED_TABLE
