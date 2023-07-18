import SplunkConvertCommentsToTable

EXPECTED_TABLE = ('|Comment |Comment time| Reviwer|\n|---|---|---|\n'
                  '| hello | 2023-05-12T20:08:00.595+0300 | admin | \n')


def test_convert_to_table(mocker):
    """
    Given:
        - A list of comments of a Jira issue in string format
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    incident = {'splunkcomments': [{"Comment": "hello", "Comment time": "2023-05-12T20:08:00.595+0300", "Reviwer": "admin"}]}
    mocker.patch('demistomock.incident', return_value=incident)
    result = SplunkConvertCommentsToTable.main()

    assert result.readable_output == EXPECTED_TABLE
