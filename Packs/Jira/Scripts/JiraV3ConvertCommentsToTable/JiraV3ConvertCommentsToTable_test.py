CONTEXT_RESULTS = (
    ('[{"Comment":"hello","Created":"2023-05-12T20:08:00.595+0300","Id":"18461","UpdateUser":"Tomer Malache",'
     '"Updated":"2023-05-12T20:08:00.595+0300","User":"Tomer Malache"}]'))

EXPECTED_TABLE = ('|Comment|Created|Id|Update User|Updated|User|\n|---|---|---|---|---|---|\n'
                  '| hello | 2023-05-12T20:08:00.595+0300 | 18461 | Tomer Malache |'
                  ' 2023-05-12T20:08:00.595+0300 | Tomer Malache |\n')


def test_convert_to_table():
    """
    Given:
        - A list of comments of a Jira issue in string format
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from JiraV3ConvertCommentsToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
