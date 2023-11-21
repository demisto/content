CONTEXT_RESULTS = ('[{"id":"21538","key":"COMPANYSA-70"},{"id":"21619","key":"COMPANYSA-145"}]')

EXPECTED_TABLE = '|Id|Key|\n|---|---|\n| 21538 | COMPANYSA-70 |\n| 21619 | COMPANYSA-145 |\n'


def test_convert_to_table():
    """
    Given:
        - A list of subtasks of a Jira issue in string format
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from JiraV3ConvertSubtasksToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
