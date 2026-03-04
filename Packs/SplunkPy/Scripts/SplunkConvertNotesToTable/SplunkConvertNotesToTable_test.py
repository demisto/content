import SplunkConvertNotesToTable

EXPECTED_TABLE = "#### Splunk Notes (1)\n\n--\n\nnew note\n\n"


def test_convert_to_table(mocker):
    """
    Given:
        - A list of notes of a Splunk finding in string format
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    incident = {"CustomFields": {"splunknotes": ['{"Note":"new note"}']}}
    mocker.patch("demistomock.incident", return_value=incident)
    result = SplunkConvertNotesToTable.main()

    assert result.readable_output == EXPECTED_TABLE
