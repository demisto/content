from ArrayToCSV import arr_to_csv_command


def test_arr_to_csv_command():
    """
        Given -
           an array
        When -
            array contains a list of two objects
        Then -
            the fumction will return the strings comma seperated
    """
    arr = ["mock", "mocker"]
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == "mock,mocker"
