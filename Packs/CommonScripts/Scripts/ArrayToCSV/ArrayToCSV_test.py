from ArrayToCSV import arr_to_csv_command


def test_arr_to_csv_command__array_of_two_values():
    """
        Given:
           A list with 2 values
        When:
           converting list to a string representing a csv
        Then:
            the function will return the string as is (which is a valid csv format)
    """
    arr = ["mock", "mocker"]
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == "mock,mocker"


def test_arr_to_csv_command__array_of_one_value():
    """
        Given:
            A list with one value
        When:
            converting list to a string representing a csv
        Then:
            validate the result is valid csv
    """
    arr = ["mock"]
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == "mock"


def test_arr_to_csv_command__empty_array():
    """
        Given:
           An empty list
        When:
           converting list to a string representing a csv
        Then:
            The result is an empty string (which is a valid csv format)
    """
    arr = ""
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == ''
