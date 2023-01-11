from ArrayToCSV import arr_to_csv_command


def test_arr_to_csv_command__array_of_two_values():
    """
        Given -
           an array
        When -
            array contains a list of two str objects
        Then -
            the function will return the strings comma seperated
    """
    arr = ["mock", "mocker"]
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == "mock,mocker"


def test_arr_to_csv_command__array_of_one_value():
    """
        Given -
           an array
        When -
            array contains a list of one str objects
        Then -
            the function will return the string as is.
    """
    arr = ["mock"]
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == "mock"

def test_arr_to_csv_command__empty_array():
    """
        Given -
           an array
        When -
            array contains nothing
        Then -
            the function will return ''
    """
    arr = ""
    command_result = arr_to_csv_command(arr)
    assert command_result.readable_output == ''