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
    result = arr_to_csv_command(arr)
    assert result == "mock,mocker"


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
    result = arr_to_csv_command(arr)
    assert result == "mock"


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
    result = arr_to_csv_command(arr)
    assert result == ''
