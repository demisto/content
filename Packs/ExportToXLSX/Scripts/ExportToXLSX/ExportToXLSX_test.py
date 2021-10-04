from ExportToXLSX import parse_data

DATA_INPUT_SINGLE_DICT = {"key1": "val1", "key2": "val2"}
DATA_INPUT_MULTIPLE_DICTS = '{\"key1\":\"val1\",\"key2\":\"val2\"},{\"key1\":\"val3\",\"key2\":\"val4\"}'


def test_parse_data_single_item_no_error():
    """ Unit test
    Given
        - parse_data help method
        - inputs:
            data : a single dictionary
            sheets: a list of one sheet name
    When
        - the data is valid
        - the sheets number is valid
    Then
        Validate the content of the response
    """
    parsed_data = parse_data(data=DATA_INPUT_SINGLE_DICT, sheets=['sheet1'])
    assert isinstance(parsed_data, list)
    assert len(parsed_data) == 1


def test_parse_data_single_item_with_error():
    """ Unit test
    Given
        - parse_data help method
        - inputs:
            data : comma-separated string represented dictionaries
            sheets: a list of two sheet names
    When
        - the data is valid
        - the sheets number is not valid (should be equal to the number of dicts in 'data')
    Then
        Validate the method raises a Value error
    """
    try:
        parse_data(data=DATA_INPUT_SINGLE_DICT, sheets=['sheet1', 'sheets2'])
        assert False
    except ValueError as err:
        assert 'Number of sheet names should be equal to the number of data items.' in err.args[0]


def test_parse_data_multiple_items_no_error():
    """ Unit test
    Given
        - parse_data help method
        - inputs:
            data : comma-separated string represented dictionaries
            sheets: a list of two sheet names
    When
        - the data is valid
        - the sheets number is valid
    Then
        Validate the content of the response
    """
    parsed_data = parse_data(data=DATA_INPUT_MULTIPLE_DICTS, sheets=['sheet1', 'sheet2'])
    assert isinstance(parsed_data, list)
    assert len(parsed_data) == 2


def test_parse_data_multiple_items_with_error():
    """ Unit test
    Given
        - parse_data help method
        - inputs:
            data : comma-separated string represented dictionaries
            sheets: a list of one sheet names
    When
        - the data is valid
        - the sheets number is not valid ( should be equal to the number of dicts in 'data')
    Then
        Validate the method raises a Value error
    """
    try:
        parse_data(data=DATA_INPUT_MULTIPLE_DICTS, sheets=['sheet1'])
        assert False
    except ValueError as err:
        assert 'Number of sheet names should be equal to the number of data items.' in err.args[0]
