from ExportToXLSX import parse_data
import pytest


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


ARGS_VERIFY = [
    (None, None),
    (1, 1)
]


@pytest.mark.parametrize('is_bold, is_border', ARGS_VERIFY)
def test_prepare_bold_and_border(is_bold: bool, is_border: bool):
    """
    Given:
        - is_bold: bool, is_border: bool
    When:
        - running prepare_bold_and_border
    Then:
        - Returns the right command result.
    """
    from ExportToXLSX import prepare_bold_and_border
    from xlsxwriter import Workbook
    workbook = Workbook()
    bold_value = 1 if is_bold else 0
    border_value = 1 if is_border else 0
    result_bold, result_border = prepare_bold_and_border(workbook, is_bold, is_border)
    assert result_bold.bold == bold_value
    assert result_bold.bottom == border_value
    assert result_border.bottom == border_value


def test_write_data(mocker):
    """
    When:
        - running write_data
    Then:
        - Checks that write function was called 4 times.
    """
    from ExportToXLSX import write_data
    import xlsxwriter
    from xlsxwriter.format import Format
    worksheet = xlsxwriter.Workbook()
    format_arg = Format()
    mocker.patch.object(xlsxwriter.Workbook, 'worksheet.write')
    write_data("", DATA_INPUT_SINGLE_DICT, None, worksheet, format_arg, format_arg)
    assert mocker.call_count == 4
