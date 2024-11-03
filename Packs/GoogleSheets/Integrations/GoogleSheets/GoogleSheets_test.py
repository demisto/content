import json
import pytest
import GoogleSheets
import os
from pathlib import Path
from googleapiclient.discovery import build
from googleapiclient.http import HttpMock
from googleapiclient.http import HttpMockSequence


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# HELPER FUNCTIONS


def test_parse_sheets_for_get_response():
    '''

    Given:
        - The sheets list from the Google api response and an argument include_grid_data = True

    When:
        - We want to process the process and filter the sheets data given by the get_spreadsheet command

    Then:
        - return a filtered list of the sheets with the relevant data
    '''
    path = 'test_data/helper_functions/test_parse_sheets_for_get_response/'
    result = util_load_json(os.path.join(path, 'res_parse.json'))
    assert result == GoogleSheets.parse_sheets_for_get_response(util_load_json(path + 'sheets.json'), True)


def test_make_markdown_matrix():
    '''
    Given:
         - The sheets after they have been processed by context_singe_get_parse

    When:
        - we prepare the human-readable response and include_grid_data is True

    Then:
        - return a Markdown table with the headers of the sheets and the data inside them
    '''
    path = 'test_data/helper_functions/test_make_markdown_matrix/'
    with open(path + 'result.md') as file:
        result = file.read()
    assert GoogleSheets.make_markdown_matrix(util_load_json(os.path.join(path, 'sheets.json'))) == result


def test_make_markdown_matrix_with_none_value():
    """
    Given:
         - The sheet with values of none after they have been processed

    When:
        - we prepare the human-readable response and include_grid_data is True

    Then:
        - return a Markdown table with the headers of the sheets and the data inside them
    """
    assert (
        GoogleSheets.make_markdown_matrix(
            util_load_json(
                "test_data/helper_functions/test_make_markdown_matrix/sheets_with_none_value.json"
            )
        )
        == Path(
            "test_data/helper_functions/test_make_markdown_matrix/result_with_none_value.md"
        ).read_text()
    )


def test_prepare_result_with_echo(mocker):
    '''

    Given:
        - a response from google api and the demisto args

    When:
        - when echo_spreadsheet is true, we want to prepare the command result

    Then:
        - return the command result

    '''
    mocker.patch.object(GoogleSheets, 'create_list_id_title',
                        return_value=[{'SheetId': 783932040, 'Sheet title': "new sheet"},
                                      {'SheetId': 0, 'Sheet title': "Sheet1"}])
    response = util_load_json('test_data/helper_functions/test_prepare_result_echo/response.json')
    command_result = GoogleSheets.prepare_result(response, {"echo_spreadsheet": "true"}, "")
    with open('test_data/helper_functions/test_prepare_result_echo/markdown_result.md') as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
    assert command_result.outputs == response


def test_prepare_result_without_echo():
    '''

    Given:
        - a response from google api and the demisto args

    When:
        - when echo spreadsheet is false and we want to prepare the command result

    Then:
        - return the command result

    '''
    assert GoogleSheets.prepare_result({}, {"echo_spreadsheet": "false"}, "").readable_output == '### Successfully \n'


def test_create_list_id_title():
    '''

    Given:
        - a sheets array from the google-sheets api response under

    When:
        - a command is being called with echo_spreadsheet argumeent is true

    Then:
        - return a proper markdown format string

    '''
    sheets = util_load_json('test_data/helper_functions/test_create_list_id_title/sheets.json')
    assert GoogleSheets.create_list_id_title(sheets) == util_load_json(
        'test_data/helper_functions/test_create_list_id_title/create_list_id_title_response.json')


handle_values_input_parametrized = [
    ("[1,2,3],[4,5,6]", [['1', '2', '3'], ['4', '5', '6']]),
    ("[1,'test, for test',3],[4,5,6]", [['1', 'test, for test', '3'], ['4', '5', '6']]),
    ("[1,[2],3],[4,5,6]", [['1', '[2]', '3'], ['4', '5', '6']]),
    ("[1,2]", [['1', '2']]),
    ("[1]", [['1']]),
    ("[]", [['']]),
    ("[[1,2,3],[4,5,6]]", [['1', '2', '3'], ['4', '5', '6']])
]


@pytest.mark.parametrize("test_input,expected", handle_values_input_parametrized)
def test_handle_values_input(test_input, expected):
    '''

    Given:
        - an input of values from the user in the format of [x,y,z],[1,2,3]

    When:
        - we want to apply one of the update function with values input

    Then:
        - return the values in a way suitable for the google-sheets api request
            in the format of [[1,2,3],[4,5,6]...]

    '''
    assert GoogleSheets.handle_values_input(test_input) == expected


handle_values_input_parametrized_exception = [
    ("1,2,3"),
    ("[4,5"),
    ("{3,4}"),
    ("(1,2,3)"),
    (None)
]


@pytest.mark.parametrize("test_input", handle_values_input_parametrized_exception)
def test_handle_values_input_exception(test_input):
    '''

        Given:
            - an input of values from the user in the wrong format

        When:
            - we want to apply one of the update function with values input

        Then:
            - a ValueError exception with a message for the user

    '''
    with pytest.raises(ValueError) as exc_info:
        GoogleSheets.handle_values_input(test_input)
    assert str(exc_info.value) == 'Wrong format of values entered, please check the documentation'


def test_markdown_single_get(mocker):
    '''

    Given:
        - a response from the google api of a get spreadsheet

    When:
        - we want to process the human readable for the war room

    Then:
        - return the markdown format

    '''
    path = 'test_data/helper_functions/test_markdown_single_get/'
    mocker.patch.object(GoogleSheets, 'create_list_id_title', return_value=[{'SheetId': 0, 'Sheet title': 'Sheet1'}])
    response = util_load_json(os.path.join(path, 'get_response.json'))
    markdown = GoogleSheets.markdown_single_get(response)
    with open(os.path.join(path, 'markdown_assert.md')) as file:
        markdown_assert = file.read()
    assert markdown == markdown_assert


grid_ranges_combinations = [(True, "Sheet1!A1:D5", "Sheet1!A1:D5"),
                            (True, None, "new sheet!A1:T500"),
                            (False, "Sheet1!A1:D5", "Sheet1!A1:D5"),
                            (False, None, None)]


@pytest.mark.parametrize("include_grid_data ,ranges, expected", grid_ranges_combinations)
def test_default_ranges_if_not_specified(include_grid_data, ranges, expected):
    '''

           Given:
               - spreadsheetId, ranges, include_grid_data Google service

           When:
               - we want to check if include_grid_data was specified but not the ranges argument

           Then:
               - if include_grid_data is true and ranges not specified return default ranges else return ranges

    '''

    path = 'test_data/helper_functions/test_default_ranges_if_not_specified/'
    http = HttpMock(os.path.join(path, 'response.json'), {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    res = GoogleSheets.default_ranges_if_not_specified("fake", ranges, include_grid_data, service)
    assert res == expected


# CREATE SPREADSHEET TEST
def test_create_spreadsheet():
    '''

    Given:
        - 'google-sheets-spreadsheet-create' is called to be executed with args to the api

    When:
        - the command is being called from main

    Then:
        - return a command result with the proper readable output and context outputs

    '''
    path = "test_data/create_spreadsheet/"
    http = HttpMock(os.path.join(path, 'response.json'), {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    args = util_load_json(path + 'args.json')
    command_result = GoogleSheets.create_spreadsheet(service, args)
    with open(os.path.join(path, 'command_results_readable_output.md')) as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
    assert command_result.outputs == util_load_json(os.path.join(path, 'command_results_outputs.json'))


# GET SPREADSHEET TESTS
@pytest.mark.parametrize("path", ['test_data/get_spreadsheet/single_spreadsheet/',
                                  'test_data/get_spreadsheet/single_spreadsheet_include_grid_data/'])
def test_get_single_spreadsheet(path):
    '''

    Given:
        - 'google-sheets-spreadsheet-get' is being called to be executed with a single id in the args

    When:
        - the command is being called from main

    Then:
        - return the proper readable output and context upon failure an exception will be raised from google.


    '''
    http = HttpMock(path + 'response.json', {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    command_result = GoogleSheets.get_spreadsheet(service, util_load_json(os.path.join(path, 'args.json')))
    with open(path + 'markdown.md') as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
    assert command_result.outputs == util_load_json(os.path.join(path, 'output.json'))


def test_get_multiple_spreadsheets():
    '''

    Given:
        - 'google-sheets-spreadsheet-get' is being called to be executed with multiple ids in the args

    When:
        - the command is being called from main

    Then:
        - return the proper readable output and context upon failure an exception will be raised from google.

    '''
    path = 'test_data/get_spreadsheet/multiple_spreadsheet/'
    args = {
        'spreadsheet_id': "13YRXawxY54RI0uPjD_BQmw31zwaAYQ53I0mxbWlhTy8,1btQWA8icPTiVd-HIXOLpzetcoXFo77deZ3tExukEk-w"
    }
    http = HttpMockSequence([
        ({'status': '200'}, json.dumps(util_load_json(os.path.join(path, 'response1.json')))),
        ({'status': '200'}, json.dumps(util_load_json(os.path.join(path, 'response2.json'))))])
    api_key = 'your_api_key'
    service = build('sheets', 'v4',
                    http=http,
                    developerKey=api_key)
    command_result = GoogleSheets.get_spreadsheet(service, args)
    with open(os.path.join(path, 'markdown.md')) as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
    assert command_result.outputs is None


# UPDATE SPREADSHEET TESTS
def test_value_update():
    '''

    Given:
        - 'google-sheets-value-update' is being called to be executed with args to the api

    When:
        - the command is being called from main

    Then:
        - if successful return the proper readable output else google api will through an error

    '''
    http = HttpMock('test_data/update_spreadsheet/test_value_update/response.json', {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    args = util_load_json("test_data/update_spreadsheet/test_value_update/command_mock.json")
    command_result = GoogleSheets.value_update_sheets(service, args)
    assert command_result.readable_output == '### Successfully updated sheet values'


@pytest.mark.parametrize("path", ['test_data/update_spreadsheet/test_sheet_create/',
                                  'test_data/update_spreadsheet/test_sheet_create_no_echo/'])
def test_sheet_create_both_ways(path):
    '''

    Given:
        - 'google-sheets-value-append' is called to be executed with args to the api
            test1: echo_spreadsheet argument = true
            test2: echo_spreadsheet argument = false

    When:
        - the command is being called from main

    Then:
        - returns a command result with the proper readable output and context

    '''
    http = HttpMock(path + 'response.json', {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    args = util_load_json(os.path.join(path, 'args.json'))
    command_result = GoogleSheets.create_sheet(service, args)
    assert command_result.outputs == util_load_json(os.path.join(path, 'command_result_output.json'))
    with open(os.path.join(path, 'readable_output.md')) as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
