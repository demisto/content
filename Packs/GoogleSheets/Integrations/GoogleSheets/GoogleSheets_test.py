"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import pytest
import GoogleSheets

from googleapiclient.discovery import build
from googleapiclient.http import HttpMock
from googleapiclient.http import HttpMockSequence


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# HELPER FUNCTIONS

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
    command_result = GoogleSheets.prepare_result(response, {"echo_spreadsheet": "true"})
    with open('test_data/helper_functions/test_prepare_result_echo/markdown_result.md', 'r') as file:
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
    assert GoogleSheets.prepare_result({}, {"echo_spreadsheet": "false"}).readable_output == '### Success\n'


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
    ("[1,2]", [['1', '2']]),
    ("[1]", [['1']]),
    ("[]", [['']])
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
    ("1,2,3", pytest.raises(ValueError)),
    ("[4,5", pytest.raises(ValueError)),
    ("{3,4}", pytest.raises(ValueError)),
    ("(1,2,3)", pytest.raises(ValueError)),
    (None, pytest.raises(ValueError))
]


@pytest.mark.parametrize("test_input,expected", handle_values_input_parametrized_exception)
def test_handle_values_input_exception(test_input, expected):
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
    mocker.patch.object(GoogleSheets, 'create_list_id_title', return_value=[{'SheetId': 0, 'Sheet title': 'Sheet1'}])
    response = util_load_json('test_data/helper_functions/test_markdown_single_get/get_response.json')
    markdown = GoogleSheets.markdown_single_get(response)
    with open('test_data/helper_functions/test_markdown_single_get/markdown_assert.md', 'r') as file:
        markdown_assert = file.read()
    assert markdown == markdown_assert


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
    http = HttpMock(path + 'response.json', {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    args = util_load_json(path + 'args.json')
    command_result = GoogleSheets.create_spreadsheet(service, args)
    assert command_result.readable_output == util_load_json(path + 'command_results_readable_output.json')
    assert command_result.outputs == util_load_json(path + 'command_results_outputs.json')


# GET SPREADSHEET TESTS
def test_get_single_spreadsheet():
    '''

    Given:
        - 'google-sheets-spreadsheet-get' is being called to be executed with a single id in the args

    When:
        - the command is being called from main

    Then:
        - return the proper readable output and context upon failure an exception will be raised from google.


    '''
    path = 'test_data/get_spreadsheet/single_spreadsheet/'
    http = HttpMock(path + 'response.json', {'status': '200'})
    api_key = 'your_api_key'
    service = build('sheets', 'v4', http=http, developerKey=api_key)
    command_result = GoogleSheets.get_spreadsheet(service,
                                                  {'spreadsheet_id': "13YRXawxY54RI0uPjD_BQmw31zwaAYQ53I0mxbWlhTy8"})
    with open(path + 'markdown.md', 'r') as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
    assert command_result.outputs == util_load_json(path + 'response.json')


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
        ({'status': '200'}, json.dumps(util_load_json(path + 'response1.json'))),
        ({'status': '200'}, json.dumps(util_load_json(path + 'response2.json')))])
    api_key = 'your_api_key'
    service = build('sheets', 'v4',
                    http=http,
                    developerKey=api_key)
    command_result = GoogleSheets.get_spreadsheet(service, args)
    with open(path + 'markdown.md', 'r') as file:
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
    assert command_result.readable_output == '### Success\n'


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
    args = util_load_json(path + 'args.json')
    command_result = GoogleSheets.create_sheet(service, args)
    assert command_result.outputs == util_load_json(path + 'command_result_output.json')
    with open(path + 'readable_output.md', 'r') as file:
        markdown_assert = file.read()
    assert command_result.readable_output == markdown_assert
