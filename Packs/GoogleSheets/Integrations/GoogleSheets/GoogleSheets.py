import ast
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from CommonServerUserPython import *  # noqa

import urllib3
import httplib2
import urllib.parse
from googleapiclient.discovery import build, Resource
from oauth2client import service_account

SERVICE_ACCOUNT_FILE = 'token.json'
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


# HELPER FUNCTIONS

def prepare_result(response: dict, args: dict, readable_comment: str) -> CommandResults:
    """
        This function is for the UPDATE command result formatting
        echo_spreadsheet is false then the HR will be only success or failed.
        If echo_spreadsheet is true then we prepare the HR.
        In any case substitute the response to the output.

        Args:
            response: the response from the google API
            args: demisto.args
            readable_comment: (str) a comment for the UI
        Returns:
            The command result ready for the server
    """
    markdown = f'### Successfully {readable_comment}\n'

    if argToBoolean(args.get('echo_spreadsheet')):
        human_readable = {
            'spreadsheet Id': response.get('spreadsheetId'),
            'spreadsheet url': response.get('updatedSpreadsheet', {}).get('spreadsheetUrl'),
        }

        table_title = response.get('updatedSpreadsheet', {}).get('properties', {}).get('title', '')
        markdown += tableToMarkdown(table_title, human_readable,
                                    headers=['spreadsheet Id', 'spreadsheet url'])
        markdown += '\n'
        sheets = response.get('updatedSpreadsheet', {}).get('sheets')  # this is an array of sheet dicts

        markdown += tableToMarkdown('Content', create_list_id_title(sheets), headers=['SheetId', 'Sheet title'])

    outputs = response

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='GoogleSheets.Spreadsheet',
        outputs_key_field='spreadsheetId',
        outputs=outputs
    )

    return results


def create_list_id_title(sheets: list) -> list:
    """
        Args:
             this function gets a list of all the sheets of a spreadsheet
                a sheet is represented as a dict format with the following fields
                 "sheets" : [
                  {
                    "properties": {
                      "sheetId": 0,
                      "title": "Sheet1",
                      "index": 0,
                      "sheetType": "GRID",
                      "gridProperties": {
                        "rowCount": 1000,
                        "columnCount": 26
                      }
                    }
                  },
                  ...
                  ]

        Returns :
            the output of the function will be a list of dict in the format
            [{'sheetId' : 123 , 'sheet title': 'title'},...]
    """
    result = []
    for sheet in sheets:
        sheetId = sheet.get('properties').get('sheetId')
        sheet_title = sheet.get('properties').get('title')
        result.append({'SheetId': sheetId, 'Sheet title': sheet_title})
    return result


def handle_values_input(values: str) -> list:
    """
    Args:
        values (str): A string representation of values in the form of "[1,2,3],[4,5,6]..."
    Returns:
         (list) A list of lists of the values for this example [[1,2,3],[4,5,6]...]
    """

    # Validate that the user has entered valid values
    if not values or not re.findall("\[(.*?)\]", values):
        raise ValueError(
            "Wrong format of values entered, please check the documentation"
        )

    # Converting the values the user entered into an array of arrays
    values_as_array = ast.literal_eval(values)

    # Checks whether the given values are a singular empty list, such as "[]".
    # if that's the case, it will convert it to [[]] (a list of lists).
    if isinstance(values_as_array, list) and len(values_as_array) == 0:
        values_as_array = [values_as_array]

    # Checks whether the given values are a single non-empty list, e.g., "[1,2,3]".
    # in such a case, it will convert it to [[1,2,3]] (a list of lists).
    elif not all(isinstance(item, list) for item in values_as_array):
        values_as_array = [values_as_array]

    # Handling all values including the `None` value to be string
    res_for_values_req = []
    for element in values_as_array:
        if not element:
            res_for_values_req.append([""])
            continue
        res_for_values_req.append([str(value) for value in element])

    return res_for_values_req


def markdown_single_get(response: dict) -> str:
    """
        Args:
            response (dict): The response from the api call
        Returns:
            (str): a mark down representation string
        Action:
        creates for a single spreadsheet a mark down with 2 tables
        table 1: spreadsheet id and title
        table 2: all the sheets under this spreadsheet id and title
        this function will be executed only for include_grid_data = False
    """
    human_readable = {
        'spreadsheet Id': response.get('spreadsheetId', {}),
        'spreadsheet url': response.get('spreadsheetUrl', {}),
    }

    markdown = tableToMarkdown(response.get('properties', {}).get('title', {}), human_readable,
                               headers=['spreadsheet Id', 'spreadsheet url'])

    markdown += '\n'
    sheets = response.get('sheets', [])
    sheets_titles = create_list_id_title(list(sheets))
    markdown += tableToMarkdown('Content', sheets_titles, headers=['SheetId', 'Sheet title'])
    return markdown


def markdown_single_get_include_grid_data(response: dict) -> str:
    """
    Args:
        response (dict): The response from the API call, after it was processed by context_single_get_output
    Returns:
        markdown to present the data of the spreadsheet including its sheets and their data.

    When:
        this function will be executed when the get_spreadsheet will be called
        with the argument include_grid_data as True
    """
    human_readable = {
        'spreadsheet Id': response.get('spreadsheetId', {}),
        'spreadsheet url': response.get('spreadsheetUrl', {}),
    }

    markdown = tableToMarkdown(response.get('properties', {}).get('spreadsheetTitle', {}), human_readable,
                               headers=['spreadsheet Id', 'spreadsheet url'])
    markdown += '\n'
    markdown += make_markdown_matrix(response.get('sheets', []))
    return markdown


def make_markdown_matrix(sheets: list) -> str:
    """
    Args:
        sheets (list) : a list of the spreadsheets sheets after process of context_single_get_parse

    Returns (str):
        This function returns a table representation of the sheet.
                if the sheet is empty the function will return EmptySheet.

    Action:
        The functions defines the table number of cols by finding the longest row.
    """
    markdown = ""
    for sheet in sheets:
        markdown += f'### ***Name: {sheet.get("title", {})}     Sheet Id: {sheet.get("sheetId", {})}***'

        # find the max number of columns in the table
        max_row_len = max(list(map(lambda elem: len(elem.get('values')), sheet.get('rowData'))))
        if max_row_len == 0:
            markdown += "\n**Empty Sheet**\n"
        else:
            markdown += "\n|"
            # this will form a header with no content
            for i in range(max_row_len):
                markdown += f"col {i} |"
            markdown += "\n"

            markdown += '|'
            for _ in range(max_row_len):
                markdown += "-------------- | "
            markdown += "\n"

            row_data = sheet.get('rowData')
            for row in row_data:
                markdown += '|'
                values = row.get('values')
                for value in values:
                    markdown += (value or "") + ' |'
                markdown += '\n'
    return markdown


def context_single_get_parse(response: dict, include_grid_data: bool) -> dict:
    """
    Args:
        response (dict): The response from the Google API call.
        include_grid_data (bool): will determine in what manner to parse the response
    Returns:
        a filtered response with the desired data.
        will parse differently for include_grid_data bool
    """
    output_dict = {
        "spreadsheetId": response.get('spreadsheetId'),
        "spreadsheetUrl": response.get('spreadsheetUrl'),
        "spreadsheetTitle": response.get('properties', {}).get('title'),
        "sheets": parse_sheets_for_get_response(response.get('sheets', []), include_grid_data),
    }
    return output_dict


def parse_sheets_for_get_response(sheets: list, include_grid_data: bool) -> list:
    """
        Args:
            sheets (list): this is the sheets list from the Google API response
            include_grid_data (bool): will determine in what manner to parse the response
        Returns:
            list : The sheets after the relevant data was extracted.

        This function will be called only upon include_grid_data = true
    """
    sheet_lst = []
    for sheet in sheets:
        output_sheet = {}
        properties = sheet.get('properties', {})
        output_sheet['title'] = properties.get('title')
        output_sheet['sheetId'] = properties.get('sheetId')
        output_sheet['index'] = properties.get('index')
        output_sheet['gridProperties'] = properties.get('gridProperties')
        row_data: list = []
        if not include_grid_data:
            output_sheet['rowData'] = []
            sheet_lst.append(output_sheet)
            continue
        response_rows_data = sheet.get('data', {})[0].get('rowData', None)
        if not response_rows_data:
            row_data.append({'values': []})
        else:
            for response_values in response_rows_data:
                values = []
                if not response_values:
                    row_data.append({'values': []})
                else:
                    for response_cell_data in response_values.get('values'):
                        if not response_cell_data:
                            values.append('')
                        else:
                            values.append(response_cell_data.get('formattedValue'))
                    row_data.append({'values': values})
        output_sheet['rowData'] = row_data
        sheet_lst.append(output_sheet)
    return sheet_lst


def default_ranges_if_not_specified(spreadsheet: str, ranges: str, include_grid_data: bool, service: Resource) -> \
        str | None:
    """
        Args:
            ranges: (str) A Google A1 notation ranges
            include_grid_data: (bool) argument specified by the user
            spreadsheet (str): The spreadsheet ID
            service (Google Resource): google-api discovery resource (google api client)
        Returns:
            (str) - A1 notation: The original ranges if specified or a default range if not

        Action:
            if include_grid_data is specified without a range, instead of overflowing the server with
            all the spreadsheet data we will take only a default range 500 rows 120 columns
    """
    if not ranges and include_grid_data:
        response = service.spreadsheets().get(spreadsheetId=spreadsheet).execute()
        first_sheet_title = response.get("sheets", [])[0].get("properties", {}).get("title")
        default_range = first_sheet_title + "!A1:T500"
        return default_range
    elif ranges == 'None':
        return None
    else:
        return ranges


# COMMANDS


def create_spreadsheet(service: Resource, args: dict) -> CommandResults:
    '''
        Args:
            service (Google Resource): google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
        Returns:
            (CommandResults) command result ready for the server
        Action : creates a new spreadsheet
    '''
    rgb_format = argToList(args.get('cell_format_backgroundColor'))
    rgb_format = [1, 1, 1, 1] if not rgb_format else rgb_format
    spreadsheet = {
        "properties": {
            "title": args.get('title'),
            "locale": args.get('locale', "en"),
            "defaultFormat": {
                "numberFormat": {
                    "type": args.get('cell_form_at_type', 'TEXT'),
                },
                "backgroundColor": {
                    "red": rgb_format[0],
                    "green": rgb_format[1],
                    "blue": rgb_format[2],
                    "alpha": rgb_format[3]
                },
                "textFormat": {
                    "fontFamily": args.get('cell_format_textformat_family', 'ariel'),
                    "fontSize": args.get('cell_format_textformat_font_size', 11),
                },
                "textDirection": args.get('cell_format_text_direction', 'LEFT_TO_RIGHT'),
            }
        },
        "sheets": [
            {
                "properties": {
                    "title": args.get('sheet_title'),
                    "sheetType": args.get('sheet_type', "GRID"),
                }
            }
        ]
    }
    spreadsheet = remove_empty_elements(spreadsheet)
    response = service.spreadsheets().create(body=spreadsheet).execute()

    human_readable = {
        'spreadsheet Id': response.get('spreadsheetId'),
        'spreadsheet title': response.get('properties').get('title'),
    }
    markdown = tableToMarkdown('Successfully created a spreadsheet', human_readable,
                               headers=['spreadsheet Id', 'spreadsheet title'])
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='GoogleSheets.Spreadsheet',
        outputs_key_field='spreadsheetId',
        outputs=response
    )
    return results


def update_spreadsheet(service: Resource, args: dict) -> CommandResults:
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            CommandResults
       Action:
            updates a spreadsheet by a user costume update request
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = safe_load_json(args.get('requests'))
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'updated the spreadsheet'
    return prepare_result(response, args, readable_comment)


def get_spreadsheet(service: Resource, args: dict) -> CommandResults:
    '''
        Args:
            service - google-api discovery resource (google api client)
                args - demisto.args() for the api call
        output : command result
        action : gets a single or multiple spreadsheets
    '''
    spread_sheets_ids = argToList(args.get('spreadsheet_id'))
    include_grid_data = argToBoolean(args.get('include_grid_data', False))
    ranges = args.get('ranges')
    markdown = ""
    if not spread_sheets_ids:
        raise DemistoException('No spreadsheet ID given')
    if len(spread_sheets_ids) > 1:
        for spreadsheet in spread_sheets_ids:
            response = service.spreadsheets().get(spreadsheetId=spreadsheet).execute()
            markdown += markdown_single_get(response)
            markdown += '---\n'

        markdown = '### Success\n\n' + markdown
        return CommandResults(readable_output=markdown)
    else:
        ranges = default_ranges_if_not_specified(spread_sheets_ids[0], str(ranges), include_grid_data, service)
        request = service.spreadsheets().get(spreadsheetId=spread_sheets_ids[0], ranges=ranges,
                                             includeGridData=include_grid_data)
        response = request.execute()
        output_response = context_single_get_parse(response, include_grid_data)
        if include_grid_data:
            markdown = markdown_single_get_include_grid_data(output_response)
        else:
            markdown = markdown_single_get(response)

        markdown = '### Success\n' + markdown

        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='GoogleSheets.Spreadsheet',
            outputs_key_field='spreadsheetId',
            outputs=output_response
        )
        return results


def create_sheet(service: Resource, args: dict) -> CommandResults:
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            CommandResults
       Action:
            creates a new sheet in a spreadsheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    rgb_format = argToList(args.get('tab_color'))
    rgb_format = [1, 1, 1, 1] if not rgb_format else rgb_format
    request_to_update = {
        "requests": [
            {
                "addSheet": {
                    "properties": {
                        "sheetId": args.get('sheet_id', None),
                        "title": args.get('sheet_title', None),
                        "index": args.get('sheet_index', None),
                        "sheetType": args.get('sheet_type', "GRID"),
                        "rightToLeft": argToBoolean(args.get('right_to_left', False)),
                        "tabColor": {
                            "red": rgb_format[0],
                            "green": rgb_format[1],
                            "blue": rgb_format[2],
                            "alpha": rgb_format[3]
                        },
                        "hidden": args.get('hidden', False),
                    }
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'created a new sheet'
    results = prepare_result(response, args, readable_comment)
    return results


def duplicate_sheet(service: Resource, args: dict) -> CommandResults:
    '''
        Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults) : the command result containing the duplicate spreadsheet sheet update api call
        Action : duplicates a sheet within a spreadsheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = {
        "requests": [
            {
                "duplicateSheet": {
                    "sourceSheetId": args.get('source_sheet_id'),
                    "insertSheetIndex": args.get('new_sheet_index'),
                    "newSheetName": args.get('new_sheet_name'),
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'duplicated the sheet'
    results = prepare_result(response, args, readable_comment)
    return results


def copy_to_sheet(service: Resource, args: dict) -> CommandResults:
    '''
        Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Copies a spreadsheet sheet from one spreadsheet to another
    '''
    spreadsheet_id_to_copy = args.get('source_spreadsheet_id')

    sheet_id_to_copy = args.get('source_sheet_id')

    copy_sheet_to_another_spreadsheet_request_body = {
        'destination_spreadsheet_id': args.get('destination_spreadsheet_id'),
    }

    request = service.spreadsheets().sheets().copyTo(spreadsheetId=spreadsheet_id_to_copy, sheetId=sheet_id_to_copy,
                                                     body=copy_sheet_to_another_spreadsheet_request_body)
    request.execute()  # we don't save the response because there is no need for output or HR
    results = CommandResults(
        readable_output="### Successfully copied the sheet"
    )

    return results


def delete_sheet(service: Resource, args: dict) -> CommandResults:      # pragma: no cover
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            deletes a sheet from a spreadsheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = {
        "requests": [
            {
                "deleteSheet": {
                    "sheetId": args.get('sheet_id'),
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'deleted the sheet'
    results = prepare_result(response, args, readable_comment)
    return results


def clear_sheet(service: Resource, args: dict) -> CommandResults:       # pragma: no cover
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Clears a sheet from a spreadsheet
     '''
    spreadsheet_id = args.get('spreadsheet_id')
    ranges = args.get('range')

    request = service.spreadsheets().values().clear(spreadsheetId=spreadsheet_id, range=ranges,
                                                    body={})
    request.execute()  # we don't save the response because there is no need for output or HR
    results = CommandResults(
        readable_output='### Successfully cleared the sheet'
    )
    return results


def dimension_delete_sheet(service: Resource, args: dict) -> CommandResults:    # pragma: no cover
    '''
        Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            deletes a specified dimension from a sheet in a specified spreadsheet
     '''
    spreadsheet_id = args.get('spreadsheet_id')

    request_to_update = {
        "requests": [
            {
                "deleteDimension": {
                    "range": {
                        "dimension": args.get('dimension_type'),
                        "sheetId": args.get('sheet_id'),
                        "startIndex": args.get('start_index'),
                        "endIndex": args.get('end_index'),
                    }
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'deleted dimensions'
    results = prepare_result(response, args, readable_comment)
    return results


def range_delete_sheet(service: Resource, args: dict) -> CommandResults:    # pragma: no cover
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Deletes a specified range from a sheet in a specified spreadsheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')

    request_to_update = {
        "requests": [
            {
                "deleteRange": {
                    "range": {
                        "sheetId": args.get('sheet_id'),
                        "startRowIndex": args.get('start_row_index'),
                        "endRowIndex": args.get('end_row_index'),
                        "startColumnIndex": args.get('start_column_index'),
                        "endColumnIndex": args.get('end_column_index'),
                    },
                    "shiftDimension": args.get('shift_dimension'),
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'deleted range'
    results = prepare_result(response, args, readable_comment)
    return results


def data_paste_sheets(service: Resource, args: dict) -> CommandResults:     # pragma: no cover
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Inserts data into a spreadsheet sheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = {
        "requests": [
            {
                "pasteData": {
                    "coordinate": {
                        "sheetId": args.get('sheet_id'),
                        "rowIndex": args.get('row_index'),
                        "columnIndex": args.get('column_index'),
                    },
                    "data": args.get('data'),
                    "type": f"PASTE_{args.get('paste_type')}",
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet', None),
    }
    request_to_update = remove_empty_elements(request_to_update)
    kind = args.get('data_kind')
    paste_data = request_to_update.get('requests')[0].get('pasteData')
    # adding a field to the paste data sub dict so that it will fit the api call needed
    if kind == 'delimiter':
        paste_data[kind] = ','
    else:
        paste_data[kind] = "true"
    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'pasted the data'
    results = prepare_result(response, args, readable_comment)
    return results


def find_replace_sheets(service: Resource, args: dict) -> CommandResults:   # pragma: no cover
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Finds a vaule in the spreadsheets sheet and replaces it.
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = {
        "requests": [
            {
                "findReplace": {
                    "find": args.get('find'),
                    "replacement": args.get('replacement'),
                    "sheetId": args.get('sheet_id'),
                    "allSheets": args.get('all_sheets'),
                    "matchCase": args.get('match_case'),
                    "matchEntireCell": args.get('match_entire_cell'),
                    "range": {
                        "sheetId": args.get('range_sheet_id'),
                        "startRowIndex": args.get('range_start_row_Index'),
                        "endRowIndex": args.get('range_end_row_Index'),
                        "startColumnIndex": args.get('range_start_column_Index'),
                        "endColumnIndex": args.get('range_end_column_Index'),
                    }
                }
            }
        ],
        "includeSpreadsheetInResponse": args.get('echo_spreadsheet'),
    }

    request_to_update = remove_empty_elements(request_to_update)
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    readable_comment = 'found and replaced'
    results = prepare_result(response, args, readable_comment)
    return results


def value_update_sheets(service: Resource, args: dict) -> CommandResults:
    '''
       Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
       Returns:
            (CommandResults): Command result with only readable output
       Action:
            Updates values in the spreadsheets sheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    input_option = args.get('input_option')
    ranges = args.get('range')
    value_range_body = {
        "majorDimension": args.get('major_dimension'),
        "values": handle_values_input(str(args.get('values'))),
    }
    request = service.spreadsheets().values().update(spreadsheetId=spreadsheet_id, range=ranges,
                                                     valueInputOption=input_option, body=value_range_body)
    request.execute()
    markdown = '### Successfully updated sheet values'
    return CommandResults(readable_output=markdown)


def value_append_sheets(service: Resource, args: dict) -> CommandResults:   # pragma: no cover
    '''
         Args:
            service (discovery Resource):  google-api discovery resource (google api client)
            args (dict): demisto.args() for the api call
         Returns:
            (CommandResults): Command result with only readable output
         Action:
            Appends values to a spreadsheets sheet
    '''
    spreadsheet_id = args.get('spreadsheet_id')
    range_ = args.get('range')
    input_option = args.get('input_option')
    insert_option = args.get('insert_option')

    value_range_body = {
        "majorDimension": args.get('major_dimension'),
        "values": handle_values_input(str(args.get("values"))),
    }
    request = service.spreadsheets().values().append(spreadsheetId=spreadsheet_id, range=range_,
                                                     valueInputOption=input_option,
                                                     insertDataOption=insert_option, body=value_range_body)
    request.execute()
    markdown = '### Successfully appended values to the sheet'
    return CommandResults(readable_output=markdown)


def get_http_client_with_proxy(proxy: bool, insecure: bool):  # pragma: no cover
    """
        Args:
            proxy (bool): Whether to use a proxy.
            insecure (bool): Whether to disable ssl and use an insecure connection.
        Returns:
            httplib2 object with the proper settings for google api client
        Action:
            Create a http client with proxy with whom to use when using a proxy.
    """
    if proxy:
        proxies = handle_proxy()
        https_proxy = proxies.get('https')
        http_proxy = proxies.get('http')
        proxy_conf = https_proxy if https_proxy else http_proxy
        # if no proxy_conf - ignore proxy
        if proxy_conf:
            if not proxy_conf.startswith('https') and not proxy_conf.startswith('http'):
                proxy_conf = 'https://' + proxy_conf
            parsed_proxy = urllib.parse.urlparse(proxy_conf)
            proxy_info = httplib2.ProxyInfo(
                proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                proxy_host=parsed_proxy.hostname,
                proxy_port=parsed_proxy.port,
                proxy_user=parsed_proxy.username,
                proxy_pass=parsed_proxy.password)
            return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=insecure)
    return httplib2.Http(disable_ssl_certificate_validation=insecure)


def build_and_authenticate(params: dict):  # pragma: no cover
    """
        Args:
            params (dict):
                demisto.params() - we use the service account key and proxy and insecure parameters in order to
                build the Google API resource.
        Returns:
            Google Resource Manager API Service object via which commands in the
            integration will make API calls
    """
    service_account_credentials = params.get('service_account_credentials', {})
    try:
        service_account_credentials = service_account_credentials.get('password')
        service_account_credentials = json.loads(service_account_credentials)
    except Exception as e:
        raise DemistoException(f'\nProblem with json format please validate the correctness\
                               of your service account json. Json parser error {e}')

    try:
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(service_account_credentials,
                                                                                       scopes=SCOPES)
    except KeyError as e:
        raise DemistoException(f'There is a problem with the authentication of the Service account credentials.\
                                Please check the correctness of your credentials. You are missing the following key\
                                 in the service account {e}')
    except ValueError as e:
        raise DemistoException(f'(There is a problem with the authentication of the Service account credentials\
                                The cred are of the wrong type. Google error is : {e})')

    # add delegation to help manage the UI - link to a google-account
    if params.get('user_id'):
        credentials = credentials.create_delegated(params.get('user_id'))

    proxy = params.get('proxy', False)
    disable_ssl = params.get('insecure', False)

    if proxy or disable_ssl:
        http_client = credentials.authorize(get_http_client_with_proxy(proxy, disable_ssl))
        return build('sheets', 'v4', http=http_client)
    else:
        return build('sheets', 'v4', credentials=credentials)


def test_module() -> str:  # pragma: no cover
    return "ok"


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        service = build_and_authenticate(demisto.params())
        if command == 'test-module':
            return_results(test_module())
        elif command == 'google-sheets-spreadsheet-create':
            return_results(create_spreadsheet(service, demisto.args()))
        elif command == 'google-sheets-spreadsheet-get':
            return_results(get_spreadsheet(service, demisto.args()))
        elif command == 'google-sheets-spreadsheet-update':
            return_results(update_spreadsheet(service, demisto.args()))
        elif command == 'google-sheets-sheet-create':
            return_results(create_sheet(service, demisto.args()))
        elif command == 'google-sheets-sheet-duplicate':
            return_results(duplicate_sheet(service, demisto.args()))
        elif command == 'google-sheets-sheet-copy-to':
            return_results(copy_to_sheet(service, demisto.args()))
        elif command == 'google-sheets-sheet-delete':
            return_results(delete_sheet(service, demisto.args()))
        elif command == 'google-sheets-sheet-clear':
            return_results(clear_sheet(service, demisto.args()))
        elif command == 'google-sheets-dimension-delete':
            return_results(dimension_delete_sheet(service, demisto.args()))
        elif command == 'google-sheets-range-delete':
            return_results(range_delete_sheet(service, demisto.args()))
        elif command == 'google-sheets-data-paste':
            return_results(data_paste_sheets(service, demisto.args()))
        elif command == 'google-sheets-find-replace':
            return_results(find_replace_sheets(service, demisto.args()))
        elif command == 'google-sheets-value-update':
            return_results(value_update_sheets(service, demisto.args()))
        elif command == 'google-sheets-value-append':
            return_results(value_append_sheets(service, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{demisto.command()}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
