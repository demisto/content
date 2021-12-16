"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

from googleapiclient.discovery import build
from google.oauth2 import service_account

SERVICE_ACCOUNT_FILE = 'token.json'
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


def create_spread_sheet(service, args: dict):
    # in this function I can set them to None and then remove them in
    # the next function, or I can set them manually to the default value.
    spreadsheet = {
        "properties": {
            "title": demisto.args().get('title'),
            "locale": "en" if args.get('locale') is None else args.get('locale'),
            "defaultFormat": {
                "numberFormat": {
                    "type": 'TEXT' if args.get('cell_form_at_type') is None else args.get('cell_form_at_type')
                },
                "backgroundColor": {
                    "red": 1 if args.get('red') is None else args.get('red'),
                    "green": 1 if args.get('green') is None else args.get('green'),
                    "blue": 1 if args.get('blue') is None else args.get('blue'),
                    "alpha": 1 if args.get('alpha') is None else args.get('alpha'),
                },
                "textFormat": {
                    "fontFamily": 'ariel' if args.get('cell_format_textformat_family') is None else args.get(
                        'cell_format_textformat_family'),
                    "fontSize": 11 if args.get('cell_format_textformat_font_size') is None else args.get(
                        'cell_format_textformat_font_size')
                },
                "textDirection": "LEFT_TO_RIGHT" if args.get('cell_format_text_direction') is None else args.get(
                    'cell_format_text_direction')
            }
        },
        "sheets": [
            {
                "properties": {
                    "title": args.get('sheet_title'),
                    "sheetType": "GRID" if args.get('sheet_type') is None else args.get('sheet_type')
                }
            }
        ]
    }
    # this removes all None values from the json in a recursive manner.
    spreadsheet = remove_empty_elements(spreadsheet)
    spreadsheet = service.spreadsheets().create(body=spreadsheet, fields='spreadsheetId').execute()
    print('Spreadsheet ID: {0}'.format(spreadsheet.get('spreadsheetId')))
    return spreadsheet


# TODO: understand better what is the type of the ranges and what is include grid data
def get_spread_sheet(service, args: dict):
    spreadsheet_id = args.get('spreadsheet_id')

    # The ranges to retrieve from the spreadsheet.
    ranges = args.get('ranges')

    # True if grid data should be returned.
    # This parameter is ignored if a field mask was set in the request.
    include_grid_data = args.get('include_grid_data')

    request = service.spreadsheets().get(spreadsheetId=spreadsheet_id, ranges=ranges, includeGridData=include_grid_data)
    response = request.execute()
    return response


def sheet_create(service , args:dict):

    spreadsheet_id = args.get('spreadsheet_id')

    request_to_update = {
        "requests": [
            {
                "addSheet": {
                    "properties": {
                        "title": "",
                        "sheetType": "",
                        "rightToLeft": False,
                        "tabColor": {
                            "red": 0,
                            "green": 0,
                            "blue": 0,
                            "alpha": 0
                        },
                        "hidden": False
                    }
                }
            }
        ],
        "includeSpreadsheetInResponse": False
    }

    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    # TO ACCEESS A SPECIFIC RESPONSE
    # find_replace_response = response.get('replies')[1].get('findReplace')
    # print('{0} replacements made.'.format(
    #     find_replace_response.get('occurrencesChanged')))
    return response


def sheet_duplicatet(service , args:dict):

    spreadsheet_id = args.get('spreadsheet_id')
    request_to_update = {
        "requests": [
            {
                "duplicateSheet": {
                    "sourceSheetId": 0,
                    "insertSheetIndex": 0,
                    "newSheetName": ""
                }
            }
        ],
        "responseIncludeGridData": false
    }
    response = service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body=request_to_update).execute()
    return response

''' COMMAND FUNCTIONS '''


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    # base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    # proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    num = 5
    # TODO: Omer check where to put this. here i also need to add to take the credentials
    try:
        servie_account_credentials = demisto.params().get('service_account_credentials')
        creds = service_account.Credentials.from_service_account_info(servie_account_credentials, scopes=SCOPES)
        # creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=creds)
    except Exception as e:
        return_error(f"Failed to connect to Google API client {e}")

    # if i got here then the Google API conneccted succssefuly and i can continue with the other commands.
    try:
        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            # result = test_module()
            return_results("ok")

        elif demisto.command() == 'google-sheets-spreadsheet-create':
            return_results(create_spread_sheet(service, demisto.args()))
        elif demisto.command() == 'google-sheets-spreadsheet-get':
            return_results(get_spread_sheet(service, demisto.args()))
        elif demisto.command() == 'google-sheets-spreadsheet-update':
            return_results(None)
        elif demisto.command() == 'google-sheets-sheet-create':
            return_results(sheet_create(service , demisto.args()))
        elif demisto.command() == 'google-sheets-sheet-duplicate':
            return_results(None)
        elif demisto.command() == 'google-sheets-sheet-copy-to':
            return_results(None)
        elif demisto.command() == 'google-sheets-sheet-delete':
            return_results(None)
        elif demisto.command() == 'google-sheets-sheet-clear':
            return_results(None)
        elif demisto.command() == 'google-sheets-dimension-delete':
            return_results(None)
        elif demisto.command() == 'google-sheets-range-delete':
            return_results(None)
        elif demisto.command() == 'google-sheets-data-paste':
            return_results(None)
        elif demisto.command() == 'google-sheets-cell-update':
            return_results(None)
        elif demisto.command() == 'google-sheets-find-replace':
            return_results(None)
        elif demisto.command() == 'google-sheets-value-update':
            return_results(None)
        elif demisto.command() == 'google-sheets-value-append':
            return_results(None)



    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
