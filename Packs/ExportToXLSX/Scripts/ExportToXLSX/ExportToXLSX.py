import traceback
from typing import List, Optional

import demistomock as demisto
import xlsxwriter
from CommonServerPython import *


def write_data(sheet, data_item, data_headers, workbook, bold, border):
    if not isinstance(data_item, list):
        data_item = [data_item]

    if not data_headers:
        data_headers = list(data_item[0].keys())

    worksheet = workbook.add_worksheet(sheet)
    row = 0
    col = 0

    for key in data_headers:
        worksheet.write(row, col, key, bold)
        col += 1

    for item in data_item:
        if len(item) > 0:
            col = 0
            row += 1
            for value in data_headers:
                if item.get(value):
                    worksheet.write(row, col, item.get(value), border)
                    col += 1
                else:
                    raise ValueError(f'The header "{value}" does not exist in the given data item.')


def parse_data(data, sheets):
    if isinstance(data, str):  # Indicates that the data is a comma-separated list of context keys.
        data_list = json.loads("[" + data + "]")
        if len(sheets) != len(data_list):
            raise ValueError("Number of sheet names should be equal to the number of data items.")

        return data_list
    else:
        if len(sheets) != 1:
            raise ValueError("Number of sheet names should be equal to the number of data items.")
    return [data]


def prepare_bold_and_border(workbook, is_bold, is_border):
    bold_value = 1 if is_bold else 0
    border_value = 1 if is_border else 0

    bold = workbook.add_format({"bold": bold_value, "border": border_value})
    border = workbook.add_format({"border": border_value})

    return bold, border


def main():
    try:
        args = demisto.args()
        data = args.get("data")
        file_name = args.get("file_name")
        sheet_name = args.get("sheet_name")
        headers = args.get("headers", None)
        is_bold = argToBoolean(args.get("bold", 'true'))
        is_border = argToBoolean(args.get("border", 'true'))

        sheets = sheet_name.split(",")
        data = parse_data(data, sheets)

        if len(sheets) != len(data):
            raise ValueError("Number of sheet names should be equal to the number of data items.")

        if headers:
            headers_list = headers.split(";")

            if len(sheets) != len(headers_list):
                raise ValueError("Number of sheet headers should be equal to the number of sheet names")
        else:
            headers_list = None

        workbook = xlsxwriter.Workbook(file_name)

        bold, border = prepare_bold_and_border(workbook, is_bold, is_border)

        multi_header_list: List[Optional[List]] = []
        if headers_list:  # Can be 1 item in case there is one sheet, or multiple items in case there are multiple
            # sheets
            for header_list in headers_list:
                multi_header_list.append(header_list.split(","))
        else:
            multi_header_list = [None] * len(sheets)
        for sheet, data_item, headers_list in zip(sheets, data, multi_header_list):
            write_data(sheet, data_item, headers_list, workbook, bold, border)

        workbook.close()
        demisto.results(file_result_existing_file(file_name))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExportToXLSX script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
