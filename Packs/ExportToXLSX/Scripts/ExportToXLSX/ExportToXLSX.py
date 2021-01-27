from typing import List, Optional, Union
from CommonServerPython import *
import demistomock as demisto
import traceback

from xlsxwriter import Workbook
from xlsxwriter.format import Format


def write_data(sheet: str, data_item: Union[dict, list], data_headers: Optional[list], workbook: Workbook, bold: Format,
               border: Format):
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
        if item and isinstance(item, dict):
            col = 0
            row += 1
            for header in data_headers:
                item_value = item.get(header)
                if item_value:
                    if isinstance(item_value, list):
                        worksheet.write(row, col, ', '.join(item_value), border)
                    else:
                        worksheet.write(row, col, str(item_value), border)
                col += 1


def parse_data(data: Union[str, dict, list], sheets: list):
    if isinstance(data, str):  # Indicates that the data is a comma-separated list of context keys.
        data_list = json.loads("[" + data + "]")
        if len(sheets) != len(data_list):
            raise ValueError("Number of sheet names should be equal to the number of data items.")

        return data_list
    else:
        if len(sheets) != 1:
            raise ValueError("Number of sheet names should be equal to the number of data items.")
    return [data]


def prepare_bold_and_border(workbook: Workbook, is_bold: bool, is_border: bool):
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
        headers = args.get("headers")
        is_bold = argToBoolean(args.get("bold", "true"))
        is_border = argToBoolean(args.get("border", "true"))

        sheets = argToList(sheet_name)
        data = parse_data(data, sheets)

        if headers:
            headers_list = argToList(headers, separator=";")

            if len(sheets) != len(headers_list):
                raise ValueError("Number of sheet headers should be equal to the number of sheet names")
        else:
            headers_list = None

        with Workbook(file_name) as workbook:

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

        return_results(file_result_existing_file(file_name))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExportToXLSX script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
