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
                worksheet.write(row, col, item.get(value, ""), border)
                col += 1


def parse_data(data, sheets):
    if isinstance(data, str):  # check that
        if len(sheets) <= 1:  # why?
            return_error("Multiple sheet names are required for an object with multiple data items")
        data_list = json.loads("[" + data + "]")  # that too
        data_dict = {}
        counter = 0
        for list_item in data_list:
            data_dict[counter] = list_item
            counter += 1

        return data_dict


def prepare_bold_and_border(workbook, is_bold, is_border):
    bold_value = 1 if is_bold else 0
    border_value = 1 if is_border else 0

    bold = workbook.add_format({"bold": bold_value, "border": border_value})
    border = workbook.add_format({"border": border_value})

    return bold, border


def main():
    args = demisto.args()
    data = args.get("data")
    file_name = args.get("file_name")
    sheet_name = args.get("sheet_name")
    headers = args.get("headers", None)
    is_bold = argToBool(args.get("bold"))
    is_border = argToBool(args.get("border"))

    sheets = sheet_name.split(",")
    data = parse_data(data, sheets)

    if len(sheets) > 1 and len(sheets) != len(data):
        return_error("Number of sheet names should be equal to the number of data items")

    if headers:
        headers_list = headers.split(";")

        if len(sheets) != len(headers_list):
            return_error("Number of sheet headers should be equal to the number of sheet names")
    else:
        headers_list = None

    workbook = xlsxwriter.Workbook(file_name)

    bold, border = prepare_bold_and_border(workbook, is_bold, is_border)

    # if len(sheets) == 1:
    #     if headers_list:
    #         data_headers = headers_list[0].split(",")
    #     else:
    #         data_headers = None
    #     write_data(sheets[0], data, data_headers, workbook, bold, border)
    #
    # else:

    multi_header_list = []
    if headers_list:  # Can be 1 item in case there is one sheet, or multiple items in case there are multiple sheets
        for header_list in headers_list:
            multi_header_list.append(header_list.split(","))
    else:
        multi_header_list = [None] * len(sheets)
    for sheet, data_item, multi_header_list in zip(sheets, data, multi_header_list):
        write_data(sheet, data[data_item], multi_header_list, workbook, bold, border)

    workbook.close()
    demisto.results(file_result_existing_file(file_name))


if __name__ in ('__builtin__', '__main__'):
    main()
