import demistomock as demisto  # noqa: F401
import xlrd
from CommonServerPython import *  # noqa: F401


def parse_excel(file_entry_id):

    res = demisto.getFilePath(file_entry_id)
    file_path = res['path']

    workbook = xlrd.open_workbook(file_path, on_demand=True)
    sheet_names = workbook.sheet_names()
    sheets = []
    context = {}

    for sheetnum in range(workbook.nsheets):
        worksheet = workbook.sheet_by_index(sheetnum)
        first_row = []
        for col in range(worksheet.ncols):
            first_row.append(str(worksheet.cell_value(0, col)))
        data = []
        for row in range(1, worksheet.nrows):
            elm = {}
            for col in range(worksheet.ncols):
                elm[first_row[col]] = worksheet.cell_value(row, col)
            data.append(elm)
        sheets.append(data)
        context["ParseExcel"] = sheets
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': data,
            'ContentsFormat': formats['json'],
            'HumanReadable': tableToMarkdown(sheet_names[sheetnum], data, first_row),
            'EntryContext': context
        })


def main():
    file_entry_id = demisto.args()['entryId']
    parse_excel(file_entry_id)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
