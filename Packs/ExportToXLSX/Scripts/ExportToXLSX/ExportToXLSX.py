import demistomock as demisto
import xlsxwriter
from CommonServerPython import *

args = demisto.args()
data = args["data"]
fileName = args["fileName"]
sheetName = args["sheetName"]
headers = args.get("headers", None)
boldArg = args["bold"]
borderArg = args["border"]


def writeData(sheet, dataItem, dataHeaders):
    if not isinstance(dataItem, list):
        dataItem = [dataItem]

    if not dataHeaders:
        dataHeaders = list(dataItem[0].keys())

    worksheet = workbook.add_worksheet(sheet)
    row = 0
    col = 0

    for key in dataHeaders:
        worksheet.write(row, col, key, bold)
        col += 1

    for item in dataItem:
        if len(item) > 0:
            col = 0
            row += 1
            for value in dataHeaders:
                worksheet.write(row, col, item.get(value, ""), border)
                col += 1


sheets = sheetName.split(",")

if isinstance(data, str):
    if len(sheets) <= 1:
        return_error("Multiple sheet names are required for an object with multiple data items")
    dataList = json.loads("[" + data + "]")
    dataDic = {}
    counter = 0
    for listItem in dataList:
        dataDic[counter] = listItem
        counter += 1
    data = dataDic

if (len(sheets) > 1 and len(sheets) != len(data)):
    return_error("Number of sheet names is different from the number of data items")

if headers:
    headersList = headers.split(";")

    if (len(sheets) != len(headersList)):
        return_error("Number of sheet headers is different from the number of sheet names")
else:
    headersList = None

workbook = xlsxwriter.Workbook(fileName)

boldFormat = 1 if boldArg == "true" else 0
borderFormat = 1 if borderArg == "true" else 0

bold = workbook.add_format({"bold": boldFormat, "border": borderFormat})
border = workbook.add_format({"border": borderFormat})

if len(sheets) == 1:
    if headersList:
        dataHeaders = headersList[0].split(",")
    else:
        dataHeaders = None
    writeData(sheets[0], data, dataHeaders)

else:
    multiHeaderList = []
    if headersList:
        for headerList in headersList:
            multiHeaderList.append(headerList.split(","))
    else:
        for s in sheets:
            multiHeaderList.append(None)
    for sheet, dataItem, multiHeaderItem in zip(sheets, data, multiHeaderList):
        writeData(sheet, data[dataItem], multiHeaderItem)

workbook.close()
demisto.results(file_result_existing_file(fileName))
