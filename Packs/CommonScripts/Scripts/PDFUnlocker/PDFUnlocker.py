import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from PyPDF2 import PdfFileReader, PdfFileWriter

res = demisto.executeCommand("getFilePath", {"id": demisto.args()["entryID"]})
originPath = res[0]['Contents']['path']
outputName = "UNLOCKED_" + res[0]['Contents']['name']

input1 = PdfFileReader(open(originPath, "rb"))
input1.decrypt(str(demisto.args()["password"]))

output = PdfFileWriter()
for pageNum in range(0, input1.getNumPages()):
    output.addPage(input1.getPage(pageNum))
outputStream = file(outputName, "wb")
output.write(outputStream)
outputStream.close()

demisto.results(file_result_existing_file(outputName))
