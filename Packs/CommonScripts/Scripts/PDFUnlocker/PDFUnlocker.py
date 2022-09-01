import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from PyPDF2 import PdfFileReader, PdfFileWriter


def unlock_pdf(entry_id):
    res = demisto.getFilePath(entry_id)
    origin_path = res['path']
    output_name = "UNLOCKED_" + res['name']

    input1 = PdfFileReader(open(origin_path, "rb"))
    input1.decrypt(str(demisto.args()["password"]))

    output = PdfFileWriter()
    for pageNum in range(0, input1.getNumPages()):
        output.addPage(input1.getPage(pageNum))
    output_stream = file(output_name, "wb")
    output.write(output_stream)
    output_stream.close()

    demisto.results(file_result_existing_file(output_name))


def main():
    entry_id = demisto.args()['entryID']
    unlock_pdf(entry_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
