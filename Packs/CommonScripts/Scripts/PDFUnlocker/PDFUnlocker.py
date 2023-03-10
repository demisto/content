import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from PyPDF2 import PdfReader, PdfWriter


def unlock_pdf(entry_id):
    res = demisto.getFilePath(entry_id)
    origin_path = res['path']
    output_name = "UNLOCKED_" + res['name']

    input1 = PdfReader(open(origin_path, "rb"))
    input1.decrypt(str(demisto.args()["password"]))

    output = PdfWriter()
    for pageNum in range(0, len(input1.pages)):
        output.add_page(input1.pages[pageNum])
    with open(output_name, "wb") as pf:
        output.write(pf)

    demisto.results(file_result_existing_file(output_name))


def main():
    entry_id = demisto.args()['entryID']
    unlock_pdf(entry_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
