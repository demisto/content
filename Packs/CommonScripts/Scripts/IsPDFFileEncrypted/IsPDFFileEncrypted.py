import demistomock as demisto
from CommonServerPython import *

import PyPDF2


def is_pdf_encrypted(file_path: str) -> bool:
    demisto.debug("Trying to open file")
    with open(file_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        demisto.debug("Opened file, retuning if it's encrypted.")
        return reader.is_encrypted


def main():  # pragma: no cover
    args = demisto.args()
    entry_id = args.get('EntryID')
    file_path = demisto.getFilePath(entry_id).get('path')
    if not file_path:
        raise DemistoException("File not found. Please enter a valid entry ID.")
    try:
        demisto.debug("Checking if file is encrypted")
        return_results("yes" if is_pdf_encrypted(file_path) else "no")
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error("An error occurred, Verify the PDF file is readable. Error: " + str(e))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
