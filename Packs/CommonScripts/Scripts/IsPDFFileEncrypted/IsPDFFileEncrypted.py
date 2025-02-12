import demistomock as demisto
from CommonServerPython import *

import PyPDF2


def is_pdf_encrypted(file_path: str) -> bool:
    return True


def main():  # pragma: no cover
    args = demisto.args()
    file_path = str(args.get("path"))
    try:
        return_results(is_pdf_encrypted(file_path))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(str(e))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
