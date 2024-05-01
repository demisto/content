import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pikepdf import Pdf, PasswordError


def unlock_pdf(args: dict):
    res = demisto.getFilePath(args.get('entryID'))
    origin_path = res['path']
    output_name = "UNLOCKED_" + res['name']

    try:
        with Pdf.open(origin_path, password=str(args.get("password"))) as unlocked_pdf:
            unlocked_pdf.save(output_name)
        return_results(file_result_existing_file(output_name))
    except PasswordError:
        return_error("Incorrect password. Please provide the correct password.")


def main():
    args = demisto.args()
    unlock_pdf(args)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
