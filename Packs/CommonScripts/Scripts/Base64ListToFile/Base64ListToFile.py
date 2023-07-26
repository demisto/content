import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import zlib


def base64_list_to_file(args):
    # Output file name
    if 'filename' in args:
        outfilename = args['filename']
    else:
        outfilename = args['listname']

    # get the list
    res = demisto.executeCommand('getList', {'listName': args['listname']})
    res = res[0]
    if is_error(res):
        raise DemistoException("error reading list %s from demisto" % args['listname'])

    # convert base64 file to binary file
    bin_file = base64.decodebytes(bytes(res['Contents'], 'utf-8'))
    if args.get('isZipFile', 'no') == 'yes':
        bin_file = zlib.decompress(bin_file)

    # output file to warroom
    return fileResult(outfilename, bin_file)


def main():
    try:
        file_entry = base64_list_to_file(demisto.args())
        return_results(file_entry)
    except DemistoException as ex:
        return_error(ex.message)


if __name__ in ["__builtin__", "builtins"]:
    main()
