import base64
import zlib

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Output file name
if 'filename' in demisto.args():
    outfilename = demisto.args()['filename']
else:
    outfilename = demisto.args()['listname']

# get the list
res = demisto.executeCommand('getList', {'listName': demisto.args()['listname']})
res = res[0]
if isError(res):
    return_error("error reading list %s from demisto" % demisto.args()['listname'])

# convert base64 file to binary file
bin_file = base64.decodestring(res['Contents'])
if demisto.args()['isZipFile'] == 'yes':
    bin_file = zlib.decompress(bin_file)

# output file to warroom
demisto.results(fileResult(outfilename, bin_file))
