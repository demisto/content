import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
new = args.get('new')
old = args.get('old')
if old:
    return_error('This field cannot be changed manually')
