import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
AsciiEncode - Demisto Automation

Takes 'data' string as an input and outputs the data encoded in an ASCII string, while ignoring any characters that are unrecognizable.

"""

# Grab 'data' from Demisto Arguments
data = demisto.args()['data']

# Encode the data, ignoring characters
try:
    encoded_data = data.encode('ascii', 'ignore')
except:
    myErrorText = "There was an error encoding the data."
    demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})

# Output the data and add results to war room

demisto.results(
    {'ContentsFormat': formats['text'],
     'Type': entryTypes['note'],
     'Contents': 'Success: ' + encoded_data,
     'EntryContext': {'asciiencode': {'encoded': encoded_data}}
     })
