import demistomock as demisto  # noqa: F401
import pysftp
from CommonServerPython import *  # noqa: F401

cnopts = pysftp.CnOpts()
cnopts.hostkeys = None

HOST = demisto.params()["host"]
USERNAME = demisto.params()['authentication']['identifier']
PASSWORD = demisto.params()['authentication']['password']

if demisto.command() == "test-module":
    with pysftp.Connection(host=HOST, username=USERNAME, password=PASSWORD, cnopts=cnopts) as sftp:
        demisto.results("ok")
if demisto.command() == "sftp-listdir":
    directory = demisto.args()["directory"]
    with pysftp.Connection(host=HOST, username=USERNAME, password=PASSWORD, cnopts=cnopts) as sftp:
        res = sftp.listdir(directory)
    entry = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': res,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': res,
        'EntryContext': {"SFTP.ListDir": res}
    }
    demisto.results(entry)
elif demisto.command() == "sftp-copyfrom":
    filePath = demisto.args()["filePath"]
    with pysftp.Connection(host=HOST, username=USERNAME, password=PASSWORD, cnopts=cnopts) as sftp:
        res = sftp.get(filePath, "/tmp/" + filePath[filePath.rindex("/") + 1:])

    with open("/tmp/" + filePath[filePath.rindex("/") + 1:], "r") as f:
        data = f.read()
    entry = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': data,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': res,
        'EntryContext': {"SFTP.File.Content": data}
    }
    demisto.results(entry)
