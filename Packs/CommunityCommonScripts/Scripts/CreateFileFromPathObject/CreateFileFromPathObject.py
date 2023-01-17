import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

obj = json.loads(demisto.args()["object"])
for attachment in obj:
    filePath = demisto.getFilePath(attachment["path"])["path"]
    with open(filePath, 'rb') as f:
        data = f.read()
        demisto.results(fileResult(attachment["name"], data))
