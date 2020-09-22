import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

listData = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Integrations Table"})
listContent = listData[0].get('Contents')

listJson = json.loads(listContent)
listTable = []
if isinstance(listJson, list):
    for instance in listJson:
        listTable.append({"Brand": instance.get('brand'), "Instance": instance.get('instance'),
                          "Category": instance.get('category'), "Information": instance.get('information')})
    demisto.results({'total': len(listTable), 'data': listTable})

elif isinstance(listJson, dict):
    listTable.append({"Brand": listJson.get('brand'), "Instance": listJson.get('instance'),
                      "Category": listJson.get('category'), "Information": listJson.get('information')})
    demisto.results({'total': len(listTable), 'data': listTable})

else:
    data = {"total": 1, "data": [{"Brand": "N\A", "Instance": "N\A", "Category": "N\A", "Information": "N\A"}]}
    demisto.results(data)
