import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Integrations Table"})
list_content = list_data[0].get('Contents')

list_table = []
list_json = json.loads(list_content)

if isinstance(list_json, list):
    for instance in list_json:
        list_table.append({"Brand": instance.get('brand'), "Instance": instance.get('instance'),
                          "Category": instance.get('category'), "Information": instance.get('information')})
    demisto.results({'total': len(list_table), 'data': list_table})

elif isinstance(list_json, dict):
    list_table.append({"Brand": list_json.get('brand'), "Instance": list_json.get('instance'),
                      "Category": list_json.get('category'), "Information": list_json.get('information')})
    demisto.results({'total': len(list_table), 'data': list_table})

else:
    data = {"total": 1, "data": [{"Brand": "N\\A", "Instance": "N\\A", "Category": "N\\A", "Information": "N\\A"}]}
    demisto.results(data)
