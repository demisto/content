import demistomock as demisto
from CommonServerPython import *

res = demisto.executeCommand("demisto-api-post",
                             {
                                 "uri": "statistics/widgets/query",
                                 "body":
                                     json.dumps(
                                         {"dataType": "indicators",
                                          "widgetType": "bar",
                                          "query": "type:\"MITRE ATT\u0026CK\" and investigationsCount:\u003e0",
                                          "params": {
                                              "groupBy": [
                                                  "name"
                                              ],
                                              "keys": [
                                                  "sum|investigationsCount"
                                              ]
                                          }
                                          })
                             })

indicators = []
for v in res[0]['Contents']['response']:
    value = v["name"]
    indicator_res = demisto.executeCommand("getIndicator", {"value": value})[0]['Contents']
    for ind in indicator_res:
        indicators.append({
            'Value': ind['value'],
            'Name': ind['CustomFields']['mitrename'],
            'Phase Name': ind['CustomFields']['mitrekillchainphases'][0]['phase_name'],
            'Description': ind['CustomFields']['mitredescription'],

        })

temp = tableToMarkdown('MITRE ATT&CK techniques by open Incidents', indicators,
                       headers=['Value', 'Name', 'Phase Name', 'Description'])
return_outputs(temp)
