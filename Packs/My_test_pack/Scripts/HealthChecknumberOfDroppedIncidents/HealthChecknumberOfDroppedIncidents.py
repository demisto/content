import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timedelta

args = demisto.args()

isWidget = args.get('isWidget', False)

daysAgo = datetime.today() - timedelta(days=30)


stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": "/settings/audits",
        "body": {
            "size": 10000,
            "query": "type:notcreated and modified:>%s" % str(daysAgo.strftime("%Y-%m-%d"))

        }
    })


if isWidget == True:
    data = {
        "Type": 17,
        "ContentsFormat": "number",
        "Contents": {
            "stats": stats[0]["Contents"]["response"]['total'],
            "params": {
                "timeFrame": "minutes",
                "colors": {
                    "isEnabled": True,
                    "items": {
                        "#D13C3C": {
                          "value": 15
                        }
                    },
                }
            }
        }
    }

    demisto.results(data)
else:
    actionItems = []
    if stats[0]["Contents"]["response"]['total'] > 2000:
        actionItems.append({'category': 'Incidents Analysis', 'severity': 'Low',
                            'description': "Too many dropped incidents, consider to tune the defined query to avoid fetching unneeded events"})

        results = CommandResults(
            readable_output="HealthCheckFileSysLog Done",
            outputs_prefix="actionableitems",
            outputs=actionItems)

        return_results(results)

    demisto.results({'Type': entryTypes['note'],
                     'Contents': stats[0]["Contents"]["response"]['total'],
                     'ContentsFormat': formats['text'],
                     'HumanReadable': stats[0]["Contents"]["response"]['total'],
                     'ReadableContentsFormat': formats['text'],
                     'EntryContext': {'numberOfDroppedIncidents': stats[0]["Contents"]["response"]['total']}
                     })
