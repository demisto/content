import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from datetime import datetime, timedelta

incident = demisto.incidents()[0]
accountName = incident.get('account')
accountName = f"acc_{accountName}/" if accountName != "" else ""

args = demisto.args()
Thresholds = {
    "NumberOfDroppedIncidents": 2000
}
thresholds = args.get('Thresholds', Thresholds)
isWidget = args.get('isWidget', True)

daysAgo = datetime.today() - timedelta(days=30)


stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": f"{accountName}settings/audits",
        "body": {
            "size": 10000,
            "query": "type:notcreated and modified:>%s" % str(daysAgo.strftime("%Y-%m-%d"))

        }
    })


if isWidget is True:
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
    if stats[0]["Contents"]["response"]['total'] > thresholds['NumberOfDroppedIncidents']:
        actionItems.append({'category': 'Incidents Analysis', 'severity': 'Low',
                            'description': "Too many dropped incidents",
                            'resolution': "Consider tuning the defined query to avoid fetching unneeded incidents"
                            })

        results = CommandResults(
            readable_output="HealthCheckFileSysLog Done",
            outputs_prefix="HealthCheck.ActionableItems",
            outputs=actionItems)

        return_results(results)

    demisto.results({'Type': entryTypes['note'],
                     'Contents': stats[0]["Contents"]["response"]['total'],
                     'ContentsFormat': formats['text'],
                     'HumanReadable': stats[0]["Contents"]["response"]['total'],
                     'ReadableContentsFormat': formats['text'],
                     'EntryContext': {'NumberOfDroppedIncidents': stats[0]["Contents"]["response"]['total']}
                     })
