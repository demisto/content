import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    partition = "/"

    res = demisto.executeCommand("demisto-api-get", {"uri": "/system/config"})
    if is_error(res):
        return_results(res)
        return_error('Failed to execute demisto-api-get. See additional error details in the above entries.')

    config_json = res[0]['Contents']['response']
    partition = config_json.get('sysConf', {}).get('disk.partitions.to.monitor') or '/'

    res = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": "/statistics/widgets/query",
            "body": {
                "size": 1440,
                "dataType": "system",
                "params": {
                    "timeFrame": "minutes",
                },
                "query": f"disk.usedPercent.{partition}",
                "dateRange": {
                    "period": {
                        "byFrom": "hours",
                        "fromValue": 24,
                    },
                },
                "widgetType": "line",
            },
        })
    if is_error(res):
        return_results(res)
        return_error('Failed to execute demisto-api-post. See additional error details in the above entries.')

    stats = res[0]["Contents"]["response"]
    output = []
    counter = 0
    higher = 0

    build_number = get_demisto_version()['buildNumber']
    if int(build_number) >= 618657:
        # Line graph:
        for counter, entry in enumerate(stats):
            higher = max(entry["data"][0], higher)
            if counter % 2 == 0:
                output.append({"name": counter, "data": [higher]})
                higher = 0

        data = {
            "Type": 17,
            "ContentsFormat": "line",
            "Contents": {
                "stats": output,
                "params": {
                    "timeFrame": "minutes",
                    "format": "HH:mm",
                    "layout": "vertical"
                }
            }
        }
    else:
        # Bar graph:
        now = datetime.utcnow()
        then = now - timedelta(days=1)
        for entry in stats:
            higher = max(entry["data"][0], higher)
            if counter % 60 == 0:
                then = then + timedelta(hours=1)
                name = then.strftime("%H:%M")
                output.append({"name": name, "data": [higher]})
                higher = 0
            counter += 1

        data = {
            "Type": 17,
            "ContentsFormat": "bar",
            "Contents": {
                "stats": output,
                "params": {
                    "layout": "horizontal"
                }
            }
        }
    return data


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
