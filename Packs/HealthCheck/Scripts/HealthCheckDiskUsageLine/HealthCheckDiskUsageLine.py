from CommonServerPython import *  # noqa: F401


def main():
    ctx = demisto.context()
    dataFromCtx = ctx.get("widgets")
    if not dataFromCtx:
        res = execute_command("demisto-api-get", {"uri": "/system/config"})

        config_json = res['response']
        partition = config_json.get('sysConf', {}).get('disk.partitions.to.monitor') or '/'

        res = execute_command(
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

        stats = res["response"]
        output = []
        higher = 0

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
        data = {
            "Type": 17,
            "ContentsFormat": "line",
            "Contents": {
                "stats": dataFromCtx['DiskUsagePerLine'],
                "params": {
                    "timeFrame": "minutes",
                    "format": "HH:mm",
                    "layout": "vertical"
                }
            }
        }
    return data


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
