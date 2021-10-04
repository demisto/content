from CommonServerPython import *  # noqa: F401


def main():
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

    build_number = get_demisto_version()['buildNumber']
    # in local development instances, the build number will be "REPLACE_THIS_WITH_CI_BUILD_NUM"
    build_number = f'{build_number}' if build_number != "REPLACE_THIS_WITH_CI_BUILD_NUM" else "618658"

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
        for counter, entry in enumerate(stats):
            higher = max(entry["data"][0], higher)
            if counter % 60 == 0:
                then = then + timedelta(hours=1)
                name = then.strftime("%H:%M")
                output.append({"name": name, "data": [higher]})
                higher = 0

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
