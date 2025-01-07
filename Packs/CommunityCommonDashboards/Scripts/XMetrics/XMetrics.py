import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


MONTHLABELS = ["01_Jan", "02_Feb", "03_Mar", "04_Apr", "05_May", "06_Jun",
               "07_Jul", "08_Aug", "09_Sep", "10_Oct", "11_Nov", "12_Dec"]

EFFORTCOLORS = ["RoyalBlue", "SkyBlue", "ForestGreen", "LimeGreen"]
SLACOLORS = ["Thistle", "Violet", "Orchid", "Magenta", "MediumOrchid",
             "MediumPurple", "BlueViolet", "Purple", "Indigo", "DarkSlateBlue"]
INCCOLORS = ["PaleGreen", "Bisque", "LightGreen", "Wheat", "DarkSeaGreen",
             "Tan", "MediumSeaGreen", "SandyBrown", "SeaGreen", "GoldenRod",
             "ForestGreen", "DarkGoldenRod", "Green", "Chocolate", "DarkGreen",
             "Sienna", "DarkOliveGreen", "Brown", "Teal", "Maroon"]

METRICCOLORS = {
    'Incident Effort': EFFORTCOLORS,
    'SLA Metrics': SLACOLORS,
    'Incidents': INCCOLORS,
    'Closed Incidents': INCCOLORS,
    "Incident Open Duration": INCCOLORS,
    "Effort Reduction": INCCOLORS
}


def SetMetricColors(wstats: list, metrictype: str) -> list:
    if metrictype in METRICCOLORS:
        colors = METRICCOLORS[metrictype]
    else:
        return (wstats)

    for stat in wstats:
        i = 0
        for g in stat['groups']:
            stat['groups'][i]['color'] = colors[i % len(colors)]
            i += 1

    return (wstats)


def StackedBars(group: list, key: str, val: list, index: int) -> list:
    group.append({'name': key, 'data': [val[index]], 'color': ""})
    return (group)


def TaskWidgetGroup(wstats: list, name: str, groups: list) -> list:
    wstats.append({'name': name, 'groups': groups, 'data': [], 'label': "", 'color': ""})
    return (wstats)


def LoadList(listname: str) -> dict:
    results = demisto.executeCommand("getList", {'listName': listname})[0]['Contents']
    fields = {}
    if "Item not found" not in results and (results is not None or results != ""):
        if results != "":
            fields = json.loads(results)
    return (fields)


def BuildIncidentTable(incidents, metrictype: str) -> dict:
    table = {}
    divisor = 1
    if metrictype in ["SLA Metrics", "Incident Open Duration"]:
        divisor = 60

    for inctype, v in incidents.items():
        monthindex = 0
        for month, cnt in v.items():
            if inctype not in table:
                table[inctype] = [0] * 12
            table[inctype][monthindex] = int(int(cnt) / divisor)
            monthindex += 1

    return (table)


def BuildEffortReductionTable(incidents, efforts) -> dict:
    table = {}
    total = [0] * 12

    for inctype, v in incidents.items():
        monthindex = 0
        for month, val in v.items():
            ival = int(val)
            if inctype in efforts:
                deleff = efforts[inctype][0] - efforts[inctype][1]
                effreduced = int(ival * deleff)
            else:
                effreduced = 0
            if inctype not in table:
                table[inctype] = [0] * 12
            table[inctype][monthindex] = effreduced
            total[monthindex] += effreduced
            monthindex += 1

    for inctype, v in table.items():
        monthindex = 0
        for month in v:
            if total[monthindex] > 0:
                table[inctype][monthindex] = int((table[inctype][monthindex] / total[monthindex]) * 100.0)
            monthindex += 1

    return (table)


def BuildEffortTable(incidents, efforts) -> dict:
    table = {
        "Manual Incident Effort": [0] * 12,
        "Manual Indicator Effort": [0] * 12,
        "Automated Incident Effort": [0] * 12,
        "Automated Indicator Effort": [0] * 12
    }

    for inctype, v in incidents.items():
        # Sum the incident counts times the effort estimates in minutes, converted to hours
        monthindex = 0
        for month, val in v.items():
            if inctype in efforts:
                table["Manual Incident Effort"][monthindex] += int((int(val) * efforts[inctype][0]) / 60)
                table["Automated Incident Effort"][monthindex] += int((int(val) * efforts[inctype][1]) / 60)
            monthindex += 1

    return (table)


def main():
    try:
        metricslist = demisto.args()["listname"]
        effortlist = demisto.args().get("efflistname", "")
        metrictype = demisto.args()["metrictype"]
        if metrictype == "Effort Reduction":
            metrics = LoadList(metricslist).get("Incidents", {})
        else:
            metrics = LoadList(metricslist).get(metrictype, {})
        if not metrics:
            return_results("[]")

        if effortlist != "":
            efforts = LoadList(effortlist)
            if metrictype == "Effort Reduction":
                stats = BuildEffortReductionTable(metrics, efforts)
            else:
                stats = BuildEffortTable(metrics, efforts)
        else:
            stats = BuildIncidentTable(metrics, metrictype)
        if len(stats) == 0:
            return
        wstats: list = []
        i = 0

        for label in MONTHLABELS:
            bars: list = []
            for key, val in stats.items():
                bars = StackedBars(bars, key, val, i)
            wstats = TaskWidgetGroup(wstats, label, bars)
            i += 1

        if effortlist != "" and metrictype == "Incidents":
            wstats = SetMetricColors(wstats, "Incident Effort")
        else:
            wstats = SetMetricColors(wstats, metrictype)

        return_results(json.dumps(wstats))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"XMetrics - exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
