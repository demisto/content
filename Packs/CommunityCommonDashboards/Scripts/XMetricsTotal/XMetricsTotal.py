import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

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

    i = 0
    for w in wstats:
        wstats[i]['color'] = colors[i % len(colors)]
        i += 1

    return (wstats)


def MetricWidget(wstats: list, name: str, data: list) -> list:
    w = {'name': name, 'data': [data], 'color': ""}
    wstats.append(w)
    return (wstats)


def LoadList(listname: str) -> dict:
    results = demisto.executeCommand("getList", {'listName': listname})[0]['Contents']
    fields = {}
    if "Item not found" not in results and (results is not None or results != ""):
        if results != "":
            fields = json.loads(results)
    return (fields)


def BuildIncidentTotal(incidents) -> dict:
    table = {}
    for inctype, v in incidents.items():
        for month, cnt in v.items():
            if inctype not in table:
                table[inctype] = 0
            table[inctype] += int(cnt)
    return (table)


def BuildIncidentAvg(incidents) -> dict:
    table = {}
    count = {}
    for inctype, v in incidents.items():
        for month, cnt in v.items():
            if inctype not in table:
                table[inctype] = 0
                count[inctype] = 0
            table[inctype] += int(cnt)
            if int(cnt) != 0:
                count[inctype] += 1

    for inctype, v in table.items():
        if count[inctype] > 0:
            table[inctype] = int(table[inctype] / count[inctype] / 60)

    return (table)


def BuildEffortReductionAvg(incidents, efforts) -> dict:
    table = {}
    count = {}
    totalreduction = 0

    for inctype, v in incidents.items():

        for month, val in v.items():
            ival = int(val)
            if inctype in efforts:
                manualeffort = int(ival * efforts[inctype][0])
                autoeffort = int(ival * efforts[inctype][1])
                reduction = manualeffort - autoeffort
            else:
                reduction = 0
            if inctype not in table:
                table[inctype] = 0
                count[inctype] = 0
            if reduction > 0:
                table[inctype] += reduction
                count[inctype] += 1
                totalreduction += reduction

    for inctype, v in table.items():
        if totalreduction > 0:
            table[inctype] = int((table[inctype] / totalreduction) * 100)
        else:
            table[inctype] = 0

    return (table)


def BuildEffortTotal(incidents, efforts) -> dict:
    table = {
        "Manual Incident Effort": 0,
        "Manual Indicator Effort": 0,
        "Automated Incident Effort": 0,
        "Automated Indicator Effort": 0
    }

    for inctype, v in incidents.items():
        for month, val in v.items():
            if inctype in efforts:
                table["Manual Incident Effort"] += int((int(val) * efforts[inctype][0]) / 60)
                table["Automated Incident Effort"] += int((int(val) * efforts[inctype][1]) / 60)

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
                stats = BuildEffortReductionAvg(metrics, efforts)
            else:
                stats = BuildEffortTotal(metrics, efforts)
        else:
            if metrictype in ["SLA Metrics", "Incident Open Duration"]:
                stats = BuildIncidentAvg(metrics)
            else:
                stats = BuildIncidentTotal(metrics)
        if len(stats) == 0:
            return

        wstats: list = []
        for key, val in stats.items():
            wstats = MetricWidget(wstats, key, val)

        if effortlist != "" and metrictype == "Incidents":
            wstats = SetMetricColors(wstats, "Incident Effort")
        else:
            wstats = SetMetricColors(wstats, metrictype)

        return_results(json.dumps(wstats))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"XMetricsTotal - exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
