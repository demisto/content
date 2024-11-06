from datetime import datetime
from operator import itemgetter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

THRESHOLDS = {
    "numberofincidentswithmorethan500entries": 300,
    "numberofincidentsbiggerthan1mb": 300,
}
DESCRIPTION = [
    "Too many incidents with high number of war room entries were found, consider to use quiet mode in task settings",
    "Large incidents were found, consider to use quiet mode in task settings and delete unneeded Context",
]
RESOLUTION = [
    "Playbook Settings: https://xsoar.pan.dev/docs/playbooks/playbook-settings",
    "Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context",
]


def format_dict_keys(entry: Dict[str, Any]) -> Dict:
    new_entry = {}
    for key, value in entry.items():
        if key == "Size(MB)":
            new_entry["size"] = f"{value} MB"
        elif key == "AmountOfEntries":
            new_entry["info"] = f"{value} Entries"
        else:
            new_entry[key.lower()] = value
    new_entry.pop("size(mb)", None)
    return new_entry


def formatToEntriesGrid(table):
    for entry in table:
        entry["amountofentries"] = entry["info"]


def get_investigations(raw_output, investigations):
    # in case getDBStatistics fails to fetch information it will return a message like so:
    # `Failed getting DB stats with filter [102020], minBytes [1000000]` -
    # in this case there are no incidents to report
    if isinstance(raw_output, str):
        return

    for db in raw_output:
        buckets = db.get("buckets")
        for entry in buckets:
            if entry.startswith("investigations-"):
                investigations[entry] = buckets.get(entry)
                investigations[entry].update({"Date": db.get("dbName")})


def parse_investigations_to_table(investigations):
    data: List = []
    widget_table = {"total": len(investigations)}
    for investigation in investigations:
        full_size = investigations[investigation].get("leafSize").split(" ")
        db_name = investigations[investigation].get("Date")
        size = float(full_size[0])
        if size >= 1.0 and full_size[1] == "MB":
            if db_name.isdigit():
                inv_id = investigation.split("-")[1]
                date = db_name[:2] + "-" + db_name[2:]
            else:
                inv_id = "-".join(investigation.split("-")[1:])
                date = ""
            data.append(
                {
                    "IncidentID": inv_id,
                    "Size(MB)": int(size) if size == int(size) else size,
                    "AmountOfEntries": investigations[investigation].get("keyN"),
                    "Date": date,
                }
            )

    widget_table["data"] = sorted(data, key=itemgetter("Size(MB)"), reverse=True)  # type: ignore

    return widget_table


def get_month_db_from_date(date):
    month = date.strftime("%m")
    year = date.strftime("%Y")
    return month + year


def main(args):
    thresholds = args.get("Thresholds", THRESHOLDS)
    append = args.get("Append", "False")
    investigations: Dict = {}
    args: Dict = demisto.args()
    now = datetime.now()
    current_year = now.year
    current_month = now.month

    # Calculate previous month and handle year transition
    if current_month == 1:
        previous_month_year = current_year - 1
        previous_month = 12
    else:
        previous_month_year = current_year
        previous_month = current_month - 1

    # Create a new date object for the previous month
    previous_month_date = datetime(previous_month_year, previous_month, 1)
    fromMonth = previous_month_date.strftime("%m%Y")
    toMonth = now.strftime("%m%Y")
    db_names = [fromMonth, toMonth]

    for db_name in db_names:
        raw_output = demisto.executeCommand("getDBStatistics", args={"filter": db_name})
        get_investigations(raw_output[0].get("Contents", {}), investigations)

    res = parse_investigations_to_table(investigations)
    incidentsbiggerthan1mb = []
    incidentswithmorethan500entries = []

    for incident in res.get("data", []):
        formatted_incident = format_dict_keys(incident)
        if incident["AmountOfEntries"] >= 200:
            incidentswithmorethan500entries.append(formatted_incident)
            continue
        incidentsbiggerthan1mb.append(formatted_incident)

    numberofincidentsbiggerthan1mb = len(incidentsbiggerthan1mb)
    numberofincidentswithmorethan500entries = len(incidentswithmorethan500entries)
    if incidentswithmorethan500entries:
        formatToEntriesGrid(incidentswithmorethan500entries)

    analyzeFields = {
        "healthchecklargeinvestigations": incidentsbiggerthan1mb,
        "healthchecknumberofinvestigationsbiggerthan1mb": numberofincidentsbiggerthan1mb,
        "healthcheckincidentslargenumberofentries": incidentswithmorethan500entries,
    }

    if append == "False":
        demisto.executeCommand("setIncident", analyzeFields)
    else:
        incident = demisto.incidents()
        prevData = incident[0].get("CustomFields", {}).get("healthchecklargeinvestigations")
        prevData.extend(analyzeFields.get("healthchecklargeinvestigations", []))
        demisto.executeCommand("setIncident", analyzeFields)

    action_items = []
    if numberofincidentswithmorethan500entries > int(thresholds["numberofincidentswithmorethan500entries"]):
        action_items.append(
            {
                "category": "DB Analysis",
                "severity": "High",
                "description": DESCRIPTION[0],
                "resolution": f"{RESOLUTION[0]}",
            }
        )

    if numberofincidentsbiggerthan1mb > thresholds["numberofincidentsbiggerthan1mb"]:
        action_items.append(
            {
                "category": "DB Analysis",
                "severity": "High",
                "description": DESCRIPTION[1],
                "resolution": f"{RESOLUTION[0]}\n{RESOLUTION[1]}",
            }
        )

    results = CommandResults(outputs_prefix="dbstatactionableitems", outputs=action_items)

    return results


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
