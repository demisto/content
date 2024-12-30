import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


THRESHOLDS = {
    "numberofincidentsIObiggerthan10mb": 1,
    "numberofincidentsIObiggerthan1mb": 10,
}


def get_investigations(raw_output, investigations):
    # in case getDBStatistics fails to fetch information it will return a message like so:
    # `Failed getting DB stats with filter [102020], minBytes [1000000]` - in this case there are no incidents to report
    if isinstance(raw_output, str):
        return

    for db in raw_output:
        buckets = db.get("buckets")
        for entry in buckets:
            if entry.startswith("investigations-"):
                investigations[entry] = buckets.get(entry)
                investigations[entry].update({"Date": db.get("dbName")})


def find_largest_input_or_output(all_args_list) -> dict:
    max_arg = {"Size(MB)": 0}
    for arg in all_args_list:
        if arg.get("Size(MB)") > max_arg.get("Size(MB)"):
            max_arg = arg

    return max_arg


def get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, incident_id) -> None:
    inputs = []
    outputs = []

    if inputs_and_outputs:
        # In case no inputs and outputs are found a getInvPlaybookMetaData will return a string.
        # in that case we ignore the results and move on.
        if isinstance(inputs_and_outputs, str):
            return

        for task in inputs_and_outputs:
            task_id = task.get("id")
            taskName = task.get("name")
            if "outputs" in task:
                for output in task.get("outputs"):
                    size = float(output.get("size", 0))
                    outputs.append(
                        {
                            "IncidentID": f"{incident_id}",
                            "Size(MB)": size,
                            "Details": f"TaskName:{taskName},\nTaskID:{task_id},\nDirection: Output",
                        }
                    )

            else:
                for arg in task.get("args"):
                    argName = arg.get("name")
                    size = float(arg.get("size", 0))
                    inputs.append(
                        {
                            "IncidentID": f"{incident_id}",
                            "Size(MB)": size,
                            "Details": f"TaskName: {taskName},\nTaskID:{task_id}, Argument Name: {argName},\nDirection: Input",
                        }
                    )

    if inputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(inputs))

    if outputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(outputs))


def get_extra_data_from_investigations(investigations: dict) -> list:
    largest_inputs_and_outputs: List = []
    for inv in investigations:
        incident_id = inv.split("investigations-")[1]
        raw_output = execute_command(
            "getInvPlaybookMetaData",
            args={"incidentId": incident_id, "minSize": "1024"},
        )
        inputs_and_outputs = raw_output.get("tasks")
        get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, incident_id)
    return largest_inputs_and_outputs


def FormatTableAndSet(data):
    newFormat = []
    for entry in data:
        newEntry = {}
        newEntry["incidentid"] = entry["IncidentID"]
        newEntry["size"] = FormatSize(entry["Size(MB)"])
        newEntry["details"] = entry["Details"]
        newFormat.append(newEntry)
    return newFormat


def FormatSize(size):
    power = 1000
    n = 0
    power_labels = {0: "KB", 1: "MB", 2: "GB"}
    while size > power:
        size /= power
        n += 1
        if n == 2:
            break
    return f"{size:.2f} {power_labels[n]}"


def main():
    try:
        args = demisto.args()
        incident_thresholds = args.get("Thresholds", THRESHOLDS)
        incident = demisto.incidents()[0]
        investigations: Dict = {}
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

        data = get_extra_data_from_investigations(investigations)
        tableFormat = FormatTableAndSet(data)

        if incident.get("CustomFields").get("healthcheckinvestigationswithlargeinputoutput"):
            tableFormat.extend(incident.get("CustomFields").get("healthcheckinvestigationswithlargeinputoutput"))
        demisto.executeCommand("setIncident", {"healthcheckinvestigationswithlargeinputoutput": tableFormat})

        actionableItems = []
        incidentsList = []
        incidentsListBiggerThan10 = []

        for entry in data:
            if entry["Size(MB)"] > 10:
                incidentsListBiggerThan10.append(entry)
            else:
                incidentsList.append(entry)
        numIncidentsList = len(incidentsList)
        numIncidentsListBiggerThan10 = len(incidentsListBiggerThan10)
        DESCRIPTION = [
            "incidents were found with large input and output, improve your task configuration",
            "incidents were found with very large input and output bigger than 10 MB, improve your task configuration",
        ]
        RESOLUTION = [
            "Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context",
        ]

        if numIncidentsList >= incident_thresholds["numberofincidentsIObiggerthan1mb"]:
            actionableItems.append(
                {
                    "category": "DB analysis",
                    "severity": "Medium",
                    "description": f"{numIncidentsList} {DESCRIPTION[0]}",
                    "resolution": RESOLUTION[0],
                }
            )
        if numIncidentsListBiggerThan10 >= incident_thresholds["numberofincidentsIObiggerthan10mb"]:
            actionableItems.append(
                {
                    "category": "DB analysis",
                    "severity": "High",
                    "description": f"{numIncidentsListBiggerThan10} {DESCRIPTION[1]}",
                    "resolution": RESOLUTION[0],
                }
            )
        results = CommandResults(outputs_prefix="dbstatactionableitems", outputs=actionableItems)

        return_results(results)

    except Exception as exc:
        return_error(f"Failed to execute GetLargestInputsAndOutputsInIncidents.\nError: {exc}", error=exc)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
