import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# This must be wrapped by demisto lock in another playbook task to work properly


def main():
    try:
        args = demisto.args()
        cmds = args['cmds'].split(",")
        tasks = args['tasks'].split(",")
        gridfield = args['gridfield']
        status = []
        sfields = args['status'].split(",")
        for s in sfields:
            status.append(s.strip() == "True")

        rows = []
        for i in range(0, len(cmds)):
            row = {
                "playbook": cmds[i],
                "task": tasks[i],
                "result": status[i]
            }
            rows.append(row)

        gridRows = demisto.incidents()[0]['CustomFields'].get(gridfield)
        if gridRows is None:
            gridRows = rows
        else:
            for r in rows:
                gridRows.append(r)
        grid = json.dumps({gridfield: gridRows})
        demisto.executeCommand("setIncident", {'customFields': grid, 'version': -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestResults: Exception failed to execute error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
