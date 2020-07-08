import demistomock as demisto
from CommonServerPython import *


def _get_departing_employees(risktags):
    tags = {} if not risktags else {"risktags": risktags.split(",")}
    command_result = demisto.executeCommand("code42-highriskemployee-get-all", tags)
    if not command_result:
        return []

    return command_result[0]["Contents"]


def _get_file_events_for_user(username):
    command_result = demisto.executeCommand("code42-securitydata-search", {"username": username})
    if not command_result:
        return
    return command_result


def get_departing_employees():
    res = {"total": 0}
    res_data = []
    risktags = demisto.args().get("risktags")

    try:
        employees = _get_departing_employees(risktags)
        res["total"] = len(employees)

        # TODO: Extract to separate script Code42SearchExposureEvents
        for employee in employees:
            username = employee.get("userName")
            employee_res = {"Username": username, "ExposureEvents": 0}
            file_events = _get_file_events_for_user(username)
            for e in file_events:
                event_data = e.get("Contents")
                if event_data and isinstance(event_data, list):
                    for data in event_data:
                        if data.get("exposure"):
                            employee_res["ExposureEvents"] += 1

            res_data.append(employee_res)

        res["data"] = res_data
        demisto.results(res)
    except Exception as e:
        res["total"] = -1
        res["data"] = str(e)

    # Submit final results to Cortex XSOAR
    demisto.results(res)

if __name__ in ("__main__", "__builtin__", "builtins"):
    get_departing_employees()
