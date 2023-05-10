import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    # get the incident type
    incident_type = demisto.incident().get("type")

    # requires an XSOAR list that contains the response process for the given Incident Type,
    # and a default list as a fallback!
    default_response_process_list = "DefaultResponseProcess"
    default_contents = f"""# Default Response Process\nCreate a List called **DefaultResponseProcess** list under 
    **Settings** to display a custom response.\n\nAlternatively create a list called **{incident_type}ResponseProcess**
     (copy and paste) to display a custom response specific to the {incident_type} incident type.
    """  # noqa W291

    # get the list for the IncidentType
    # list name must be formatted as follows: IncidentType Response Process
    response_process = demisto.executeCommand("getList", {"listName": f"{incident_type}ResponseProcess"})[0]['Contents']

    # check if the list exists and return it's contents, if not get or create the Default list and return it's contents.
    if "Item not found" in response_process:
        response_process = demisto.executeCommand("getList", {"listName": default_response_process_list})[0]['Contents']
        if "Item not found" in response_process:
            result = CommandResults(readable_output=default_contents, ignore_auto_extract=True)
        else:
            result = CommandResults(readable_output=response_process, ignore_auto_extract=True)
        return_results(result)
    else:
        result = CommandResults(readable_output=response_process, ignore_auto_extract=True)
        return_results(result)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
