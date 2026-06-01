import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DEFAULT_INCIDENT_TYPE = "Vectra RUX Events Detection"


def check_if_found_incident(res: list):
    """Check whether the getIncidents response contains any incidents.

    Args:
        res (list): Raw response from the getIncidents command.

    Returns:
        bool: True if incidents were found, False if the data field is None.

    Raises:
        DemistoException: If the response structure is invalid or contains an error.
    """
    if res and isinstance(res, list) and isinstance(res[0].get("Contents"), dict):
        if "data" not in res[0]["Contents"]:
            raise DemistoException(str(res[0].get("Contents")))
        elif res[0]["Contents"]["data"] is None:
            return False
        return True
    else:
        raise DemistoException(f"failed to get incidents from xsoar.\nGot: {res}")


def search_incidents(args: dict):  # pragma: no cover
    res: list = execute_command("getIncidents", args, extract_contents=False)
    incident_found: bool = check_if_found_incident(res)
    if not incident_found:
        return "Incidents not found.", {}, {}

    all_found_incidents = res[0]["Contents"]["data"]

    headers = ["id", "name", "severity", "status", "owner", "created", "closed"]
    md = tableToMarkdown(name="Incidents found", t=all_found_incidents, headers=headers)

    demisto.debug(f"amount of all the incidents that were found {len(all_found_incidents)}")

    return md, all_found_incidents, res


def main():  # pragma: no cover
    args: dict = demisto.args()
    incident_type = args.get("incident_type", DEFAULT_INCIDENT_TYPE)
    args.update({"size": 50, "sort": "created.asc", "query": f'-status:closed -category:job type:"{incident_type}"'})
    try:
        readable_output, outputs, raw_response = search_incidents(args)
        results = CommandResults(
            outputs_prefix="VectraRUXGetIncidents",
            outputs_key_field="id",
            readable_output=readable_output,
            outputs=outputs,
            raw_response=raw_response,
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
