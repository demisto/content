
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import strftime
from typing import List, Dict

DATE_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"


def is_valid_field(field_name: str, incident: Dict[str, Any]) -> bool:
    """
    Checks whether the field supplied exists in current incident.
    Both custom fields and OOB fields are checked.
    """

    custom_fields = get_custom_fields_from_incident(incident)
    demisto.debug(f"Found {len(custom_fields)} custom fields in incident")

    if field_name in custom_fields:
        return False

    oob_fields = get_oob_fields_from_incident(incident)
    demisto.debug(f"Found {len(oob_fields)} OOB fields in incident")

    if field_name in oob_fields:
        return True

    return False


def get_custom_fields_from_incident(incident: Dict[str, Any]) -> List[str]:
    """
    Retrieves all custom fields from incident
    """

    fields = incident.get("CustomFields", {})

    if fields:
        return list(fields.keys())
    else:
        return []


def get_oob_fields_from_incident(incident: Dict[str, Any]) -> List[str]:
    """
    Retrieves all out of the box incident fields
    """

    fields: List[str] = []

    for field in incident.keys():
        if field != "CustomFields":
            fields.append(field)

    return fields


def get_time_str(format: str = DATE_FORMAT) -> str:
    """
    Get current time string in specified format
    """

    dts = strftime(format)
    demisto.debug(f"Date is {dts}")

    return dts


def main():  # pragma: no cover
    try:
        args = demisto.args()

        field_name: str = args.get('field')
        time_str = get_time_str(DATE_FORMAT)

        incident: Dict[str, Any] = demisto.incident()

        cmd_res = CommandResults()

        if is_valid_field(field_name, incident):

            res = demisto.executeCommand("setIncident", {field_name: time_str})

            if isError(res):
                error_msg = res[0].get("Contents")
                if error_msg == "missing argument for setIncident (7)":
                    raise RuntimeError(f"Error executing [setIncident {field_name}='{time_str}']: Cannot set this field.")
                else:
                    raise RuntimeError(f"Error executing [setIncident {field_name}='{time_str}']: {error_msg}")
            else:
                cmd_res.readable_output = f"Field '{field_name}' set successfully to '{time_str}'"

        else:
            raise RuntimeError(f"Field '{field_name}' was not found in Incident. Note, custom fields are not supported.")

        return_results(cmd_res)
    except Exception as e:
        return_error(f"Failed to execute SetDateField error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
