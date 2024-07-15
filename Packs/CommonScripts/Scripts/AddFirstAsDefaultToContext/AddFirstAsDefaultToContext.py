import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import traceback


""" STANDALONE FUNCTION """


def get_incidenttype(incident_type_name: str) -> dict:
    all_incidenttype = demisto.executeCommand("core-api-get", {"uri": "/incidenttype"})[
        0
    ]
    response = all_incidenttype.get("Contents", {}).get("response")
    for incidenttype in response:
        if incidenttype.get("id", "") == incident_type_name:
            return incidenttype

    return {}


def get_incidentfields(type_name: str, name_fields: list[str]) -> list:
    res = demisto.executeCommand("core-api-get", {"uri": "/incidentfields"})
    all_incidentfields = res[0]["Contents"]["response"]

    singleSelect_field = []
    for field in all_incidentfields:
        if (
            field.get("type", "") == type_name
            and field.get("cliName", "") in name_fields
        ):
            singleSelect_field.append(field)

    return singleSelect_field


def get_fieldname_and_default_val(fields: list[dict]) -> dict:
    result = {}
    for field in fields:
        field_name = field.get("cliName", "")
        select_values = field.get("selectValues", [])
        if isinstance(select_values, list) and len(select_values) > 0:
            result[field_name] = select_values[0]

    return result


def update_context(fields: dict, context: dict) -> None:
    outputs = {}
    for field_name, default_values in fields.items():
        if not context.get("CustomFields",{}).get(field_name):
            outputs[field_name] = default_values
    demisto.executeCommand("setIncident", outputs)

""" MAIN FUNCTION """


def main():
    try:
        context = demisto.incident()
        incident_type_name = context.get("type", "")
        incident_type_file = get_incidenttype(incident_type_name)
        layout_name = incident_type_file.get("layout", "")
        layout_file = demisto.executeCommand(
            "core-api-get", {"uri": f"/layout/{layout_name}"}
        )

        pattern = r"'fieldId':\s*'([^']+)'"
        name_of_fields_in_layout = re.findall(pattern, str(layout_file))
        incidentfields_filtered = get_incidentfields("singleSelect", name_of_fields_in_layout)
        incidentfields_to_update_in_context = get_fieldname_and_default_val(incidentfields_filtered)
        return_results(update_context(incidentfields_to_update_in_context, context))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
