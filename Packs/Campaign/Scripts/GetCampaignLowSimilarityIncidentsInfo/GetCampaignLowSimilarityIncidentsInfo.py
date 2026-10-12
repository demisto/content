import copy
from collections.abc import Callable
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
This Script is a duplicate of Packs/Campaign/Scripts/GetCampaignIncidentsInfo with the only change of the context field
the data is taken from. The reason is that dynamic section in layout cannot use arguments in the scripts they use.
"""

DEFAULT_HEADERS = ["id", "name", "emailfrom", "recipients", "severity", "status", "created"]
KEYS_FETCHED_BY_QUERY = ["status", "severity"]
NO_CAMPAIGN_INCIDENTS_MSG = "There is no Campaign Incidents in the Context"
STATUS_DICT = {
    0: "Pending",
    1: "Active",
    2: "Closed",
    3: "Archive",
}
DEFAULT_CUSTOM_FIELDS = {
    "campaignclosenotes": "Notes explaining why the incident was closed",
    "campaignemailsubject": "Campaign detected",
    "campaignemailbody": "Fill here message for the recipients",
    "selectcampaignincidents": ["All"],
}
SEVERITIES = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0.5: "Info", 0: "Unknown"}


def get_incident_link_creator() -> Callable[[Any], str]:
    """Returns a function to build a markdown link to an incident details page.

    The URL format depends on the platform:

    - Unified Cortex platform (XSIAM v3 / XSOAR on platform): ``/issue-view/{id}``
    - Cortex XSOAR 8.x (SaaS, non-platform): ``/Details/{id}``
    - Cortex XSOAR 6.x (on-prem, legacy): ``#/Details/{id}``

    This ensures the generated hyperlinks navigate directly to the incident/issue on
    every supported platform.

    :return: A function that takes an incident_id and returns a markdown-formatted link.
    """
    if is_platform():
        template = "[{id}](/issue-view/{id})"
    elif is_demisto_version_ge("8.4.0"):
        template = "[{id}](/Details/{id})"
    else:
        template = "[{id}](#/Details/{id})"

    def create_incident_link(incident_id: Any) -> str:
        return template.format(id=incident_id)

    return create_incident_link


def update_incident_with_required_keys(incidents, required_keys):
    """
    Update the given incident dict (from context) with values retrieved by GetIncidentsByQuery command

    :type incidents: ``list``
    :param incidents: campaign incidents from the context

    :type required_keys: ``list``
    :param required_keys: keys need to be updated

    """
    ids = [str(incident["id"]) for incident in incidents]
    res = demisto.executeCommand("GetIncidentsByQuery", {"query": "id:({})".format(" ".join(ids))})
    if isError(res):
        return_error(f"Error occurred while trying to get incidents by query: {get_error(res)}")

    incidents_from_query = json.loads(res[0]["Contents"])
    id_to_updated_incident_map = {incident["id"]: incident for incident in incidents_from_query}
    for incident in incidents:
        updated_incident = id_to_updated_incident_map[incident["id"]]
        for key in required_keys:
            incident[key] = updated_incident.get(key)


def convert_incident_to_hr(incident, create_incident_link: Callable[[Any], str] | None = None) -> dict:
    """
    Get the value from incident dict and convert it in some cases e.g. make id linkable etc.
    Note: this script change the original incident

    :type incident: ``dict``
    :param incident: the incident to get the value from

    :type create_incident_link: ``Callable``
    :param create_incident_link: function building a platform-aware markdown link for an incident id.
        Built via ``get_incident_link_creator()`` when not supplied.

    :rtype: ``None``
    :return None
    """
    if create_incident_link is None:
        create_incident_link = get_incident_link_creator()

    converted_incident = copy.deepcopy(incident)

    for key in converted_incident:
        if key == "status":
            converted_incident[key] = STATUS_DICT.get(converted_incident.get(key))

        if key == "id":
            converted_incident[key] = create_incident_link(converted_incident.get(key))

        if key == "severity":
            converted_incident[key] = SEVERITIES.get(converted_incident.get(key), "")

        if key == "similarity":
            if str(converted_incident[key])[0] == "1":
                converted_incident[key] = "1"

            elif len(str(converted_incident[key])) > 4:
                converted_incident[key] = str(round(converted_incident[key], 3))
                converted_incident[key] = (
                    converted_incident[key][:-1] if len(converted_incident[key]) > 4 else converted_incident[key]
                )

            else:
                converted_incident[key] = str(converted_incident[key])

        converted_incident[key] = converted_incident.get(key.replace("_", ""))

    return converted_incident


def get_campaign_incidents_from_context():
    return demisto.get(demisto.context(), "EmailCampaign.LowerSimilarityIncidents")


def get_incidents_info_md(incidents, fields_to_display=None):
    """
    Get the campaign incidents relevant info in MD table

    :type incidents: ``list``
    :param incidents: the campaign incidents to collect the info from
    :type fields_to_display: ``list``
    :param fields_to_display: list of result headers

    :rtype: ``str``
    :return the MD table str

    """

    if incidents:
        if not fields_to_display:
            headers = DEFAULT_HEADERS
        else:
            headers = fields_to_display

        create_incident_link = get_incident_link_creator()
        converted_incidents = [convert_incident_to_hr(incident, create_incident_link) for incident in incidents]

        return tableToMarkdown(
            name="",
            t=converted_incidents,
            headerTransform=string_to_table_header,
            headers=headers,
            removeNull=True,
        )

    return None


def update_empty_fields():
    """
    Update the campaign dynamic section empty field with default values in order for them to appear in the page
    """
    incident = demisto.incidents()[0]
    custom_fields = incident.get("customFields", {})

    for field in DEFAULT_CUSTOM_FIELDS:
        if not custom_fields.get(field):
            custom_fields[field] = DEFAULT_CUSTOM_FIELDS[field]
    demisto.executeCommand("setIncident", {"id": incident["id"], "customFields": custom_fields})


def main():
    try:
        incidents = get_campaign_incidents_from_context()
        fields_to_display = demisto.get(demisto.context(), "EmailCampaign.fieldsToDisplay")
        if incidents:
            update_incident_with_required_keys(incidents, KEYS_FETCHED_BY_QUERY)
            update_empty_fields()
            readable_output = get_incidents_info_md(incidents, fields_to_display)
        else:
            readable_output = NO_CAMPAIGN_INCIDENTS_MSG

        return_results(CommandResults(readable_output=readable_output, raw_response=readable_output))
    except Exception as err:
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
