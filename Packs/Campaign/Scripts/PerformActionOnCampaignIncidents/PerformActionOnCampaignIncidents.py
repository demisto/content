from more_itertools import always_iterable
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum

ALL_OPTION = "All"
NO_CAMPAIGN_INCIDENTS_MSG = "There is no Campaign Incidents in the Context"
COMMAND_SUCCESS = "The following incidents was successfully {action}: {ids}"
COMMAND_ERROR_MSG = (
    'Error occurred while trying to perform "{action}" on the selected incident ids: {ids}\n'
    "Error details: {error}"
)
ACTION_ON_CAMPAIGN_FIELD_NAME = "actionsoncampaignincidents"
ACTION_ON_CAMPAIGN_LOWER_FIELD_NAME = "actionsonlowsimilarityincidents"

SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME = "selectcampaignincidents"
SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME = "selectlowsimilarityincidents"
RECIPIENT_FIELDS = ["CustomFields.emailto", "CustomFields.emailcc", "CustomFields.emailbcc"]

REMOVED_FROM_CAMPAIGNS_FIELD_NAME = "CustomFields.removedfromcampaigns"

# this list of 'fields to display' got from the default value of the fieldsToDisplay argument
# in `Detect & Manage Phishing Campaigns` playbook
FIELDS_TO_DISPLAY = ["id", "name", "similarity", "emailfrom", "recipients", "severity", "status", "occurred"]


class ACTIONS(Enum):
    REMOVE = 'remove',
    ADD = 'add'


def _set_involved_incidents_count(campaign_id: str, count: int) -> None:
    """Sets the EmailCampaign.involvedIncidentsCount field on the campaign incident.

    Args:
        campaign_id (str): The ID of the campaign incident. Required.
        count (int): The number to set as the involvedIncidentsCount. Required.
    """
    res = demisto.executeCommand(
        "SetByIncidentId",
        {
            "id": campaign_id,
            "key": "EmailCampaign.involvedIncidentsCount",
            "value": count,
        },
    )
    if isError(res):
        return_error(
            f"Error occurred while trying to set the involvedIncidentsCount field"
            f" on the campaign incident {campaign_id}: {get_error(res)}"
        )


def _set_part_of_campaign_field(incident_id: str, campaign_id: str | None) -> None:
    """Sets the partofcampaign field on the incident.

    Args:
        incident_id (str): The ID of the incident to update. Required.
        campaign_id (str | None): The ID of the campaign to set on the incident,
            or None to clear the field. Required.
    """
    res = demisto.executeCommand(
        "setIncident", {"id": incident_id, "partofcampaign": campaign_id}
    )
    if isError(res):
        return_error(
            f"Error occurred while trying to set the partofcampaign field on the incident: {get_error(res)}"
        )


def _set_removed_from_campaigns_field(incident_id: str, campaign_id: str, action: ACTIONS) -> None:
    """
    Sets or removes the specified campaign ID from the 'removedfromcampaigns' field of the incident.

    Args:
        incident_id (str): The ID of the incident to update. Required.
        campaign_id (str): The ID of the campaign to set or remove from the 'removedfromcampaigns' field.
            Required.
        action (str): The action to perform. Should be either 'add' to associate the incident with the
            campaign or 'remove' to disassociate it. Required.

    Raises:
        RuntimeError: If an error occurs while trying to set the 'removedfromcampaigns' field on the incident.
    """
    incident_context = _get_incident(incident_id)
    campaign_ids_removed = _get_data_from_incident(incident_context, REMOVED_FROM_CAMPAIGNS_FIELD_NAME)
    if not campaign_ids_removed:
        campaign_ids_removed = []

    set_campaign_ids_removed: set = set(campaign_ids_removed)

    if action == ACTIONS.ADD:
        set_campaign_ids_removed.add(campaign_id)
    else:
        set_campaign_ids_removed.discard(campaign_id)

    res = demisto.executeCommand(
        "setIncident", {"id": incident_id, "removedfromcampaigns": sorted(set_campaign_ids_removed)}
    )
    if isError(res):
        raise DemistoException(
            f"Error occurred while trying to set the removedfromcampaigns field on the incident: {get_error(res)}"
        )


def _link_or_unlink_between_incidents(incident_id: str, linked_incident_id: list[str], action: str) -> None:
    """Links or unlinks the incidents, sets the `linkedIncidents` filed.

    Args:
        incident_id (str): The ID of the source incident to link from. Required.
        linked_incident_id (list[str]): The ID(s) of the incidents to link to. Required.
        action (str): The action to perform. Either "Link" or "Unlink". Required.
    """
    if action not in ("link", "unlink"):
        return_error(f"Invalid {action=}, should be Link or Unlink")

    res = demisto.executeCommand(
        "linkIncidents",
        {
            "incidentId": incident_id,
            "linkedIncidentIDs": linked_incident_id,
            "action": action,
        },
    )
    if isError(res):
        return_error(
            f"Error occurred while trying to {action} between incident {incident_id} and linked incidents {linked_incident_id}:"
            f" {get_error(res)}"
        )


def _set_incidents_to_campaign(campaign_id: str, incidents_context: list | dict, append: bool = False) -> None:
    """Sets incidents to an email campaign.

    Args:
        campaign_id (str): The ID of the campaign incident. Required.
        incidents_context (list or dict): The incidents context to add. Required.
        append (bool): Whether to append the incidents to existing ones
            or override. Default is False. Optional.
    """
    res = demisto.executeCommand(
        "SetByIncidentId",
        {
            "id": campaign_id,
            "key": "EmailCampaign.incidents",
            "value": incidents_context,
            "append": append,
        },
    )

    if isError(res):
        return_error(
            f"Error occurred while trying to set incidents to campaign with ID {campaign_id}. Error: {get_error(res)}"
        )


def _get_context(incident_id: str):
    """Gets the context for an incident.

    Args:
        incident_id (str): The ID of the incident to get context for. Required.
    Returns:
        dict: The context of the incident.
    """
    res = demisto.executeCommand("getContext", {"id": incident_id})

    if isError(res):
        return_error(
            f"Error occurred while trying to get context for incident with ID {incident_id}. Error: {get_error(res)}"
        )

    return res


def _get_incident(incident_id: str):
    """Gets the incident.

    Args:
        incident_id: The ID of the incident to get. Required.
    Returns:
        list: The incident data.
    """
    res = demisto.executeCommand("getIncidents", {"id": incident_id})

    if isError(res):
        return_error(
            f"Error occurred while trying to get incident with ID {incident_id}. Error: {get_error(res)}"
        )

    return res


def extract_domain(email: str | None) -> str | None:
    """Extracts the domain from an email address.

    Args:
        email (str | None): The email address to extract the domain from.
            Required.

    Returns:
        str | None: The domain of the email address, or None if no domain.

    """
    return email.split("@")[-1] if email and "@" in email else None


def extract_single_or_list(data) -> Any:
    """Extracts a single item from a list if there is only one item.

    This function is useful when working with the `demisto.dt` function which
    always returns a list, even if there is only one result item.

    Args:
        data (list): The list to extract from or return directly. Required.

    Returns:
        str | list: A single item if there was only one in the list, otherwise
            the original list.

    """
    if not data:
        return None
    if isinstance(data, list) and len(data) == 1:
        return data[0]
    return data


def _get_data_from_incident(incident_context, field: str) -> Any:
    """Extracts data from the incident context for a specific field.

    Args:
        incident_context (dict): The incident context.
        field (str): The field to extract data for.

    Returns:
        Any: The data for the specified field.
    """
    return demisto.dt(incident_context, f"Contents.data.{field}")


def _get_email_fields(incident_context) -> dict:
    """Extracts email fields from the incident context.

    Args:
        incident_context (dict): The incident context.

    Returns:
        dict: A dictionary mapping email field names to their values.

    Note:
        If an email field is None, it is replaced with an empty list.
    """
    return {field: (_get_data_from_incident(incident_context, field) or []) for field in RECIPIENT_FIELDS}


def _get_recipients(email_address_data: dict) -> list:
    """Extracts recipients from the email fields.

    Args:
        email_address_data (dict): A dictionary mapping email field names to their values.

    Returns:
        list: A list of recipients.
    """
    list_recipients: list = []
    for email_field in RECIPIENT_FIELDS:
        for recipient in email_address_data[email_field]:
            if recipient:
                list_recipients.append(recipient)
    return list_recipients


def _extract_incident_fields(incident_context, recipients: list) -> dict:
    """Extracts relevant fields from the incident context.

    Args:
        incident_context (dict): The incident context.
        recipients (list): A list of recipients.

    Returns:
        dict: A dictionary mapping field names to their values.
    """
    email_from = list(always_iterable(_get_data_from_incident(incident_context, "CustomFields.emailfrom")))
    email_from_domain = [extract_domain(email) for email in email_from]
    recipients_domain = [extract_domain(email) for email in recipients]
    return {
        "similarity": None,
        "occurred": _get_data_from_incident(incident_context, "occurred")[0],
        "emailfrom": extract_single_or_list(email_from),
        "emailfromdomain": extract_single_or_list(email_from_domain),
        "name": _get_data_from_incident(incident_context, "name")[0],
        "status": _get_data_from_incident(incident_context, "status")[0],
        "recipients": recipients,
        "id": _get_data_from_incident(incident_context, "id")[0],
        "severity": _get_data_from_incident(incident_context, "severity")[0],
        "recipientsdomain": extract_single_or_list(recipients_domain),
    }


def _parse_incident_context_to_valid_incident_campaign_context(incident_id: str, fields_to_display: list[str]) -> dict:
    """Parses the incident context and returns a dict with requested fields.

    Args:
        incident_id (str): The ID of the incident to get context for.
        fields_to_display (List[str]): The fields from the incident context to include in
            the returned dict.

    Returns:
        dict: The parsed incident context containing only the requested fields.
    """
    incident_context = _get_incident(incident_id)
    emails = _get_email_fields(incident_context)
    recipients = _get_recipients(emails)
    data = _extract_incident_fields(incident_context, recipients)

    additional_requested_fields = {
        field: _get_data_from_incident(incident_context, field)
        for field in fields_to_display
        if field not in data
    }

    data.update(additional_requested_fields)

    # Ensure 'emailfromdomain' is in the results when 'emailfrom' is requested, and same with 'recipients'.
    for key in ('emailfrom', 'recipients'):
        if key in fields_to_display and (with_domain := f'{key}domain') not in fields_to_display:
            fields_to_display.append(with_domain)

    data = {field: data[field] for field in fields_to_display}
    data["added_manually_to_campaign"] = True
    return data


def get_custom_field(filed_name: str) -> Any:
    return demisto.incidents()[0].get("CustomFields", {}).get(filed_name)


def _get_campaign_info() -> tuple[str, Any, list]:
    """Gets information about the current campaign.

    Returns:
        campaign_id (str): The ID of the current campaign incident.
        campaign_context (dict): The context of the current campaign incident.
        campaign_incidents_context (list): The incidents associated with the current campaign.

    """
    campaign_id = demisto.incident()["id"]
    campaign_context = _get_context(campaign_id)
    campaign_incidents_context = demisto.dt(campaign_context, "Contents.context.EmailCampaign.incidents") or []
    return campaign_id, campaign_context, campaign_incidents_context


def get_campaign_incident_ids(context_path: str) -> list[str] | None:
    """
    Collect the campaign incidents ids form the context

    :return: list of campaign incident ids if exist, None otherwise
    """
    incident_id = demisto.incidents()[0]["id"]
    res = _get_context(incident_id)

    incidents: list[dict] = demisto.get(res[0], context_path)
    if incidents:
        return sorted((str(incident.get("id")) for incident in incidents), key=lambda val: int(val))

    return None


def perform_add_to_campaign(ids: list[str], action: str) -> str:
    """Adds incidents to an email campaign.

    Args:
        ids (list[str]): The IDs of the incidents to add to the campaign. Required.
        action (str): The action that was performed, e.g. "linked". Required.

    Returns:
        str: A message indicating the incidents were successfully added.

    Steps:
        1. Get the current campaign context
        2. Get the existing campaign incident IDs
        3. Calculate new count of involved incidents
        4. Filter new incidents to add
        5. Parse incident contexts
        6. Update campaign metadata
        7. Update links between incidents
        8. Return success message
    """
    campaign_id, campaign_context, campaign_incidents_context = _get_campaign_info()
    campaign_incidents_ids = [incident["id"] for incident in campaign_incidents_context]
    fields_to_display = demisto.dt(campaign_context, "Contents.context.EmailCampaign.fieldsToDisplay") or FIELDS_TO_DISPLAY
    # contains only new incidents not already in the campaign
    ids_to_add_to_campaign = sorted(set(ids).difference(campaign_incidents_ids))
    if not ids_to_add_to_campaign:
        return "No new incidents to add to campaign."
    involved_incidents_count = int(demisto.dt(campaign_context, "Contents.context.EmailCampaign.involvedIncidentsCount")[0])
    involved_incidents_count += len(ids_to_add_to_campaign)

    for id_ in ids_to_add_to_campaign:
        _set_removed_from_campaigns_field(id_, campaign_id, ACTIONS.REMOVE)
        _set_part_of_campaign_field(id_, campaign_id)

    campaign_incidents_context = [_parse_incident_context_to_valid_incident_campaign_context(
        id, fields_to_display) for id in ids_to_add_to_campaign]
    _set_incidents_to_campaign(campaign_id, campaign_incidents_context, True)
    _link_or_unlink_between_incidents(campaign_id, ids_to_add_to_campaign, "link")
    _set_involved_incidents_count(campaign_id, involved_incidents_count)

    return COMMAND_SUCCESS.format(action="added to campaign", ids=ids_to_add_to_campaign)


def perform_remove_from_campaign(ids: list[str], action: str) -> str:
    """Removes incidents from an email campaign.

    Args:
        ids (list[str]): The IDs of the incidents to remove. Required.
        action (str): The action that was performed to trigger this, e.g. "unlink".
            Required.

    Returns:
        str: A message indicating success.

    Steps:
        1. Get the current campaign context
        2. Get the existing campaign incident IDs
        3. Calculate new count of involved incidents
        4. Filter incidents to remove
        5. Update campaign metadata
        6. Update links between incidents
        7. Return success message
    """
    campaign_id, campaign_context, campaign_incidents_context = _get_campaign_info()

    campaign_incidents_ids = [incident["id"] for incident in campaign_incidents_context]
    ids_to_remove_from_campaign = sorted(set(ids) & set(campaign_incidents_ids))
    if not ids_to_remove_from_campaign:
        return "No incidents to remove from the campaign."
    involved_incidents_count = int(demisto.dt(campaign_context, "Contents.context.EmailCampaign.involvedIncidentsCount")[0])
    involved_incidents_count -= len(ids_to_remove_from_campaign)
    campaign_incidents_context = [
        incident for incident in campaign_incidents_context if incident['id'] not in ids_to_remove_from_campaign]

    for id_ in ids_to_remove_from_campaign:
        _set_removed_from_campaigns_field(id_, campaign_id, ACTIONS.ADD)
        _set_part_of_campaign_field(id_, "None")
    _set_incidents_to_campaign(campaign_id, campaign_incidents_context)
    _link_or_unlink_between_incidents(campaign_id, ids_to_remove_from_campaign, "unlink")
    _set_involved_incidents_count(campaign_id, involved_incidents_count)

    return COMMAND_SUCCESS.format(action="removed from campaign", ids=ids_to_remove_from_campaign)


def perform_reopen(ids: list[str], action: str) -> str:
    for incident_id in ids:
        res = demisto.executeCommand("reopenInvestigation", {"id": incident_id})
        if isError(res):
            return_error(
                COMMAND_ERROR_MSG.format(
                    action=action, ids=",".join(ids), error=get_error(res)
                )
            )

    return COMMAND_SUCCESS.format(action="reopened", ids=",".join(ids))


def perform_link_and_close(ids: list[str], action: str) -> str:
    perform_add_to_campaign(ids, "link")
    perform_close(ids, "close")
    return COMMAND_SUCCESS.format(action=action, ids=",".join(ids))


def perform_unlink_and_reopen(ids: list[str], action: str) -> str:
    perform_remove_from_campaign(ids, "unlink")
    perform_reopen(ids, "reopen")
    return COMMAND_SUCCESS.format(action=action, ids=",".join(ids))


""""Close Notes"""


def get_close_notes():
    return demisto.incidents()[0].get("closeNotes", "")


def perform_close(ids: list[str], action: str) -> str:
    close_notes = get_close_notes()
    for incident_id in ids:
        res = demisto.executeCommand(
            "closeInvestigation", {"id": incident_id, "closeNotes": close_notes}
        )
        if isError(res):
            return_error(
                COMMAND_ERROR_MSG.format(
                    action=action, ids=",".join(ids), error=get_error(res)
                )
            )

    return COMMAND_SUCCESS.format(action="closed", ids=",".join(ids))


"""Take Ownership"""


def set_incident_owners(incident_ids: list, action: str, user_name):
    incident_ids.append(demisto.incident()["id"])

    for incident_id in incident_ids:
        res = demisto.executeCommand(
            "setIncident", {"id": incident_id, "owner": user_name}
        )

        if isError(res):
            return_error(
                COMMAND_ERROR_MSG.format(
                    action=action, ids=",".join(incident_ids), error=get_error(res)
                )
            )


def perform_take_ownership(ids: list, action: str) -> str:
    current_user_name = (
        demisto.callingContext.get("context", {}).get("ParentEntry", {}).get("user")
    )

    if not current_user_name:
        return_error("Could not find the current user.")

    set_incident_owners(ids, action, current_user_name)

    return COMMAND_SUCCESS.format(action=action, ids=",".join(ids))


ACTIONS_MAPPER = {
    "close": perform_close,
    "reopen": perform_reopen,
    "add to campaign": perform_add_to_campaign,
    "remove from campaign": perform_remove_from_campaign,
    "add to campaign & close": perform_link_and_close,
    "remove from campaign & reopen": perform_unlink_and_reopen,
    "take ownership": perform_take_ownership,
}


def main():
    try:
        similarity: str = demisto.args().get("similarity", "High")

        action_field_name = (
            ACTION_ON_CAMPAIGN_LOWER_FIELD_NAME
            if similarity.lower() == "low"
            else ACTION_ON_CAMPAIGN_FIELD_NAME
        )
        select_field_name = (
            SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME
            if similarity.lower() == "low"
            else SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME
        )

        action = get_custom_field(action_field_name).lower()
        ids = get_custom_field(select_field_name)
        if ALL_OPTION in ids:
            context_path = (
                "Contents.context.EmailCampaign.LowerSimilarityIncidents"
                if similarity.lower() == "low"
                else "Contents.context.EmailCampaign.incidents"
            )
            ids = get_campaign_incident_ids(context_path)

        res = ACTIONS_MAPPER[action](ids, action) if ids else NO_CAMPAIGN_INCIDENTS_MSG
        return_results(res)

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
