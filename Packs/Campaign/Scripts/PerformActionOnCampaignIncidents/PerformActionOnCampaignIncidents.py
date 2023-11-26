import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from email.utils import parseaddr

ALL_OPTION = 'All'
NO_CAMPAIGN_INCIDENTS_MSG = 'There is no Campaign Incidents in the Context'
COMMAND_ERROR_MSG = 'Error occurred while trying to perform \"{action}\" on the selected incident ids: {ids}\n' \
                    'Error details: {error}'
ACTION_ON_CAMPAIGN_FIELD_NAME = 'actionsoncampaignincidents'
ACTION_ON_CAMPAIGN_LOWER_FIELD_NAME = 'actionsonlowsimilarityincidents'

SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME = 'selectcampaignincidents'
SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME = 'selectlowsimilarityincidents'

COMMAND_SUCCESS = 'The following incidents was successfully {action}: {ids}'

ACTION_LINK = "link"
ACTION_UNLINK = "unlink"

EMAIL_TO_FIELD = 'emailto'
EMAIL_CC_FIELD = 'emailcc'
EMAIL_BCC_FIELD = 'emailbcc'
RECIPIENTS_COLUMNS = [EMAIL_TO_FIELD, EMAIL_CC_FIELD, EMAIL_BCC_FIELD]
# Helper Function


def _add_campaign_to_incident(campaign_id, incident_id):
    res = demisto.executeCommand('setIncident', {'id': incident_id,
                                                 'customFields': {'partofcampaign': campaign_id}})
    if is_error(res):
        return_error(f'Failed to add campaign data to incident {incident_id}. Error details:\n{get_error(res)}')
    demisto.debug(f"Added campaign {campaign_id} to incident {incident_id}")


def _link_or_unlink_between_incidents(incident_id: str, linked_incident_id: str, action: str):
    res = demisto.executeCommand("linkIncidents",
                                 {"incidentId": incident_id,
                                     "linkedIncidentIDs": linked_incident_id, "action": action})
    if isError(res):
        return_error(COMMAND_ERROR_MSG.format(action=action, ids=linked_incident_id, error=get_error(res)))


def _add_incidents_to_campaign(campaign_id: str, incidents_context: Any):
    res = demisto.executeCommand('SetByIncidentId', {
        'id': campaign_id,
        'key': 'EmailCampaign.incidents',
        'value': incidents_context})
    if is_error(res):
        return_error(f'Failed to change current context. Error details:\n{get_error(res)}')


def _get_context(incident_id: str):
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')
    # if isError(campaign_context):
    #     return_error(COMMAND_ERROR_MSG.format(action=action, ids=ids,
    #                                           error=get_error(res)))
    return res


def _parse_incident_context_to_valid_incident_campaign_context(incident_id, fields_to_display):
    incident_context = _get_context(incident_id)
    recipients = get_recipients(incident_context)
    recipientsdomain = extract_domain_from_recipients(recipients)
    return {"similarity": None,
            "occurred": demisto.dt(incident_context, "incident.occurred"),
            "emailfrom": demisto.dt(incident_context, "incident.emailfrom"),
            "emailfromdomain": demisto.dt(incident_context, "incident.emailfrom").split('@')[1],
            "name": demisto.dt(incident_context, "incident.name"),
            "status": demisto.dt(incident_context, "incident.status"),
            "recipients": recipients,
            "id": demisto.dt(incident_context, "incident.id"),
            "severity": demisto.dt(incident_context, "incident.severity"),
            "recipientsdomain": recipientsdomain
            }


def get_recipients(incident_context: dict):
    return [recipient for col in RECIPIENTS_COLUMNS for recipient in incident_context.get(col, [])]


def extract_domain_from_recipients(recipients):
    domains = [email.split('@')[1] for email in recipients if '@' in email]
    return domains


def get_custom_field(filed_name: str) -> Any:
    incident: dict = demisto.incidents()[0]
    custom_fields: dict = incident.get('CustomFields', {})
    return custom_fields.get(filed_name)


def get_campaign_incident_ids(context_path: str) -> list[str] | None:
    """
        Collect the campaign incidents ids form the context

        :return: list of campaign incident ids if exist, None otherwise
    """
    incident_id = demisto.incidents()[0]['id']
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')

    incidents: list[dict] = demisto.get(res[0], context_path)
    if incidents:
        ids = [str(incident.get('id')) for incident in incidents]
        ids.sort(key=lambda val: int(val))
        return ids

    return None


def get_close_notes():
    return demisto.incidents()[0].get('closeNotes', '')


def perform_link_unlink(ids, action):
    ids: str = ','.join(ids)
    campaign_id = demisto.incident()['id']
    campaign_context = _get_context(campaign_id)

    campaign_incidents_context = demisto.dt(campaign_context, 'Contents.context.EmailCampaign.incidents')
    if isinstance(campaign_incidents_context, dict | str):
        campaign_incidents_context = [campaign_incidents_context]  # TODO ????
    fields_to_display = demisto.dt(campaign_context, "EmailCampaign.fieldsToDisplay")
    campaign_incidents_context = [_parse_incident_context_to_valid_incident_campaign_context(id, fields_to_display) for id in ids]
    [_add_campaign_to_incident(id, campaign_id) for id in ids]
    _add_incidents_to_campaign(campaign_id, campaign_incidents_context)
    _link_or_unlink_between_incidents(campaign_id, ids, action)

    return COMMAND_SUCCESS.format(action=f'{action}ed', ids=ids)


def perform_close(ids, action):
    close_notes = get_close_notes()
    for incident_id in ids:
        res = demisto.executeCommand("closeInvestigation", {'id': incident_id, 'closeNotes': close_notes})
        if isError(res):
            return_error(COMMAND_ERROR_MSG.format(action=action, ids=','.join(ids), error=get_error(res)))

    return COMMAND_SUCCESS.format(action='closed', ids=','.join(ids))


def perform_reopen(ids, action):
    for incident_id in ids:
        res = demisto.executeCommand("reopenInvestigation", {'id': incident_id})
        if isError(res):
            return_error(COMMAND_ERROR_MSG.format(action=action, ids=','.join(ids), error=get_error(res)))

    return COMMAND_SUCCESS.format(action='reopened', ids=','.join(ids))


def perform_link_and_close(ids, action):
    perform_link_unlink(ids, 'link')
    perform_close(ids, 'close')
    return COMMAND_SUCCESS.format(action='linked & closed', ids=','.join(ids))


def perform_unlink_and_reopen(ids, action):
    perform_link_unlink(ids, 'unlink')
    perform_reopen(ids, 'reopen')
    return COMMAND_SUCCESS.format(action='unlinked & reopen', ids=','.join(ids))


def _remove_incident_from_lower_similarity_context(incident_context, incident_ids):
    lower_similarity_incident_context = demisto.dt(incident_context,
                                                   'Contents.context.EmailCampaign.LowerSimilarityIncidents')

    lower_similarity_incident_context = list(filter(
        lambda x: x.get('id') not in incident_ids, lower_similarity_incident_context))

    demisto.executeCommand('DeleteContext', {'key': 'EmailCampaign.LowerSimilarityIncidents'})

    res = demisto.executeCommand('SetByIncidentId', {'key': 'EmailCampaign.LowerSimilarityIncidents',
                                                     'value': lower_similarity_incident_context})
    if is_error(res):
        return_error(f'Failed to change context. Error details:\n{get_error(res)}')


def perform_add_to_campaign(ids, action):
    demisto.debug('starting add to campaign')
    campaign_id = demisto.incident()['id']
    campaign_incident_context = _get_context(campaign_id)
    demisto.debug(f'got incident context: {campaign_incident_context}')

    incident_context = demisto.dt(campaign_incident_context, 'Contents.context.EmailCampaign.incidents')
    if isinstance(incident_context, dict | str):
        incident_context = [incident_context]

    for incident_id in ids:
        search_path = f'Contents.context.EmailCampaign.LowerSimilarityIncidents(val.id=={incident_id})'
        similar_incident_data = demisto.dt(campaign_incident_context, search_path)

        if similar_incident_data:
            similar_incident_data = similar_incident_data[0]
            _add_campaign_to_incident(incident_id, campaign_id)

            # Add the incident to context under "incidents":
            incident_context.append(similar_incident_data)

    _remove_incident_from_lower_similarity_context(campaign_incident_context, ids)

    res = demisto.executeCommand('SetByIncidentId', {'key': 'EmailCampaign.incidents',
                                                     'value': incident_context})
    if is_error(res):
        return_error(f'Failed to change current context. Error details:\n{get_error(res)}')

    return COMMAND_SUCCESS.format(action=action, ids=','.join(ids))


def set_incident_owners(incident_ids, action, user_name):

    incident_ids.append(demisto.incident()["id"])

    for incident_id in incident_ids:
        res = demisto.executeCommand("setIncident", {"id": incident_id, "owner": user_name})

        if isError(res):
            return_error(COMMAND_ERROR_MSG.format(action=action, ids=','.join(incident_ids), error=get_error(res)))


def perform_take_ownership(ids, action):

    current_user_name = demisto.callingContext.get("context", {}).get("ParentEntry", {}).get("user")

    if not current_user_name:
        return_error("Could not find the current user.")

    set_incident_owners(ids, action, current_user_name)

    return COMMAND_SUCCESS.format(action=action, ids=','.join(ids))


ACTIONS_MAPPER = {
    'link': perform_link_unlink,
    'unlink': perform_link_unlink,
    'close': perform_close,
    'reopen': perform_reopen,
    'link & close': perform_link_and_close,
    'unlink & reopen': perform_unlink_and_reopen,
    'add to campaign': perform_add_to_campaign,
    'take ownership': perform_take_ownership
}


def main():
    try:
        similarity = demisto.args().get('similarity', 'High')

        action_field_name = ACTION_ON_CAMPAIGN_LOWER_FIELD_NAME if similarity.lower() == 'low' \
            else ACTION_ON_CAMPAIGN_FIELD_NAME
        select_field_name = SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME if similarity.lower() == 'low' \
            else SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME

        action = get_custom_field(action_field_name).lower()
        ids = get_custom_field(select_field_name)

        if ALL_OPTION in ids:
            context_path = 'Contents.context.EmailCampaign.LowerSimilarityIncidents' if similarity.lower() == 'low' \
                else 'Contents.context.EmailCampaign.incidents'
            ids = get_campaign_incident_ids(context_path)

        res = ACTIONS_MAPPER[action](ids, action) if ids else NO_CAMPAIGN_INCIDENTS_MSG
        return_results(res)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
