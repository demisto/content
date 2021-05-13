import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INCIDENTS_HEADER = ['id', 'name', 'email_from', 'recipients', 'severity', 'status', 'created']
KEYS_FETCHED_BY_QUERY = ['status', 'severity']
NO_CAMPAIGN_INCIDENTS_MSG = 'There is no Campaign Incidents in the Context'
LINKABLE_ID_FORMAT = '[{incident_id}](#/Details/{incident_id})'
STATUS_DICT = {
    0: "Pending",
    1: "Active",
    2: "Closed",
    3: "Archive",
}
DEFAULT_CUSTOM_FIELDS = {
    'campaignclosenotes': 'Notes explaining why the incident was closed',
    'campaignemailsubject': 'Campaign detected',
    'campaignemailbody': 'Fill here message for the recipients',
    'selectcampaignincidents': ['All']
}


def update_incident_with_required_keys(incidents, required_keys):
    """
        Update the given incident dict (from context) with values retrieved by GetIncidentsByQuery command

        :type incidents: ``list``
        :param incidents: campaign incidents from the context

        :type required_keys: ``list``
        :param required_keys: keys need to be updated

    """
    ids = [str(incident['id']) for incident in incidents]
    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': "id:({})".format(' '.join(ids))
    })
    if isError(res):
        return_error(f'Error occurred while trying to get incidents by query: {get_error(res)}')

    incidents_from_query = json.loads(res[0]['Contents'])
    id_to_updated_incident_map = {incident['id']: incident for incident in incidents_from_query}
    for incident in incidents:
        updated_incident = id_to_updated_incident_map[incident['id']]
        for key in required_keys:
            incident[key] = updated_incident.get(key)


def get_incident_val(incident, key):
    """
        Get the value from incident dict and convert it in some cases e.g. make id linkable etc.

        :type incident: ``dict``
        :param incident: the incident to get the value from

        :type key: ``str``
        :param key: the key in dict

        :rtype: ``str``
        :return the value form dict
    """
    if key == 'status':
        return STATUS_DICT.get(incident.get(key))

    if key == 'id':
        return LINKABLE_ID_FORMAT.format(incident_id=incident.get(key))

    return incident.get(key.replace('_', ''))


def get_campaign_incidents_from_context():
    return demisto.get(demisto.context(), 'EmailCampaign.incidents')


def get_incidents_info_md(incidents):
    """
        Get the campaign incidents relevant info in MD table

        :type incidents: ``list``
        :param incidents: the campaign incidents to collect the info from

        :rtype: ``str``
        :return the MD table str

    """
    if incidents:
        incidents_info = [
            {key: get_incident_val(incident, key) for key in INCIDENTS_HEADER} for incident in incidents
        ]
        return tableToMarkdown(
            name='',
            t=incidents_info,
            headerTransform=string_to_table_header,
            headers=INCIDENTS_HEADER,
            removeNull=True,
        )

    return None


def update_empty_fields():
    """
        Update the campaign dynamic section empty field with default values in order for them to appear in the page
    """
    incident = demisto.incidents()[0]
    custom_fields = incident.get('customFields', {})

    for field in DEFAULT_CUSTOM_FIELDS.keys():
        if not custom_fields.get(field):
            custom_fields[field] = DEFAULT_CUSTOM_FIELDS[field]
    demisto.executeCommand('setIncident', {'id': incident['id'], 'customFields': custom_fields})


def main():
    try:
        incidents = get_campaign_incidents_from_context()
        if incidents:
            update_incident_with_required_keys(incidents, KEYS_FETCHED_BY_QUERY)
            update_empty_fields()
            readable_output = get_incidents_info_md(incidents)
        else:
            readable_output = NO_CAMPAIGN_INCIDENTS_MSG

        return_results(CommandResults(readable_output=readable_output))
    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
