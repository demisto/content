import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def query(self, data, variables={}):
        return self._http_request(
            method='POST',
            json_data={'query': data, 'variables': variables})

    def add_incident_note(self, incident_id: Optional[str], note_text: Optional[str]) -> Dict[str, Any]:
        mutation = '''
        mutation CreateIncidentNote($incidentId: ID!, $note: IncidentNoteInput!) {
            addIncidentNote(
                incidentId: $incidentId
                note: $note
            ) {
                notes {
                    _id
                    text
                }
            }
        }
        '''
        variables = {
            'incidentId': incident_id,
            'note': {
                'text': note_text
            }
        }
        return self.query(mutation, variables)

    def remove_incident_threats(self, incident_id: Optional[str]) -> Dict[str, Any]:
        mutation = '''
        mutation RemoveIncidentThreats($incidentId: String!) {
          removeIncidentThreats(incidentId: $incidentId)
        }
        '''
        variables = {"incidentId": incident_id}
        return self.query(mutation, variables)

    def send_incident_soc_feedback(self, incident_id: Optional[str], custom_message: Optional[str] = None,
                                   threat_feedback_reported_at_limit: Optional[str] = None) -> Dict[str, Any]:
        mutation = '''
        mutation SendIncidentSocFeedback($incidentId: String!, $customMessage: String, $threatFeedbackReportedAtLimit: Date) {
            sendIncidentSocFeedback(
                incidentId: $incidentId,
                customMessage: $customMessage,
                threatFeedbackReportedAtLimit: $threatFeedbackReportedAtLimit
            )
        }
        '''
        variables = {
            'incidentId': incident_id,
            'customMessage': custom_message,
            'threatFeedbackReportedAtLimit': threat_feedback_reported_at_limit
        }
        return self.query(mutation, variables)

    def set_incident_sensitive(self, incident_id: Optional[str], is_sensitive: bool) -> Dict[str, Any]:
        mutation = '''
        mutation SetIncidentSensitive($incidentId: String!, $isSensitive: Boolean!) {
            setIncidentSensitive(
                incidentId: $incidentId
                isSensitive: $isSensitive
            ) {
                _id
                hasSensitiveInformation
            }
        }
        '''
        variables = {
            'incidentId': incident_id,
            'isSensitive': is_sensitive
        }
        response = self.query(mutation, variables)
        if 'errors' in response:
            raise ValueError(f"Failed to set incident sensitive: {response['errors']}")
        data = response.get('data', {}).get('setIncidentSensitive')
        if data is None:
            raise ValueError("Failed to set incident sensitive: No data returned.")
        return {
            '_id': data.get('_id'),
            'hasSensitiveInformation': data.get('hasSensitiveInformation'),
        }

    def set_incident_soc_classification(self, incident_id: Optional[str], classification: Optional[str]) -> Dict[str, Any]:
        mutation = '''
        mutation SetIncidentSocClassification($incidentId: String!, $classification: SocClassification!) {
            setIncidentSocClassification(
                incidentId: $incidentId
                classification: $classification
            ) {
                _id
                humanReadableId
                updatedAt
                socClassification
            }
        }
        '''
        variables = {
            'incidentId': incident_id,
            'classification': classification
        }
        return self.query(mutation, variables)

    def update_incident_state(self, incident_id: Optional[str], state: Optional[str]) -> Dict[str, Any]:
        mutation = '''
        mutation UpdateIncidentState($incidentId: ID!, $state: IncidentState!) {
            updateIncidentState(
                incidentId: $incidentId
                state: $state
            ) {
                _id
                humanReadableId
                updatedAt
                state
            }
        }
        '''
        variables = {
            'incidentId': incident_id,
            'state': state
        }
        return self.query(mutation, variables)


def test_module(client, query) -> str:
    result = client.query(query)
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def create_output(results: Dict[str, str], endpoint: str, keyfield: str = '') -> CommandResults:
    human_readable = tableToMarkdown('Hoxhunt results', results)
    return CommandResults(
        outputs_prefix=f'Hoxhunt.{endpoint}',
        outputs_key_field=keyfield,
        outputs=results,
        readable_output=human_readable
    )


def create_incident_from_log(incident: Dict[str, Any]) -> Dict[str, Any]:
    occurred = incident.get('createdAt')
    humanreadable = incident.get('humanReadableId')
    dbotMirrorId = str(incident.get('_id'))
    keys = incident.keys()
    labels = []
    for key in keys:
        labels.append({'type': key, 'value': str(incident[key])})
        formatted_description = f'Hoxhunt Incident: {humanreadable}'
    return {
        'name': formatted_description,
        'dbotMirrorId': dbotMirrorId,
        'rawJSON': json.dumps(incident),
        'occurred': occurred
    }


def form_incindents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    listofincidents = []
    for item in incidents:
        listofincidents.append(create_incident_from_log(item))
    return listofincidents


def fetch_incidents(client: Client, fetch_time: str, queryfilter: str):
    fetch_time_parsed = dateparser.parse(fetch_time)
    if fetch_time_parsed is None:
        raise ValueError("Invalid fetch_time format")
    timefrom = fetch_time_parsed.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
    else:
        start_time = timefrom
    fields = '''_id, createdAt, updatedAt, humanReadableId, lastReportedAt, firstReportedAt,
                policyName, state, threats{_id, createdAt, updatedAt, severity, feedbackSentAt,
                ratedAt, state, userRequestedFeedback, reporterUser{_id, emails{address}}, organizationId,
                organization{_id, name}, email{to{address}, from{address}, subject},
                enrichments{links{href, score}}, userModifiers{userActedOnThreat, repliedToEmail, downloadedFile,
                openedAttachment, visitedLink, enteredCredentials, userMarkedAsSpam, forwardedEmail, other},
                threatRedirectId, prediction{mlopsIocEmailMaliciousnessProbability,
                mlopsIocEmailMaliciousFlags{flag}}, classification, isVipReport}, organization{_id, name},
                organizationId, threatCount, globalThreatCount, notes{_id, user{emails{address}}, text,
                timestamp, editedAt, deletedAt}, severity, escalation{escalatedAt, creationThreshold},
                classification, socClassification, hasSensitiveInformation,
                ruleMatches{incidentRule{_id, name, priority}}'''
    if queryfilter:
        query = f'''
        {{
          incidents(sort: createdAt_DESC, filter: {{ {queryfilter}, createdAt_gt: "{start_time}" }}) {{
            {fields}
          }}
        }}
        '''
    else:
        query = f'''
        {{
          incidents(sort: createdAt_DESC, filter: {{createdAt_gt: "{start_time}" }}) {{
            {fields}
          }}
        }}
        '''
    results = client.query(query)
    incidents = results.get('data', {}).get('incidents')
    if incidents and len(incidents) > 0:
        end_time = results.get('data', {}).get('incidents', [{}])[0].get('createdAt')
        demisto.setLastRun({'start_time': end_time})
        demisto.incidents(form_incindents(results.get('data', {}).get('incidents')))
    else:
        demisto.incidents([])


def main():
    base_url = demisto.params().get('url')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)
    api_key = demisto.params().get('api_key')

    headers = {'Authorization': f'Authtoken {api_key}'}

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            query = '{currentUser {emails {address}}}'
            result = test_module(client, query)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_time = demisto.params().get('fetch_time')
            queryfilter = demisto.params().get('queryfilter')
            fetch_incidents(client, fetch_time, queryfilter)
        elif demisto.command() == 'hoxhunt-get-current-user':
            # Get the current user’s emails, no arguments required
            query = '{currentUser {emails {address}}}'
            results = client.query(query)
            return_results(create_output(results.get('data', {}).get('currentUser', {}).get('emails'), 'CurrentUser'))
        elif demisto.command() == 'hoxhunt-get-incidents':
            # Retrieve incidents from the Hoxhunt platform
            # Arguments:
            #   filter (str): Optional filter string to narrow down the incidents retrieved.
            queryfilter = args.get('filter')
            fields = '''_id, state, classification, socClassification,
                        hasSensitiveInformation, threatCount, createdAt,
                        updatedAt, humanReadableId, policyName, organizationId'''
            query = f'{{incidents({queryfilter}){{{fields}}}}}' if queryfilter else f'{{incidents{{{fields}}}}}'
            results = client.query(query)
            return_results(create_output(results.get('data', {}).get('incidents', []), 'Incidents', '_id'))
        elif demisto.command() == 'hoxhunt-get-threats':
            # Retrieve threats from the Hoxhunt platform
            # Arguments:
            #   filter (str): Optional filter string to narrow down the threats retrieved.
            queryfilter = args.get('filter')
            fields = '''_id, createdAt, updatedAt, feedbackSentAt, classification,
                        state, organizationId, severity, userRequestedFeedback,
                        threatRedirectId, isVipReport'''
            query = f'{{threats({queryfilter}){{{fields}}}}}' if queryfilter else f'{{threats{{{fields}}}}}'
            results = client.query(query)
            threats = results.get('data', {}).get('threats', [])
            return_results(create_output(threats, 'Threats', '_id'))
        elif demisto.command() == 'hoxhunt-add-incident-note':
            # Add a note to an incident
            # Arguments:
            #   incident_id (str): The ID of the incident to which the note will be added.
            #   note (str): The content of the note to add to the incident.
            incident_id = args.get('incident_id')
            note_text = args.get('note')
            response = client.add_incident_note(incident_id, note_text)
            if not response.get('errors'):
                note_data = response.get('data', {}).get('addIncidentNote', {}).get('notes', [])
                note = note_data[-1]
                transformed_data = {'incident_id': incident_id, 'note_id': note.get('_id', ''),
                                    'note': note.get('text', '')}
                return_results(create_output(transformed_data, 'IncidentNote', 'note_id'))
            else:
                return_error(response.get('errors'))
        elif demisto.command() == 'hoxhunt-remove-incident-threats':
            # Remove all threats that belong to an incident.
            # Arguments:
            #   incident_id (str): The ID of the incident from which threats will be removed.
            incident_id = args.get('incident_id')
            response = client.remove_incident_threats(incident_id)
            if response.get('data'):
                result_message = response.get('data', {}).get('removeIncidentThreats', 0)
                result_data = {'incident_id': incident_id, 'removed threats number': result_message}
                return_results(create_output(result_data, 'RemoveIncidentThreats'))
            else:
                return_error(response.get('errors'))
        elif demisto.command() == 'hoxhunt-send-incident-soc-feedback':
            # Send feedback to reporters of incident about whether the reported email was safe, spam or malicious.
            # Arguments:
            #   incident_id (str): The ID of the incident for which SOC feedback will be sent.
            #   custom_message (str): A custom message to include with the SOC feedback.
            #   threat_feedback_reported_at_limit (str): Datetime limit.
            incident_id = args.get('incident_id')
            custom_message = args.get('custom_message')
            threat_feedback_reported_at_limit = args.get('threat_feedback_reported_at_limit')
            response = client.send_incident_soc_feedback(incident_id, custom_message, threat_feedback_reported_at_limit)
            if response.get('data'):
                result_data = {'_id': incident_id, 'custom_message': custom_message,
                               'limit date': threat_feedback_reported_at_limit}
                return_results(create_output(result_data, 'SendIncidentSocFeedback'))
            else:
                return_error(response.get('errors'))
        elif demisto.command() == 'hoxhunt-set-incident-sensitive':
            # Mark an incident as sensitive or not sensitive
            # Arguments:
            #   incident_id (str): The ID of the incident to be marked as sensitive or not sensitive.
            #   is_sensitive (str): Set 'true' to mark the incident as sensitive, 'false' to mark it as not sensitive.
            incident_id = args.get('incident_id')
            is_sensitive_str = args.get('is_sensitive', 'false').lower()
            is_sensitive_bool = argToBoolean(is_sensitive_str)
            response = client.set_incident_sensitive(incident_id, is_sensitive_bool)
            sensitive_data: Dict[str, str] = {'incident_id': str(response.get('_id', '')),
                                              'is_sensitive': str(response.get('hasSensitiveInformation', ''))}
            return_results(create_output(sensitive_data, 'SetIncidentSensitive', 'incident_id'))
        elif demisto.command() == 'hoxhunt-set-incident-soc-classification':
            # Set SOC classification for an incident
            # Arguments:
            #   incident_id (str): The ID of the incident to classify.
            #   classification (str): The SOC classification to apply to the incident (e.g., MALICIOUS,SPAM,SAFE).
            incident_id = args.get('incident_id')
            classification = args.get('classification')
            response = client.set_incident_soc_classification(incident_id, classification)
            if not response.get('errors'):
                soc_classification_data = response.get('data', {}).get('setIncidentSocClassification', {})
                return_results(create_output(soc_classification_data, 'SetIncidentSocClassification', '_id'))
            else:
                return_error(response.get('errors'))
        elif demisto.command() == 'hoxhunt-update-incident-state':
            # Update the state of an incident
            # Arguments:
            #   incident_id (str): The ID of the incident to update.
            #   state (str): The new state of the incident (e.g., RESOLVED, OPEN).
            incident_id = args.get('incident_id')
            state = args.get('state')
            response = client.update_incident_state(incident_id, state)
            if not response.get('errors'):
                incident_state_data = response.get('data', {}).get('updateIncidentState', {})
                return_results(create_output(incident_state_data, 'UpdateIncidentState', '_id'))
            else:
                return_error(response.get('errors'))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
