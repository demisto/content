import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from collections.abc import Callable
from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
CURRENT_USER_FIELDS = '''
    _id
    emails {
        address
    }
'''

FETCH_INCIDENTS_FIELDS = '''
    _id
    createdAt
    updatedAt
    humanReadableId
    lastReportedAt
    firstReportedAt
    policyName
    state
    globalThreatCount
    responseUrl
    notes {
        _id
        user {
            emails {
                address
            }
        }
        text
        timestamp
        editedAt
        deletedAt
    }
    hoxhuntClassification: classification
    externalClassification: socClassification
    hasSensitiveInformation
    ruleMatches {
        incidentRule {
            _id
            name
            priority
        }
        actions
        timestamp
    }
    firstThreat: threats(
        sort: createdAt_ASC
        first: 1
    ) {
        _id
        hoxhuntClassification: classification
        prediction {
            mlopsIocEmailMaliciousnessProbability
        }
        enrichments {
            links {
                label
                href
                score
            }
        }
        email {
            to {
                address
                name
            }
            from {
                address
                name
            }
            cc {
                address
                name
            }
            bcc {
                address
                name
            }
            sanitizedBody {
                signedUrl
                expiresAt
            }
            date
            messageId
            attachments {
                name
                type
                hash
                size
                content {
                    signedUrl
                    expiresAt
                }
                score
            }
            subject
        }
        createdAt
    }
    threatMetadata {
      likelyTargetEntity
      threatCount
      vipReportCount
      reportCountFromInbox
      phishReportCount
      userActions
      threatIndicators
      resources {
        hasLink
        hasAttachment
      }
    }
'''

FETCH_MODIFIED_INCIDENTS_FIELDS = '''
    _id
'''

CREATE_INCIDENT_NOTE_FIELDS = '''
    notes {
        _id
        text
    }
'''

SET_INCIDENT_SENSITIVE_FIELDS = '''
    _id
    hasSensitiveInformation
'''

SET_INCIDENT_SOC_CLASSIFICATION_FIELDS = '''
    _id
    humanReadableId
    updatedAt
    socClassification
'''

UPDATE_INCIDENT_STATE_FIELDS = '''
    _id
    humanReadableId
    updatedAt
    state
'''

GET_THREATS_FIELDS = '''
    _id
    createdAt
    updatedAt
    feedbackSentAt
    classification
    state
    organizationId
    severity
    userRequestedFeedback
    threatRedirectId
    isVipReport
'''


CAMPAIGN_INCIDENT_TYPE_NAME = "Hoxhunt Campaign"
USER_ACTED_TYPE_NAME = "Hoxhunt User Acted"
BEC_TYPE_NAME = "Hoxhunt BEC"

HOXHUNT_STATE_TO_REMOTE_DATA_ENTRY_MAP = {
    'RESOLVED': {
        'Type': EntryType.NOTE,
        'Contents': {'closeReason': 'Incident was resolved in Hoxhunt platform', 'dbotIncidentClose': True},
        'ContentsFormat': EntryFormat.JSON,
    },
    'OPEN': {
        'Type': EntryType.NOTE,
        'Contents': {'dbotIncidentReopen': True},
        'ContentsFormat': EntryFormat.JSON,
    }
}

INCIDENT_MAPPING_FIELDS = {
    "state": {
        "description": "incident can be either open or resolved",
        "xsoar_field_name": "hoxstate"
    },
    "socClassification": {
        "description": "external classification given for the incident by soc",
        "xsoar_field_name": "hoxexternalclassification"
    },
    "isSensitive": {
        "description": "does the incident contain sensitive information",
        "xsoar_field_name": "hoxhassensitiveinformation"
    },
    "shouldSendFeedback": {
        "description": "should feedback be sent to the reporter(s)",
        "xsoar_field_name": "hoxsendfeedback"
    },
    "feedbackReportedAtLimit": {
        "description": "time limit for feedback",
        "xsoar_field_name": "hoxreportedatlimit"
    },
    "socMessage": {
        "description": "custom message to send with feedback",
        "xsoar_field_name": "hoxmessagetousers"
    }
}


QUERIES = {
    "GetCurrentUser": f"""
        query GetCurrentUser {{
            currentUser {{
                {CURRENT_USER_FIELDS}
            }}
        }}
    """,
    "GetIncidentById": f"""
        query GetIncidentById($id: ID!, $lastUpdate: Date!) {{
            incidents(filter: {{ _id_eq: $id, updatedAt_gt: $lastUpdate }}) {{
                {FETCH_INCIDENTS_FIELDS}
            }}
        }}
    """,
    "GetModifiedIncidents": f"""
        query GetModifiedIncidents($lastUpdate: Date!) {{
            incidents(filter: {{ updatedAt_gt: $lastUpdate }}) {{
                {FETCH_MODIFIED_INCIDENTS_FIELDS}
            }}
        }}
    """
}


MUTATIONS = {
    "CreateIncidentNote": f"""
        mutation CreateIncidentNote($incidentId: ID!, $note: IncidentNoteInput!) {{
            addIncidentNote(
                incidentId: $incidentId
                note: $note
            ) {{
               {CREATE_INCIDENT_NOTE_FIELDS}
            }}
        }}
    """,
    "RemoveIncidentThreats": """
        mutation RemoveIncidentThreats($incidentId: String!) {
            removeIncidentThreats(incidentId: $incidentId)
        }
    """,
    "SendIncidentSocFeedback": """
        mutation SendIncidentSocFeedback($incidentId: String!, $customMessage: String, $threatFeedbackReportedAtLimit: Date) {
            sendIncidentSocFeedback(
                incidentId: $incidentId,
                customMessage: $customMessage,
                threatFeedbackReportedAtLimit: $threatFeedbackReportedAtLimit
            )
        }
    """,
    "SetIncidentSensitive": f"""
        mutation SetIncidentSensitive($incidentId: String!, $isSensitive: Boolean!) {{
            setIncidentSensitive(
                incidentId: $incidentId
                isSensitive: $isSensitive
            ) {{
                {SET_INCIDENT_SENSITIVE_FIELDS}
            }}
        }}
    """,
    "SetIncidentSocClassification": f"""
        mutation SetIncidentSocClassification($incidentId: String!, $classification: SocClassification!) {{
            setIncidentSocClassification(
                incidentId: $incidentId
                classification: $classification
            ) {{
                {SET_INCIDENT_SOC_CLASSIFICATION_FIELDS}
            }}
        }}
    """,
    "UpdateIncidentState": f"""
        mutation UpdateIncidentState($incidentId: ID!, $state: IncidentState!) {{
            updateIncidentState(
                incidentId: $incidentId
                state: $state
            ) {{
                {UPDATE_INCIDENT_STATE_FIELDS}
            }}
        }}
    """
}

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}.get(demisto.params().get('mirror_direction'))  # type: ignore


''' HELPER CLASSES '''


class GqlResult:
    def __init__(self, data: dict[str, Any] | None = None, errors: list[str] | None = None):
        self.data = data or {}
        self.errors = errors or []

    def has_errors(self) -> bool:
        return bool(self.errors)


def http_error_handler(res):
    if res.status_code == 429:
        raise Exception("API rate limit")

    # Copied from CommonServerPython
    err_msg = f'Error in API call [{res.status_code}] - {res.reason}'
    try:
        # Try to parse json error response
        error_entry = res.json()
        err_msg += f'\n{json.dumps(error_entry)}'
        raise DemistoException(err_msg, res=res)
    except ValueError:
        err_msg += f'\n{res.text}'
        raise DemistoException(err_msg, res=res)


''' CLIENT CLASS '''


class Client(BaseClient):
    def query(self, data: str, variables=None) -> GqlResult:
        '''
        Fire GraphQl requests towards Hoxhunt external API

        :return: GqlResult containing .data (and .errors)
        :rtype: ``GqlResult``
        '''
        variables = variables or {}

        response = self._http_request(
            method='POST',
            json_data={'query': data, 'variables': variables},
            error_handler=http_error_handler
        )

        gql_result = GqlResult(data=response.get('data'), errors=[
            error.get('message', '')
            for error in response.get('errors', [])
        ])

        return gql_result

    def add_incident_note(self, incident_id: str | None, note_text: str | None):
        return self.query(MUTATIONS['CreateIncidentNote'], {
            'incidentId': incident_id,
            'note': {
                'text': note_text
            }
        })

    def remove_incident_threats(self, incident_id: str | None):
        return self.query(MUTATIONS['RemoveIncidentThreats'], {"incidentId": incident_id})

    def send_incident_soc_feedback(self, incident_id: str | None, custom_message: str | None = None,
                                   threat_feedback_reported_at_limit: str | None = None):
        return self.query(MUTATIONS['SendIncidentSocFeedback'], variables={
            'incidentId': incident_id,
            'customMessage': custom_message,
            'threatFeedbackReportedAtLimit': threat_feedback_reported_at_limit
        })

    def set_incident_sensitive(self, incident_id: str | None, is_sensitive: bool) -> dict[str, Any]:
        response = self.query(MUTATIONS['SetIncidentSensitive'], {
            'incidentId': incident_id,
            'isSensitive': is_sensitive
        })

        if response.has_errors():
            raise ValueError(f"Failed to set incident sensitive: {response.errors}")
        data = response.data.get('setIncidentSensitive')
        if data is None:
            raise ValueError("Failed to set incident sensitive: No data returned.")
        return {
            '_id': data.get('_id'),
            'hasSensitiveInformation': data.get('hasSensitiveInformation'),
        }

    def set_incident_soc_classification(self, incident_id: str | None, classification: str | None):
        return self.query(MUTATIONS['SetIncidentSocClassification'], {
            'incidentId': incident_id,
            'classification': classification
        })

    def update_incident_state(self, incident_id: str | None, state: str | None):
        return self.query(MUTATIONS['UpdateIncidentState'], {
            'incidentId': incident_id,
            'state': state
        })

    def get_current_user(self):
        return self.query(QUERIES['GetCurrentUser'])

    def get_incident_by_id(self, incident_id: str, last_update: str):
        results = self.query(QUERIES['GetIncidentById'], {'lastUpdate': last_update, 'id': incident_id})
        incidents = results.data.get('incidents')
        if not incidents:
            return {}

        return incidents[0]

    def get_modified_incidents(self, last_update: str):
        return self.query(QUERIES['GetModifiedIncidents'], {"lastUpdate": last_update})

    def update_changed_incident_fields(self, incident_id: str, delta: dict[str, Any]):
        if delta.get('socClassification'):
            self.set_incident_soc_classification(incident_id, delta.get('socClassification'))
        if delta.get('isSensitive'):
            self.set_incident_sensitive(incident_id, delta.get('isSensitive'))  # type: ignore

    def handle_soc_feedback(self, incident_id: str, delta: dict[str, Any], incident_data: dict[str, Any]):
        should_send_feedback = incident_data.get('shouldSendFeedback')
        soc_message = incident_data.get('socMessage')
        feedback_reported_at_limit = incident_data.get('feedbackReportedAtLimit')
        updated_soc_classification = delta.get('socClassification')

        # send feedback if enabled and if soc classification has changed (initial set or update)
        if should_send_feedback and updated_soc_classification:
            self.send_incident_soc_feedback(incident_id, soc_message, feedback_reported_at_limit)

    def add_closing_incident_note(self, incident_id: str, incident_data: dict[str, Any]):
        xsoar_close_note = incident_data.get("xsoarCloseNotes")
        note = f"Incident closed via XSOAR{' - ' + xsoar_close_note if xsoar_close_note else ''}"
        self.add_incident_note(incident_id, note)


''' TYPES '''
DemistoCommandReturnType = Union[CommandResults, PollResult, str, dict, BaseWidget,
                                 list, GetMappingFieldsResponse, GetModifiedRemoteDataResponse, GetRemoteDataResponse]

HoxCommandType = Callable[[Client, dict, dict], DemistoCommandReturnType]
HoxNonReturningCommandType = Callable[[Client, dict, dict], None]

''' FNS '''


def camel_to_title(text: str) -> str:
    result = []
    for i, char in enumerate(text):
        if char.isupper() and (i == 0 or not text[i - 1].isupper()):
            result.append(' ')
        result.append(char)
    return ''.join(result).strip().title()


def create_output(results: dict[str, str], endpoint: str, key_field: str = '') -> CommandResults:
    human_readable = tableToMarkdown(name='Hoxhunt results', t=results, headerTransform=camel_to_title, removeNull=True)
    return CommandResults(
        outputs_prefix=f'Hoxhunt.{endpoint}',
        outputs_key_field=key_field,
        outputs=results,
        readable_output=human_readable
    )


def create_incident_from_log(incident: dict[str, Any], now: float) -> dict[str, Any]:
    occurred = incident.get('createdAt')
    human_readable_id = incident.get('humanReadableId')
    dbot_mirror_id = str(incident.get('_id'))
    incident['mirror_instance'] = demisto.integrationInstance()
    incident['mirror_direction'] = MIRROR_DIRECTION
    incident['last_mirrored_in'] = int(now * 1000)

    return {
        'name': human_readable_id,
        'dbotMirrorId': dbot_mirror_id,
        'rawJSON': json.dumps(incident),
        'occurred': occurred
    }


def fetch_incidents(
    client: Client,
    first_fetch: str | None,
    max_fetch: str | None,
    only_open_incidents: bool,
    only_escalated_incidents: bool,
    now: float,
    last_run: dict[str, Any]
) -> tuple[list[dict], dict | None]:
    first_fetch = first_fetch or '7 days'
    max_fetch = max_fetch or '50'
    first_fetch_parsed = dateparser.parse(first_fetch)

    if first_fetch_parsed is None:
        raise ValueError('Invalid first_fetch format')

    max_fetch_parsed = min(int(max_fetch), 100)

    timefrom = first_fetch_parsed.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    last_run = demisto.getLastRun()
    start_time = last_run.get('start_time') if last_run and 'start_time' in last_run else timefrom

    filters = [f'createdAt_gt: "{start_time}"']

    if only_escalated_incidents:
        filters.append('escalation__escalatedAt_exists: true')
    if only_open_incidents:
        filters.append('state_eq: OPEN')

    filters_str = ', '.join(filters)

    query = f"""
    {{
      incidents(first: {max_fetch_parsed}, sort: createdAt_DESC, filter: {{ {filters_str} }}) {{
        {FETCH_INCIDENTS_FIELDS}
      }}
    }}
    """

    result = client.query(query)

    if result.has_errors():
        raise Exception(str(result.errors))

    raw_incidents = result.data.get('incidents', [])

    next_run = None

    if raw_incidents:
        next_run = {'start_time': raw_incidents[0].get('createdAt')}

    incidents: list[dict] = []

    for incident in raw_incidents:
        incidents.append(create_incident_from_log(incident, now))

    return incidents, next_run


def is_open_in_xsoar(xsoar_status: str) -> bool:
    return xsoar_status == IncidentStatus.ACTIVE or xsoar_status == IncidentStatus.PENDING


def is_closed_in_xsoar(xsoar_status: str) -> bool:
    return xsoar_status == IncidentStatus.DONE


''' COMMANDS '''


def test_module_command(client: Client, args: dict, params: dict):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: Hoxhunt client

    Returns:
        'ok' if test passed, anything else correlates to failing the test
    """
    result = client.get_current_user()
    if result.has_errors():
        return 'Test failed: ' + str(result)
    else:
        return 'ok'


def get_remote_data_command(client: Client, args: dict, params: dict):
    parsed_args = GetRemoteDataArgs(args)

    incident_id = parsed_args.remote_incident_id
    last_update = parsed_args.last_update
    last_update_parsed = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
    last_update_utc = last_update_parsed.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # type: ignore
    new_incident_data: dict = client.get_incident_by_id(incident_id, last_update_utc)

    if '_id' in new_incident_data:
        new_incident_data['id'] = new_incident_data['_id']

    entries = []
    state = new_incident_data.get('state')
    if state in HOXHUNT_STATE_TO_REMOTE_DATA_ENTRY_MAP:
        entries.append(HOXHUNT_STATE_TO_REMOTE_DATA_ENTRY_MAP[state])

    return GetRemoteDataResponse(new_incident_data, entries)


def get_mapping_fields_command(client: Client, args: dict, params: dict):
    campaign_incident_type_scheme = SchemeTypeMapping(type_name=CAMPAIGN_INCIDENT_TYPE_NAME)
    user_acted_incident_type_scheme = SchemeTypeMapping(type_name=USER_ACTED_TYPE_NAME)
    bec_incident_type_scheme = SchemeTypeMapping(type_name=BEC_TYPE_NAME)

    for mapping_field in INCIDENT_MAPPING_FIELDS:
        campaign_incident_type_scheme.add_field(
            name=mapping_field, description=INCIDENT_MAPPING_FIELDS[mapping_field].get('description'))  # type: ignore
        user_acted_incident_type_scheme.add_field(
            name=mapping_field, description=INCIDENT_MAPPING_FIELDS[mapping_field].get('description'))  # type: ignore
        bec_incident_type_scheme.add_field(
            name=mapping_field, description=INCIDENT_MAPPING_FIELDS[mapping_field].get('description'))  # type: ignore

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(campaign_incident_type_scheme)
    mapping_response.add_scheme_type(user_acted_incident_type_scheme)
    mapping_response.add_scheme_type(bec_incident_type_scheme)
    return mapping_response


def update_remote_system_command(client: Client, args: dict, params: dict) -> str:
    remote_args = UpdateRemoteSystemArgs(args)

    delta: dict[str, Any] = remote_args.delta
    incident_changed = remote_args.incident_changed
    xsoar_status = remote_args.inc_status
    incident_data: dict[str, Any] = remote_args.data
    incident_id = remote_args.remote_incident_id

    # incident was closed or opened in xsoar
    if incident_changed and delta:
        if is_open_in_xsoar(xsoar_status):
            client.update_incident_state(incident_id, 'OPEN')
            client.update_changed_incident_fields(incident_id, delta)

        elif is_closed_in_xsoar(xsoar_status):
            client.update_incident_state(incident_id, 'RESOLVED')
            client.update_changed_incident_fields(incident_id, delta)
            client.handle_soc_feedback(incident_id, delta, incident_data)
            client.add_closing_incident_note(incident_id, incident_data)

    return incident_id


def get_modified_remote_data_command(client: Client, args: dict, params: dict):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    last_update_parsed = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
    last_update_utc = last_update_parsed.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # type: ignore

    result = client.get_modified_incidents(last_update_utc)

    if result.has_errors():
        raise Exception(str(result.errors))

    raw_incidents = result.data.get('incidents') or []

    modified_incident_ids = []
    for raw_incident in raw_incidents:
        incident_id = raw_incident.get('_id')
        modified_incident_ids.append(incident_id)

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def fetch_incidents_command(client: Client, args: dict, params: dict):
    first_fetch = params.get('first_fetch')
    max_fetch = params.get('max_fetch')
    only_open_incidents = argToBoolean(params.get('only_open_incidents') or True)
    only_escalated_incidents = argToBoolean(params.get('only_escalated_incidents') or False)

    incidents, next_run = fetch_incidents(
        client=client,
        first_fetch=first_fetch,
        max_fetch=max_fetch,
        only_open_incidents=only_open_incidents,
        only_escalated_incidents=only_escalated_incidents,
        last_run=demisto.getLastRun(),
        now=datetime.now().timestamp()
    )

    demisto.incidents(incidents)

    if next_run:
        demisto.setLastRun(next_run)
    # Note: fetch_incidents does not return results; it directly creates incidents.


def hoxhunt_get_current_user_command(client: Client, args: dict, params: dict):
    results = client.get_current_user()
    if results.has_errors():
        raise Exception(results.errors)

    data = results.data.get('currentUser', {}).get('emails')
    return create_output(data, 'CurrentUser')


def hoxhunt_get_incident_threats_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')

    if not incident_id:
        raise Exception("incident_id must be present")

    query_filter = args.get('filter') or ''
    query_sort = args.get('sort') or 'createdAt_DESC'
    query_limit = min(int(args.get('limit') or 50), 100)

    query_options = f'filter: {{{query_filter}}}, sort: {query_sort}, first: {query_limit}'
    query = f'{{incidents(filter: {{_id_eq: "{incident_id}"}}) {{ threats({query_options}) {{ {GET_THREATS_FIELDS} }} }}}}'

    result = client.query(query)

    if result.has_errors():
        raise Exception(result.errors)

    threats = result.data.get('incidents', [])[0].get('threats', [])

    return create_output(threats, 'Threats', '_id')


def hoxhunt_add_incident_note_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    note_text = args.get('note')
    response = client.add_incident_note(incident_id, note_text)

    if response.has_errors():
        raise Exception(response.errors)

    note_data = response.data.get('addIncidentNote', {}).get('notes', [])
    note = note_data[-1]
    transformed_data = {'incident_id': incident_id, 'note_id': note.get('_id', ''),
                        'note': note.get('text', '')}
    return create_output(transformed_data, 'IncidentNote', 'note_id')


def hoxhunt_remove_incident_threats_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    response = client.remove_incident_threats(incident_id)

    if response.has_errors():
        raise Exception(response.errors)

    result_message = response.data.get('removeIncidentThreats', 0)
    result_data = {'incident_id': incident_id, 'removed threats number': result_message}
    return create_output(result_data, 'RemoveIncidentThreats')


def hoxhunt_send_incident_soc_feedback_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    custom_message = args.get('custom_message')
    threat_feedback_reported_at_limit = args.get('threat_feedback_reported_at_limit')

    threat_feedback_reported_at_limit_parsed = arg_to_datetime(arg=threat_feedback_reported_at_limit, is_utc=True)
    date_limit_as_iso_string = threat_feedback_reported_at_limit_parsed.strftime(  # type: ignore
        '%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    response = client.send_incident_soc_feedback(incident_id, custom_message, date_limit_as_iso_string)

    if response.has_errors():
        raise Exception(response.errors)

    result_data: dict = {'_id': incident_id, 'custom_message': custom_message,
                         'limit date': threat_feedback_reported_at_limit}
    return create_output(result_data, 'SendIncidentSocFeedback')


def hoxhunt_set_incident_sensitive_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    is_sensitive_bool = argToBoolean(args.get('is_sensitive') or False)
    response = client.set_incident_sensitive(incident_id, is_sensitive_bool)
    sensitive_data = {'incident_id': str(response.get('_id', '')),
                      'is_sensitive': str(response.get('hasSensitiveInformation', ''))}

    return create_output(sensitive_data, 'SetIncidentSensitive', 'incident_id')


def hoxhunt_set_incident_soc_classification_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    classification = args.get('classification')
    response = client.set_incident_soc_classification(incident_id, classification)

    if response.has_errors():
        raise Exception(response.errors)

    soc_classification_data = response.data.get('setIncidentSocClassification', {})
    return create_output(soc_classification_data, 'SetIncidentSocClassification', '_id')


def hoxhunt_update_incident_state_command(client: Client, args: dict, params: dict):
    incident_id = args.get('incident_id')
    state = args.get('state')
    response = client.update_incident_state(incident_id, state)

    if response.has_errors():
        raise Exception(response.errors)

    incident_state_data = response.data.get('updateIncidentState', {})
    return create_output(incident_state_data, 'UpdateIncidentState', '_id')


''' MAIN '''


def main():  # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    base_url: str = params.get('url', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key: str = params.get('api_key', '')

    if not all([base_url, api_key]):
        return return_error('url and api_key must be provided.')

    headers = {'Authorization': f'Bearer {api_key}'}

    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        commands: dict[str, HoxCommandType] = {
            'test-module': test_module_command,
            'hoxhunt-current-user-get': hoxhunt_get_current_user_command,
            'hoxhunt-incident-note-add': hoxhunt_add_incident_note_command,
            'hoxhunt-incident-threats-get': hoxhunt_get_incident_threats_command,
            'hoxhunt-incident-threats-remove': hoxhunt_remove_incident_threats_command,
            'hoxhunt-incident-soc-feedback-send': hoxhunt_send_incident_soc_feedback_command,
            'hoxhunt-incident-set-sensitive': hoxhunt_set_incident_sensitive_command,
            'hoxhunt-incident-set-soc-classification': hoxhunt_set_incident_soc_classification_command,
            'hoxhunt-incident-update-state': hoxhunt_update_incident_state_command,
            'get-remote-data': get_remote_data_command,
            'get-mapping-fields': get_mapping_fields_command,
            'update-remote-system': update_remote_system_command,
            'get-modified-remote-data': get_modified_remote_data_command,
        }

        non_returning_commands: dict[str, HoxNonReturningCommandType] = {
            'fetch-incidents': fetch_incidents_command,
        }

        if command in commands:
            result = commands[command](client, args, params)
            return return_results(result)
        elif command in non_returning_commands:
            non_returning_commands[command](client, args, params)
        else:
            raise NotImplementedError(f"The command '{command}' is not recognized.")

    except Exception as e:
        # https://xsoar.pan.dev/docs/integrations/mirroring_integration#get-modified-remote-data
        # Let XSOAR know explicitly that we're being rate limited -> XSOAR has special handling for it
        if "API rate limit" in str(e):
            return_error("API rate limit")

        match command:
            # https://xsoar.pan.dev/docs/integrations/mirroring_integration#get-modified-remote-data
            # get-modified-remote-data should return skip update when it fails -> XSOAR has special handling for it
            case "get-modified-remote-data":
                return_error(f'skip update - {e}')
            case _:
                return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
