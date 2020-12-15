import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *
import json
from datetime import datetime, timedelta
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS/GLOBALS '''
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = 'RespondSoftwareAnalyst'
BASE_URL = demisto.params().get('base_url')
VERIFY_CERT = not demisto.params().get('insecure', False)
API_TOKEN = demisto.params().get('token')

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Both': 'Both'
}

RESPOND_FEEDBACK_STATUS = {
    'ConfirmedIncident': 'Confirmed Incident',
    'NonActionable': 'Non-Actionable',
    'Inconclusive': 'Inconclusive'
}

RESPOND_INCIDENT_FIELDS = {
    "feedback comments": {
        "description": "the user assigned outcome of a closed incident",
        "xsoar_field_name": "feedbackcomments"
    },
    "title": {
        "description": "incident title",
        "xsoar_field_name": "Title"
    },
    "feedback outcome": {
        "description": "the outcome of the incident close",
        "xsoar_field_name": "feedbackoutcome"
    }
}

RESPOND_INCIDENT_TYPE_NAME = 'Respond Software Incident'


def convert_epoch_to_milli(timestamp):
    if timestamp is None:
        return None
    if 9 < len(str(timestamp)) < 13:
        timestamp = int(timestamp) * 1000
    return int(timestamp)


def convert_datetime_to_epoch(the_time=0):
    if the_time is None:
        return None
    try:
        if isinstance(the_time, datetime):
            return int(the_time.strftime('%s'))
    except Exception as err:
        demisto.error(err)
        return 0


def convert_datetime_to_epoch_millis(the_time=0):
    return convert_epoch_to_milli(convert_datetime_to_epoch(the_time=the_time))


def arg_to_timestamp(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp that str - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # if the arg is string of date format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp() * 1000)
    if isinstance(arg, (int, float)):
        return arg


# helper function gets incident ids from Respond into array format
def extract_id(incident_id_map):
    return int(incident_id_map.get('id'))


class RestClient(BaseClient):
    def send_graphql_request(self, tenant_id, data):
        return self._http_request(
            method='POST',
            url_suffix=f'/graphql?tempId={API_TOKEN}&tenantId={tenant_id}',
            retries=3,
            json_data=data,
        )

    def get_tenant_mappings(self):
        # need to send one request to big-monolith service to get the external tenant id
        res = self._http_request(
            method='GET',
            url_suffix=f'/session/tenantIdMapping?tempId={API_TOKEN}',
            retries=3,
            resp_type='none'
        )

        '''
        this is a hacky way of checking for a bad api token
        if an api token is bad, Respond will redirect to the login page, which is html
        normally requests using the BaseClient assume resp_type=json and return a parsed json object from the body
        for this request we specifically use a resp_type that will return the entire response and allow us to attempt
        to parse the json. if parsing fails, try to parse as text, and then search the text for 'login'
        if we find that, it is sufficient to say we have a bad token, and can return a more helpful error.
        
        this isn't ideal. this is also, at the time of this writing, the first REST request made by all of our commands
        because we need to get the internal tenant id before doing anything else. that's why we only do this hack on 
        this request.
        '''
        try:
            tenant_mappings = res.json()
            if len(tenant_mappings) == 0:
                raise Exception('no tenants found for user')
            return tenant_mappings
        except ValueError as e:
            if 'login' in res.text.lower():
                raise Exception(f'invalid API token for {BASE_URL}')

    def get_current_user(self):
        return self._http_request(
            method='GET',
            url_suffix=f'/session/activeUser?tempId={API_TOKEN}',
            retries=3
        )

    def get_all_users(self):
        return self._http_request(
            method='GET',
            url_suffix=f'/api/v0/users?tempId={API_TOKEN}',
            retries=3
        )

    # sadly the linting process will fail if the format below is not used. Hard to read
    def construct_and_send_full_incidents_query(self, tenant_id, incident_ids):
        query = {"query": "query { "
                          "fullIncidents(ids: " + str(incident_ids) + ") {"
                                                                      "         id"
                                                                      "         dateCreated"
                                                                      "         eventCount"
                                                                      "         firstEventTime"
                                                                      "         lastEventTime"
                                                                      "         title"
                                                                      "         description"
                                                                      "         attackStage"
                                                                      "         assetClass"
                                                                      "         probabilityBucket"
                                                                      "         status"
                                                                      "         priority"
                                                                      "         internalSystemsCount"
                                                                      "         allSystems{"
                                                                      "            hostname"
                                                                      "            ipAddress"
                                                                      "            isInternal"
                                                                      "         }"
                                                                      "         avAccounts{"
                                                                      "            name"
                                                                      "            domain"
                                                                      "         }"
                                                                      "         wpAccounts{"
                                                                      "            name"
                                                                      "            domain"
                                                                      "         }"
                                                                      "         authDataAccounts{"
                                                                      "            name"
                                                                      "            domain"
                                                                      "         }"
                                                                      "         edrAccounts{"
                                                                      "            name"
                                                                      "            domain"
                                                                      "         }"
                                                                      "         avMalwareNames{"
                                                                      "            name"
                                                                      "            vendor"
                                                                      "            type"
                                                                      "         }"
                                                                      "         nidsSignatures{"
                                                                      "            vendor"
                                                                      "            name"
                                                                      "            category"
                                                                      "         }"
                                                                      "         wpHosts{"
                                                                      "            hostname"
                                                                      "            categorizations"
                                                                      "         }"
                                                                      "         avFileHashes{"
                                                                      "            hash"
                                                                      "         }"
                                                                      "         feedback {"
                                                                      "             newStatus"
                                                                      "             status"
                                                                      "             newSelectedOptions{"
                                                                      "                 id"
                                                                      "                 key"
                                                                      "                 value"
                                                                      "             }"
                                                                      "             timeGiven"
                                                                      "             optionalText"
                                                                      "             userId"
                                                                      "             closedAt"
                                                                      "             closedBy"
                                                                      "         }"
                                                                      "         userIds"
                                                                      "         tags {"
                                                                      "             label"
                                                                      "         }"
                                                                      "} }"
                 }
        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('fullIncidents')

    def construct_and_send_get_incident_ids_query(self, tenant_id, from_time_str):
        if from_time_str == '':
            query = {"query": "query { incidents( statusFilters: [ { incidentStatus: Open } "
                              " ] ){ id } }"}
        else:
            query = {"query": "query { incidents( createdAfter:\"" + from_time_str + "\" ){ id } }"}
        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('incidents')

    def construct_and_send_close_incident_mutation(self, tenant_id, feedback_status,
                                                   feedback_selected_options,
                                                   feedback_optional_text, incident_id, user):
        if feedback_selected_options is None:
            feedback_selected_options = []

        # sadly the linting process will fail if the format below is not used. Hard to read
        query = {"query": "mutation closeIncident( "
                          "$incidentId: ID! "
                          "$user: User! "
                          "$feedbackStatus: FeedbackStatus! "
                          "$newFeedbackSelectedOptions: [FeedbackSelectionInput!] "
                          "$feedbackOptionalText: String ){ "
                          "closeIncident( "
                          "incidentId: $incidentId "
                          "user: $user "
                          "feedbackStatus: $feedbackStatus "
                          "newFeedbackSelectedOptions: $newFeedbackSelectedOptions "
                          "feedbackOptionalText: $feedbackOptionalText "
                          ") { "
                          "id "
                          "status "
                          "feedback { "
                          "userId "
                          "newStatus "
                          "timeGiven "
                          "newSelectedOptions{ "
                          "id "
                          "key "
                          "value "
                          "} "
                          "optionalText "
                          "} "
                          "} "
                          "}",
                 "variables": {"incidentId": incident_id, "user": user,
                               "feedbackStatus": feedback_status,
                               "newFeedbackSelectedOptions": feedback_selected_options,
                               "feedbackOptionalText": feedback_optional_text}
                 }
        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('closeIncident')

    def construct_and_send_add_user_to_incident_mutation(self, tenant_id, user_id, incident_id):
        query = {"query": "mutation addUserToIncident($id: ID! $userId: String!) { "
                          "addUserToIncident(incidentId: $id userId: $userId) { "
                          "id "
                          "userIds "
                          "} "
                          "}",
                 "variables": {"id": incident_id, "userId": user_id}
                 }

        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('addUserToIncident')

    def construct_and_send_remove_user_from_incident_mutation(self, tenant_id, user_id,
                                                              incident_id):
        query = {"query": "mutation removeUserFromIncident($id: ID! $userId: String!) { "
                          "removeUserFromIncident(incidentId: $id userId: $userId) { "
                          "id "
                          "userIds "
                          "} "
                          "}",
                 "variables": {"id": incident_id, "userId": user_id}
                 }

        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('removeUserFromIncident')

    def construct_and_send_new_escalations_query(self, tenant_id, incident_id):
        query = {"query": "query {"
                          "newEscalations(consumer: \"XSOAR" + tenant_id + "\", patterns: [{type: INCIDENT_ID, value: \"" + incident_id + "\"}]) { "
                                                                                                                                          "    timeGenerated "
                                                                                                                                          "    sourceType "
                                                                                                                                          "    incident { "
                                                                                                                                          "      id "
                                                                                                                                          "      priority "
                                                                                                                                          "      probabilityBucket "
                                                                                                                                          "    } "
                                                                                                                                          "    ... on NIDSEvent { "
                                                                                                                                          "      idx "
                                                                                                                                          "      nidsAction: action { "
                                                                                                                                          "        action "
                                                                                                                                          "      } "
                                                                                                                                          "      actionExt "
                                                                                                                                          "      trafficFlow "

                                                                                                                                          "      signature { "
                                                                                                                                          "        vendor "
                                                                                                                                          "        category "
                                                                                                                                          "        idx "
                                                                                                                                          "      } "
                                                                                                                                          "      signatureImportance "
                                                                                                                                          "      signatureName "
                                                                                                                                          "      categoryExt "
                                                                                                                                          "      deviceId "

                                                                                                                                          "      protocol "

                                                                                                                                          "      sourceHostname "
                                                                                                                                          "      sourceIpAddress "
                                                                                                                                          "      sourceZone "
                                                                                                                                          "      sourceSystem { "
                                                                                                                                          "        isInternal "
                                                                                                                                          "        isCritical "
                                                                                                                                          "      } "
                                                                                                                                          "      sourceAssetClassification "
                                                                                                                                          "      sourceSubClassifications "
                                                                                                                                          "      sourceCriticality "
                                                                                                                                          "      sourcePort { "
                                                                                                                                          "        number "
                                                                                                                                          "      } "
                                                                                                                                          "      sourceSuspicion "

                                                                                                                                          "      destinationHostname "
                                                                                                                                          "      destinationIpAddress "
                                                                                                                                          "      destinationZone "
                                                                                                                                          "      destinationSystem { "
                                                                                                                                          "        isInternal "
                                                                                                                                          "        isCritical "
                                                                                                                                          "      } "
                                                                                                                                          "      destinationAssetClassification "
                                                                                                                                          "      destinationSubClassifications "
                                                                                                                                          "      destinationCriticality "
                                                                                                                                          "      destinationPort { "
                                                                                                                                          "        number "
                                                                                                                                          "      } "
                                                                                                                                          "      destinationSuspicion "
                                                                                                                                          "    } "
                                                                                                                                          "    ... on AVEvent {"
                                                                                                                                          "      system {"
                                                                                                                                          "        hostname"
                                                                                                                                          "        ipAddress"
                                                                                                                                          "        zone "
                                                                                                                                          "      }"
                                                                                                                                          "      account {"
                                                                                                                                          "        domain"
                                                                                                                                          "        name"
                                                                                                                                          "      }"
                                                                                                                                          "      hash {"
                                                                                                                                          "        hash"
                                                                                                                                          "      }"
                                                                                                                                          "      malwareName {"
                                                                                                                                          "        name"
                                                                                                                                          "        type"
                                                                                                                                          "        vendor"
                                                                                                                                          "      }"
                                                                                                                                          "      accountType "
                                                                                                                                          "      isKnownBadHash "
                                                                                                                                          "      deviceId"
                                                                                                                                          "      scanTypeExt"
                                                                                                                                          "      actionExt"
                                                                                                                                          "      malwareSeverity"
                                                                                                                                          "      malwareSeverityExt"
                                                                                                                                          "      malwareTypeExt"
                                                                                                                                          "      assetClassification"
                                                                                                                                          "      assetSubClassifications"
                                                                                                                                          "      assetCriticality"
                                                                                                                                          "      systemRepeatOffender"
                                                                                                                                          "      accountRepeatOffender"
                                                                                                                                          "      malwareSpreading"
                                                                                                                                          "      avFilepath: filepath"
                                                                                                                                          "    }"

                                                                                                                                          "    ... on WPEvent {"
                                                                                                                                          "      wpAction: action { "
                                                                                                                                          "        action "
                                                                                                                                          "      } "
                                                                                                                                          "      sourceSystem {"
                                                                                                                                          "        hostname"
                                                                                                                                          "        ipAddress"
                                                                                                                                          "        zone "
                                                                                                                                          "        isInternal "
                                                                                                                                          "      }"
                                                                                                                                          "      sourceAssetClassification "
                                                                                                                                          "      sourceSubClassifications "
                                                                                                                                          "      sourceCriticality "
                                                                                                                                          "      destinationAddress {"
                                                                                                                                          "        hostname"
                                                                                                                                          "        ipAddress"
                                                                                                                                          "        zone "
                                                                                                                                          "        isInternal "
                                                                                                                                          "      }"
                                                                                                                                          "      destinationAssetClassification "
                                                                                                                                          "      destinationSubClassifications "
                                                                                                                                          "      destinationCriticality "
                                                                                                                                          "      account {"
                                                                                                                                          "        domain"
                                                                                                                                          "        name"
                                                                                                                                          "      }"
                                                                                                                                          "      accountType "
                                                                                                                                          "      categorizationsExternal "
                                                                                                                                          "      protocol "
                                                                                                                                          "      method  "
                                                                                                                                          "      status  "
                                                                                                                                          "      userAgent "
                                                                                                                                          "      contentType "
                                                                                                                                          "      fileType    "
                                                                                                                                          "      deviceId "
                                                                                                                                          "      deviceVendor "
                                                                                                                                          "      fullUrl "
                                                                                                                                          "      campaign "
                                                                                                                                          "  } "
                                                                                                                                          "    ... on EDREvent {"
                                                                                                                                          "      system {"
                                                                                                                                          "        hostname"
                                                                                                                                          "        ipAddress"
                                                                                                                                          "        zone "
                                                                                                                                          "        isInternal "
                                                                                                                                          "      }"
                                                                                                                                          "      assetClassification"
                                                                                                                                          "      assetSubClassifications"
                                                                                                                                          "      assetCriticality"
                                                                                                                                          "      account {"
                                                                                                                                          "        domain"
                                                                                                                                          "        name"
                                                                                                                                          "      }"
                                                                                                                                          "      accountType "
                                                                                                                                          "      deviceId "
                                                                                                                                          "      deviceVendor "
                                                                                                                                          "      edrFilepath: filepath "
                                                                                                                                          "      fileHash "
                                                                                                                                          "      watchlistName "
                                                                                                                                          "      processName "
                                                                                                                                          "      isBinarySigned "
                                                                                                                                          "      parentProcessName "
                                                                                                                                          "      parentFileHash "
                                                                                                                                          "      parentFilepath "
                                                                                                                                          "      isParentBinarySigned "
                                                                                                                                          "      binarySuspicion "
                                                                                                                                          "      accountActivitySuspicion "
                                                                                                                                          "      diskOperationSuspicion "
                                                                                                                                          "      networkConnectionSuspicion "
                                                                                                                                          "    } "
                                                                                                                                          "}"
                                                                                                                                          "}"}
        res = self.send_graphql_request(tenant_id, query)
        return res.get('data').get('newEscalations')

    def construct_and_send_update_description_mutation(self, tenant_id, incident_id,
                                                       description):
        mutation = {
            "query": "mutation updateIncidentDescription($incidentId: ID!, $input: IncidentDescription!) { "
                     "updateIncidentDescription( "
                     "incidentId: $incidentId "
                     "input: $input "
                     ") { "
                     "id "
                     "description"
                     "} "
                     "}",
            "variables": {"incidentId": incident_id, "input": {"description": description}}
        }

        res = self.send_graphql_request(tenant_id, mutation)
        return res.get('data').get('updateIncidentDescription')

    def construct_and_send_update_title_mutation(self, tenant_id, incident_id, title):
        mutation = {
            "query": "mutation updateIncidentTitle($incidentId: ID!, $input: IncidentTitle!) { "
                     "updateIncidentTitle( "
                     "incidentId: $incidentId "
                     "input: $input "
                     ") { "
                     "id "
                     "title"
                     "} "
                     "}",
            "variables": {"incidentId": incident_id, "input": {"title": title}}
        }

        res = self.send_graphql_request(tenant_id, mutation)
        return res.get('data').get('updateIncidentTitle')


def test_module(client):
    """
    Tests connection to Respond Analyst Server

    Returns:
        nothing if test passed
    """
    client.get_tenant_mappings()


def fetch_incidents_for_tenant(rest_client, internal_tenant_id, external_tenant_id, from_time):
    # first time fetch is handled in query
    try:
        response = rest_client.construct_and_send_get_incident_ids_query(internal_tenant_id,
                                                                         from_time)
        id_list = list(map(extract_id, response))
        raw_incidents = rest_client.construct_and_send_full_incidents_query(internal_tenant_id,
                                                                            id_list)
    except Exception as err:
        # log error but continue getting incidents for other tenants
        demisto.error(
            'Exception thrown retrieving incidents for tenant ' + external_tenant_id + ': \n ' + str(
                err))
        return []
    return raw_incidents


def format_raw_incident(raw_incident, external_tenant_id, internal_tenant_id):
    # separate internal and external systems. internal system = asset
    assets = []
    external_systems = []
    if raw_incident.get('allSystems'):
        assets = list(
            filter(lambda system: system['isInternal'] is True, raw_incident['allSystems']))
        external_systems = list(
            filter(lambda system: system['isInternal'] is False, raw_incident['allSystems']))

    # aggregate accounts
    accounts = []
    accounts.extend(raw_incident.get('avAccounts'))
    accounts.extend(raw_incident.get('wpAccounts'))
    accounts.extend(raw_incident.get('authDataAccounts'))
    accounts.extend(raw_incident.get('edrAccounts'))

    # if there are unknown accounts, only keep one, and make the name 'unknown'
    unknown = False
    for account in accounts:
        if not account.get('name') and not account.get('domain'):
            accounts.remove(account)
            unknown = True
    if unknown:
        accounts.append({'name': 'Unknown', 'domain': None})

    # dedupe accounts
    seen = set()
    deduped_accounts = []
    for account in accounts:
        t = tuple(account.items())
        if t not in seen:
            seen.add(t)
            deduped_accounts.append(account)

    accounts = deduped_accounts

    # collect hashes
    hashes = []
    for hash_map in raw_incident.get('avFileHashes'):
        hashes.append(hash_map.get('hash'))

    # collect domains
    domains = []
    for domain in raw_incident.get('wpHosts'):
        domains.append(domain.get('hostname'))

    # convert graphql response to standardized JSON output for an incident
    formatted_incident = {
        'incidentId': raw_incident.get('id'),
        'timeGenerated': timestamp_to_datestring(raw_incident.get('dateCreated'),
                                                 TIME_FORMAT + 'Z'),
        'eventCount': raw_incident.get('eventCount'),
        'firstEventTime': timestamp_to_datestring(raw_incident.get('firstEventTime'),
                                                  TIME_FORMAT + 'Z'),
        'lastEventTime': timestamp_to_datestring(raw_incident.get('lastEventTime'),
                                                 TIME_FORMAT + 'Z'),
        'URL': BASE_URL + '/secure/incidents/' + raw_incident.get(
            'id') + '?tenantId=' + internal_tenant_id,
        'closeURL': BASE_URL + '/secure/incidents/feedback/' + raw_incident.get(
            'id') + '?tenantId=' + internal_tenant_id,
        'title': raw_incident.get('title'),
        'description': raw_incident.get('description'),
        'status': raw_incident.get('status'),
        'severity': raw_incident.get('priority'),
        'probability': raw_incident.get('probabilityBucket'),
        'attackStage': raw_incident.get('attackStage'),
        'attackTactic': raw_incident.get('attackTactic'),
        'assetCriticality': raw_incident.get('assetClass'),
        'assetCount': raw_incident.get('internalSystemsCount'),
        'assets': assets,
        'externalSystems': external_systems,
        'accounts': accounts,
        'domains': domains,
        'hashes': hashes,
        'malware': raw_incident.get('avMalwareNames'),
        'signatures': raw_incident.get('nidsSignatures'),
        'escalationReasons': raw_incident.get('tags'),
        'assignedUsers': raw_incident.get('userIds'),
        'tenantIdRespond': internal_tenant_id,
        'tenantId': external_tenant_id,
        'respondRemoteId': f'{external_tenant_id}:{raw_incident.get("id")}',
        'dbotMirrorDirection': MIRROR_DIRECTION.get(
            demisto.params().get('mirror_direction', 'None'), None),
        'dbotMirrorInstance': demisto.integrationInstance()
    }
    if len(raw_incident.get('userIds')) > 0:
        formatted_incident['owner'] = demisto.findUser(email=raw_incident.get('userIds')[0]).get(
            'username')

    if raw_incident.get('feedback') is not None:
        formatted_incident['feedback'] = {
            'timeUpdated': raw_incident.get('feedback').get('timeGiven'),
            'userId': raw_incident.get('feedback').get('userId'),
            'outcome': RESPOND_FEEDBACK_STATUS.get(raw_incident.get('feedback').get('newStatus')),
            'comments': raw_incident.get('feedback').get('optionalText')
        }
    return formatted_incident


def get_internal_tenant_from_mapping_with_external(tenant_mappings, external_tenant_id):
    """
    finds the respond tenant id that matches the external tenant id provided, if exists and accessible
    :param tenant_mappings: dictionary where (k,v) -> (internal_tenant_id,external_tenant_id)
    :param external_tenant_id:
    :return:
    """
    for curr_internal_tid, curr_external_tid in tenant_mappings.items():
        if external_tenant_id == curr_external_tid:
            return curr_internal_tid
    raise Exception(
        'no respond tenant matches external tenant: ' + external_tenant_id + ' or user does not have '
                                                                             'permission to access tenant')


def get_tenant_map_if_single_tenant(user_tenant_mappings):
    """
    returns respond tenant id and external tenant id if the user is single tenant, otherwise raises exception
    :param user_tenant_mappings: list of user mappings. expect length 1
    :return: internal_tenant_id, external_tenant_id
    """
    if len(user_tenant_mappings) > 1:
        demisto.error(
            'multi-tenant users must specify a tenant id in params, but no tenant id was found')
        raise Exception(
            'multi-tenant users must specify a tenant id in params, but no tenant id was found')
    if len(user_tenant_mappings) == 0:
        demisto.error('no tenants found for user')
        raise Exception('no tenants found for user')
    return list(user_tenant_mappings.items())[0]


def get_user_id_from_email(email, users):
    """
    given an email address and a list of Respond users, find the user id of the user with the provided email,
    and raise an exception if no user is found
    :param email: valid email for a user
    :param users: list of Respond Users
    :return: user id (string) of the user with email provided
    """
    # find the user id that matches the email provided in user_to_add field
    for user in users:
        if user.get('email') == email:
            return user.get('userId')

    raise Exception('no user found with email ' + email)


def get_formatted_incident(rest_client, args):
    external_tenant_id = args.get('tenant_id')
    user_tenant_mappings = rest_client.get_tenant_mappings()

    if external_tenant_id is None:
        internal_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        internal_tenant_id = get_internal_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                            external_tenant_id)

    incident_id = int(args['incident_id'])

    raw_incident = \
        rest_client.construct_and_send_full_incidents_query(internal_tenant_id, [incident_id])[0]

    return format_raw_incident(raw_incident, external_tenant_id, internal_tenant_id)


def get_tenant_ids(rest_client, args):
    external_tenant_id = args.get('tenant_id')
    user_tenant_mappings = rest_client.get_tenant_mappings()

    if external_tenant_id is None:
        internal_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        internal_tenant_id = get_internal_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                            external_tenant_id)
    return internal_tenant_id, external_tenant_id


def validate_user(rest_client, args):
    user_to_remove = args['username']

    try:
        users = rest_client.get_all_users()
    except Exception as err:
        demisto.error('error adding user to incident: ' + str(err))
        raise Exception('error adding user to incident: ' + str(err))

    valid_user = False
    for user in users:
        if user.get('email') == user_to_remove:
            valid_user = True
            break

    if valid_user is False:
        demisto.error('no user found with email ' + user_to_remove)
        raise Exception('no user found with email ' + user_to_remove)

    return user_to_remove


def remove_user_command(rest_client, args):
    incident_id = int(args['incident_id'])
    internal_tenant_id, external_tenant_id = get_tenant_ids(rest_client, args)
    user_to_remove = validate_user(rest_client, args)

    try:
        res = rest_client.construct_and_send_remove_user_from_incident_mutation(internal_tenant_id,
                                                                                user_to_remove,
                                                                                incident_id)
        return 'user with email: ' + user_to_remove + ' removed from incident with id ' + res[
            'id'] + ' on tenant ' + str(external_tenant_id)
    except Exception as err:
        demisto.error('error removing user from incident: ' + str(err))
        raise Exception('error removing user from incident: ' + str(err))


def assign_user_command(rest_client, args):
    incident_id = int(args['incident_id'])
    internal_tenant_id, external_tenant_id = get_tenant_ids(rest_client, args)
    user_to_add = validate_user(rest_client, args)

    try:
        res = rest_client.construct_and_send_add_user_to_incident_mutation(internal_tenant_id,
                                                                           user_to_add,
                                                                           incident_id)
        return 'user with email: ' + user_to_add + ' added to incident with id ' + res.get('id') + \
               ' on tenant ' + str(external_tenant_id)
    except Exception as err:
        demisto.error('error adding user to incident: ' + str(err))
        raise Exception('error adding user to incident: ' + str(err))


def close_incident_command(rest_client, args):
    """
    :param rest_client: REST client
    :param args: parameters include: user_to_add:email, user_to_remove:email,
    feedback_status:string, feedback_selected_options:[{id, key, value}], feedback_optional_text:string
    :return: ??
    """
    respond_user = rest_client.get_current_user()
    incident_id = int(args['incident_id'])
    internal_tenant_id, external_tenant_id = get_tenant_ids(rest_client, args)

    feedback_status = args['incident_feedback']
    feedback_selected_options = args.get('feedback_selected_options')
    feedback_optional_text = args.get('incident_comments')
    try:
        incident = \
            rest_client.construct_and_send_full_incidents_query(internal_tenant_id, [incident_id])[
                0]
        if feedback_status is None:
            if incident.get('status') == 'Open':
                demisto.error('cannot close an incident without providing feedback status')
                raise Exception('cannot close an incident without providing feedback status')
            feedback_status = incident.get('feedback').get('newStatus')
        if incident.get('feedback') is not None:
            if feedback_selected_options is None:
                feedback_selected_options = incident.get('feedback').get('newSelectedOptions')
            if feedback_optional_text is None:
                feedback_optional_text = incident.get('feedback').get('optionalText')

        # get user info with rest client and construct user object
        respond_graphql_formatted_user = {
            'userId': respond_user['email'],
            'firstname': respond_user['firstname'],
            'lastname': respond_user['lastname']
        }
        res = rest_client.construct_and_send_close_incident_mutation(internal_tenant_id,
                                                                     feedback_status,
                                                                     feedback_selected_options,
                                                                     feedback_optional_text,
                                                                     incident_id,
                                                                     respond_graphql_formatted_user)
        return ('incident closed and/or feedback updated for incident with id ' + str(incident_id)
                + ' on tenant ' + external_tenant_id + ':\n' + str(res))
    except Exception as err:
        demisto.error('error closing incident and/or updating feedback: ' + str(err))
        raise Exception('error closing incident and/or updating feedback: ' + str(err))


def get_incident_command(rest_client, args):
    formatted_incident = get_formatted_incident(rest_client, args)
    new_incident = {
        'name': args['tenant_id'] + ': ' + formatted_incident['incidentId'],
        'occurred': formatted_incident.get('timeGenerated'),
        'rawJSON': json.dumps(formatted_incident)
    }
    return new_incident


def get_escalations_command(rest_client, args):
    start = datetime.now().timestamp()
    fourMinutes = 240

    try:
        external_tenant_id = args.get('tenant_id')
        user_tenant_mappings = rest_client.get_tenant_mappings()

        if external_tenant_id is None:
            internal_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
                user_tenant_mappings)
        else:
            internal_tenant_id = get_internal_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                                external_tenant_id)
        entries = []

        more_data = True
        while more_data:
            if datetime.now().timestamp() - start > fourMinutes:
                demisto.debug(
                    f'exiting safely for incident {args["incident_id"]} on {external_tenant_id} starting at {start}')
                entries.append({
                    'Type': EntryType.NOTE,
                    'Contents': 'Safely exited before timeout, but more data needs to be collected. Please re-run command.',
                    'ContentsFormat': EntryFormat.TEXT
                })
                break
            all_escalations = rest_client.construct_and_send_new_escalations_query(
                internal_tenant_id, args['incident_id'])
            for escalation in all_escalations:
                valid_entry = {
                    'Type': EntryType.NOTE,
                    'Contents': escalation,
                    'ContentsFormat': EntryFormat.JSON
                }
                entries.append(valid_entry)
            if len(all_escalations) == 0:
                more_data = False
    except Exception as e:
        demisto.debug(
            f'Error while getting escalation data in Respond incoming mirror for incident {args["incident_id"]} Error message: {str(e)}')
        raise e
    if len(entries) == 0:
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': 'No new escalations',
            'ContentsFormat': EntryFormat.TEXT
        })

    demisto.debug(
        f'returning escalations for incident {args["incident_id"]} on {external_tenant_id}: {entries}')
    return entries


def get_remote_data_command(rest_client, args):
    args['tenant_id'] = args.get('id').split(':')[0]
    args['incident_id'] = args.get('id').split(':')[1]
    entries = []
    try:
        updated_incident = get_formatted_incident(rest_client, args)
        updated_incident['id'] = args.get('id')
        demisto.debug(f"Respond incident {args.get('id')}\n"
                      f"update time:   {arg_to_timestamp(args.get('last_update'), 'last_update')}")
    except Exception as e:
        demisto.debug(
            f'Error while getting incident data in Respond incoming mirror for incident {args["id"]} \n'
            f'Error message: {str(e)}')
        raise e

    # updated_incident['feedback'] = get_incident_feedback(updated_incident)
    demisto.debug(f'incident feedback: {updated_incident.get("feedback")}')

    if updated_incident.get('feedback') is not None:
        demisto.debug(f"Closing Respond issue {updated_incident.get('id')}")
        closing_entry = {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': updated_incident.get('feedback').get('outcome'),
                'closeNotes': updated_incident.get('feedback').get('comments')
            },
            'ContentsFormat': EntryFormat.JSON
        }
        entries.append(closing_entry)
        demisto.debug(f'entries: {closing_entry} for incident {args["incident_id"]}')

    demisto.debug(f'update incident: {updated_incident} for incident {args["incident_id"]}')

    return [updated_incident] + entries


def update_remote_system_command(rest_client, args):
    remote_args = UpdateRemoteSystemArgs(args)
    try:
        if remote_args.delta:
            # get incident id and tenant id from remote_system_id
            tenant_id = remote_args.remote_incident_id.split(':')[0]
            incident_id = remote_args.remote_incident_id.split(':')[1]
            user_tenant_mappings = rest_client.get_tenant_mappings()
            internal_tenant_id = get_internal_tenant_from_mapping_with_external(
                user_tenant_mappings, tenant_id)

            demisto.debug(f'Got the following delta keys {str(list(remote_args.delta.keys()))} to '
                          f' update Respond incident {remote_args.remote_incident_id}')

            if remote_args.delta.get('title'):
                demisto.debug(
                    f'changed title for {remote_args.remote_incident_id}: {remote_args.delta["title"]}')
                rest_client.construct_and_send_update_title_mutation(internal_tenant_id,
                                                                     incident_id,
                                                                     remote_args.delta[
                                                                         'title'])

            if remote_args.delta.get('responddescription'):
                demisto.debug(
                    f'changed description for {remote_args.remote_incident_id}: {remote_args.delta["responddescription"]}')
                rest_client.construct_and_send_update_description_mutation(internal_tenant_id,
                                                                           incident_id,
                                                                           remote_args.delta[
                                                                               'responddescription'])

            if remote_args.delta.get('closeReason'):
                # todo do we want to map xsoar close reasons to respond incident outcomes
                # for now just set everything to inconclusive
                feedback_args = {
                    'tenant_id': tenant_id,
                    'incident_id': incident_id,
                    'incident_feedback': 'Inconclusive',
                    'incident_comments': remote_args.delta.get('closeNotes')
                }
                demisto.debug(
                    f'feedback args for {remote_args.remote_incident_id}: {feedback_args}')
                close_incident_command(rest_client, feedback_args)
            if remote_args.delta.get('owner'):
                # todo support unassign
                demisto.debug(
                    f'changed owner for {remote_args.remote_incident_id}: {remote_args.delta["owner"]}')
                user_email = demisto.findUser(username=remote_args.delta['owner']).get('email')
                assigned_user_args = {
                    'tenant_id': tenant_id,
                    'incident_id': incident_id,
                    'username': user_email
                }
                demisto.debug(f'assigned user args {assigned_user_args}')
                assign_user_command(rest_client, assigned_user_args)

    except Exception as e:
        demisto.debug(
            f"Error in Respond outgoing mirror for incident {remote_args.remote_incident_id} Error message: {str(e)}")

    return remote_args.remote_incident_id


def get_mapping_fields_command():
    respond_incident_type_scheme = SchemeTypeMapping(type_name=RESPOND_INCIDENT_TYPE_NAME)
    for field in RESPOND_INCIDENT_FIELDS:
        respond_incident_type_scheme.add_field(name=field,
                                               description=RESPOND_INCIDENT_FIELDS[field].get(
                                                   'description'))

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(respond_incident_type_scheme)
    return mapping_response


def fetch_incidents(rest_client, last_run=dict()):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        rest_client (Client): Demisto BaseClient
        last_run (dict): Information about the last successful execution of fetch incidents
        If last_run is None then fetch all open incidents

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    if last_run is None:
        last_run = dict()

    # get tenant ids
    tenant_mappings = rest_client.get_tenant_mappings()

    incidents = []
    next_run = last_run

    # get incidents for each tenant
    for internal_tenant_id, external_tenant_id in tenant_mappings.items():
        # Get the last fetch time for tenant, if exists, which will be used as the 'search from here onward' time
        latest_time = None
        from_time = ''
        if last_run.get(external_tenant_id) is not None:
            latest_time = last_run.get(external_tenant_id).get('time')
            if latest_time is not None:
                # latest_time+1 (ms) to prevent duplicates
                from_time = datetime.utcfromtimestamp((int(latest_time) + 1) / 1000).strftime(
                    '%Y-%m-%d %H:%M:%S.%f')

        # convert to utc datetime for incidents filter
        raw_incidents = fetch_incidents_for_tenant(rest_client, internal_tenant_id,
                                                   external_tenant_id, from_time)

        raw_incidents.sort(key=lambda x: x.get('dateCreated'))
        for raw_incident in raw_incidents:
            try:
                formatted_incident = format_raw_incident(raw_incident, external_tenant_id,
                                                         internal_tenant_id)
                new_incident = {
                    'name': external_tenant_id + ': ' + raw_incident['id'],
                    'occurred': formatted_incident.get('timeGenerated'),
                    'rawJSON': json.dumps(formatted_incident)
                }
                incidents.append(new_incident)
                if latest_time is None or raw_incident['dateCreated'] > latest_time:
                    latest_time = raw_incident['dateCreated']
            except Exception as err:
                demisto.error(
                    'Exception thrown collecting specific incident for tenant: ' + external_tenant_id + str(
                        err) + '\n incident: ' + str(raw_incident))
                break
        # store
        if external_tenant_id in next_run:
            next_run[external_tenant_id]['time'] = latest_time
        else:
            next_run[external_tenant_id] = {'time': latest_time}
    return next_run, incidents


def main():
    """
    Executes an integration command
    """
    LOG('Command being called is ' + demisto.command())

    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    rest_client = RestClient(
        base_url=BASE_URL,
        verify=VERIFY_CERT,
        proxy=True
    )

    try:
        if demisto.command() == 'test-module':
            test_module(rest_client)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            # get all tenant ids
            next_run, incidents = fetch_incidents(rest_client, demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'respond-close-incident':
            return_outputs(close_incident_command(rest_client, demisto.args()))

        elif demisto.command() == 'respond-assign-user':
            return_outputs(assign_user_command(rest_client, demisto.args()))

        elif demisto.command() == 'respond-remove-user':
            return_outputs(remove_user_command(rest_client, demisto.args()))

        elif demisto.command() == 'respond-get-incident':
            return_outputs(get_incident_command(rest_client, demisto.args()))

        elif demisto.command() == 'update-remote-system':
            demisto.debug('in update-remote-system')
            return_results(update_remote_system_command(rest_client, demisto.args()))

        elif demisto.command() == 'get-mapping-fields':
            demisto.debug('get-mapping-fields called')
            return_results(get_mapping_fields_command())

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(rest_client, demisto.args()))

        elif demisto.command() == 'respond-get-escalations':
            return_results(get_escalations_command(rest_client, demisto.args()))

    except Exception as err:
        demisto.debug(f'Error caught at top level: {str(err)}')
        if demisto.command() == 'fetch-incidents':
            LOG(str(err))
            raise
        raise
        # return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
