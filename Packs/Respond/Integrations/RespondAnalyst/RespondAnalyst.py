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
USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')
VERIFY_CERT = not demisto.params().get('insecure', False)


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
    def get_tenant_mappings(self):
        # need to send one request to big-monolith service to get the external tenant id
        tenant_mappings = self._http_request(
            method='GET',
            url_suffix='/session/tenantIdMapping',
            retries=3
        )
        if len(tenant_mappings) == 0:
            demisto.error('no tenants found for user')
            raise Exception('no tenants found for user')
        return tenant_mappings

    def get_current_user(self):
        return self._http_request(
            method='GET',
            url_suffix='/session/activeUser',
            retries=3
        )

    def get_all_users(self):
        return self._http_request(
            method='GET',
            url_suffix='/api/v0/users',
            retries=3
        )

    # sadly the linting process will fail if the format below is not used. Hard to read
    def construct_and_send_full_incidents_query(self, tenant_id, incident_ids):
        query = {"query": "query { fullIncidents(ids: " + str(incident_ids) + ") { "
                                                                              "id "
                                                                              "dateCreated "
                                                                              "eventCount "
                                                                              "firstEventTime "
                                                                              "lastEventTime "
                                                                              "title "
                                                                              "attackStage "
                                                                              "assetClass "
                                                                              "probabilityBucket "
                                                                              "status "
                                                                              "priority "
                                                                              "internalSystems{ "
                                                                              "hostname "
                                                                              "} "
                                                                              "internalSystemsCount "
                                                                              "feedback { "
                                                                              "newStatus "
                                                                              "status "
                                                                              "newSelectedOptions{ "
                                                                              "id "
                                                                              "key "
                                                                              "value "
                                                                              "} "
                                                                              "timeGiven "
                                                                              "optionalText "
                                                                              "userId "
                                                                              "closedAt "
                                                                              "closedBy "
                                                                              "} "
                                                                              "userIds "
                                                                              "tags { "
                                                                              "label "
                                                                              "} "
                                                                              "} }"
                 }
        res = self._http_request(
            method='POST',
            url_suffix='/graphql?tenantId=' + tenant_id,
            retries=3,
            json_data=query
        )
        return res.get('data').get('fullIncidents')

    def construct_and_send_get_incident_ids_query(self, tenant_id, from_time_str):
        if from_time_str == '':
            query = {"query": "query { incidents( statusFilters: [ { incidentStatus: Open } { "
                              "incidentStatus: Closed } ] ){ id } }"}
        else:
            query = {"query": "query { incidents( createdAfter:\"" + from_time_str + "\" ){ id } }"}
        res = self._http_request(
            method='POST',
            url_suffix='/graphql?tenantId=' + tenant_id,
            retries=3,
            json_data=query
        )
        return res.get('data').get('incidents')

    def construct_and_send_close_incident_mutation(self, tenant_id, feedback_status,
                                                   feedback_selected_options,
                                                   feedback_optional_text, incident_id, user):
        if feedback_selected_options is None:
            feedback_selected_options = []

        # sadly the linting process will fail if the format below is not used. Hard to read
        data = {"query": "mutation closeIncident( "
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
        res = self._http_request(
            method='POST',
            url_suffix='/graphql?tenantId=' + tenant_id,
            retries=3,
            json_data=data
        )
        return res.get('data').get('closeIncident')

    def construct_and_send_add_user_to_incident_mutation(self, tenant_id, user_id, incident_id):
        data = {"query": "mutation addUserToIncident($id: ID! $userId: String!) { "
                         "addUserToIncident(incidentId: $id userId: $userId) { "
                         "id "
                         "userIds "
                         "} "
                         "}",
                "variables": {"id": incident_id, "userId": user_id}
                }

        res = self._http_request(
            method='POST',
            url_suffix='/graphql?tenantId=' + tenant_id,
            retries=3,
            json_data=data
        )
        return res.get('data').get('addUserToIncident')

    def construct_and_send_remove_user_from_incident_mutation(self, tenant_id, user_id,
                                                              incident_id):
        data = {"query": "mutation removeUserFromIncident($id: ID! $userId: String!) { "
                         "removeUserFromIncident(incidentId: $id userId: $userId) { "
                         "id "
                         "userIds "
                         "} "
                         "}",
                "variables": {"id": incident_id, "userId": user_id}
                }

        res = self._http_request(
            method='POST',
            url_suffix='/graphql?tenantId=' + tenant_id,
            retries=3,
            json_data=data
        )
        return res.get('data').get('removeUserFromIncident')


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    response = client.construct_and_send_get_incident_ids_query(
        convert_datetime_to_epoch_millis(datetime.now() - timedelta(hours=1)))
    id_list = list(map(extract_id, response))
    client.construct_and_send_full_incidents_query(id_list)
    return 'ok'


def fetch_incidents_for_tenant(rest_client, respond_tenant_id, external_tenant_id, from_time):
    # first time fetch is handled in query
    try:
        response = rest_client.construct_and_send_get_incident_ids_query(respond_tenant_id,
                                                                         from_time)
        id_list = list(map(extract_id, response))
        raw_incidents = rest_client.construct_and_send_full_incidents_query(respond_tenant_id,
                                                                            id_list)
    except Exception as err:
        # log error but continue getting incidents for other tenants
        demisto.error(
            'Exception thrown retrieving incidents for tenant ' + external_tenant_id + ': \n ' + str(
                err))
        return []
    return raw_incidents


def format_raw_incident(raw_incident, external_tenant_id, respond_tenant_id):
    # convert graphql response to standardized JSON output for an incident
    # only format feedback if exists
    if raw_incident.get('feedback') is not None:
        standardized_feedback = {
            'timeUpdated': raw_incident.get('feedback').get('timeGiven'),
            'userId': raw_incident.get('feedback').get('userId'),
            'outcome': raw_incident.get('feedback').get('newStatus'),
            'comments': raw_incident.get('feedback').get('optionalText'),
        }
    else:
        standardized_feedback = {}

    standardized_incident = {
        'incidentId': raw_incident.get('id'),
        'timeGenerated': timestamp_to_datestring(raw_incident.get('dateCreated'),
                                                 TIME_FORMAT + 'Z'),
        'eventCount': raw_incident.get('eventCount'),
        'firstEventTime': timestamp_to_datestring(raw_incident.get('firstEventTime'),
                                                  TIME_FORMAT + 'Z'),
        'lastEventTime': timestamp_to_datestring(raw_incident.get('lastEventTime'),
                                                 TIME_FORMAT + 'Z'),
        'URL': BASE_URL + '/secure/incidents/' + raw_incident.get(
            'id') + '?tenantId=' + respond_tenant_id,
        'closeURL': BASE_URL + '/secure/incidents/feedback/' + raw_incident.get(
            'id') + '?tenantId=' + respond_tenant_id,
        'title': raw_incident.get('title'),
        'status': raw_incident.get('status'),
        'severity': raw_incident.get('priority'),
        'probability': raw_incident.get('probabilityBucket'),
        'attackStage': raw_incident.get('attackStage'),
        'attackTactic': raw_incident.get('attackTactic'),
        'assetCriticality': raw_incident.get('assetClass'),
        'internalSystemsCount': raw_incident.get('internalSystemsCount'),
        'internalSystems': raw_incident.get('internalSystems'),
        'escalationReasons': raw_incident.get('tags'),  # todo only get the labels with a mapping
        'assignedUsers': raw_incident.get('userIds'),
        'feedback': standardized_feedback,
        'tenantIdRespond': respond_tenant_id,
        'tenantId': external_tenant_id,
        'respondRemoteId': f'{external_tenant_id}:{raw_incident.get("id")}',
        'dbotMirrorDirection': 'In',
        'dbotMirrorInstance': demisto.integrationInstance()
    }
    # add tenant ids and incident URLs to incidents (cannot get them with gql query)
    raw_incident['tenantId'] = external_tenant_id
    raw_incident['incidentURL'] = BASE_URL + '/secure/incidents/' + raw_incident[
        'id'] + '?tenantId=' + respond_tenant_id
    raw_incident['incidentCloseURL'] = BASE_URL + '/secure/incidents/feedback/' + raw_incident[
        'id'] + '?tenantId=' + respond_tenant_id

    occurred = standardized_incident.get('timeGenerated')
    new_incident = {
        'name': external_tenant_id + ': ' + raw_incident['id'],  # or maybe this should be title?
        'occurred': occurred,
        'rawJSON': json.dumps(standardized_incident)
    }
    return new_incident


def get_respond_tenant_from_mapping_with_external(tenant_mappings, external_tenant_id):
    """
    finds the respond tenant id that matches the external tenant id provided, if exists and accessible
    :param tenant_mappings: dictionary where (k,v) -> (respond_tenant_id,external_tenant_id)
    :param external_tenant_id:
    :return:
    """
    for curr_respond_tid, curr_external_tid in tenant_mappings.items():
        if external_tenant_id == curr_external_tid:
            return curr_respond_tid
    demisto.error(
        'no respond tenant matches external tenant: ' + external_tenant_id + 'or user does not have '
                                                                             'permission to access tenant')
    raise Exception(
        'no respond tenant matches external tenant: ' + external_tenant_id + 'or user does not have '
                                                                             'permission to access tenant')


def get_tenant_map_if_single_tenant(user_tenant_mappings):
    """
    returns respond tenant id and external tenant id if the user is single tenant, otherwise raises exception
    :param user_tenant_mappings: list of user mappings. expect length 1
    :return: respond_tenant_id, external_tenant_id
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


def remove_user_command(rest_client, args):
    external_tenant_id = args.get('tenant_id')
    incident_id = int(args['incident_id'])
    user_to_remove = args['username']
    user_tenant_mappings = rest_client.get_tenant_mappings()

    if external_tenant_id is None:
        respond_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        respond_tenant_id = get_respond_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                          external_tenant_id)

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

    try:
        res = rest_client.construct_and_send_remove_user_from_incident_mutation(respond_tenant_id,
                                                                                user_to_remove,
                                                                                incident_id)
        return 'user with email: ' + user_to_remove + ' removed from incident with id ' + res[
            'id'] + ' on tenant ' + str(external_tenant_id)
    except Exception as err:
        demisto.error('error removing user from incident: ' + str(err))
        raise Exception('error removing user from incident: ' + str(err))


def assign_user_command(rest_client, args):
    incident_id = int(args['incident_id'])
    user_to_add = args['username']
    external_tenant_id = args.get('tenant_id')
    user_tenant_mappings = rest_client.get_tenant_mappings()

    if external_tenant_id is None:
        respond_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        respond_tenant_id = get_respond_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                          external_tenant_id)

    try:
        users = rest_client.get_all_users()
    except Exception as err:
        demisto.error('error adding user to incident: ' + str(err))
        raise Exception('error adding user to incident: ' + str(err))

    valid_user = False
    for user in users:
        if user.get('email') == user_to_add:
            valid_user = True
            break

    if valid_user is False:
        demisto.error('no user found with email ' + user_to_add)
        raise Exception('no user found with email ' + user_to_add)

    try:
        res = rest_client.construct_and_send_add_user_to_incident_mutation(respond_tenant_id,
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
    user_tenant_mappings = rest_client.get_tenant_mappings()
    incident_id = int(args['incident_id'])
    external_tenant_id = args.get('tenant_id')

    if external_tenant_id is None:
        respond_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        respond_tenant_id = get_respond_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                          external_tenant_id)

    feedback_status = args['incident_feedback']
    feedback_selected_options = args.get('feedback_selected_options')
    feedback_optional_text = args.get('incident_comments')
    try:
        incident = \
            rest_client.construct_and_send_full_incidents_query(respond_tenant_id, [incident_id])[0]
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
        res = rest_client.construct_and_send_close_incident_mutation(respond_tenant_id,
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


def get_incident_command(rest_client, args, format=True):
    external_tenant_id = args.get('tenant_id')
    user_tenant_mappings = rest_client.get_tenant_mappings()

    if external_tenant_id is None:
        respond_tenant_id, external_tenant_id = get_tenant_map_if_single_tenant(
            user_tenant_mappings)
    else:
        respond_tenant_id = get_respond_tenant_from_mapping_with_external(user_tenant_mappings,
                                                                          external_tenant_id)

    incident_id = int(args['incident_id'])

    raw_incident = \
        rest_client.construct_and_send_full_incidents_query(respond_tenant_id, [incident_id])[0]

    if format:
        return format_raw_incident(raw_incident, external_tenant_id, respond_tenant_id)
    else:
        return raw_incident


def get_remote_data_command(rest_client, args):
    args['tenant_id'] = args.get('id').split(':')[0]
    args['incident_id'] = args.get('id').split(':')[1]

    incident_data = {}
    entries = []
    try:
        updated_incident = get_incident_command(rest_client, args, False)
        updated_incident['id'] = updated_incident.get('respondRemoteId')
        demisto.debug(f"Respond incident {args.get('id')}\n"
                      f"update time:   {arg_to_timestamp(args.get('last_update'), 'last_update')}")

        return [updated_incident] + entries

    except Exception as e:
        demisto.debug(
            f'Error in Respond incoming mirror for incident {args["id"]} \n'
            f'Error message: {str(e)}')


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
    for respond_tenant_id, external_tenant_id in tenant_mappings.items():
        # Get the last fetch time for tenant, if exists, which will be used as the 'search from here onward' time
        if last_run.get(external_tenant_id):
            latest_time = last_run.get(external_tenant_id).get('time')
            # latest_time+1 (ms) to prevent duplicates
            from_time = datetime.utcfromtimestamp((int(latest_time) + 1) / 1000).strftime(
                '%Y-%m-%d %H:%M:%S.%f')
        else:
            latest_time = None
            from_time = ''
        # convert to utc datetime for incidents filter
        raw_incidents = fetch_incidents_for_tenant(rest_client, respond_tenant_id,
                                                   external_tenant_id, from_time)

        raw_incidents.sort(key=lambda x: x.get('dateCreated'))
        for raw_incident in raw_incidents:
            try:
                incidents.append(
                    format_raw_incident(raw_incident, external_tenant_id, respond_tenant_id))
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
        auth=(USERNAME, PASSWORD),
        proxy=True
    )

    try:
        if demisto.command() == 'test-module':
            # todo
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            demisto.debug('fetch incidents called')
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

        elif demisto.command() == 'get-remote-data':
            demisto.debug('remote data called')
            return_results(get_remote_data_command(rest_client, demisto.args()))

    except Exception as err:
        if demisto.command() == 'fetch-incidents':
            LOG(str(err))
            raise
        demisto.error("Uncaught exception: " + str(err))
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
