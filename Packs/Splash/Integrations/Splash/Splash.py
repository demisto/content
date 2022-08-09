import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta
import dateparser
import requests


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, client_id, client_secret, username, password, access_token,
                 refresh_token, timeout, grant_type, scope):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)
        self._client_id = client_id
        self._client_secret = client_secret
        self._username = username
        self._password = password
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._timeout = timeout
        self._grant_type = grant_type
        self._scope = scope

        # If there is no access token, request one
        if not self._access_token:
            timeout = datetime.utcnow().isoformat()
            token_request = self.access_token_request()
            self._access_token = token_request.get('access_token')
            self._refresh_token = token_request.get('refresh_token')
            demisto.setIntegrationContext({
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
                "timeout": timeout
            })

        # If the access token has expired (older than 7 days), request a new one
        if datetime.now() >= dateparser.parse(self._timeout) + timedelta(days=6, hours=23):
            timeout = datetime.utcnow().isoformat()
            new_refresh_token: Dict = self.refresh_token_request()
            self._access_token = new_refresh_token.get('access_token')
            self._refresh_token = new_refresh_token.get('refresh_token')
            self.timeout = timeout
            demisto.setIntegrationContext({
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
                "timeout": self._timeout
            })

        self._headers.update({
            "Authorization": f"Bearer {self._access_token}"
        })

    def access_token_request(self):
        params = assign_params(client_id=self._client_id, client_secret=self._client_secret,
                               grant_type=self._grant_type, scope=self._scope,
                               username=self._username, password=self._password)
        headers = self._headers

        response = self._http_request('GET', 'oauth/v2/token', params=params, headers=headers)

        return response

    def refresh_token_request(self) -> Dict:
        params = assign_params(client_id=self._client_id, client_secret=self._client_secret,
                               grant_type=self._grant_type, scope=self._scope,
                               refresh_token=self._refresh_token)
        headers = self._headers

        response = self._http_request('GET', 'oauth/v2/token', params=params, headers=headers)

        return response

    def all_events_request(self, params):
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if params:
            response = self._http_request('GET', 'events', params=params, headers=headers)
        else:
            response = self._http_request('GET', 'events', headers=headers)

        return response

    def individual_event_request(self, event_id):
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request('GET', f'events/{event_id}', headers=headers)

        return response

    def event_details_request(self, event_id):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'events/{event_id}/settings', headers=headers)

        return response

    def update_an_event_request(self, event_id, update_data):

        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PATCH', f'events/{event_id}/settings', json_data=update_data, headers=headers)

        return response

    def delete_event_request(self, ids):
        data = {"ids": ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('DELETE', 'events', json_data=data, headers=headers)

        return response

    def workflow_status_update_request(self, workflow_id, status):
        headers = self._headers

        response = self._http_request('PUT', f'workflows/{workflow_id}/status/{status}', headers=headers)

        return response

    def single_group_contact_request(self, group_contact_id):
        headers = self._headers
        headers['Content-Type'] = 'text/plain'

        response = self._http_request('GET', f'groupcontact/{group_contact_id}', headers=headers)

        return response

    def group_contacts_for_one_event_request(self, event_id, limit, page, sort, status, text_filter, event_rsvp_conditions,
                                             custom_question_ids, statistics, additional_columns):
        params = assign_params(event_id=event_id, limit=limit, page=page, sort=sort, status=status, text_filter=text_filter,
                               event_rsvp_conditions=event_rsvp_conditions, custom_question_ids=custom_question_ids,
                               statistics=statistics, additional_columns=additional_columns)
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request('GET', 'groupcontacts', params=params, headers=headers)

        return response

    def all_group_contacts_request(self, params):
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request('GET', 'groupcontacts', params=params, headers=headers)

        return response

    def create_single_group_contact_request(self, contact_data):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'groupcontact', headers=headers, json_data=contact_data)

        return response

    def update_group_contact_request(self, group_contact_id, update_data):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'groupcontact/{group_contact_id}', headers=headers, json_data=update_data)

        return response

    def batch_cancel_rsvps_request(self, group_contact_id):
        headers = self._headers

        response = self._http_request('DELETE', f'groupcontact/{group_contact_id}', headers=headers)

        return response

    def get_list_of_contacts_request(self, limit, page):
        params = assign_params(limit=limit, page=page)
        headers = self._headers

        response = self._http_request('GET', 'contacts', params=params, headers=headers)

        return response

    def get_single_contact_by_id_request(self, contact_id):
        headers = self._headers

        response = self._http_request('GET', f'contacts/{contact_id}', headers=headers)

        return response

    def get_contact_history_request(self, contact_id):
        headers = self._headers

        response = self._http_request('GET', f'contact/{contact_id}/history', headers=headers)

        return response

    def delete_a_contact_request(self, contact_id):
        headers = self._headers

        response = self._http_request('DELETE', f'contacts/{contact_id}', headers=headers)

        return response

    def anonymize_contact_request(self, contact_id):
        data = {
            "delete": False
        }
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'contacts/{contact_id}/anonymize', headers=headers, json_data=data)

        return response

    def retrieve_unsubscribe_request(self, unsub_tag, unsub_type, event_id):
        params = assign_params(event_id=event_id)
        headers = self._headers

        response = self._http_request(
            'GET', f'public/unsubscribe/{unsub_tag}/{unsub_type}', params=params, headers=headers)

        return response

    def create_an_unsubscribe_request(self, unsub_tag, unsub_type, event_id):
        params = assign_params(event_id=event_id)
        headers = self._headers

        response = self._http_request(
            'POST', f'public/unsubscribe/{unsub_tag}/{unsub_type}', params=params, headers=headers)

        return response

    def resubscribe_request(self, unsub_tag, unsub_type, event_id):
        params = assign_params(event_id=event_id)
        headers = self._headers

        response = self._http_request(
            'DELETE', f'public/unsubscribe/{unsub_tag}/{unsub_type}', params=params, headers=headers)

        return response

    def create_event_request(self, event_data):
        headers = self._headers
        headers['AUTHORIZATION'] = 'SplashCRM {{my_crm_api_key}}'
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/v2/crm/events', headers=headers, json_data=event_data)

        return response


def all_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    params = assign_params(**args)
    response = client.all_events_request(params)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Event',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('All Events:', outputs),
        raw_response=response
    )

    return command_results


def individual_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')

    response = client.individual_event_request(event_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Event',
        outputs_key_field='',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Event ID {event_id}:', outputs),
        raw_response=response
    )

    return command_results


def event_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')

    response = client.event_details_request(event_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Event',
        outputs_key_field='',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Event Details for Event ID {event_id}', outputs),
        raw_response=response
    )

    return command_results


def update_an_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    event_id = args.get('event_id')
    try:
        update_data = json.loads(str(args.get('update_data')))
    except Exception as err:
        raise Exception(f"Invalid JSON provided for 'update_data': {err}")

    response = client.update_an_event_request(event_id, update_data)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Event',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown(f"Updated Event ID {event_id}:", outputs),
        raw_response=response
    )

    return command_results


def delete_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ids = args.get('ids')
    id_list = argToList(ids)

    client.delete_event_request(id_list)
    command_results = CommandResults(
        readable_output=f"Event IDs {ids} deleted successfully."
    )

    return command_results


def single_group_contact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_contact_id = args.get('group_contact_id')

    response = client.single_group_contact_request(group_contact_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.GroupContact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Group Contact {group_contact_id}:', outputs),
        raw_response=response
    )

    return command_results


def group_contacts_for_one_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    event_id = arg_to_number(args.get('event_id'))
    limit = args.get('limit')
    page = args.get('page')
    sort = args.get('sort')
    status = args.get('status')
    text_filter = args.get('text_filter')
    event_rsvp_conditions = args.get('event_rsvp_conditions')
    custom_question_ids = args.get('custom_question_ids')
    statistics = args.get('statistics')
    additional_columns = args.get('additional_columns')

    response = client.group_contacts_for_one_event_request(event_id, limit, page, sort, status, text_filter,
                                                           event_rsvp_conditions, custom_question_ids,
                                                           statistics, additional_columns)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Event',
        outputs_key_field='id',
        outputs={
            "id": event_id,
            "GroupContacts": outputs
        },
        readable_output=tableToMarkdown(f'Contacts for Event ID {event_id}:', outputs),
        raw_response=response
    )

    return command_results


def all_group_contacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    params = assign_params(**args)

    response = client.all_group_contacts_request(params)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.GroupContact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown("Group Contacts:", outputs),
        raw_response=response
    )

    return command_results


def create_single_group_contact_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    event_id = arg_to_number(args.get('event_id'))
    try:
        contact_data = json.loads(str(args.get('contact_data')))
        contact_data['event_id'] = event_id
    except Exception as err:
        raise Exception(f"Invalid JSON provided for 'contact_data': {err}")
    response = client.create_single_group_contact_request(contact_data)
    outputs = response.get('data')

    command_results = CommandResults(
        outputs_prefix='Splash.GroupContact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Created new Group Contact:', outputs),
        raw_response=response
    )

    return command_results


def update_group_contact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_contact_id = arg_to_number(args.get('group_contact_id'))
    try:
        update_data = json.loads(str(args.get('update_data')))
    except Exception as err:
        raise Exception(f"Invalid JSON provided for 'update_data': {err}")

    response = client.update_group_contact_request(group_contact_id, update_data)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.GroupContact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Updated Group Contact {group_contact_id}:', outputs),
        raw_response=response
    )

    return command_results


def batch_cancel_rsvps_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_contact_id = args.get('group_contact_id')

    response = client.batch_cancel_rsvps_request(group_contact_id)
    command_results = CommandResults(
        readable_output=f"Successfully canclled RSVPs for Group Contact ID {group_contact_id}",
        raw_response=response
    )

    return command_results


def get_list_of_contacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = args.get('limit')
    page = args.get('page')

    response = client.get_list_of_contacts_request(limit, page)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Contact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Contacts:', outputs),
        raw_response=response
    )

    return command_results


def get_single_contact_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    contact_id = args.get('contact_id')

    response = client.get_single_contact_by_id_request(contact_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Contact',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Contact ID {contact_id}:', outputs),
        raw_response=response
    )

    return command_results


def get_contact_history_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    contact_id = arg_to_number(args.get('contact_id'))

    response = client.get_contact_history_request(contact_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.Contact',
        outputs_key_field='id',
        outputs={
            "id": contact_id,
            "History": outputs
        },
        readable_output=tableToMarkdown(f"Contact History for ID {contact_id}:", outputs),
        raw_response=response
    )

    return command_results


def delete_a_contact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    contact_id = args.get('contact_id')

    response = client.delete_a_contact_request(contact_id)
    command_results = CommandResults(
        readable_output=f"Successfully deleted contact ID {contact_id}",
        raw_response=response
    )

    return command_results


def anonymize_contact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    contact_id = args.get('contact_id')

    response = client.anonymize_contact_request(contact_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs=outputs,
        readable_output=f"Contact ID {contact_id} was successfully anonymized.",
        raw_response=response
    )

    return command_results


def retrieve_unsubscribe_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    unsub_tag = args.get('unsub_tag')
    unsub_type = args.get('unsub_type')
    event_id = args.get('event_id')

    response = client.retrieve_unsubscribe_request(unsub_tag, unsub_type, event_id)
    command_results = CommandResults(
        outputs_prefix='Splash.RetrieveUnsubscribe',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_an_unsubscribe_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    unsub_tag = args.get('unsub_tag')
    unsub_type = args.get('unsub_type')
    event_id = args.get('event_id')

    response = client.create_an_unsubscribe_request(unsub_tag, unsub_type, event_id)
    outputs = response.get('data')
    command_results = CommandResults(
        outputs_prefix='Splash.CreateAnUnsubscribe',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def resubscribe_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    unsub_tag = args.get('unsub_tag')
    unsub_type = args.get('unsub_type')
    event_id = args.get('event_id')

    response = client.resubscribe_request(unsub_tag, unsub_type, event_id)
    command_results = CommandResults(
        outputs_prefix='Splash.Resubscribe',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    event_data = assign_params(keys_to_ignore=[], **args)

    response = client.create_event_request(event_data)
    command_results = CommandResults(
        outputs_prefix='Splash.CreateEvent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    integration_context = demisto.getIntegrationContext()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    credentials: Dict = params.get('credentials', {})
    username = credentials.get('identifier')
    password = credentials.get('password')
    access_token = integration_context.get('acccess_token')
    refresh_token = integration_context.get('refresh_token')
    timeout = integration_context.get('timeout')
    scope = "user"
    grant_type = "password"

    headers: Dict = {}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(url, verify_certificate, proxy, headers, client_id, client_secret, username, password,
                                access_token, refresh_token, timeout, grant_type, scope)

        commands = {
            'splash-list-events': all_events_command,
            'splash-get-event': individual_event_command,
            'splash-event-details': event_details_command,
            'splash-update-event': update_an_event_command,
            'splash-delete-event': delete_event_command,
            'splash-get-group-contact': single_group_contact_command,
            'splash-get-event-group-contacts': group_contacts_for_one_event_command,
            'splash-list-group-contacts': all_group_contacts_command,
            'splash-create-group-contact': create_single_group_contact_command,
            'splash-update-group-contact': update_group_contact_command,
            'splash-batch-cancel-rsvps': batch_cancel_rsvps_command,
            'splash-list-contacts': get_list_of_contacts_command,
            'splash-get-contact': get_single_contact_by_id_command,
            'splash-get-contact-history': get_contact_history_command,
            'splash-delete-contact': delete_a_contact_command,
            'splash-anonymize-contact': anonymize_contact_command
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
