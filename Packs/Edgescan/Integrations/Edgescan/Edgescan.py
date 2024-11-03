import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time
from typing import cast

from dateutil import parser
import urllib3

MAX_INCIDENTS_TO_FETCH = 250


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def host_get_hosts_request(self):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/hosts.json', headers=headers)
        return response

    def host_get_request(self, id):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/hosts/' + id + '.json', headers=headers)
        return response

    def host_get_export_request(self, export_format):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/hosts/export.' + export_format, headers=headers, resp_type="Raw")
        return response

    def host_get_query_request(self, request):
        data = {"c": request, "l": 50}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/hosts/query.json', json_data=data, headers=headers)
        return response

    def host_update_request(self, label, id):
        data = {"host": {"label": label}}
        headers = self._headers
        response = self._http_request('PUT', 'api/v1/hosts/' + id + '.json', json_data=data, headers=headers)

        return response

    def asset_get_assets_request(self, detail_level):
        params = assign_params(detail_level=detail_level)
        headers = self._headers
        response = self._http_request('GET', 'api/v1/assets.json', params=params, headers=headers)

        return response

    def asset_get_request(self, id):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/assets/' + id + '.json', headers=headers)
        return response

    def asset_get_query_request(self, request):
        data = {"c": request, "l": 50}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/assets/query.json', json_data=data, headers=headers)
        return response

    def asset_create_request(self, id_, name, priority, type_, authenticatied, tags, location_specifiers):
        data = {"asset": {"authenticatied": authenticatied, "id": id_, "location_specifiers": location_specifiers,
                          "name": name, "priority": priority, "tags": tags, "type": type_}}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/assets.json', json_data=data, headers=headers)
        return response

    def asset_update_request(self, id, name, priority, type_, authenticatied, tags, location_specifiers):
        data = {"asset": {"authenticatied": authenticatied, "location_specifiers": location_specifiers,
                          "name": name, "priority": priority, "tags": tags, "type": type_}}
        headers = self._headers
        response = self._http_request('PUT', 'api/v1/assets/' + id + '.json', json_data=data, headers=headers)
        return response

    def asset_delete_request(self, id, name, priority, type_, authenticatied, tags, location_specifiers):
        data = {"authenticatied": authenticatied, "location_specifiers": location_specifiers,
                "name": name, "priority": priority, "tags": tags, "type": type_}
        headers = self._headers
        response = self._http_request('DELETE', 'api/v1/assets/' + id + '.json', json_data=data, headers=headers)
        return response

    def user_get_users_request(self):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/users.json', headers=headers)
        return response

    def user_get_request(self, id):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/users/' + id + '.json', headers=headers)
        return response

    def user_get_query_request(self, request):
        data = {"c": request, "l": 50}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users/query.json', json_data=data, headers=headers)
        return response

    def user_create_request(self, username, email, first_name, last_name, phone_number, mfa_enabled, mfa_method, is_super):
        data = {"user": {"email": email, "first_name": first_name, "last_name": last_name,
                         "mfa_enabled": mfa_enabled, "mfa_method": mfa_method,
                         "phone_number": phone_number, "username": username, "is_super": is_super}}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users.json', json_data=data, headers=headers)
        return response

    def user_delete_request(self, id):
        headers = self._headers
        response = self._http_request('DELETE', 'api/v1/users/' + id + '.json', headers=headers)
        return response

    def user_reset_password_request(self, id):
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users/' + id + '/reset.json', headers=headers)
        return response

    def user_reset_email_request(self, id):
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users/' + id + '/reset_email.json', headers=headers)
        return response

    def user_lock_account_request(self, id):
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users/' + id + '/lock.json', headers=headers)
        return response

    def user_unlock_account_request(self, id):
        headers = self._headers
        response = self._http_request('POST', 'api/v1/users/' + id + '/unlock.json', headers=headers)
        return response

    def user_get_permissions_request(self, id):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/users/' + id + '/permissions.json', headers=headers)
        return response

    def vulnerabilities_get_request(self):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/vulnerabilities.json', headers=headers)
        return response

    def vulnerabilities_get_export_request(self, export_format):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/vulnerabilities/export.' + export_format, headers=headers,
                                      resp_type="Raw")
        return response

    def vulnerabilities_get_details_request(self, id):
        headers = self._headers
        response = self._http_request('GET', 'api/v1/vulnerabilities/' + id + '.json', headers=headers)
        return response

    def vulnerabilities_get_query_request(self, request, limit, o):
        data = {"c": request,
                "l": limit, "o": o, "s": {"date_opened": "asc"}}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/vulnerabilities/query.json', json_data=data, headers=headers)
        return response

    def vulnerabilities_retest_request(self, id):
        headers = self._headers
        response = self._http_request('POST', 'api/v1/vulnerabilities/' + id + '/retest.json', headers=headers)
        return response

    def vulnerabilities_risk_accept_request(self, id, value):
        data = {"value": value}
        headers = self._headers
        response = self._http_request('POST', 'api/v1/vulnerabilities/' + id + '/risk_accept.json',
                                      json_data=data, headers=headers)
        return response

    def vulnerabilities_add_annotation_request(self, id, text):
        annotation = {
            "text": text
        }
        data = {
            "annotation": annotation
        }
        headers = self._headers
        response = self._http_request('POST', 'api/v1/vulnerabilities/' + id + '/annotations.json',
                                      json_data=data, headers=headers)
        return response


def host_get_hosts_command(client, args):
    response = client.host_get_hosts_request()['hosts']
    readable_output = tableToMarkdown('Hosts', response, ['os_name', 'id', 'location', 'status'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.HostGetHosts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], cvss_score: Optional[float],
                    risk_more_than: Optional[str], cvss_score_greater_than: Optional[float]
                    ) -> tuple[Dict[str, int], List[dict]]:

    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch', None)

    # Get the offset
    offset = last_run.get('offset', 0)

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    request = {
        "risk_more_than": risk_more_than,
        "cvss_score_greater_than": cvss_score_greater_than,
        "cvss_score": cvss_score,
        "date_opened_after": str(datetime.fromtimestamp(last_fetch).isoformat()) + ".000Z"  # type: ignore
    }

    if cvss_score == "" or cvss_score is None:
        del request['cvss_score']

    if cvss_score_greater_than == "" or cvss_score_greater_than is None:
        del request['cvss_score_greater_than']

    if risk_more_than == "" or risk_more_than is None:
        del request['risk_more_than']

    response = client.vulnerabilities_get_query_request(request=request, limit=max_results, o=offset)
    offset += max_results
    total = response['total']

    alerts = response['vulnerabilities']
    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        date_opened = alert.get('date_opened', '0')
        dt = parser.parse(date_opened)
        incident_created_time = int(time.mktime(dt.timetuple()))

        # If no name is present it will throw an exception
        incident_name = alert['name']

        incident = {
            'name': incident_name,
            'occurred': date_opened,
            'rawJSON': json.dumps(alert),
            'severity': alert.get('severity', 'Low'),
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time and offset >= total:
            latest_created_time = incident_created_time + 1

    if offset >= total:
        offset = 0

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {
        'last_fetch': latest_created_time,
        'offset': offset,
        'total': total
    }
    return next_run, incidents


def test_module(client: Client) -> str:
    try:
        client.host_get_hosts_request()['hosts']
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def host_get_command(client, args):
    id = args.get('id')
    response = client.host_get_request(id)['host']
    readable_output = tableToMarkdown('Host', response, ['os_name', 'id', 'location', 'status', 'services'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.HostGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def host_get_export_command(client, args):
    export_format = args.get("format", "json")
    response = client.host_get_export_request(export_format=export_format)
    filename = response.headers['Content-Disposition'].split("=")[1].replace('"', "")
    file = fileResult(filename=filename, data=response.content, file_type=EntryType.ENTRY_INFO_FILE)

    return file


def host_get_query_command(client, args):
    response = client.host_get_query_request(args)['hosts']
    readable_output = tableToMarkdown('Hosts query', response, ['os_name', 'id', 'location', 'status', 'services'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.HostGetQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def host_update_command(client, args):
    label = args.get('label')
    id = args.get('id')

    response = client.host_update_request(label=label, id=id)
    command_results = CommandResults(
        outputs_prefix='Edgescan.HostUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_get_assets_command(client, args):
    detail_level = args.get('detail_level')

    response = client.asset_get_assets_request(detail_level)['assets']
    readable_output = tableToMarkdown('Assets', response,
                                      ['id', 'name', 'asset_status', 'blocked_status', 'hostname'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.AssetGetAssets',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_get_command(client, args):
    id = args.get('id')
    response = client.asset_get_request(id=id)['asset']
    readable_output = tableToMarkdown('Asset', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.AssetGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_get_query_command(client, args):
    response = client.asset_get_query_request(args)['assets']
    readable_output = tableToMarkdown('Assets query', response,
                                      ['id', 'name', 'asset_status', 'blocked_status', 'hostname'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.AssetGetQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_create_command(client, args):
    id_ = args.get('id')
    name = args.get('name')
    priority = args.get('priority')
    type_ = args.get('type')
    authenticatied = args.get('authenticatied')
    tags = args.get('tags')
    location_secifiers = args.get('location_secifiers')

    response = client.asset_create_request(id_, name, priority, type_, authenticatied, tags, location_secifiers)['asset']
    command_results = CommandResults(
        outputs_prefix='Edgescan.AssetCreate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_update_command(client, args):
    id = args.get('id')
    name = args.get('name')
    priority = args.get('priority')
    type_ = args.get('type')
    authenticatied = args.get('authenticatied')
    tags = args.get('tags')
    location_specifiers = args.get('location_specifiers')

    response = client.asset_update_request(id, name, priority, type_, authenticatied, tags, location_specifiers)['asset']
    command_results = CommandResults(
        outputs_prefix='Edgescan.AssetUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asset_delete_command(client, args):
    name = args.get('name')
    id = args.get('id')
    priority = args.get('priority')
    type_ = args.get('type')
    authenticatied = args.get('authenticatied')
    tags = args.get('tags')
    location_specifiers = args.get('location_specifiers')

    response = client.asset_delete_request(id, name, priority, type_, authenticatied, tags, location_specifiers)['asset']
    command_results = CommandResults(
        outputs_prefix='Edgescan.AssetDelete',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_get_users_command(client, args):
    response = client.user_get_users_request()['users']
    readable_output = tableToMarkdown('Users', response,
                                      ['id', 'username', 'email', 'phone_number', "mfa_enabled"])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserGetUsers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_get_command(client, args):
    id = args.get('id')
    response = client.user_get_request(id=id)['user']
    readable_output = tableToMarkdown('User', response,
                                      ['id', 'username', 'email', 'phone_number', "mfa_enabled"])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_get_query_command(client, args):
    response = client.user_get_query_request(args)['users']
    readable_output = tableToMarkdown('User query', response,
                                      ['id', 'username', 'email', 'phone_number', "mfa_enabled"])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserGetQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_create_command(client, args):
    username = args.get('username')
    email = args.get('email')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    phone_number = args.get('phone_number')
    mfa_enabled = args.get('mfa_enabled')
    mfa_method = args.get('mfa_method')
    is_super = args.get('is_super')

    response = client.user_create_request(username, email, first_name, last_name,
                                          phone_number, mfa_enabled, mfa_method, is_super)['user']
    readable_output = tableToMarkdown('User created', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserCreate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_delete_command(client, args):
    id = args.get('id')
    response = client.user_delete_request(id=id)['user']
    readable_output = tableToMarkdown('User deleted', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserDelete',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_reset_password_command(client, args):
    id = args.get('id')
    response = client.user_reset_password_request(id=id)
    command_results = CommandResults(
        outputs_prefix='Edgescan.UserResetPassword',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_reset_email_command(client, args):
    id = args.get('id')
    response = client.user_reset_email_request(id=id)
    command_results = CommandResults(
        outputs_prefix='Edgescan.UserResetEmail',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_lock_account_command(client, args):
    id = args.get('id')
    response = client.user_lock_account_request(id=id)['user']
    readable_output = tableToMarkdown('User locked', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserLockAccount',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_unlock_account_command(client, args):
    id = args.get('id')
    response = client.user_unlock_account_request(id=id)['user']
    readable_output = tableToMarkdown('User unlocked', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserUnlockAccount',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def user_get_permissions_command(client, args):
    id = args.get('id')
    response = client.user_get_permissions_request(id=id)['permissions']
    readable_output = tableToMarkdown('User permissions', response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.UserGetPermissions',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_get_command(client, args):
    response = client.vulnerabilities_get_request()['vulnerabilities']
    readable_output = tableToMarkdown('Vulnerabilities', response, ['id', 'asset_id', 'name', 'severity', 'cvss_score'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.VulnerabilitiesGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_get_export_command(client, args):
    export_format = args.get("format", "json")
    response = client.vulnerabilities_get_export_request(export_format=export_format)
    filename = response.headers['Content-Disposition'].split("=")[1].replace('"', "")
    file = fileResult(filename=filename, data=response.content, file_type=EntryType.ENTRY_INFO_FILE)

    return file


def vulnerabilities_get_details_command(client, args):
    id = args.get('id')
    response = client.vulnerabilities_get_details_request(id)['vulnerability']
    readable_output = tableToMarkdown('Vulnerability ID:' + id, response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.VulnerabilitiesGetDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_get_query_command(client, args):
    response = client.vulnerabilities_get_query_request(args, 50, 0)['vulnerabilities']
    readable_output = tableToMarkdown('Vulnerabilities', response,
                                      ['id', 'asset_id', 'name', 'severity', 'cvss_score'])
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.VulnerabilitiesGetQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_retest_command(client, args):
    id = args.get('id')
    response = client.vulnerabilities_retest_request(id=id)
    readable_output = tableToMarkdown('Vulnerability retested ID:' + id, response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.VulnerabilitiesRetest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_risk_accept_command(client, args):
    value = args.get('value')
    id = args.get('id')
    response = client.vulnerabilities_risk_accept_request(value=value, id=id)
    readable_output = tableToMarkdown('Vulnerability Risk-accepted ID:' + id, response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.VulnerabilitiesRiskAccept',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def vulnerabilities_add_annotation_command(client, args):
    text = args.get('text')
    id = args.get('id')
    response = client.vulnerabilities_add_annotation_request(text=text, id=id)['annotation']
    readable_output = tableToMarkdown('Annotation added:' + id, response)
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Edgescan.AnnotationAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}
    headers['X-API-TOKEN'] = params['api_key']

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'edgescan-host-get-hosts': host_get_hosts_command,
            'edgescan-host-get': host_get_command,
            'edgescan-host-get-export': host_get_export_command,
            'edgescan-host-get-query': host_get_query_command,
            'edgescan-host-update': host_update_command,
            'edgescan-asset-get-assets': asset_get_assets_command,
            'edgescan-asset-get': asset_get_command,
            'edgescan-asset-get-query': asset_get_query_command,
            'edgescan-asset-create': asset_create_command,
            'edgescan-asset-update': asset_update_command,
            'edgescan-asset-delete': asset_delete_command,
            'edgescan-user-get-users': user_get_users_command,
            'edgescan-user-get': user_get_command,
            'edgescan-user-get-query': user_get_query_command,
            'edgescan-user-create': user_create_command,
            'edgescan-user-delete': user_delete_command,
            'edgescan-user-reset-password': user_reset_password_command,
            'edgescan-user-reset-email': user_reset_email_command,
            'edgescan-user-lock-account': user_lock_account_command,
            'edgescan-user-unlock-account': user_unlock_account_command,
            'edgescan-user-get-permissions': user_get_permissions_command,
            'edgescan-vulnerabilities-get': vulnerabilities_get_command,
            'edgescan-vulnerabilities-get-export': vulnerabilities_get_export_command,
            'edgescan-vulnerabilities-get-details': vulnerabilities_get_details_command,
            'edgescan-vulnerabilities-get-query': vulnerabilities_get_query_command,
            'edgescan-vulnerabilities-retest': vulnerabilities_retest_command,
            'edgescan-vulnerabilities-risk-accept': vulnerabilities_risk_accept_command,
            'edgescan-vulnerabilities-add-annotation': vulnerabilities_add_annotation_command,
        }

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            cvss_score = demisto.params().get('cvss_score', None)
            cvss_score_greater_than = demisto.params().get('cvss_score_greater_than', None)
            risk_more_than = demisto.params().get('risk_more_than', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            if cvss_score and cvss_score_greater_than:
                raise DemistoException('Both cvss_score and cvs_score_greater_than have been provided. Please provide '
                                       'at most one.')

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                cvss_score=cvss_score,
                risk_more_than=risk_more_than,
                cvss_score_greater_than=cvss_score_greater_than
            )

            demisto.setLastRun(next_run)

            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
