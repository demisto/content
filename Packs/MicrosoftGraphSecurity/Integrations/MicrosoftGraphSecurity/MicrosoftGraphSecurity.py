import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, List, Any

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

APP_NAME = 'ms-graph-security'

''' HELPER FUNCTIONS '''


def get_timestamp(time_description):
    if time_description == 'Last24Hours':
        time_delta = 1
    elif time_description == 'Last48Hours':
        time_delta = 2
    else:
        time_delta = 7
    return datetime.strftime(datetime.now() - timedelta(time_delta), '%Y-%m-%d')


def capitalize_first_letter(string):
    return string[:1].upper() + string[1:]


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed):
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name, base_url=base_url, verify=verify,
            proxy=proxy, self_deployed=self_deployed)

    def search_alerts(self, last_modified, severity, category, vendor, time_from, time_to, filter_query):
        filters = []
        if last_modified:
            filters.append("lastModifiedDateTime gt {}".format(get_timestamp(last_modified)))
        if category:
            filters.append("category eq '{}'".format(category))
        if severity:
            filters.append("severity eq '{}'".format(severity))
        if time_from:  # changed to ge and le in order to solve issue #27884
            filters.append("createdDateTime ge {}".format(time_from))
        if time_to:
            filters.append("createdDateTime le {}".format(time_to))
        if filter_query:
            filters.append("{}".format(filter_query))
        filters = " and ".join(filters)
        cmd_url = 'security/alerts'
        params = {'$filter': filters}
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)
        return response

    def get_alert_details(self, alert_id):
        cmd_url = f'security/alerts/{alert_id}'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response

    def update_alert(self, alert_id, vendor_information, provider_information,
                     assigned_to, closed_date_time, comments, feedback, status, tags):
        cmd_url = f'/security/alerts/{alert_id}'
        data: Dict[str, Any] = {
            'vendorInformation': {
                'provider': provider_information,
                'vendor': vendor_information
            }
        }
        if assigned_to:
            data['assignedTo'] = assigned_to
        if closed_date_time:
            data['closedDateTime'] = closed_date_time
        if comments:
            data['comments'] = [comments]
        if feedback:
            data['feedback'] = feedback
        if status:
            data['status'] = status
        if tags:
            data['tags'] = [tags]
        self.ms_client.http_request(method='PATCH', url_suffix=cmd_url, json_data=data, resp_type="text")

    def get_users(self):
        cmd_url = 'users'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response

    def get_user(self, user_id):
        cmd_url = f'users/{user_id}'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response


def create_filter_query(filter_param: str, providers_param: str):
    filter_query = ""
    if providers_param:
        providers_query = []
        providers_lst = providers_param.split(',')
        for provider in providers_lst:
            providers_query.append(f"vendorInformation/provider eq '{provider}'")
        filter_query = (" or ".join(providers_query))
    if filter_param:  # overrides the providers query, if given
        filter_query = filter_param
    return filter_query


def fetch_incidents(client: MsGraphClient, fetch_time: str, fetch_limit: int, filter: str, providers: str) \
        -> list:

    filter_query = create_filter_query(filter, providers)
    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'unknown': 0, 'informational': 0}

    last_run = demisto.getLastRun()
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    if not last_run:  # if first time running
        new_last_run = {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
    else:
        new_last_run = last_run
    demisto_incidents: List = list()
    time_from = new_last_run.get('time')
    time_to = datetime.now().strftime(timestamp_format)

    # Get incidents from MS Graph Security
    demisto.debug(f'Fetching MS Graph Security incidents. From: {time_from}. To: {time_to}. Filter: {filter_query}')
    incidents = client.search_alerts(last_modified=None, severity=None, category=None, vendor=None, time_from=time_from,
                                     time_to=time_to, filter_query=filter_query)['value']

    if incidents:
        count = 0
        incidents = sorted(incidents, key=lambda k: k['createdDateTime'])  # sort the incidents by time-increasing order
        last_incident_time = last_run.get('time', '0')
        demisto.debug(f'Incidents times: {[incidents[i]["createdDateTime"] for i in range(len(incidents))]}\n')
        for incident in incidents:
            incident_time = incident.get('createdDateTime')
            if incident_time > last_incident_time and count < fetch_limit:
                demisto_incidents.append({
                    'name': incident.get('title') + " - " + incident.get('id'),
                    'occurred': incident.get('createdDateTime'),
                    'severity': severity_map.get(incident.get('severity', ''), 0),
                    'rawJSON': json.dumps(incident)
                })
                count += 1
        if demisto_incidents:
            last_incident_time = demisto_incidents[-1].get('occurred')
            new_last_run.update({'time': last_incident_time})

    demisto.setLastRun(new_last_run)
    return demisto_incidents


def search_alerts_command(client: MsGraphClient, args):
    last_modified = args.get('last_modified')
    severity = args.get('severity')
    category = args.get('category')
    vendor = args.get('vendor')
    time_from = args.get('time_from')
    time_to = args.get('time_to')
    filter_query = args.get('filter')
    alerts = client.search_alerts(last_modified, severity, category, vendor, time_from, time_to, filter_query)['value']
    outputs = []
    for alert in alerts:
        outputs.append({
            'ID': alert['id'],
            'Title': alert['title'],
            'Category': alert['category'],
            'Severity': alert['severity'],
            'CreatedDate': alert['createdDateTime'],
            'EventDate': alert['eventDateTime'],
            'Status': alert['status'],
            'Vendor': alert['vendorInformation']['vendor'],
            'Provider': alert['vendorInformation']['provider']
        })
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': outputs
    }
    table_headers = ['ID', 'Vendor', 'Provider', 'Title', 'Category', 'Severity', 'CreatedDate', 'EventDate', 'Status']
    human_readable = tableToMarkdown('Microsoft Security Graph Alerts', outputs, table_headers, removeNull=True)
    return human_readable, ec, alerts


def get_alert_details_command(client: MsGraphClient, args):
    alert_id = args.get('alert_id')
    fields_to_include = args.get('fields_to_include')
    if fields_to_include:
        fields_list = fields_to_include.split(',')
    else:
        fields_list = []

    show_all_fields = True if 'All' in fields_list else False

    alert_details = client.get_alert_details(alert_id)

    hr = '## Microsoft Security Graph Alert Details - {}\n'.format(alert_id)

    basic_properties_title = 'Basic Properties'
    basic_properties = {
        'ActivityGroupName': alert_details['activityGroupName'],
        'AssignedTo': alert_details['assignedTo'],
        'AzureTenantID': alert_details['azureTenantId'],
        'Category': alert_details['category'],
        'ClosedDate': alert_details['closedDateTime'],
        'Confidence': alert_details['confidence'],
        'CreatedDate': alert_details['createdDateTime'],
        'Description': alert_details['description'],
        'EventDate': alert_details['eventDateTime'],
        'LastModifiedDate': alert_details['eventDateTime'],
        'Severity': alert_details['severity'],
        'Status': alert_details['status'],
        'Title': alert_details['title']
    }
    hr += tableToMarkdown(basic_properties_title, basic_properties, removeNull=True)

    if 'CloudAppStates' in fields_list or show_all_fields:
        cloud_apps_states = alert_details['cloudAppStates']
        if cloud_apps_states:
            cloud_apps_hr = []
            for state in cloud_apps_states:
                cloud_apps_hr.append({
                    'DestinationSerivceIP': state['destinationServiceIp'],
                    'DestinationSerivceName': state['destinationServiceName'],
                    'RiskScore': state['riskScore']
                })
            cloud_apps_title = 'Cloud Application States for Alert'
            hr += tableToMarkdown(cloud_apps_title, cloud_apps_hr, removeNull=True)

    if 'CustomerComments' in fields_list or show_all_fields:
        comments = alert_details['comments']
        if comments:
            comments_hr = '### Customer Provided Comments for Alert\n'
            for comment in comments:
                comments_hr += '- {}\n'.format(comment)
            hr += comments_hr

    if 'FileStates' in fields_list or show_all_fields:
        file_states = alert_details['fileStates']
        if file_states:
            file_states_hr = []
            for state in file_states:
                file_state = {
                    'Name': state['name'],
                    'Path': state['path'],
                    'RiskScore': state['riskScore']
                }
                file_hash = state.get('fileHash')
                if file_hash:
                    file_state['FileHash'] = file_hash['hashValue']
                file_states_hr.append(file_state)
            file_states_title = 'File Security States for Alert'
            hr += tableToMarkdown(file_states_title, file_states_hr, removeNull=True)

    if 'HostStates' in fields_list or show_all_fields:
        host_states = alert_details['hostStates']
        if host_states:
            host_states_hr = []
            for state in host_states:
                host_state = {
                    'Fqdn': state['fqdn'],
                    'NetBiosName': state['netBiosName'],
                    'OS': state['os'],
                    'PrivateIPAddress': state['privateIpAddress'],
                    'PublicIPAddress': state['publicIpAddress']
                }
                aad_joined = state.get('isAzureAadJoined')
                if aad_joined:
                    host_state['IsAsureAadJoined'] = aad_joined
                aad_registered = state.get('isAzureAadRegistered')
                if aad_registered:
                    host_state['IsAsureAadRegistered'] = aad_registered
                risk_score = state.get('riskScore')
                if risk_score:
                    host_state['RiskScore'] = risk_score
                host_states_hr.append(host_state)
            host_states_title = 'Host Security States for Alert'
            hr += tableToMarkdown(host_states_title, host_states_hr, removeNull=True)

    if 'MalwareStates' in fields_list or show_all_fields:
        malware_states = alert_details['malwareStates']
        if malware_states:
            malware_states_hr = []
            for state in malware_states:
                malware_states_hr.append({
                    'Category': state['category'],
                    'Familiy': state['family'],
                    'Name': state['name'],
                    'Severity': state['severity'],
                    'WasRunning': state['wasRunning']
                })
            malware_states_title = 'Malware States for Alert'
            hr += tableToMarkdown(malware_states_title, malware_states_hr, removeNull=True)

    if 'NetworkConnections' in fields_list or show_all_fields:
        network_connections = alert_details['networkConnections']
        if network_connections:
            network_connections_hr = []
            for connection in network_connections:
                connection_hr = {}
                for key, value in connection.items():
                    if value or value is False:
                        connection_hr[capitalize_first_letter(key)] = value
                network_connections_hr.append(connection_hr)
            network_connections_title = 'Network Connections for Alert'
            hr += tableToMarkdown(network_connections_title, network_connections_hr, removeNull=True)

    if 'Processes' in fields_list or show_all_fields:
        processes = alert_details['processes']
        if processes:
            processes_hr = []
            for process in processes:
                process_hr = {}
                for key, value in process.items():
                    if value or value is False:
                        process_hr[capitalize_first_letter(key)] = value
                processes_hr.append(process_hr)
            processes_title = 'Processes for Alert'
            hr += tableToMarkdown(processes_title, processes_hr, removeNull=True)

    if 'Triggers' in fields_list or show_all_fields:
        triggers = alert_details['triggers']
        if triggers:
            triggers_hr = []
            for trigger in triggers:
                triggers_hr.append({
                    'Name': trigger['name'],
                    'Type': trigger['type'],
                    'Value': trigger['value']
                })
            triggers_title = 'Triggers for Alert'
            hr += tableToMarkdown(triggers_title, triggers_hr, removeNull=True)

    if 'UserStates' in fields_list or show_all_fields:
        user_states = alert_details['userStates']
        if user_states:
            user_states_hr = []
            for state in user_states:
                state_hr = {}
                for key, value in state.items():
                    if value or value is False:
                        state_hr[capitalize_first_letter(key)] = value
                user_states_hr.append(state_hr)
            user_states_title = 'User Security States for Alert'
            hr += tableToMarkdown(user_states_title, user_states_hr, removeNull=True)

    if 'VendorInformation' in fields_list or show_all_fields:
        vendor_information = alert_details['vendorInformation']
        if vendor_information:
            vendor_info_hr = {
                'Provider': vendor_information['provider'],
                'ProviderVersion': vendor_information['providerVersion'],
                'SubProvider': vendor_information['subProvider'],
                'Vendor': vendor_information['vendor']
            }
            vendor_info_title = 'Vendor Information for Alert'
            hr += tableToMarkdown(vendor_info_title, vendor_info_hr, removeNull=True)

    if 'VulnerabilityStates' in fields_list or show_all_fields:
        vulnerability_states = alert_details['vulnerabilityStates']
        if vulnerability_states:
            vulnerability_states_hr = []
            for state in vulnerability_states:
                vulnerability_states_hr.append({
                    'CVE': state['cve'],
                    'Severity': state['severity'],
                    'WasRunning': state['wasRunning']
                })
            vulnerability_states_title = 'Vulnerability States for Alert'
            hr += tableToMarkdown(vulnerability_states_title, vulnerability_states_hr, removeNull=True)

    if 'RegistryKeys' in fields_list or show_all_fields:
        registry_keys = alert_details['registryKeyStates']
        if registry_keys:
            registry_keys_hr = []
            for r_key in registry_keys:
                r_key_hr = {}
                for key, value in r_key.items():
                    if value or value is False:
                        r_key_hr[capitalize_first_letter(key)] = value
                registry_keys_hr.append(r_key_hr)
            registry_keys_title = 'Registry Keys for Alert'
            hr += tableToMarkdown(registry_keys_title, registry_keys_hr, removeNull=True)

    context = {
        'ID': alert_details['id'],
        'Title': alert_details['title'],
        'Category': alert_details['category'],
        'Severity': alert_details['severity'],
        'CreatedDate': alert_details['createdDateTime'],
        'EventDate': alert_details['eventDateTime'],
        'Status': alert_details['status'],
        'Vendor': alert_details['vendorInformation']['vendor'],
        'Provider': alert_details['vendorInformation']['provider']
    }
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
    }
    return hr, ec, alert_details


def update_alert_command(client: MsGraphClient, args):
    alert_id = args.get('alert_id')
    vendor_information = args.get('vendor_information')
    provider_information = args.get('provider_information')
    assigned_to = args.get('assigned_to')
    closed_date_time = args.get('closed_date_time')
    comments = args.get('comments')
    feedback = args.get('feedback')
    status = args.get('status')
    tags = args.get('tags')
    if all(v is None for v in [assigned_to, closed_date_time, comments, feedback, status, tags]):
        return_error('No data to update was provided')
    client.update_alert(alert_id, vendor_information, provider_information,
                        assigned_to, closed_date_time, comments, feedback, status, tags)
    context = {
        'ID': alert_id
    }
    if status:
        context['Status'] = status
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
    }
    human_readable = 'Alert {} has been successfully updated.'.format(alert_id)
    if status and provider_information in {'IPC', 'MCAS', 'Azure Sentinel'}:
        human_readable += f'\nUpdating status for alerts from provider {provider_information} gets updated across \
Microsoft Graph Security API integrated applications but not reflected in the provider’s management experience.\n \
        For more details, see the \
[Microsoft documentation](https://docs.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0#alerts)'
    return human_readable, ec, context


def get_users_command(client: MsGraphClient, args):
    users = client.get_users()['value']
    outputs = []
    for user in users:
        outputs.append({
            'Name': user['displayName'],
            'Title': user['jobTitle'],
            'Email': user['mail'],
            'ID': user['id']
        })
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': outputs
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    human_readable = tableToMarkdown('Microsoft Graph Users', outputs, table_headers, removeNull=True)
    return human_readable, ec, users


def get_user_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    raw_user = client.get_user(user_id)
    user = {
        'Name': raw_user['displayName'],
        'Title': raw_user['jobTitle'],
        'Email': raw_user['mail'],
        'ID': raw_user['id']
    }
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': user
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    human_readable = tableToMarkdown('Microsoft Graph User ' + user_id, user, table_headers, removeNull=True)
    return human_readable, ec, raw_user


def test_function(client: MsGraphClient, args):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    response = client.ms_client.http_request(
        method='GET', url_suffix='security/alerts', params={'$top': 1}, resp_type='response')
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to MS Graph Security failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {demisto.get(data, "error.message")}')

        params: dict = demisto.params()

        if params.get('isFetch'):
            fetch_time = params.get('fetch_time', '1 day')
            fetch_providers = params.get('fetch_providers', '')
            fetch_filter = params.get('fetch_filter', '')

            filter_query = create_filter_query(fetch_filter, fetch_providers)
            timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
            time_from = parse_date_range(fetch_time, date_format=timestamp_format)[0]
            time_to = datetime.now().strftime(timestamp_format)

            try:
                client.search_alerts(last_modified=None, severity=None, category=None, vendor=None, time_from=time_from,
                                     time_to=time_to, filter_query=filter_query)['value']
            except Exception as e:
                if 'Invalid ODATA query filter' in e.args[0]:
                    raise DemistoException("Wrong filter format, correct usage: {property} eq '{property-value}'"
                                           "\n\n" + e.args[0])
                raise e

        return 'ok', None, None

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to MS Graph Security failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


def main():
    params: dict = demisto.params()
    url = params.get('host', '').rstrip('/') + '/v1.0/'
    tenant = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id', '')
    enc_key = params.get('enc_key')
    use_ssl = not params.get('insecure', False)
    self_deployed: bool = params.get('self_deployed', False)
    proxy = params.get('proxy', False)

    commands = {
        'test-module': test_function,
        'msg-search-alerts': search_alerts_command,
        'msg-get-alert-details': get_alert_details_command,
        'msg-update-alert': update_alert_command,
        'msg-get-users': get_users_command,
        'msg-get-user': get_user_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client: MsGraphClient = MsGraphClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key,
                                              app_name=APP_NAME, base_url=url, verify=use_ssl, proxy=proxy,
                                              self_deployed=self_deployed)
        if command == "fetch-incidents":
            fetch_time = params.get('fetch_time', '1 day')
            fetch_limit = params.get('fetch_limit', 10)
            fetch_providers = params.get('fetch_providers', '')
            fetch_filter = params.get('fetch_filter', '')
            incidents = fetch_incidents(client, fetch_time=fetch_time, fetch_limit=int(fetch_limit),
                                        filter=fetch_filter, providers=fetch_providers)
            demisto.incidents(incidents)
        else:
            human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


# from MicrosoftApiModule import *  # noqa: E402
import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import re
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'
    security_center_apt_service = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
