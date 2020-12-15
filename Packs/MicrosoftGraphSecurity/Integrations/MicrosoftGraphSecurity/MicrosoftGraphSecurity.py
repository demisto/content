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


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
