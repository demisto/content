from typing import Optional, Dict, Tuple, List, Union
from CommonServerPython import *
import urllib3
from dateutil.parser import parse
from requests import Response

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
APP_NAME = 'ms-defender-atp'

''' HELPER FUNCTIONS '''

SEVERITY_TO_NUMBER = {
    'Informational': 0,
    'Low': 1,
    'MediumLow': 2,
    'MediumHigh': 3,
    'High': 4
}

NUMBER_TO_SEVERITY = {
    0: 'Informational',
    1: 'Low',
    2: 'MediumLow',
    3: 'MediumHigh',
    4: 'High',
    5: 'Informational'
}


def file_standard(observable: Dict) -> Common.File:
    """Gets a file observable and returns a context key

    Args:
        observable: APT's file observable

    Returns:
        Context standard
    """
    file_obj = Common.File(
        Common.DBotScore.NONE,
        name=observable.get('fileName'),
        size=observable.get('fileSize'),
        path=observable.get('filePath')
    )
    hash_type = observable.get('fileHashType', '').lower()
    if hash_type:
        if hash_type in INDICATOR_TYPE_TO_CONTEXT_KEY:
            hash_value = observable.get('fileHashValue')
            if hash_type == 'md5':
                file_obj.md5 = hash_value
            elif hash_type == 'sha256':
                file_obj.sha256 = hash_value
            elif hash_type == 'sha1':
                file_obj.sha1 = hash_value
    return file_obj


def network_standard(observable: Dict) -> Optional[Union[Common.Domain, Common.IP, Common.URL]]:
    """Gets a network observable and returns a context key

    Args:
        observable: APT's network observable

    Returns:
        Context standard or None of not supported
    """
    domain_name = observable.get('domainName')
    url = observable.get('url')
    ip = observable.get('networkIPv4', observable.get('networkIPv6'))
    if domain_name:
        return Common.Domain(domain_name, Common.DBotScore.NONE)
    elif ip:
        return Common.IP(ip, Common.DBotScore(ip, DBotScoreType.IP, 'Microsoft Defender Advanced Threat Protection', 0))
    elif url:
        return Common.URL(url, Common.DBotScore.NONE)
    return None


def standard_output(observable: Dict) -> Optional[Union[Common.Domain, Common.IP, Common.URL, Common.File]]:
    """Gets an observable and returns a context standard object.

    Args:
        observable: File or network observable from API.

    Links:
        File observable: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---file  # noqa: E501
        Network observable: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---network  # noqa: E501

    Returns:
        File, IP, URL or Domain object. If observable is not supported, will return None.
    """
    file_keys = {
        'fileHashType', 'fileHashValue', 'fileName', 'filePath', 'fileSize', 'fileType'
    }
    # Must be file key
    if any(key in observable for key in file_keys):
        return file_standard(observable)
    # Else it's a network
    return network_standard(observable)


def build_std_output(indicators: Union[Dict, List]) -> Dict:
    """

    Args:
        indicators: Network or File observable

    Returns:
        Dict of standard outputs.
    """
    if isinstance(indicators, dict):
        indicators = [indicators]
    outputs = dict()
    for indicator in indicators:
        output = standard_output(indicator)
        if output:
            for key, value in output.to_context().items():
                if key not in outputs:
                    outputs[key] = [value]
                else:
                    outputs[key].append(value)
    return outputs


def get_future_time(expiration_time: str) -> str:
    """ Gets a time and returns a string of the future time of it.

    Args:
        expiration_time: (3 days, 1 hour etc)

    Returns:
        time now + the expiration time

    Examples:
        time now: 20:00
        function get expiration_time=1 hour
        returns: 21:00 (format '%Y-%m-%dT%H:%M:%SZ')
    """
    start, end = parse_date_range(
        expiration_time
    )
    future_time: datetime = end + (end - start)
    return future_time.strftime('%Y-%m-%dT%H:%M:%SZ')


def alert_to_incident(alert, alert_creation_time):
    incident = {
        'rawJSON': json.dumps(alert),
        'name': 'Microsoft Defender ATP Alert ' + alert['id'],
        'occurred': alert_creation_time.isoformat() + 'Z'
    }

    return incident


class MsClient:
    """
     Microsoft  Client enables authorized access to Microsoft Defender Advanced Threat Protection (ATP)
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed,
                 alert_severities_to_fetch, alert_status_to_fetch, alert_time_to_fetch):
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
            base_url=base_url, verify=verify, proxy=proxy, self_deployed=self_deployed,
            scope='https://securitycenter.onmicrosoft.com/windowsatpservice/.default')
        self.alert_severities_to_fetch = alert_severities_to_fetch,
        self.alert_status_to_fetch = alert_status_to_fetch
        self.alert_time_to_fetch = alert_time_to_fetch
        # TODO: Replace with v1 endpoint when out.
        self.indicators_endpoint = 'https://graph.microsoft.com/beta/security/tiIndicators'

    def indicators_http_request(self, *args, **kwargs):
        """ Wraps the ms_client.http_request with scope=Scopes.graph
        """
        kwargs['scope'] = "graph" if self.ms_client.auth_type == OPROXY_AUTH_TYPE else Scopes.graph
        return self.ms_client.http_request(*args, **kwargs)

    def isolate_machine(self, machine_id, comment, isolation_type):
        """Isolates a machine from accessing external network.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action.
            isolation_type (str): Type of the isolation.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/isolate'
        json_data = {
            "Comment": comment,
            "IsolationType": isolation_type
        }
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)
        return response

    def unisolate_machine(self, machine_id, comment):
        """Undo isolation of a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/unisolate'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_machines(self, filter_req):
        """Retrieves a collection of Machines that have communicated with Microsoft Defender ATP cloud on the last 30 days.

        Returns:
            dict. Machine's info
        """
        cmd_url = '/machines'
        params = {'$filter': filter_req} if filter_req else None
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_file_related_machines(self, file):
        """Retrieves a collection of Machines related to a given file hash.

        Args:
            file (str): File's hash

        Returns:
            dict. Related machines
        """
        cmd_url = f'/files/{file}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_machine_details(self, machine_id):
        """Retrieves specific Machine by its machine ID.

        Args:
            machine_id (str): Machine ID

        Returns:
            dict. Machine's info
        """
        cmd_url = f'/machines/{machine_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def run_antivirus_scan(self, machine_id, comment, scan_type):
        """Initiate Windows Defender Antivirus scan on a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): 	Comment to associate with the action
            scan_type (str): Defines the type of the Scan (Quick, Full)

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/runAntiVirusScan'
        json_data = {
            'Comment': comment,
            'ScanType': scan_type
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def list_alerts(self, filter_req=None):
        """Retrieves a collection of Alerts.

        Returns:
            dict. Alerts info
        """
        cmd_url = '/alerts'
        params = {'$filter': filter_req} if filter_req else None
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def update_alert(self, alert_id, json_data):
        """Updates properties of existing Alert.

        Returns:
            dict. Alerts info
        """
        cmd_url = f'/alerts/{alert_id}'
        return self.ms_client.http_request(method='PATCH', url_suffix=cmd_url, json_data=json_data)

    def get_advanced_hunting(self, query: str, timeout: int) -> dict:
        """Retrieves results according to query.

        Args:
            query (str): Query to do advanced hunting on
            timeout (int): Connection timeout

        Returns:
            dict. Advanced hunting results
        """
        cmd_url = '/advancedqueries/run'
        json_data = {
            'Query': query
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data, timeout=timeout)

    def create_alert(self, machine_id, severity, title, description, event_time, report_id, rec_action, category):
        """Creates new Alert on top of Event.

        Args:
            machine_id (str): ID of the machine on which the event was identified
            severity (str): Severity of the alert
            title (str): Title for the alert
            description (str): Description of the alert
            event_time (str): The precise time of the event as string
            report_id (str): The reportId of the event
            rec_action (str): Action that is recommended to be taken by security officer when analyzing the alert
            category (Str): Category of the alert

        Returns:
            dict. Related domains
        """
        cmd_url = '/alerts/CreateAlertByReference'
        json_data = {
            'machineId': machine_id,
            'severity': severity,
            'title': title,
            'description': description,
            'eventTime': event_time,
            'reportId': report_id,
            'recommendedAction': rec_action,
            'category': category
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_alert_related_domains(self, alert_id):
        """Retrieves all domains related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related domains
        """
        cmd_url = f'/alerts/{alert_id}/domains'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_files(self, alert_id):
        """Retrieves all files related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related files
        """
        cmd_url = f'/alerts/{alert_id}/files'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_ips(self, alert_id):
        """Retrieves all IPs related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related IPs
        """
        cmd_url = f'/alerts/{alert_id}/ips'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_user(self, alert_id):
        """Retrieves the User related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related user
        """
        cmd_url = f'/alerts/{alert_id}/user'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_machine_action_by_id(self, action_id):
        """Retrieves specific Machine Action by its ID.

        Args:
            action_id (str): Action ID

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine Action entity
        """
        cmd_url = f'/machineactions/{action_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_machine_actions(self, filter_req):
        """Retrieves all Machine Actions.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine Action entity
        """
        cmd_url = '/machineactions'
        params = {'$filter': filter_req} if filter_req else None
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_investigation_package(self, machine_id, comment):
        """Collect investigation package from a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action
        Returns:

            dict. Machine's investigation_package
        """
        cmd_url = f'/machines/{machine_id}/collectInvestigationPackage'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_investigation_package_sas_uri(self, action_id):
        """Get a URI that allows downloading of an Investigation package.

        Args:
            action_id (str): Action ID

        Returns:
            dict. An object that holds the link for the package
        """
        cmd_url = f'/machineactions/{action_id}/getPackageUri'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def restrict_app_execution(self, machine_id, comment):
        """Restrict execution of all applications on the machine except a predefined set.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/restrictCodeExecution'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def remove_app_restriction(self, machine_id, comment):
        """Enable execution of any application on the machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/unrestrictCodeExecution'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request('POST', cmd_url, json_data=json_data)

    def stop_and_quarantine_file(self, machine_id, file_sha1, comment):
        """Stop execution of a file on a machine and delete it.

        Args:
            machine_id (str): Machine ID
            file_sha1: (str): File's hash
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/stopAndQuarantineFile'
        json_data = {
            'Comment': comment,
            'Sha1': file_sha1
        }
        return self.ms_client.http_request('POST', cmd_url, json_data=json_data)

    def get_investigation_by_id(self, investigation_id):
        """Get the investigation ID and return the investigation details.

        Args:
            investigation_id (str): The investigation ID

        Returns:
            dict. Investigations entity
        """
        cmd_url = f'/investigations/{investigation_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_by_id(self, alert_id):
        """Get the alert ID and return the alert details.

        Args:
            alert_id (str): The alert ID

        Returns:
            dict. Alert's entity
        """
        cmd_url = f'/alerts/{alert_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_investigation_list(self, ):
        """Retrieves a collection of Investigations.

        Returns:
            dict. A collection of Investigations entities.
        """
        cmd_url = '/investigations'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def start_investigation(self, machine_id, comment):
        """Start automated investigation on a machine.

        Args:
            machine_id (str): The Machine ID
            comment (str): Comment to associate with the action

        Returns:
            dict. Investigation's entity
        """
        cmd_url = f'/machines/{machine_id}/startInvestigation'
        json_data = {
            'Comment': comment,
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_domain_statistics(self, domain):
        """Retrieves the statistics on the given domain.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Domain's statistics
        """
        cmd_url = f'/domains/{domain}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_file_statistics(self, file_sha1):
        """Retrieves the statistics on the given file.

        Args:
            file_sha1 (str): The file's hash

        Returns:
            dict. File's statistics
        """
        cmd_url = f'/files/{file_sha1}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_ip_statistics(self, ip):
        """Retrieves the statistics on the given IP.

        Args:
            ip (str): The IP address

        Returns:
            dict. IP's statistics
        """
        cmd_url = f'/ips/{ip}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_domain_alerts(self, domain):
        """Retrieves a collection of Alerts related to a given domain address.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/domains/{domain}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_file_alerts(self, file_sha1):
        """Retrieves a collection of Alerts related to a given file hash.

        Args:
            file_sha1 (str): The file's hash

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/files/{file_sha1}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_ip_alerts(self, ip):
        """Retrieves a collection of Alerts related to a given IP.

        Args:
            ip (str): The IP address

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/ips/{ip}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_user_alerts(self, username):
        """Retrieves a collection of Alerts related to a given  user ID.

        Args:
            username (str): The user ID

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/users/{username}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_domain_machines(self, domain):
        """Retrieves a collection of Machines that have communicated to or from a given domain address.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Machines entities
        """
        cmd_url = f'/domains/{domain}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_user_machines(self, username):
        """Retrieves a collection of machines related to a given user ID.

        Args:
            username (str): The user name

        Returns:
            dict. Machines entities
        """
        cmd_url = f'/users/{username}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def add_remove_machine_tag(self, machine_id, action, tag):
        """Retrieves a collection of machines related to a given user ID.

        Args:
            machine_id (str): The machine ID
            action (str): Add or Remove action
            tag (str): The tag name

        Returns:
            dict. Updated machine's entity
        """
        cmd_url = f'/machines/{machine_id}/tags'
        new_tags = {
            "Value": tag,
            "Action": action
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=new_tags)

    def get_file_data(self, file_hash):
        """Retrieves a File by identifier SHA1.

        Args:
            file_hash(str): The file SHA1 hash

        Returns:
            dict. File entities
        """
        cmd_url = f'/files/{file_hash}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def list_indicators(self, indicator_id: Optional[str] = None) -> List:
        """Lists indicators. if indicator_id supplied, will get only that indicator.

        Args:
            indicator_id: if provided, will get only this specific id.

        Returns:
            List of responses.
        """
        cmd_url = urljoin(self.indicators_endpoint, indicator_id) if indicator_id else self.indicators_endpoint
        # For getting one indicator
        # TODO: check in the future if the filter is working. Then remove the filter function.
        # params = {'$filter': 'targetProduct=\'Microsoft Defender ATP\''}
        resp = self.indicators_http_request(
            'GET', full_url=cmd_url, url_suffix=None, timeout=1000,
            ok_codes=(200, 204, 206, 404), resp_type='response'
        )
        # 404 - No indicators found, an empty list.
        if resp.status_code == 404:
            return []
        resp = resp.json()
        # If 'value' is in the response, should filter and limit. The '@odata.context' key is in the root which we're
        # not returning
        if 'value' in resp:
            resp['value'] = list(
                filter(lambda item: item.get('targetProduct') == 'Microsoft Defender ATP', resp.get('value', []))
            )
            resp = resp['value']
        # If a single object - should remove the '@odata.context' key.
        else:
            resp.pop('@odata.context')
            resp = [resp]
        return [assign_params(values_to_ignore=[None], **item) for item in resp]

    def create_indicator(self, body: Dict) -> Dict:
        """Creates indicator from the given body.

        Args:
            body: Body represents an indicator.

        Returns:
            A response from the API.
        """
        resp = self.indicators_http_request(
            'POST', full_url=self.indicators_endpoint, json_data=body, url_suffix=None
        )
        # A single object - should remove the '@odata.context' key.
        resp.pop('@odata.context')
        return assign_params(values_to_ignore=[None], **resp)

    def update_indicator(
            self, indicator_id: str, expiration_date_time: str,
            description: Optional[str], severity: Optional[str]
    ) -> Dict:
        """Updates a given indicator

        Args:
            indicator_id: ID of the indicator to update
            expiration_date_time: Expiration time of the indicator
            description: A Brief description of the indicator
            severity: The severity of the indicator

        Returns:
            A response from the API.
        """
        cmd_url = urljoin(self.indicators_endpoint, indicator_id)
        header = {'Prefer': 'return=representation'}
        body = {
            'targetProduct': 'Microsoft Defender ATP',
            'expirationDateTime': expiration_date_time
        }
        body.update(assign_params(
            description=description,
            severity=severity
        ))
        resp = self.indicators_http_request(
            'PATCH', full_url=cmd_url, json_data=body, url_suffix=None, headers=header
        )
        # A single object - should remove the '@odata.context' key.
        resp.pop('@odata.context')
        return assign_params(values_to_ignore=[None], **resp)

    def delete_indicator(self, indicator_id: str) -> Response:
        """Deletes a given indicator

        Args:
            indicator_id: ID of the indicator to delete

        Returns:
            A response from the API.
        """
        cmd_url = urljoin(self.indicators_endpoint, indicator_id)
        return self.indicators_http_request(
            'DELETE', None, full_url=cmd_url, ok_codes=(204, ), resp_type='response'
        )


''' Commands '''


def get_alert_related_user_command(client: MsClient, args: dict):
    """Retrieves the User related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    response = client.get_alert_related_user(alert_id)

    user_data = get_user_data(response)
    context_output = {
        'AlertID': alert_id,
        'User': user_data
    }
    ec = {
        'MicrosoftATP.AlertUser(val.AlertID === obj.AlertID)': context_output
    }

    hr = tableToMarkdown('Alert Related User:', user_data, removeNull=True)
    return hr, ec, response


def get_user_data(user_response):
    """Get the user raw response and returns the user info in context and human readable format

    Returns:
        dict. User data
    """
    user_data = {
        'ID': user_response.get('id'),
        'AccountName': user_response.get('accountName'),
        'AccountDomain': user_response.get('accountDomain'),
        'AccountSID': user_response.get('accountSid'),
        'FirstSeen': user_response.get('firstSeen'),
        'LastSeen': user_response.get('lastSeen'),
        'MostPrevalentMachineID': user_response.get('mostPrevalentMachineId'),
        'LeastPrevalentMachineID': user_response.get('leastPrevalentMachineId'),
        'LogonTypes': user_response.get('logonTypes'),
        'LogonCount': user_response.get('logOnMachinesCount'),
        'DomainAdmin': user_response.get('isDomainAdmin'),
        'NetworkUser': user_response.get('isOnlyNetworkUser')
    }
    return user_data


def isolate_machine_command(client: MsClient, args: dict):
    """Isolates a machine from accessing external network.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']

    machine_id = args.get('machine_id')
    comment = args.get('comment')
    isolation_type = args.get('isolation_type')
    machine_action_response = client.isolate_machine(machine_id, comment, isolation_type)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }
    human_readable = tableToMarkdown("The isolation request has been submitted successfully:", machine_action_data,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machine_action_response


def unisolate_machine_command(client: MsClient, args: dict):
    """Undo isolation of a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.unisolate_machine(machine_id, comment)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }

    human_readable = tableToMarkdown("The request to stop the isolation has been submitted successfully:",
                                     machine_action_data, headers=headers, removeNull=True)
    return human_readable, entry_context, machine_action_response


def get_machines_command(client: MsClient, args: dict):
    """Retrieves a collection of machines that have communicated with WDATP cloud on the last 30 days

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    hostname = args.get('hostname', '')
    ip = args.get('ip', '')
    risk_score = args.get('risk_score', '')
    health_status = args.get('health_status', '')
    os_platform = args.get('os_platform', '')

    fields_to_filter_by = {
        'computerDnsName': hostname,
        'lastIpAddress': ip,
        'riskScore': risk_score,
        'healthStatus': health_status,
        'osPlatform': os_platform
    }
    filter_req = reformat_filter(fields_to_filter_by)
    machines_response = client.get_machines(filter_req)
    machines_list = get_machines_list(machines_response)

    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machines_list
    }
    human_readable = tableToMarkdown('Microsoft Defender ATP Machines:', machines_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, machines_response


def get_machines_list(machines_response):
    """Get a raw response of machines list

    Args:
        machines_response (dict): The raw response with the machines list in it

    Returns:
        list. Machines list
    """
    machines_list = []
    for machine in machines_response['value']:
        machine_data = get_machine_data(machine)
        machines_list.append(machine_data)
    return machines_list


def reformat_filter(fields_to_filter_by):
    """Get a dictionary with all of the fields to filter

    Args:
        fields_to_filter_by (dict): Dictionary with all the fields to filter

    Returns:
        string. Filter to send in the API request
    """
    filter_req = ' and '.join(
        f"{field_key} eq '{field_value}'" for field_key, field_value in fields_to_filter_by.items() if field_value)
    return filter_req


def get_file_related_machines_command(client: MsClient, args: dict):
    """Retrieves a collection of Machines related to a given file hash.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    file = args.get('file_hash')
    machines_response = client.get_file_related_machines(file)
    machines_list = get_machines_list(machines_response)

    context_output = {
        'File': file,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.FileMachine(val.ID === obj.ID)': context_output
    }
    human_readable = tableToMarkdown(f'Microsoft Defender ATP machines related to file {file}', machines_list,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machines_response


def get_machine_details_command(client: MsClient, args: dict):
    """Retrieves specific Machine by its machine ID or computer name.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    machine_id = args.get('machine_id')
    machine_response = client.get_machine_details(machine_id)
    machine_data = get_machine_data(machine_response)

    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machine_data
    }
    human_readable = tableToMarkdown(f'Microsoft Defender ATP machine {machine_id} details:', machine_data,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machine_response


def run_antivirus_scan_command(client: MsClient, args: dict):
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    scan_type = args.get('scan_type')
    comment = args.get('comment')

    machine_action_response = client.run_antivirus_scan(machine_id, comment, scan_type)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }
    human_readable = tableToMarkdown('Antivirus scan successfully triggered', machine_action_data, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, machine_action_response


def list_alerts_command(client: MsClient, args: dict):
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    severity = args.get('severity')
    status = args.get('status')
    fields_to_filter_by = {
        'severity': severity,
        'status': status
    }
    filter_req = reformat_filter(fields_to_filter_by)
    alerts_response = client.list_alerts(filter_req)
    alerts_list = get_alerts_list(alerts_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alerts_list
    }
    human_readable = tableToMarkdown('Microsoft Defender ATP alerts:', alerts_list, headers=headers, removeNull=True)
    return human_readable, entry_context, alerts_response


def get_alerts_list(alerts_response):
    """Get a raw response of alerts list

    Args:
        alerts_response (dict): The raw response with the alerts list in it

    Returns:
        list. Alerts list
    """
    alerts_list = []
    for alert in alerts_response['value']:
        alert_data = get_alert_data(alert)
        alerts_list.append(alert_data)
    return alerts_list


def update_alert_command(client: MsClient, args: dict):
    """Updates properties of existing Alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('alert_id')
    assigned_to = args.get('assigned_to')
    status = args.get('status')
    classification = args.get('classification')
    determination = args.get('determination')
    comment = args.get('comment')

    args_list = [assigned_to, status, classification, determination, comment]
    check_given_args_update_alert(args_list)
    json_data, context = add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination,
                                                      comment)
    alert_response = client.update_alert(alert_id, json_data)
    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': context
    }
    human_readable = f'The alert {alert_id} has been updated successfully'
    return human_readable, entry_context, alert_response


def check_given_args_update_alert(args_list):
    """Gets an arguments list and returns an error if all of them are empty
    """
    if all(v is None for v in args_list):
        raise Exception('No arguments were given to update the alert')


def add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination, comment):
    """Gets arguments and returns the json and context with the arguments inside
    """
    json_data = {}
    context = {
        'ID': alert_id
    }
    if assigned_to:
        json_data['assignedTo'] = assigned_to
        context['AssignedTo'] = assigned_to
    if status:
        json_data['status'] = status
        context['Status'] = status
    if classification:
        json_data['classification'] = classification
        context['Classification'] = classification
    if determination:
        json_data['determination'] = determination
        context['Determination'] = determination
    if comment:
        json_data['comment'] = comment
        context['Comment'] = comment
    return json_data, context


def get_advanced_hunting_command(client: MsClient, args: dict):
    """Get results of advanced hunting according to user query.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    query = args.get('query')
    timeout = int(args.get('timeout'))
    response = client.get_advanced_hunting(query, timeout)
    results = response.get('Results')
    if isinstance(results, list) and len(results) == 1:
        report_id = results[0].get('ReportId')
        if report_id:
            results[0]['ReportId'] = str(report_id)
    entry_context = {
        'MicrosoftATP.Hunt.Result': results
    }
    human_readable = tableToMarkdown('Hunt results', results, removeNull=True)

    return human_readable, entry_context, response


def create_alert_command(client: MsClient, args: dict):
    """Creates new Alert on top of Event.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    alert_response = client.create_alert(
        args.get('machine_id'),
        args.get('severity'),
        args.get('title'),
        args.get('description'),
        args.get('event_time'),
        args.get('report_id'),
        args.get('recommended_action'),
        args.get('category')
    )
    alert_data = get_alert_data(alert_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alert_data
    }
    human_readable = tableToMarkdown('Alert created:', alert_data, headers=headers, removeNull=True)
    return human_readable, entry_context, alert_response


def get_alert_related_files_command(client: MsClient, args: dict):
    """Retrieves all files related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['Sha1', 'Sha256', 'SizeInBytes', 'FileType', 'FilePublisher', 'FileProductName']
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = client.get_alert_related_files(alert_id)
    response_files_list = response['value']

    files_data_list = []
    from_index = min(offset, len(response_files_list))
    to_index = min(offset + limit, len(response_files_list))
    for file_obj in response_files_list[from_index:to_index]:
        files_data_list.append(get_file_data(file_obj))

    context_output = {
        'AlertID': alert_id,
        'Files': files_data_list
    }
    entry_context = {
        'MicrosoftATP.AlertFile(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = tableToMarkdown(f'Alert {alert_id} Related Files:', files_data_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response_files_list


def check_limit_and_offset_values(limit, offset):
    """Gets the limit and offset values and return an error if the values are invalid
    """
    if not limit.isdigit():
        raise Exception("Error: You can only enter a positive integer or zero to limit argument.")
    elif not offset.isdigit():
        raise Exception("Error: You can only enter a positive integer to offset argument.")
    else:
        limit_int = int(limit)
        offset_int = int(offset)

        if limit_int == 0:
            raise Exception("Error: The value of the limit argument must be a positive integer.")

        return limit_int, offset_int


def get_file_data(file_response):
    """Get file raw response and returns the file's info for context and human readable.

    Returns:
        dict. File's info
    """
    file_data = assign_params(**{
        'Sha1': file_response.get('sha1'),
        'Sha256': file_response.get('sha256'),
        'Md5': file_response.get('md5'),
        'GlobalPrevalence': file_response.get('globalPrevalence'),
        'GlobalFirstObserved': file_response.get('globalFirstObserved'),
        'GlobalLastObserved': file_response.get('globalLastObserved'),
        'SizeInBytes': file_response.get('size'),
        'FileType': file_response.get('fileType'),
        'IsPeFile': file_response.get('isPeFile'),
        'FilePublisher': file_response.get('filePublisher'),
        'FileProductName': file_response.get('fileProductName'),
        'Signer': file_response.get('signer'),
        'Issuer': file_response.get('issuer'),
        'SignerHash': file_response.get('signerHash'),
        'IsValidCertificate': file_response.get('isValidCertificate'),
        'DeterminationType': file_response.get('determinationType'),
        'DeterminationValue': file_response.get('determinationValue')
    })
    return file_data


def get_alert_related_ips_command(client: MsClient, args: dict):
    """Retrieves all IPs related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = client.get_alert_related_ips(alert_id)
    response_ips_list = response['value']

    ips_list = []
    from_index = min(offset, len(response_ips_list))
    to_index = min(offset + limit, len(response_ips_list))

    for ip in response_ips_list[from_index:to_index]:
        ips_list.append(ip['id'])

    context_output = {
        'AlertID': alert_id,
        'IPs': ips_list
    }
    entry_context = {
        'MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related IPs: {ips_list}'
    return human_readable, entry_context, response_ips_list


def get_alert_related_domains_command(client: MsClient, args: dict):
    """Retrieves all domains related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)
    response = client.get_alert_related_domains(alert_id)
    response_domains_list = response['value']
    domains_list = []
    from_index = min(offset, len(response_domains_list))
    to_index = min(offset + limit, len(response_domains_list))
    for domain in response_domains_list[from_index:to_index]:
        domains_list.append(domain['host'])
    context_output = {
        'AlertID': alert_id,
        'Domains': domains_list
    }
    entry_context = {
        'MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related Domains: {domains_list}'
    return human_readable, entry_context, response_domains_list


def get_machine_action_by_id_command(client: MsClient, args: dict):
    """Returns machine's actions, if machine ID is None, return all actions.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    action_id = args.get('id', '')
    status = args.get('status', '')
    machine_id = args.get('machine_id', '')
    type = args.get('type', '')
    requestor = args.get('requestor', '')
    if action_id:
        for index in range(3):
            try:
                response = client.get_machine_action_by_id(action_id)
                if response:
                    break
            except Exception as e:
                if 'ResourceNotFound' in str(e) and index < 3:
                    time.sleep(1)
                else:
                    raise Exception(f'Machine action {action_id} was not found')
        response = client.get_machine_action_by_id(action_id)
        action_data = get_machine_action_data(response)
        human_readable = tableToMarkdown(f'Action {action_id} Info:', action_data, headers=headers, removeNull=True)
        context_output = action_data
    else:
        # A dictionary that contains all of the fields the user want to filter results by.
        # It will be sent in the request so the requested filters are applied on the results
        fields_to_filter_by = {
            'status': status,
            'machineId': machine_id,
            'type': type,
            'requestor': requestor
        }
        filter_req = reformat_filter(fields_to_filter_by)
        response = client.get_machine_actions(filter_req)
        machine_actions_list = []
        for machine_action in response['value']:
            machine_actions_list.append(get_machine_action_data(machine_action))
        human_readable = tableToMarkdown('Machine actions Info:', machine_actions_list, headers=headers,
                                         removeNull=True)
        context_output = machine_actions_list
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_machine_action_data(machine_action_response):
    """Get machine raw response and returns the machine action info in context and human readable format.

    Notes:
         Machine action is a collection of actions you can apply on the machine, for more info
         https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action's info
    """
    action_data = \
        {
            "ID": machine_action_response.get('id'),
            "Type": machine_action_response.get('type'),
            "Scope": machine_action_response.get('scope'),
            "Requestor": machine_action_response.get('requestor'),
            "RequestorComment": machine_action_response.get('requestorComment'),
            "Status": machine_action_response.get('status'),
            "MachineID": machine_action_response.get('machineId'),
            "ComputerDNSName": machine_action_response.get('computerDnsName'),
            "CreationDateTimeUtc": machine_action_response.get('creationDateTimeUtc'),
            "LastUpdateTimeUtc": machine_action_response.get('lastUpdateTimeUtc'),
            "RelatedFileInfo": {
                "FileIdentifier": machine_action_response.get('fileIdentifier'),
                "FileIdentifierType": machine_action_response.get('fileIdentifierType')

            }
        }
    return action_data


def get_machine_investigation_package_command(client: MsClient, args: dict):
    """Collect investigation package from a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.get_investigation_package(machine_id, comment)
    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating collect investigation package from {machine_id} machine :',
                                     action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def get_investigation_package_sas_uri_command(client: MsClient, args: dict):
    """Returns a URI that allows downloading an Investigation package.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    action_id = args.get('action_id')
    response = client.get_investigation_package_sas_uri(action_id)
    link = {'Link': response['value']}
    human_readable = f'Success. This link is valid for a very short time and should be used immediately for' \
                     f' downloading the package to a local storage{link["Link"]}'
    entry_context = {
        'MicrosoftATP.InvestigationURI(val.Link === obj.Link)': link
    }
    return human_readable, entry_context, response


def restrict_app_execution_command(client: MsClient, args: dict):
    """Restrict execution of all applications on the machine except a predefined set.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.restrict_app_execution(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating Restrict execution of all applications on the machine {machine_id} '
                                     f'except a predefined set:', action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def remove_app_restriction_command(client: MsClient, args: dict):
    """Enable execution of any application on the machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.remove_app_restriction(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Removing applications restriction on the machine {machine_id}:', action_data,
                                     headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def stop_and_quarantine_file_command(client: MsClient, args: dict):
    """Stop execution of a file on a machine and delete it.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    file_sha1 = args.get('file_hash')
    comment = args.get('comment')
    machine_action_response = client.stop_and_quarantine_file(machine_id, file_sha1, comment)
    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Stopping the execution of a file on {machine_id} machine and deleting it:',
                                     action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def get_investigations_by_id_command(client: MsClient, args: dict):
    """Returns the investigation info, if investigation ID is None, return all investigations.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    investigation_id = args.get('id', '')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    if investigation_id:
        response = client.get_investigation_by_id(investigation_id)
        investigation_data = get_investigation_data(response)
        human_readable = tableToMarkdown(f'Investigation {investigation_id} Info:', investigation_data, headers=headers,
                                         removeNull=True)
        context_output = investigation_data
    else:
        response = client.get_investigation_list()['value']
        investigations_list = []
        from_index = min(offset, len(response))
        to_index = min(offset + limit, len(response))
        for investigation in response[from_index:to_index]:
            investigations_list.append(get_investigation_data(investigation))
        human_readable = tableToMarkdown('Investigations Info:', investigations_list, headers=headers, removeNull=True)
        context_output = investigations_list
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_investigation_data(investigation_response):
    """Get investigation raw response and returns the investigation info for context and human readable.

    Args:
        investigation_response: The investigation raw response
    Returns:
        dict. Investigation's info
    """
    investigation_data = {
        "ID": investigation_response.get('id'),
        "StartTime": investigation_response.get('startTime'),
        "EndTime": investigation_response.get('endTime'),
        "InvestigationState": investigation_response.get('state'),
        "CancelledBy": investigation_response.get('cancelledBy'),
        "StatusDetails": investigation_response.get('statusDetails'),
        "MachineID": investigation_response.get('machineId'),
        "ComputerDNSName": investigation_response.get('computerDnsName'),
        "TriggeringAlertID": investigation_response.get('triggeringAlertId')
    }
    return investigation_data


def start_investigation_command(client: MsClient, args: dict):
    """Start automated investigation on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    response = client.start_investigation(machine_id, comment)
    investigation_id = response['id']
    investigation_data = get_investigation_data(response)
    human_readable = tableToMarkdown(f'Starting investigation {investigation_id} on {machine_id} machine:',
                                     investigation_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': investigation_data
    }
    return human_readable, entry_context, response


def get_domain_statistics_command(client: MsClient, args: dict):
    """Retrieves the statistics on the given domain.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    domain = args.get('domain')
    response = client.get_domain_statistics(domain)
    domain_statistics = get_domain_statistics_context(response)
    human_readable = tableToMarkdown(f'Statistics on {domain} domain:', domain_statistics, removeNull=True)

    context_output = {
        'Domain': domain,
        'Statistics': domain_statistics
    }
    entry_context = {
        'MicrosoftATP.DomainStatistics(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_domain_statistics_context(domain_stat_response):
    """Gets the domain statistics response and returns it in context format.

    Returns:
        (dict). domain statistics context
    """
    domain_statistics = assign_params(**{
        "Host": domain_stat_response.get('host'),
        "OrgPrevalence": domain_stat_response.get('orgPrevalence'),
        "OrgFirstSeen": domain_stat_response.get('orgFirstSeen'),
        "OrgLastSeen": domain_stat_response.get('orgLastSeen')
    })
    return domain_statistics


def get_domain_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    domain = args.get('domain')
    response = client.get_domain_alerts(domain)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'Domain {domain} related alerts Info:', alerts_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Domain': domain,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.DomainAlert(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_alert_data(alert_response):
    """Get alert raw response and returns the alert info in context and human readable format.

    Returns:
        dict. Alert info
    """
    alert_data = {
        "ID": alert_response.get('id'),
        "IncidentID": alert_response.get('incidentId'),
        "InvestigationID": alert_response.get('investigationId'),
        "InvestigationState": alert_response.get('investigationState'),
        "AssignedTo": alert_response.get('assignedTo'),
        "Severity": alert_response.get('severity'),
        "Status": alert_response.get('status'),
        "Classification": alert_response.get('classification'),
        "Determination": alert_response.get('determination'),
        "DetectionSource": alert_response.get('detectionSource'),
        "Category": alert_response.get('category'),
        "ThreatFamilyName": alert_response.get('threatFamilyName'),
        "Title": alert_response.get('title'),
        "Description": alert_response.get('description'),
        "AlertCreationTime": alert_response.get('alertCreationTime'),
        "FirstEventTime": alert_response.get('firstEventTime'),
        "LastEventTime": alert_response.get('lastEventTime'),
        "LastUpdateTime": alert_response.get('lastUpdateTime'),
        "ResolvedTime": alert_response.get('resolvedTime'),
        "MachineID": alert_response.get('machineId'),
        "ComputerDNSName": alert_response.get('computerDnsName'),
        "AADTenantID": alert_response.get('aadTenantId'),
        "Comments": [
            {
                "Comment": alert_response.get('comment'),
                "CreatedBy": alert_response.get('createdBy'),
                "CreatedTime": alert_response.get('createdTime')
            }
        ],
        "Evidence": alert_response.get('evidence')
    }

    return alert_data


def get_domain_machine_command(client: MsClient, args: dict):
    """Retrieves a collection of Machines that have communicated to or from a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """

    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    domain = args.get('domain')
    response = client.get_domain_machines(domain)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that have communicated with {domain} domain:', machines_list,
                                     headers=headers, removeNull=True)
    context_output = {
        'Domain': domain,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.DomainMachine(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_machine_data(machine):
    """Get machine raw response and returns the machine's info in context and human readable format.

    Returns:
        dict. Machine's info
    """
    machine_data = assign_params(**{
        'ID': machine.get('id'),
        'ComputerDNSName': machine.get('computerDnsName'),
        'FirstSeen': machine.get('firstSeen'),
        'LastSeen': machine.get('lastSeen'),
        'OSPlatform': machine.get('osPlatform'),
        'OSVersion': machine.get('version'),
        'OSProcessor': machine.get('osProcessor'),
        'LastIPAddress': machine.get('lastIpAddress'),
        'LastExternalIPAddress': machine.get('lastExternalIpAddress'),
        'AgentVersion': machine.get('agentVersion'),
        'OSBuild': machine.get('osBuild'),
        'HealthStatus': machine.get('healthStatus'),
        'RBACGroupID': machine.get('rbacGroupId'),
        'RBACGroupName': machine.get('rbacGroupName'),
        'RiskScore': machine.get('riskScore'),
        'ExposureLevel': machine.get('exposureLevel'),
        'AADDeviceID': machine.get('aadDeviceId'),
        'IsAADJoined': machine.get('isAadJoined'),
        'MachineTags': machine.get('machineTags'),
    })
    return machine_data


def get_file_statistics_command(client: MsClient, args: dict):
    """Retrieves the statistics on the given file.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    file_sha1 = args.get('file_hash')
    response = client.get_file_statistics(file_sha1)
    file_stat = get_file_statistics_context(response)
    human_readable = tableToMarkdown(f'Statistics on {file_sha1} file:', file_stat, removeNull=True)
    context_output = {
        'Sha1': file_sha1,
        'Statistics': file_stat
    }
    entry_context = {
        'MicrosoftATP.FileStatistics(val.Sha1 === obj.Sha1)': context_output
    }
    return human_readable, entry_context, response


def get_file_statistics_context(file_stat_response):
    """Gets the file statistics response and returns it in context format.

    Returns:
        (dict). File statistics context
    """
    file_stat = assign_params(**{
        "OrgPrevalence": file_stat_response.get('orgPrevalence'),
        "OrgFirstSeen": file_stat_response.get('orgFirstSeen'),
        "OrgLastSeen": file_stat_response.get('orgLastSeen'),
        "GlobalPrevalence": file_stat_response.get('globalPrevalence'),
        "GlobalFirstObserved": file_stat_response.get('globalFirstObserved'),
        "GlobalLastObserved": file_stat_response.get('globalLastObserved'),
        "TopFileNames": file_stat_response.get('topFileNames')
    })
    return file_stat


def get_file_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given file hash.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    file_sha1 = args.get('file_hash')
    response = client.get_file_alerts(file_sha1)
    alerts_list = get_alerts_list(response)
    hr = tableToMarkdown(f'File {file_sha1} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'Sha1': file_sha1,
        'Alerts': alerts_list
    }
    ec = {
        'MicrosoftATP.FileAlert(val.Sha1 === obj.Sha1)': context_output
    }
    return hr, ec, response


def get_ip_statistics_command(client: MsClient, args: dict):
    """Retrieves the statistics on the given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    ip = args.get('ip')
    response = client.get_ip_statistics(ip)
    ip_statistics = get_ip_statistics_context(response)
    hr = tableToMarkdown(f'Statistics on {ip} IP:', ip_statistics, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Statistics': ip_statistics
    }
    ec = {
        'MicrosoftATP.IPStatistics(val.IPAddress === obj.IPAddress)': context_output
    }
    return hr, ec, response


def get_ip_statistics_context(ip_statistics_response):
    """Gets the IP statistics response and returns it in context format.

    Returns:
        (dict). IP statistics context
    """
    ip_statistics = assign_params(**{
        "OrgPrevalence": ip_statistics_response.get('orgPrevalence'),
        "OrgFirstSeen": ip_statistics_response.get('orgFirstSeen'),
        "OrgLastSeen": ip_statistics_response.get('orgLastSeen')
    })
    return ip_statistics


def get_ip_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    ip = args.get('ip')
    response = client.get_ip_alerts(ip)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'IP {ip} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.IPAlert(val.IPAddress === obj.IPAddress)': context_output
    }
    return human_readable, entry_context, response


def get_user_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    username = args.get('username')
    response = client.get_user_alerts(username)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'User {username} related alerts Info:', alerts_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Username': username,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.UserAlert(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def get_user_machine_command(client: MsClient, args: dict):
    """Retrieves a collection of machines related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    username = args.get('username')
    response = client.get_user_machines(username)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that are related to user {username}:', machines_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Username': username,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.UserMachine(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def add_remove_machine_tag_command(client: MsClient, args: dict):
    """Adds or remove tag to a specific Machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIpAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel', 'MachineTags']
    machine_id = args.get('machine_id')
    action = args.get('action')
    tag = args.get('tag')
    response = client.add_remove_machine_tag(machine_id, action, tag)
    machine_data = get_machine_data(response)
    human_readable = tableToMarkdown(f'Succeed to {action} tag to {machine_id}:', machine_data, headers=headers,
                                     removeNull=True)
    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machine_data
    }
    return human_readable, entry_context, response


def fetch_incidents(client: MsClient, last_run):
    last_alert_fetched_time = get_last_alert_fetched_time(last_run, client.alert_time_to_fetch)
    existing_ids = last_run.get('existing_ids', [])
    latest_creation_time = last_alert_fetched_time
    filter_alerts_creation_time = create_filter_alerts_creation_time(last_alert_fetched_time)
    alerts = client.list_alerts(filter_alerts_creation_time)['value']

    incidents, new_ids, latest_creation_time = all_alerts_to_incidents(alerts, latest_creation_time, existing_ids,
                                                                       client.alert_status_to_fetch,
                                                                       client.alert_severities_to_fetch)

    demisto.setLastRun({
        'last_alert_fetched_time': datetime.strftime(latest_creation_time, '%Y-%m-%dT%H:%M:%S'),
        'existing_ids': new_ids
    })
    demisto.incidents(incidents)


def create_filter_alerts_creation_time(last_alert_fetched_time):
    """Create filter with the last alert fetched time to send in the request.

    Args:
        last_alert_fetched_time(date): Last date and time of alert that been fetched

    Returns:
        (str). The filter of alerts creation time that will be send in the  alerts list API request
    """
    filter_alerts_creation_time = f"alertCreationTime+gt+{last_alert_fetched_time.isoformat()}"

    if not filter_alerts_creation_time.endswith('Z'):
        filter_alerts_creation_time = filter_alerts_creation_time + "Z"

    return filter_alerts_creation_time


def all_alerts_to_incidents(alerts, latest_creation_time, existing_ids, alert_status_to_fetch,
                            alert_severities_to_fetch):
    """Gets the alerts list and convert it to incidents.

    Args:
        alerts(list): List of alerts filtered by the first_fetch_timestamp parameter
        latest_creation_time(date):  Last date and time of alert that been fetched
        existing_ids(list): List of alerts IDs that already been fetched
        alert_status_to_fetch(str): Status to filter out alerts for fetching as incidents.
        alert_severities_to_fetch(str): Severity to filter out alerts for fetching as incidents.

    Returns:(list, list, date). Incidents list, new alerts IDs list, latest alert creation time
    """
    incidents = []
    new_ids = []
    for alert in alerts:
        alert_creation_time_for_incident = parse(alert['alertCreationTime'])
        reformatted_alert_creation_time_for_incident = \
            aware_timestamp_to_naive_timestamp(alert_creation_time_for_incident)

        if should_fetch_alert(alert, existing_ids, alert_status_to_fetch, alert_severities_to_fetch):
            incident = alert_to_incident(alert, reformatted_alert_creation_time_for_incident)
            incidents.append(incident)

            if reformatted_alert_creation_time_for_incident == latest_creation_time:
                new_ids.append(alert["id"])
            if reformatted_alert_creation_time_for_incident > latest_creation_time:
                latest_creation_time = reformatted_alert_creation_time_for_incident
                new_ids = [alert['id']]

    if not new_ids:
        new_ids = existing_ids
    return incidents, new_ids, latest_creation_time


def aware_timestamp_to_naive_timestamp(aware_timestamp):
    """Gets aware timestamp and reformatting it to naive timestamp

    Args:
        aware_timestamp(date): The alert creation time after parse to aware timestamp

    Returns:(date). Naive timestamp for alert creation time
    """
    iso_aware = aware_timestamp.isoformat()
    # Deal with timestamp like: 2020-03-26T17:24:58.441093
    if '.' in iso_aware:
        iso_aware = iso_aware.split('.')[0]
    # Deal with timestamp like: 2020-03-14T22:11:20+0000
    elif '+' in iso_aware:
        iso_aware = iso_aware.split('+')[0]
    return datetime.strptime(iso_aware, '%Y-%m-%dT%H:%M:%S')


def should_fetch_alert(alert, existing_ids, alert_status_to_fetch, alert_severities_to_fetch):
    """ Check the alert to see if it's data stands by the conditions.

    Args:
        alert (dict): The alert data
        existing_ids (list): The existing alert's ids list
        alert_status_to_fetch(str): Status to filter out alerts for fetching as incidents.
        alert_severities_to_fetch(str): Severity to filter out alerts for fetching as incidents.


    Returns:
        True - if the alert is according to the conditions, else False
    """
    alert_status = alert['status']
    alert_severity = alert['severity']
    return (alert_status in alert_status_to_fetch
            and alert_severity in str(alert_severities_to_fetch) and alert['id'] not in existing_ids)


def get_last_alert_fetched_time(last_run, alert_time_to_fetch):
    """Gets fetch last run and returns the last alert fetch time.

    Returns:
        (date). The date and time of the last alert that been fetched
    """
    if last_run and last_run['last_alert_fetched_time']:
        last_alert_fetched_time = datetime.strptime(last_run['last_alert_fetched_time'], '%Y-%m-%dT%H:%M:%S')
    else:
        last_alert_fetched_time, _ = parse_date_range(date_range=alert_time_to_fetch, date_format='%Y-%m-%dT%H:%M:%S',
                                                      utc=False, to_timestamp=False)
        last_alert_fetched_time = datetime.strptime(str(last_alert_fetched_time), '%Y-%m-%dT%H:%M:%S')

    return last_alert_fetched_time


def list_indicators_command(client: MsClient, args: Dict[str, str]) -> Tuple[str, Optional[Dict], Optional[List]]:
    """

    Args:
        client: MsClient
        args: arguments from CortexSOAR. May include 'indicator_id'

    Returns:
        human_readable, outputs.
    """
    raw_response = client.list_indicators(args.get('indicator_id'))
    limit = int(args.get('limit', 50))
    raw_response = raw_response[:limit]
    if raw_response:
        indicators = list()
        for item in raw_response:
            item['severity'] = NUMBER_TO_SEVERITY.get(item['severity'])
            indicators.append(item)

        human_readable = tableToMarkdown(
            'Microsoft Defender ATP Indicators:',
            indicators,
            headers=[
                'id',
                'action',
                'threatType',
                'severity',
                'fileName',
                'fileHashType',
                'fileHashValue',
                'domainName',
                'networkIPv4',
                'url'
            ],
            removeNull=True
        )
        outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicators}
        std_outputs = build_std_output(indicators)
        outputs.update(std_outputs)
        return human_readable, outputs, indicators
    else:
        return 'No indicators found', None, None


def create_indicator_command(client: MsClient, args: Dict, specific_args: Dict) -> Dict:
    """Adds required arguments to indicator (arguments that must be in every create call).

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must include the following keys:
            - action
            - description
            - expiration_time
            - threat_type
        specific_args: file, email or network object.

    Returns:
        A response from API.

    Raises:
        AssertionError: For some arguments.

    Documentation:
    https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#properties
    """
    action = args.get('action', '')
    description = args.get('description', '')
    assert 1 <= len(description) <= 100, 'The description argument must contain at' \
                                         ' least 1 character and not more than 100'
    expiration_time = get_future_time(args.get('expiration_time', ''))
    threat_type = args.get('threat_type', '')
    tlp_level = args.get('tlp_level', '')
    confidence = args.get('confidence', None)
    try:
        if confidence is not None:
            confidence = int(confidence)
            assert 0 <= confidence <= 100, 'The confidence argument must be between 0 and 100'
    except ValueError:
        raise DemistoException('The confidence argument must be an integer.')
    severity = NUMBER_TO_SEVERITY.get(args.get('severity', 'Informational'))
    tags = argToList(args.get('tags'))
    body = assign_params(
        action=action,
        description=description,
        expirationDateTime=expiration_time,
        targetProduct='Microsoft Defender ATP',
        threatType=threat_type,
        tlpLevel=tlp_level,
        confidence=confidence,
        severity=severity,
        tags=tags
    )
    body.update(specific_args)
    return client.create_indicator(body)


def create_file_indicator_command(client: MsClient, args: Dict) -> Tuple[str, Dict, Dict]:
    """Creates a file indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Should contain a file observable:
            - https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---file

    Returns:
        human readable, outputs, raw response

    Raises:
        AssertionError: If no file arguments.
    """
    file_object = assign_params(
        fileCompileDateTime=args.get('file_compile_date_time'),
        fileCreatedDateTime=args.get('file_created_date_time'),
        fileHashType=args.get('file_hash_type'),
        fileHashValue=args.get('file_hash_value'),
        fileMutexName=args.get('file_mutex_name'),
        fileName=args.get('file_name'),
        filePacker=args.get('file_packer'),
        filePath=args.get('file_path'),
        fileSize=args.get('file_size'),
        fileType=args.get('file_type')
    )
    assert file_object, 'Must supply at least one file attribute.'
    raw_response = create_indicator_command(client, args, file_object)
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator {indicator.get("id")} was successfully created:',
        indicator,
        headers=[
            'id',
            'action',
            'threatType',
            'severity',
            'fileName',
            'fileHashType',
            'fileHashValue',
            'domainName',
            'networkIPv4',
            'url'
        ],
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def create_network_indicator_command(client, args) -> Tuple[str, Dict, Dict]:
    """Creates a network indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Should contain a a network observable:
            - https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-betaindicator-observables---network  # noqa: E501
    Returns:
        human readable, outputs, raw response

    Raises:
        AssertionError: If no file arguments.
    """
    network_object = assign_params(
        domainName=args.get('domain_name'),
        networkCidrBlock=args.get('network_cidr_block'),
        networkDestinationAsn=args.get('network_destination_asn'),
        networkDestinationCidrBlock=args.get('network_destination_cidr_block'),
        networkDestinationIPv4=args.get('network_destination_ipv4'),
        networkDestinationIPv6=args.get('network_destination_ipv6'),
        networkDestinationPort=args.get('network_destination_port'),
        networkIPv4=args.get('network_ipv4'),
        networkIPv6=args.get('network_ipv6'),
        networkPort=args.get('network_port'),
        networkProtocol=args.get('network_protocol'),
        networkSourceAsn=args.get('network_source_asn'),
        networkSourceCidrBlock=args.get('network_source_cidr_block'),
        networkSourceIPv4=args.get('network_source_ipv4'),
        networkSourceIPv6=args.get('network_source_ipv6'),
        networkSourcePort=args.get('network_source_port'),
        userAgent=args.get('user_agent'),
        url=args.get('url')
    )
    assert network_object, 'Must supply at least one network attribute.'
    raw_response = create_indicator_command(client, args, network_object)
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator {indicator.get("id")} was successfully created:',
        indicator,
        headers=[
            'id',
            'action',
            'threatType',
            'severity',
            'fileName',
            'fileHashType',
            'fileHashValue',
            'domainName',
            'networkIPv4',
            'url'
        ],
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def update_indicator_command(client: MsClient, args: dict) -> Tuple[str, Dict, Dict]:
    """Updates an indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must contains 'indicator_id' and 'expiration_time'
    Returns:
        human readable, outputs
    """
    indicator_id = args.get('indicator_id', '')
    severity = NUMBER_TO_SEVERITY.get(args.get('severity', 'Informational'))
    expiration_time = get_future_time(args.get('expiration_time', ''))
    description = args.get('description')
    if description is not None:
        assert 1 <= len(
            description) <= 100, 'The description argument must contain at least 1 character and not more than 100'

    raw_response = client.update_indicator(
        indicator_id=indicator_id, expiration_date_time=expiration_time,
        description=description, severity=severity
    )
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator ID: {indicator_id} was updated successfully.',
        indicator,
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def delete_indicator_command(client: MsClient, args: dict) -> str:
    """Deletes an indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must contains 'indicator_id'
    Returns:
        human readable
    """
    indicator_id = args.get('indicator_id', '')
    client.delete_indicator(indicator_id)
    return f'Indicator ID: {indicator_id} was successfully deleted'


def test_module(client: MsClient):
    client.ms_client.http_request(method='GET', url_suffix='/alerts', params={'$top': '1'})
    demisto.results('ok')


''' EXECUTION CODE '''


def main():
    params: dict = demisto.params()
    base_url: str = params.get('url', '').rstrip('/') + '/api'
    tenant_id = params.get('tenant_id')
    auth_id = params.get('auth_id')
    enc_key = params.get('enc_key')
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    alert_severities_to_fetch = params.get('fetch_severity')
    alert_status_to_fetch = params.get('fetch_status')
    alert_time_to_fetch = params.get('first_fetch_timestamp', '3 days')
    last_run = demisto.getLastRun()

    command = demisto.command()
    args = demisto.args()
    LOG(f'command is {command}')
    try:
        client = MsClient(
            base_url=base_url, tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=APP_NAME, verify=use_ssl,
            proxy=proxy, self_deployed=self_deployed, alert_severities_to_fetch=alert_severities_to_fetch,
            alert_status_to_fetch=alert_status_to_fetch, alert_time_to_fetch=alert_time_to_fetch)
        if command == 'test-module':
            test_module(client)

        elif command == 'fetch-incidents':
            fetch_incidents(client, last_run)

        elif command == 'microsoft-atp-isolate-machine':
            return_outputs(*isolate_machine_command(client, args))

        elif command == 'microsoft-atp-unisolate-machine':
            return_outputs(*unisolate_machine_command(client, args))

        elif command == 'microsoft-atp-get-machines':
            return_outputs(*get_machines_command(client, args))

        elif command == 'microsoft-atp-get-file-related-machines':
            return_outputs(*get_file_related_machines_command(client, args))

        elif command == 'microsoft-atp-get-machine-details':
            return_outputs(*get_machine_details_command(client, args))

        elif command == 'microsoft-atp-run-antivirus-scan':
            return_outputs(*run_antivirus_scan_command(client, args))

        elif command == 'microsoft-atp-list-alerts':
            return_outputs(*list_alerts_command(client, args))

        elif command == 'microsoft-atp-update-alert':
            return_outputs(*update_alert_command(client, args))

        elif command == 'microsoft-atp-advanced-hunting':
            return_outputs(*get_advanced_hunting_command(client, args))

        elif command == 'microsoft-atp-create-alert':
            return_outputs(*create_alert_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-user':
            return_outputs(*get_alert_related_user_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-files':
            return_outputs(*get_alert_related_files_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-ips':
            return_outputs(*get_alert_related_ips_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-domains':
            return_outputs(*get_alert_related_domains_command(client, args))

        elif command == 'microsoft-atp-list-machine-actions-details':
            return_outputs(*get_machine_action_by_id_command(client, args))

        elif command == 'microsoft-atp-collect-investigation-package':
            return_outputs(*get_machine_investigation_package_command(client, args))

        elif command == 'microsoft-atp-get-investigation-package-sas-uri':
            return_outputs(*get_investigation_package_sas_uri_command(client, args))

        elif command == 'microsoft-atp-restrict-app-execution':
            return_outputs(*restrict_app_execution_command(client, args))

        elif command == 'microsoft-atp-remove-app-restriction':
            return_outputs(*remove_app_restriction_command(client, args))

        elif command == 'microsoft-atp-stop-and-quarantine-file':
            return_outputs(*stop_and_quarantine_file_command(client, args))

        elif command == 'microsoft-atp-list-investigations':
            return_outputs(*get_investigations_by_id_command(client, args))

        elif command == 'microsoft-atp-start-investigation':
            return_outputs(*start_investigation_command(client, args))

        elif command == 'microsoft-atp-get-domain-statistics':
            return_outputs(*get_domain_statistics_command(client, args))

        elif command == 'microsoft-atp-get-domain-alerts':
            return_outputs(*get_domain_alerts_command(client, args))

        elif command == 'microsoft-atp-get-domain-machines':
            return_outputs(*get_domain_machine_command(client, args))

        elif command == 'microsoft-atp-get-file-statistics':
            return_outputs(*get_file_statistics_command(client, args))

        elif command == 'microsoft-atp-get-file-alerts':
            return_outputs(*get_file_alerts_command(client, args))

        elif command == 'microsoft-atp-get-ip-statistics':
            return_outputs(*get_ip_statistics_command(client, args))

        elif command == 'microsoft-atp-get-ip-alerts':
            return_outputs(*get_ip_alerts_command(client, args))

        elif command == 'microsoft-atp-get-user-alerts':
            return_outputs(*get_user_alerts_command(client, args))

        elif command == 'microsoft-atp-get-user-machines':
            return_outputs(*get_user_machine_command(client, args))

        elif command == 'microsoft-atp-add-remove-machine-tag':
            return_outputs(*add_remove_machine_tag_command(client, args))

        elif command in ('microsoft-atp-indicator-list', 'microsoft-atp-indicator-get-by-id'):
            return_outputs(*list_indicators_command(client, args))
        elif command == 'microsoft-atp-indicator-create-file':
            return_outputs(*create_file_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-create-network':
            return_outputs(*create_network_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-update':
            return_outputs(*update_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-delete':
            return_outputs(delete_indicator_command(client, args))
    except Exception as err:
        return_error(str(err))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
