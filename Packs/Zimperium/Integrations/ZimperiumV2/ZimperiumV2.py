import urllib3
from CommonServerPython import *
import demistomock as demisto

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'
FETCH_FIELD = 'timestamp'


class Client(BaseClient):
    """
    Client to use in the ZimperiumV2 integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        self._headers = {'Content-Type': 'application/json'}
        super().__init__(base_url=base_url, verify=verify, headers=self._headers, proxy=proxy)
        access_token = self.auth(client_id, client_secret)
        self._headers['Authorization'] = f'Bearer {access_token}'

    def auth(self, client_id: str, client_secret: str):
        """
        Args:
            client_id: The client id for authentication
            client_secret: The client secret for authentication

        Return:
            access_token for requests authentication.
        """
        body = {
            'clientId': client_id,
            'secret': client_secret,
        }
        response = self._http_request(method='POST', url_suffix='/auth/v1/api_keys/login', json_data=body)
        access_token = response.get('accessToken')
        return access_token

    def users_search(self, size: Optional[int], page: Optional[int], team_id: Optional[str] = None,
                     user_id: Optional[str] = None, email: Optional[str] = None):
        """Search users by sending a GET request.

        Args:
            size: response size.
            page: response page.
            user_id: the id of the user to search.
            team_id: the id of the team filter by.
            email: the email of the user to search.

        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
            'teamId': team_id,
        })

        if not email:
            return self._http_request(method='GET', url_suffix=f'auth/public/v1/users/{user_id if user_id else ""}',
                                      headers=self._headers,
                                      params=params)

        res = self._http_request(method='GET', url_suffix='auth/public/v1/users',
                                 headers=self._headers,
                                 params=params)

        users = []
        for user in res.get('content'):
            if user.get('email') == email or user.get('id') == user_id:
                users.append(user)

        return users

    def device_search(self, size: Optional[int], page: Optional[int], device_id: Optional[str]):
        """Search devices by sending a GET request.

        Args:
            size: response size.
            page: response page.
            device_id: the device id to get.

        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
        })

        return self._http_request(method='GET',
                                  url_suffix=f'/devices/public/v2/devices/{device_id if device_id else "start-scroll"}',
                                  headers=self._headers, params=params)

    def report_get(self, app_version_id: Optional[str]):
        """ Generates JSON report using GET request.

        Args:
            app_version_id: The Id to get the app version JSON report.

        Returns:
            Response from API.
        """

        return self._http_request(method='GET', url_suffix=f'/devices/public/v1/appVersions/'
                                                           f'{app_version_id}/json',
                                  headers=self._headers)

    def threat_search(self, after: Optional[str], size: Optional[int] = None,
                      page: Optional[int] = 0,
                      before: Optional[str] = None,
                      search_params: Optional[dict] = None,
                      team_id: Optional[str] = None,
                      operating_system: Optional[str] = None,
                      severity: Optional[List] = None,
                      sort: Optional[str] = None):
        """Search threats by sending a GET request.

        Args:
            size: response size.
            page: response page.
            after: threats after this date.
            before: threats before this date.
            search_params: params to query.
            team_id: threats related to team.
            operating_system: os of device with a threat.
            severity: threat severity.
            sort: field to sort by.
        Returns:
            Response from API.
        """
        params = {
            'page': page,
            'size': size,
            'module': 'ZIPS',
            'after': after,
            'before': before,
            'teamId': team_id,
            'os': operating_system,
            'severityName': severity,
            'sort': sort
        }
        if search_params:
            params.update(search_params)

        params = assign_params(**params)

        return self._http_request(method='GET', url_suffix='/threats/public/v1/threats', headers=self._headers,
                                  params=params)

    def app_version_list(self, size: Optional[int], page: Optional[int], bundle_id: Optional[str] = None):
        """List App Versions by sending a GET request.

        Args:
            bundle_id: The Bundle ID of the app to get its app version.
            size: response size.
            page: response page.

        Returns:
            Response from API.
        """
        params = assign_params(**{
            'query': f'bundleId=={bundle_id}' if bundle_id else None,
            'page': page,
            'size': size,
        })
        return self._http_request(method='GET', url_suffix='/devices/public/v1/appVersions',
                                  headers=self._headers, params=params)

    def device_by_cve_get(self, cve_id: Optional[str], size: Optional[int], page: Optional[int],
                          after: Optional[str] = None, before: Optional[str] = None,
                          team_id: Optional[str] = None):
        """Get Devices that has CVE with cve_id  a GET request.

        Args:
            cve_id: the ID of the CVE which is input.
            size: response size.
            page: response page.
            after: the date from when the data can be retrieved.
            before: the date until when the data can be retrieved.
            team_id: filter the data to the respective team.
        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
            'module': 'ZIPS',
            'after': after,
            'before': before,
            'teamId': team_id,
            'cveId': cve_id
        })

        return self._http_request(method='GET', url_suffix='/devices/public/v2/devices/data-cve-filter', headers=self._headers,
                                  params=params)

    def policy_group_list(self, module: Optional[str] = 'ZIPS'):
        """List policy groups by sending a GET request.

        Returns:
            Response from API.
        """
        params = {
            'module': module if module else 'ZIPS',
        }
        return self._http_request(method='GET', url_suffix='/mtd-policy/public/v1/groups/page',
                                  headers=self._headers, params=params)

    def devices_os_version(self, os_version: Optional[str], size: Optional[int], page: Optional[int],
                           deleted: Optional[bool] = None, os_patch_date: Optional[str] = None,
                           after: Optional[str] = None, before: Optional[str] = None, team_id: Optional[str] = None):
        """Search devices by os version by sending a GET request.

        Args:
            os_version: os version of the device.
            deleted: is device deleted.
            os_patch_date: os patch date.
            size: response size.
            page: response page.
            after: the date from when the data can be retrieved.
            before: the date until when the data can be retrieved.
            team_id: filter devices related to the team id.
        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
            'module': 'ZIPS',
            'after': after,
            'before': before,
            'teamId': team_id,
            'osPatchDate': os_patch_date,
            'osVersion': os_version,
            'deleted': deleted,
        })

        return self._http_request(method='GET', url_suffix='/devices/public/v2/devices/data-version-filter',
                                  headers=self._headers,
                                  params=params)

    def cve_devices_get(self, size: Optional[int], page: Optional[int], device_id: Optional[str]):
        """Get the CVEs associated with a specific device

        Args:
            device_id: the device to query.
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
            'module': 'ZIPS',
        })

        return self._http_request(method='GET',
                                  url_suffix=f'/devices/public/v2/devices/{device_id}/cves',
                                  headers=self._headers,
                                  params=params)

    def vulnerability_get(self, size: Optional[int], page: Optional[int]):
        """Get the list of vulnerabilities.

        Args:
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = assign_params(**{
            'page': page,
            'size': size,
        })

        return self._http_request(method='GET',
                                  url_suffix='/devices/public/v1/os-versions',
                                  headers=self._headers,
                                  params=params)

    def policy_privacy(self, policy_id: Optional[str]):
        """Get a privacy policy by id.

        Args:
            policy_id: the policy id to query.

        Returns:
            Response from API.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/mtd-policy/public/v1/privacy/policies/{policy_id}',
                                  headers=self._headers)

    def policy_threat(self, policy_id: Optional[str]):
        """Get a threat policy by id.

        Args:
            policy_id: the policy id to query.

        Returns:
            Response from API.
        """

        return self._http_request(method='GET',
                                  url_suffix=f'/mtd-policy/public/v1/trm/policies/{policy_id}',
                                  headers=self._headers)

    def policy_phishing(self, policy_id: Optional[str]):
        """Get the phishing policy by id.

        Args:
            policy_id: the policy id to query.

        Returns:
            Response from API.
        """

        return self._http_request(method='GET',
                                  url_suffix=f'/mtd-policy/public/v1/phishing/policies/{policy_id}',
                                  headers=self._headers)

    def policy_app_settings(self, app_settings_policy_id: Optional[str]):
        """Get the policy app settings by id.

        Args:
            app_settings_policy_id: the policy id to query.

        Returns:
            Response from API.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/mtd-policy/public/v1/app-settings/policies/{app_settings_policy_id}',
                                  headers=self._headers)

    def policy_device_inactivity_list(self, size: Optional[int], page: Optional[int], team_id: Optional[str] = None):
        """List the device inactivity policies.

        Args:
            team_id: filter the data to its respective team.
            size: response size.
            page: response page.

        Returns:
            Response from API.
        """
        params = assign_params(**{
            'teamId': team_id,
            'page': page,
            'size': size,
        })
        return self._http_request(method='GET', url_suffix='/devices/public/v1/dormancy/policies',
                                  headers=self._headers, params=params)

    def policy_device_inactivity_get(self, policy_id: Optional[str]):
        """Get the device inactivity policy by id.

        Args:
            policy_id: the policy id to query.

        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/devices/public/v1/dormancy/policies/{policy_id}',
                                  headers=self._headers)


def test_module(client: Client, first_fetch_time: Optional[str],
                fetch_query: Optional[list], max_fetch: int, look_back: int = 1) -> str:
    """
    Performs basic get request to get incident samples
    """
    if demisto.params().get('isFetch'):
        fetch_incidents(
            client=client,
            last_run={},
            fetch_query=fetch_query,
            first_fetch_time=first_fetch_time,
            max_fetch=max_fetch,
            look_back=look_back,
        )
    else:
        client.users_search(size=10, page=0)

    return 'ok'


def users_search_command(client: Client, args: dict) -> CommandResults:
    """Search users.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    team_id = args.get('team_id')
    user_id = args.get('user_id')
    email = args.get('email')
    size = page_size if page_size else limit

    response = client.users_search(size=size, page=page, team_id=team_id, user_id=user_id, email=email)
    content = response.get('content') if (not user_id and not email) else response

    hr = tableToMarkdown(name='Users Search Results', t=content,
                         headers=['id', 'firstName', 'lastName', 'email', 'created', 'role', 'teams'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.User',
        outputs=content,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def devices_search_command(client: Client, args: dict) -> CommandResults:
    """Search devices.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    device_id = args.get('device_id')

    size = page_size if page_size else limit

    response = client.device_search(size=size, page=page, device_id=device_id)

    content = response.get('content') if not device_id else [response]
    hr_output = content.copy()

    for item in hr_output:
        bundle_id_item = item.get('zappInstance', [{}])[0].get('bundleId')
        item.update({'bundleId': bundle_id_item})

    hr = tableToMarkdown(name='Device Search Results', t=hr_output,
                         headers=['riskPostureName', 'id', 'model', 'os', 'bundleId', 'lastSeen'],
                         removeNull=True,
                         date_fields=['lastSeen'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Device',
        outputs=content,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def report_get_command(client: Client, args: dict) -> CommandResults:
    """Get report by ID.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    app_version_id = args.get('app_version_id')
    importance = args.get('importance', 'High')

    response = client.report_get(app_version_id=app_version_id)

    scan_details = response.get('report', {}).get('scanDetails')
    if importance != 'All':
        # changing the list in place (in the response dict)
        scan_details[:] = [entry for entry in scan_details if entry["importance"] == importance]

    hr = tableToMarkdown(name='Report', t=scan_details,
                         headers=["riskType", "kind", "description", "location", "importance"],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Report',
        outputs=response,
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def threat_search_command(client: Client, args: dict) -> CommandResults:
    """Search threats.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    after = arg_to_datetime(args.get('after'), required=True, arg_name='after')
    before = arg_to_datetime(args.get('before'))
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    search_params = argToList(args.get('search_params'))
    team_id = args.get('team_id')
    operating_system = args.get('os')
    severity = args.get('severity')

    after_srt = after.strftime(DATE_FORMAT) if after else None
    before_str = before.strftime(DATE_FORMAT) if before else None

    search_params_dict = {key: value for param in search_params for key, value in [param.split('=', 1)]}
    size = page_size if page_size else limit

    response = client.threat_search(size=size, page=page, after=after_srt,
                                    before=before_str, search_params=search_params_dict,
                                    team_id=team_id, operating_system=operating_system, severity=severity)

    hr = tableToMarkdown(name='Threat Search Result', t=response.get('content'),
                         headers=['id', 'severityName', 'state', 'vectorName',
                                  'threatTypeName', 'os', 'deviceOwner', 'deviceId',
                                  'teamName', 'timestamp'],
                         date_fields=['timestamp'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Threat',
        outputs=response.get('content'),
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def app_version_list_command(client: Client, args: dict) -> CommandResults:
    """List app versions.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    bundle_id = args.get('bundle_id')
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))

    size = page_size if page_size else limit

    response = client.app_version_list(bundle_id=bundle_id, size=size, page=page)

    hr = tableToMarkdown(name='App Version List', t=response.get('content'),
                         headers=['id', 'name', 'bundleId', 'version', 'platform',
                                  'security', 'privacy', 'classification', 'developerName', 'created', 'updatedOn'],
                         date_fields=['created', 'updatedOn'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.AppVersion',
        outputs=response.get('content'),
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def get_devices_by_cve_command(client: Client, args: dict) -> CommandResults:
    """Retrieve the devices associated with a specific CVE

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    cve_id = args.get('cve_id')
    after = arg_to_datetime(args.get('after'))
    before = arg_to_datetime(args.get('before'))
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    team_id = args.get('team_id')

    after_srt = after.strftime(DATE_FORMAT) if after else None
    before_str = before.strftime(DATE_FORMAT) if before else None

    size = page_size if page_size else limit

    response = client.device_by_cve_get(cve_id=cve_id, size=size, page=page, after=after_srt,
                                        before=before_str, team_id=team_id, )

    for item in response.get('content', []):
        item['cveId'] = cve_id

    hr = tableToMarkdown(name=f'Devices Associated with {cve_id}', t=response.get('content'),
                         headers=['id', 'zdeviceId', 'teamId', 'os'],
                         headerTransform=pascalToSpace)

    contex = {'Zimperium.DeviceByCVE(val.id == obj.id && val.cveId == obj.cveId)': response.get('content')}
    command_results = CommandResults(
        outputs=contex,
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def devices_os_version_command(client: Client, args: dict) -> CommandResults:
    """Search devices by os version.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    os_version = args.get('os_version')
    os_patch_date = arg_to_datetime(args.get('os_patch_date'))
    deleted = argToBoolean(args.get('deleted')) if args.get('deleted') else None
    after = arg_to_datetime(args.get('after'))
    before = arg_to_datetime(args.get('before'))
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    team_id = args.get('team_id')

    after_srt = after.strftime(DATE_FORMAT) if after else None
    os_patch_date_str = os_patch_date.strftime('YYYY-MM-DD') if os_patch_date else None
    before_str = before.strftime(DATE_FORMAT) if before else None

    size = page_size if page_size else limit

    response = client.devices_os_version(os_version=os_version, size=size, page=page, after=after_srt,
                                         before=before_str, team_id=team_id, deleted=deleted, os_patch_date=os_patch_date_str)

    hr = tableToMarkdown(name='Device Os Version', t=response.get('content'),
                         headers=['id', 'teamId', 'os'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.DeviceOsVersion',
        outputs=response.get('content'),
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def get_cves_by_device_command(client: Client, args: dict) -> CommandResults:
    """Search CVE for specific device.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    device_id = args.get('device_id')
    size = page_size if page_size else limit

    response = client.cve_devices_get(size=size, page=page, device_id=device_id)

    for item in response.get('content', []):
        item['deviceId'] = device_id

    hr = tableToMarkdown(name=f'CVE on Device {device_id}', t=response.get('content'),
                         headers=['id', 'type', 'severity', 'url', 'activeExploit', 'exploitPocUrl'],
                         headerTransform=pascalToSpace)

    contex = {'Zimperium.CVEByDevice(val.id == obj.id && val.deviceId == obj.deviceId)': response.get('content')}
    command_results = CommandResults(
        outputs=contex,
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def vulnerability_get_command(client: Client, args: dict) -> CommandResults:
    """Gets a list of vulnerabilities.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    size = page_size if page_size else limit

    response = client.vulnerability_get(size=size, page=page)

    hr = tableToMarkdown(name='Vulnerabilities List', t=response.get('content'),
                         headers=['id', 'os', 'osVersionAndPatchDate', 'osVersion', 'osPatchDate', 'risk',
                                  'cveCount', 'lastCveSync', 'osRiskChecksum', 'blueBorneVulnerable'],
                         date_fields=['lastCveSync'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Vulnerability',
        outputs=response.get('content'),
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_group_list_command(client: Client, args: dict) -> CommandResults:
    """List policies groups.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    module = args.get('module')
    response = client.policy_group_list(module)

    hr = tableToMarkdown(name='Policy Group List', t=response.get('content'),
                         headers=['id', 'name', 'team', 'emmConnectionId', 'privacyId', 'trmId', 'phishingPolicyId',
                                  'appSettingsId', 'appPolicyId', 'networkPolicyId', 'osRiskPolicyId'],
                         headerTransform=pascalToSpace,
                         removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyGroup',
        outputs=response.get('content'),
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_privacy_get_command(client: Client, args: dict) -> CommandResults:
    """Get privacy policy by id.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    policy_id = args.get('policy_id')

    response = client.policy_privacy(policy_id=policy_id)

    hr = tableToMarkdown(name='Privacy Policy', t=response,
                         headers=['id', 'name', 'created', 'modified', 'team', 'teamId'],
                         headerTransform=pascalToSpace,
                         removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyPrivacy',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_threat_get_command(client: Client, args: dict) -> CommandResults:
    """Get threat policy by id.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    policy_id = args.get('policy_id')

    response = client.policy_threat(policy_id=policy_id)

    hr = tableToMarkdown(name='Threat Policy', t=response,
                         headers=['id', 'isDeployed', 'name', 'created', 'modified'],
                         headerTransform=pascalToSpace,
                         removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyThreat',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_phishing_get_command(client: Client, args: dict) -> CommandResults:
    """Get phishing policy by id.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    policy_id = args.get('policy_id')

    response = client.policy_phishing(policy_id=policy_id)

    hr = tableToMarkdown(name='Phishing Policy', t=response,
                         headers=['id', 'name', 'created', 'modified', 'team', 'teamId',
                                  'enableSafariBrowserExtensionTutorial', 'enableDnsPhishingTutorial',
                                  'useLocalVpn', 'useUrlSharing', 'allowEndUserControl', 'useRemoteContentInspection',
                                  'enableMessageFilterTutorial',
                                  'phishingDetectionAction', 'phishingPolicyType'],
                         headerTransform=pascalToSpace,
                         removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyPhishing',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_app_settings_get_command(client: Client, args: dict) -> CommandResults:
    """Get policy app settings by id.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """

    app_settings_policy_id = args.get('app_settings_policy_id')

    response = client.policy_app_settings(app_settings_policy_id=app_settings_policy_id)

    hr = tableToMarkdown(name='Policy App Settings', t=response,
                         headers=['id', 'name', 'detectionEnabled', 'cogitoEnabled', 'cogitoThreshold', 'phishingEnabled',
                                  'phishingThreshold', 'phishingDBRefreshMinutes', 'created', 'modified', 'staticFilesWritten',
                                  'jsonHash', 'protoHash', 'dangerzoneEnabled', 'siteInsightEnabled',
                                  'phishingLocalClassifierEnabled', 'appRiskLookupEnabled', 'autoBatteryOptimizationEnabled',
                                  'autoActivateKnox', 'privacySummaryEnabled', 'forensicAnalysisEnabled', 'team', 'assigned',
                                  'teamId', 'global'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyAppSetting',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_device_inactivity_list_command(client: Client, args: dict) -> CommandResults:
    """List device inactivity policies

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    page = arg_to_number(args.get('page', '0'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', '50'))
    team_id = args.get('team_id')

    size = page_size if page_size else limit

    response = client.policy_device_inactivity_list(size=size, page=page, team_id=team_id)

    hr = tableToMarkdown(name='Device Inactivity List', t=response,
                         headers=['id', 'name', 'teamId'],
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyDeviceInactivity',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def policy_device_inactivity_get_command(client: Client, args: dict) -> CommandResults:
    """Get device inactivity policy by id.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    policy_id = args.get('policy_id')

    response = client.policy_device_inactivity_get(policy_id=policy_id)

    hr = tableToMarkdown(name='Device Inactivity', t=response,
                         headers=['id', 'name', 'teamId', 'pendingActivationSettings',
                                  'inactiveAppSettings', 'created', 'modified',
                                  ],
                         headerTransform=pascalToSpace,
                         removeNull=True,
                         date_fields=['created', 'modified']
                         )

    command_results = CommandResults(
        outputs_prefix='Zimperium.PolicyDeviceInactivity',
        outputs=response,
        outputs_key_field='id',
        readable_output=hr,
        raw_response=response,
    )
    return command_results


def fetch_incidents(client: Client, last_run: dict, fetch_query: Optional[list],
                    first_fetch_time: Optional[str], max_fetch: int, look_back: int = 1) -> tuple[list, dict]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Zimperium V2 client.
        last_run (dict): the last fetch object.
        fetch_query(list): fetch query to search.
        first_fetch_time (time): If last_run is None then fetch all incidents since first_fetch_time.
        max_fetch(int): max events to fetch.
        look_back(int): minutes to look back when fetching.

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created
    """
    fetch_query = fetch_query or []
    demisto.debug(f"Last run before the fetch run: {last_run}")
    limit = last_run.get('limit', max_fetch)
    start_time, end_time = get_fetch_run_time_range(
        last_run=last_run,
        first_fetch=first_fetch_time,
        look_back=look_back,
        date_format=DATE_FORMAT,
    )
    demisto.debug(f"fetching incidents between {start_time=} and {end_time=}, with {limit=}")

    search_params = {key: value for param in fetch_query for key, value in [param.split('=', 1)]}
    demisto.debug(f'The query for fetch: {search_params}')

    res = client.threat_search(after=start_time, search_params=search_params, size=limit, sort=FETCH_FIELD)
    incidents_res = res.get('content', [])
    demisto.debug(f'Got {len(incidents_res)} incidents from the API, before filtering')

    incidents_filtered = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents_res,
        last_run=last_run,
        fetch_limit=max_fetch,
        id_field='id'
    )
    demisto.debug(f'After filtering, there are {len(incidents_filtered)} incidents')

    incidents: list[dict] = []
    for incident in incidents_filtered:
        occurred = timestamp_to_datestring(incident.get(FETCH_FIELD))
        demisto.debug(f'Looking on: {incident.get("id")}, {occurred=}')
        incident[FETCH_FIELD] = occurred
        incidents.append({
            'name': f"Threat {incident.get('id')} on Device ID {incident.get('deviceId')}",
            'occurred': occurred,
            'dbotMirrorId': incident.get('id'),
            'severity': incident.get('severity'),
            'rawJSON': json.dumps(incident)
        })

    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents_filtered,
        fetch_limit=max_fetch,
        start_fetch_time=start_time,
        end_fetch_time=end_time,
        look_back=look_back,
        created_time_field=FETCH_FIELD,
        id_field='id',
        date_format=DATE_FORMAT,
        increase_last_run_time=False
    )
    demisto.debug(f"Last run after the fetch run: {last_run}")
    return incidents, last_run


def main():     # pragma: no cover
    params = demisto.params()
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('url'), '/api')
    verify = not params.get('insecure', False)
    proxy = argToBoolean(params.get('proxy', False))

    # fetch params
    max_fetch = arg_to_number(params.get('max_fetch', 50)) or 50
    fetch_query = argToList(params.get('fetch_query')) or []
    first_fetch = params.get('first_fetch', '7 days').strip()
    look_back = arg_to_number(params.get('look_back')) or 1

    first_fetch_time = arg_to_datetime(first_fetch)
    first_fetch_time_str = first_fetch_time.strftime(DATE_FORMAT) if first_fetch_time else None

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url=base_url, client_id=client_id, client_secret=client_secret, verify=verify, proxy=proxy)
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, first_fetch_time_str, fetch_query, max_fetch, look_back))

        elif command == 'fetch-incidents':
            incidents, next_run = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                fetch_query=fetch_query,
                first_fetch_time=first_fetch_time_str,
                max_fetch=max_fetch,
                look_back=look_back,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'zimperium-users-search':
            return_results(users_search_command(client, args))

        elif command == 'zimperium-devices-search':
            return_results(devices_search_command(client, args))

        elif command == 'zimperium-report-get':
            return_results(report_get_command(client, args))

        elif command == 'zimperium-threat-search':
            return_results(threat_search_command(client, args))

        elif command == 'zimperium-app-version-list':
            return_results(app_version_list_command(client, args))

        elif command == 'zimperium-get-devices-by-cve':
            return_results(get_devices_by_cve_command(client, args))

        elif command == 'zimperium-devices-os-version':
            return_results(devices_os_version_command(client, args))

        elif command == 'zimperium-get-cves-by-device':
            return_results(get_cves_by_device_command(client, args))

        elif command == 'zimperium-vulnerability-get':
            return_results(vulnerability_get_command(client, args))

        elif command == 'zimperium-policy-group-list':
            return_results(policy_group_list_command(client, args))

        elif command == 'zimperium-policy-privacy-get':
            return_results(policy_privacy_get_command(client, args))

        elif command == 'zimperium-policy-threat-get':
            return_results(policy_threat_get_command(client, args))

        elif command == 'zimperium-policy-phishing-get':
            return_results(policy_phishing_get_command(client, args))

        elif command == 'zimperium-policy-app-settings-get':
            return_results(policy_app_settings_get_command(client, args))

        elif command == 'zimperium-policy-device-inactivity-list':
            return_results(policy_device_inactivity_list_command(client, args))

        elif command == 'zimperium-policy-device-inactivity-get':
            return_results(policy_device_inactivity_get_command(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
