import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib


CSRF_PARSING_CHARS = 14


class Client:
    """
    Client to use in the APN-OS Policy Optimizer integration.
    """

    def __init__(self, url: str, username: str, password: str, vsys: str, device_group: str,
                 verify: bool, tid: int, version: str):
        # The TID is used to track individual commands send to the firewall/Panorama during a PHP session, and
        # is also used to generate the security token (Data String) that is used to validate each command.
        # Setting tid as a global variable with an arbitrary value of 50
        self.session_metadata: Dict[str, Any] = {'panorama': url, 'base_url': url, 'username': username,
                                                 'password': password, 'tid': tid}
        if device_group and vsys:
            raise DemistoException(
                'Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama.')
        if not device_group and not vsys:
            raise DemistoException('Set vsys for firewall or Device group for Panorama.')

        if vsys:  # firewall instance
            self.machine = vsys
            self.is_cms_selected = False
        else:
            self.machine = device_group
            self.is_cms_selected = True
        self.verify = verify
        self.version = version
        handle_proxy()
        # Use Session() in order to maintain cookies for persisting the login PHP session cookie
        self.session = requests.Session()

    def session_post(self, url: str, json_cmd: dict) -> dict:
        response = self.session.post(url=url, json=json_cmd, verify=self.verify,
                                     headers=self.session_metadata.get("headers"))
        json_response = json.loads(response.text)
        if 'type' in json_response and json_response['type'] == 'exception':
            if 'message' in json_response:
                raise Exception(f'Operation to PAN-OS failed. with: {str(json_response["message"])}')
            raise Exception(f'Operation to PAN-OS failed. with: {str(json_response)}')
        return json_response

    @staticmethod
    def extract_csrf(response_text: str) -> str:
        # the constant amount of chars until the value we want for the csrf
        csrf_start = response_text.find('_csrf') + CSRF_PARSING_CHARS
        csrf_end = response_text.find('"', csrf_start)
        return response_text[csrf_start:csrf_end]

    def login(self) -> str:  # pragma: no cover
        # This is the data sent to Panorama from the Login screen to complete the login and get a PHPSESSID cookie
        login_data = {
            'prot': 'https:',
            'server': self.session_metadata['panorama'],
            'authType': 'init',
            'challengeCookie': '',
            'user': self.session_metadata['username'],
            'passwd': self.session_metadata['password'],
            'challengePwd': '',
            'ok': 'Log In'
        }
        try:
            headers = {}
            if LooseVersion(self.version) >= LooseVersion('10.1.6'):
                # We do this to get the cookie we need to add to the requests in the new version of PAN-OS
                response = self.session.get(url=f'{self.session_metadata["base_url"]}/php/login.php?',
                                            verify=self.verify)
                csrf = self.extract_csrf(response.text)
                login_data['_csrf'] = csrf
                self.session_metadata["cookie"] = f'PHPSESSID={response.cookies.get_dict().get("PHPSESSID")}'
                headers = {
                    'Cookie': self.session_metadata["cookie"],
                }
            # Use a POST command to login to Panorama and create an initial session
            response = self.session.post(url=f'{self.session_metadata["base_url"]}/php/login.php?', data=login_data,
                                         verify=self.verify, headers=headers)
            self.session_metadata["cookie"] = f'PHPSESSID={response.cookies.get_dict().get("PHPSESSID")}'
            headers['Cookie'] = self.session_metadata["cookie"]
            # Use a GET command to the base URL to get the ServerToken which looks like this:
            #  window.Pan.st.st.st539091 = "8PR8ML4A67PUMD3NU00L3G67M4958B996F61Q97T"
            response = self.session.post(url=f'{self.session_metadata["base_url"]}/', verify=self.verify,
                                         headers=headers)
        except Exception as err:
            raise Exception(f'Failed to login. Please double-check the credentials and the server URL. {str(err)}')
        # Use RegEx to parse the ServerToken string from the JavaScript variable
        match = re.search(r'(?:window\.Pan\.st\.st\.st[0-9]+\s=\s\")(\w+)(?:\")', response.text)
        # Fix to login validation for version 9
        if LooseVersion(self.version) >= LooseVersion('9') and 'window.Pan.staticMOTD' not in response.text:
            match = None
        # The JavaScript calls the ServerToken a "cookie" so we will use that variable name
        # The "data" field is the MD5 calculation of "cookie" + "TID"
        if not match:
            raise Exception('Failed to login. Please double-check the credentials and the server URL.')
        return match.group(1)

    def logout(self):  # pragma: no cover
        self.session.post(url=f'{self.session_metadata["base_url"]}/php/logout.php?', verify=False)

    def token_generator(self) -> str:
        """
        The PHP Security Token (Data String) is generated with the TID (counter) and a special session "cookie"
        :return: hash token
        """
        data_code = f'{self.session_metadata["cookie_key"]}{str(self.session_metadata["tid"])}'
        # Use the hashlib library function to calculate the MD5, or SHA256 for version 10.2.0 and above
        if LooseVersion(self.version) >= LooseVersion('10.2.0'):
            data_hash = hashlib.sha256(data_code.encode())  # nosec
        else:
            data_hash = hashlib.md5(data_code.encode())  # nosec
        data_string = data_hash.hexdigest()  # Convert the hash to a proper hex string
        return data_string

    def get_policy_optimizer_statistics(self, position: str) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run", "data": [
                self.token_generator(),
                "PoliciesDirect.getRuleCountInRuleUsage",
                [{"type": "security", "position": position, "vsysName": self.machine}]
            ],
            "type": "rpc", "tid": self.session_metadata['tid']
        }

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getRuleCountInRuleUsage',
            json_cmd=json_cmd)

    def policy_optimizer_no_apps(self, position: str) -> dict:
        isCmsSelected = is_cms_selected(self.version, self.is_cms_selected)
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [
                self.token_generator(),
                "PoliciesDirect.getPoliciesByUsage", [
                    {
                        "type": "security",
                        "position": position,
                        "vsysName": self.machine,
                        "isCmsSelected": isCmsSelected,
                        "isMultiVsys": False,
                        "showGrouped": False,
                        "usageAttributes": {
                            "timeframeTag": "30",
                            "application/member": "any",
                            "apps-seen-count": "geq \'1\'",
                            "action": "allow"
                        },
                        "pageContext": "app_usage",
                        "field": "$.bytes",
                        "direction": "DESC"
                    }
                ]
            ],
            "type": "rpc",
            "tid": self.session_metadata['tid']}

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json_cmd=json_cmd)

    def policy_optimizer_get_unused_apps(self, position: str) -> dict:
        isCmsSelected = is_cms_selected(self.version, self.is_cms_selected)
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [
                self.token_generator(),
                "PoliciesDirect.getPoliciesByUsage",
                [
                    {
                        "type": "security",
                        "position": position,
                        "vsysName": self.machine,
                        "serialNumber": "",
                        "isCmsSelected": isCmsSelected,
                        "isMultiVsys": False,
                        "showGrouped": False,
                        "usageAttributes": {
                            "timeframeTag": "30",
                            "application/member": "unused",
                            "action": "allow"
                        },
                        "pageContext": "app_usage",
                        "field": "$.bytes",
                        "direction": "DESC"
                    }
                ]
            ],
            "type": "rpc",
            "tid": self.session_metadata['tid']}

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json_cmd=json_cmd)

    def policy_optimizer_get_rules(self, timeframe: str, usage: str, exclude: bool, position: str, rule_type: str,
                                   page_size: int = 200, limit: int = 200, page: int | None = None) -> dict:
        def generate_paginated_request(_start: int, _limit: int) -> dict:
            return {
                "action": "PanDirect", "method": "run",
                "data": [
                    self.token_generator(),
                    "PoliciesDirect.getPoliciesByUsage",
                    [
                        {
                            "type": rule_type,
                            "position": position,
                            "vsysName": self.machine,
                            "isCmsSelected": self.is_cms_selected,
                            "isMultiVsys": False,
                            "showGrouped": False,
                            "usageAttributes": {
                                "timeframe": timeframe,
                                "usage": usage, "exclude": exclude,
                                "exclude-reset-text": "90"
                            },
                            "pageContext": "rule_usage",
                            "start": _start,
                            "limit": _limit,
                        }
                    ]
                ],
                "type": "rpc",
                "tid": self.session_metadata['tid'],
            }

        self.session_metadata['tid'] += 1  # Increment TID

        start = page_size * (page - 1) if page else 0

        response = self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json_cmd=generate_paginated_request(_start=start, _limit=min(page_size, limit)),
        )

        if page:  # If returning a specific page, we don't need to handle pagination
            return response

        # Handle pagination
        total_results_count = int(response.get('result', {}).get('result', {}).get('@total-count', 0))
        collected_results_count = int(response.get('result', {}).get('result', {}).get('@count', 0))

        while collected_results_count < limit and collected_results_count < total_results_count:
            offset = collected_results_count
            remaining_results_count = min(total_results_count - collected_results_count, limit - collected_results_count)

            if remaining_results_count > page_size:  # If we have more than 'page_size' results left to fetch
                current_limit = page_size

            else:  # If we have less than 'page_size' results left, we'll set the limit to the amount of the remaining results
                current_limit = remaining_results_count

            current_response = self.session_post(
                url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
                json_cmd=generate_paginated_request(_start=offset, _limit=current_limit),
            )

            # Update collected results
            current_entry_data = current_response.get('result', {}).get('result', {}).get('entry', [])
            response['result']['result']['entry'].extend(current_entry_data)

            # Update collected results count
            current_results_count = int(current_response.get('result', {}).get('result', {}).get('@count', 0))
            collected_results_count += current_results_count
            response['result']['result']['@count'] = str(collected_results_count)

        return response

    def policy_optimizer_app_and_usage(self, rule_uuid: str) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {"action": "PanDirect", "method": "run",
                    "data": [
                        self.token_generator(),
                        "PoliciesDirect.getAppDetails",
                        [
                            {
                                "type": "security",
                                "vsysName": self.machine,
                                "position": "main",
                                "ruleUuidList": [rule_uuid],
                                "summary": "no",
                                "resultfields":
                                    "<member>apps-seen</member>"
                                    "<member>last-app-seen-since-count"
                                    "</member><member>days-no-new-app-count</member>",
                                "appsSeenTimeframe": "any",
                                "trafficTimeframe": 30
                            }
                        ]
                    ],
                    "type": "rpc",
                    "tid": self.session_metadata['tid']}

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getAppDetails',
            json_cmd=json_cmd)

    def policy_optimizer_get_dag(self, dag: str) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect",
            "method": "execute",
            "data": [
                self.token_generator(),
                "AddressGroup.showDynamicAddressGroup", {
                    "id": dag,
                    "vsysName": self.machine
                }
            ],
            "type": "rpc",
            "tid": self.session_metadata['tid']}

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/AddressGroup.showDynamicAddressGroup',
            json_cmd=json_cmd)


def get_unused_rules_by_position(client: Client, position: str, exclude: bool, rule_type: str, usage: str,
                                 timeframe: str, page_size: int, limit: int, page: int | None = None) -> tuple[Dict, List]:
    """
    Get unused rules from panorama based on user defined arguments.
    """

    raw_response = client.policy_optimizer_get_rules(
        timeframe=timeframe, usage=usage, exclude=exclude, position=position, rule_type=rule_type,
        page_size=page_size, limit=limit, page=page,
    )

    stats = raw_response.get('result', {})
    if stats.get('@status') == 'error':
        raise Exception(f'Operation failed: {stats}')

    return raw_response, stats.get('result', {}).get('entry', [])


def get_policy_optimizer_statistics_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    Args:
        client:  APN-OS Policy Optimizer client
        args:  Demisto arguments, will be used in panorama instance only
    """
    outputs_stats = {}
    # panorama instance has multiple positions, firewall instance has only main position
    position = define_position(version=client.version, args=args, is_panorama=client.is_cms_selected)
    client.machine = args.get('device_group') or client.machine

    raw_response = client.get_policy_optimizer_statistics(position)
    stats = raw_response['result']
    if '@status' in stats and stats['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(stats)}')

    stats = stats['result']
    # we need to spin the keys and values and put them into dict so they'll look better in the context
    for i in stats['entry']:
        outputs_stats[i['@name']] = i['text']

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.Stats',
        outputs=outputs_stats,
        readable_output=tableToMarkdown(name='Policy Optimizer Statistics:', t=stats['entry'], removeNull=True),
        raw_response=raw_response
    )


def policy_optimizer_no_apps_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    Args:
        client:  APN-OS Policy Optimizer client
        args:  Demisto arguments, will be used in panorama instance only
    Returns:
        CommandResults object
    """
    # panorama instance has multiple positions, firewall instance has only main position
    position = define_position(version=client.version, args=args, is_panorama=client.is_cms_selected)
    client.machine = args.get('device_group') or client.machine

    raw_response = client.policy_optimizer_no_apps(position=position)
    stats = raw_response['result']
    if '@status' in stats and stats['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(stats)}')

    stats = stats['result']
    if '@count' in stats and stats['@count'] == '0':
        return CommandResults(readable_output='No Rules without apps were found.', raw_response=raw_response)

    rules_no_apps = stats['entry']
    if not isinstance(rules_no_apps, list):
        rules_no_apps = rules_no_apps[0]

    headers = ['@name', '@uuid', 'action', 'description', 'source', 'destination']

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.NoApps',
        outputs_key_field='@uuid',
        outputs=rules_no_apps,
        readable_output=tableToMarkdown(name='Policy Optimizer No App Specified:', t=rules_no_apps, headers=headers,
                                        removeNull=True),
        raw_response=raw_response
    )


def policy_optimizer_get_unused_apps_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    Args:
        client:  APN-OS Policy Optimizer client
        args:  Demisto arguments, will be used in panorama instance only
    Returns:
        CommandResults object
    """
    # panorama instance has multiple positions, firewall instance has only main position
    position = define_position(version=client.version, args=args, is_panorama=client.is_cms_selected)
    client.machine = args.get('device_group') or client.machine

    raw_response = client.policy_optimizer_get_unused_apps(position=position)
    stats = raw_response['result']
    if '@status' in stats and stats['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(stats)}')

    stats = stats['result']
    if '@count' in stats and stats['@count'] == '0':
        return CommandResults(readable_output='No Rules with unused apps were found.', raw_response=raw_response)

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.UnusedApps',
        outputs_key_field='Stats',
        outputs=stats,
        readable_output=tableToMarkdown(name='Policy Optimizer Unused Apps:', t=stats['entry'], removeNull=True),
        raw_response=raw_response
    )


def policy_optimizer_get_rules_command(client: Client, args: dict) -> CommandResults:
    """
    Get rules information from Panorama/Firewall instances.
    """
    timeframe: str = args['timeframe']
    usage: str = args['usage']
    exclude: bool = argToBoolean(args.get('exclude', False))
    position: str = args['position'] if client.is_cms_selected else 'main'  # Firewall instances have only main position
    rule_type: str = args.get('rule_type', 'security')
    page_size: int = arg_to_number(args.get('page_size')) or 200
    limit: int = arg_to_number(args.get('limit')) or 200
    page: int | None = arg_to_number(args.get('page'))

    client.machine = args.get('device_group') or client.machine

    if page_size > 200:
        raise ValueError('The maximum page size is 200.')

    params: dict[str, Any] = {  # All params without the 'position' param
        'client': client,
        'exclude': exclude,
        'rule_type': rule_type,
        'usage': usage,
        'timeframe': timeframe,
        'page_size': page_size,
        'limit': limit,
        'page': page,
    }

    rules = []

    if position == 'both':
        post_raw, post_rules = get_unused_rules_by_position(position='post', **params)
        pre_raw, pre_rules = get_unused_rules_by_position(position='pre', **params)
        raw_response = {
            'post': post_raw,
            'pre': pre_raw,
        }
        rules.extend(post_rules)
        rules.extend(pre_rules)

    else:
        raw_response, rules = get_unused_rules_by_position(position=position, **params)

    if rules:
        headers = ['@name', '@uuid', 'action', 'description', 'source', 'destination']
        table = tableToMarkdown(
            name=f'PolicyOptimizer {usage.capitalize()} {rule_type.capitalize()} Rules: ({len(rules)} Results)',
            t=rules, headers=headers, removeNull=True
        )
    else:
        table = f'No {usage.lower()} {rule_type.lower()} rules were found.'

    return CommandResults(
        outputs_prefix=f'PanOS.PolicyOptimizer.{usage}Rules',
        outputs_key_field='@uuid',
        outputs=rules,
        readable_output=table,
        raw_response=raw_response
    )


def policy_optimizer_app_and_usage_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    rule_uuid = str(args.get('rule_uuid'))
    client.machine = args.get('device_group') or client.machine

    raw_response = client.policy_optimizer_app_and_usage(rule_uuid)

    stats = raw_response['result']
    if '@status' in stats and stats['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(stats)}')

    stats = stats['result']
    if '@count' in stats and stats['@count'] == '0':
        return CommandResults(readable_output=f'Rule with UUID:{rule_uuid} does not use apps.',
                              raw_response=raw_response)

    rule_stats = stats['rules']['entry'][0]

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.AppsAndUsage',
        outputs_key_field='@uuid',
        outputs=rule_stats,
        readable_output=tableToMarkdown(name='Policy Optimizer Apps and Usage:', t=rule_stats, removeNull=True),
        raw_response=raw_response
    )


def policy_optimizer_get_dag_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the Dynamic Address group.
    """
    dag = str(args.get('dag'))

    client.machine = args.get('device_group') or client.machine

    raw_response = client.policy_optimizer_get_dag(dag)
    result = raw_response['result']
    if '@status' in result and result['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(result)}')

    try:
        result = result['result']['dyn-addr-grp']['entry'][0]['member-list']['entry']
    except (KeyError, TypeError, IndexError):
        return CommandResults(readable_output=f'Dynamic Address Group {dag} was not found.', raw_response=raw_response)

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.DAG',
        outputs_key_field='Stats',
        outputs=result,
        readable_output=tableToMarkdown(name='Policy Optimizer Dynamic Address Group:', t=result, removeNull=True),
        raw_response=raw_response
    )


''' HELPER FUNCTIONS '''


def define_position(version: str, args: dict, is_panorama: bool) -> str:
    """
    This function defines the rule's position in the query. For Panorama instances from versions 10.1.10 and above
    it uses the `position` argument;
    for Firewall instances, it always uses 'main' position.
    Currently, it's fixed for versions 10.1.10 and above, as those are the accessible versions.
    Args:
        version: PAN-OS version
        args: Demisto arguments
        is_panorama: True if the instance is Panorama, False if the instance is a firewall
    Returns:
        The position of the rule in the query (pre, post or main)
    """
    if LooseVersion(version) >= LooseVersion('10.1.10') and is_panorama:
        return args.get('position', 'pre')
    else:
        return 'main'


def is_cms_selected(version: str, is_panorama: bool) -> bool:
    """"
    in panorama the 'isCmsSelected' parameter should be True, in firewall it is False.
    this should be probably fixed in all versions,
    but for now we'll just fix it for version 10.1.10 and above since that's the version we have access to.
    Args:
        version (str): PAN-OS version
        is_panorama (bool): True if the instance is Panorama, False if the instance is a firewall

    Returns:
        bool: True or False
    """
    return is_panorama if LooseVersion(version) >= LooseVersion('10.1.10') else False


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    version = params.get('version') or '8'
    demisto.debug(f'Command being called is: {command}')
    client: Client = None  # type: ignore
    try:
        client = Client(url=params.get('server_url'), username=params['credentials']['identifier'],
                        password=params['credentials']['password'], vsys=params.get('vsys'),
                        device_group=params.get('device_group'), verify=not params.get('insecure'), tid=50, version=version)
        client.session_metadata['cookie_key'] = client.login()  # Login to PAN-OS and return the GUI cookie value
        headers = {}
        if LooseVersion(version) >= LooseVersion('10.1.6'):
            headers['Cookie'] = client.session_metadata["cookie"]
            headers['Content-Type'] = 'application/json'
            client.session_metadata["headers"] = headers
        if command == 'test-module':
            # run a command to test connectivity
            get_policy_optimizer_statistics_command(client, args)
            return_results('ok')
        elif command == 'pan-os-po-get-stats':
            return_results(get_policy_optimizer_statistics_command(client, args))
        elif command == 'pan-os-po-no-apps':
            return_results(policy_optimizer_no_apps_command(client, args))
        elif command == 'pan-os-po-unused-apps':
            return_results(policy_optimizer_get_unused_apps_command(client, args))
        elif command == 'pan-os-po-get-rules':
            return_results(policy_optimizer_get_rules_command(client, args))
        elif command == 'pan-os-po-app-and-usage':
            return_results(policy_optimizer_app_and_usage_command(client, args))
        elif command == 'pan-os-get-dag':
            return_results(policy_optimizer_get_dag_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')

    except Exception as err:
        return_error(f'{str(err)}.\n Trace:{traceback.format_exc()}')

    finally:
        try:
            client.logout()  # Logout of PAN-OS
        except Exception as err:
            return_error(f'{str(err)}.\n Trace:{traceback.format_exc()}')


if __name__ in ("__builtin__", "builtins", '__main__'):
    main()
