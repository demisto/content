import hashlib

from CommonServerPython import *


class Client:
    """
    Client to use in the APN-OS Policy Optimizer integration.
    """
    def __init__(self, url: str, username: str, password: str, vsys: str, device_group: str, verify: bool, tid: int):
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
        handle_proxy()
        # Use Session() in order to maintain cookies for persisting the login PHP session cookie
        self.session = requests.Session()

    def session_post(self, url: str, json_cmd: dict) -> dict:
        response = self.session.post(url=url, json=json_cmd, verify=self.verify)
        json_response = json.loads(response.text)
        if 'type' in json_response and json_response['type'] == 'exception':
            if 'message' in json_response:
                raise Exception(f'Operation to PAN-OS failed. with: {str(json_response["message"])}')
            raise Exception(f'Operation to PAN-OS failed. with: {str(json_response)}')
        return json_response

    def login(self) -> str:
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
            # Use a POST command to login to Panorama and create an initial session
            self.session.post(url=f'{self.session_metadata["base_url"]}/php/login.php?', data=login_data,
                              verify=self.verify)
            # Use a GET command to the base URL to get the ServerToken which looks like this:
            #  window.Pan.st.st.st539091 = "8PR8ML4A67PUMD3NU00L3G67M4958B996F61Q97T"
            response = self.session.post(url=f'{self.session_metadata["base_url"]}/', verify=self.verify)
        except Exception as err:
            raise Exception(f'Failed to login. Please double-check the credentials and the server URL. {str(err)}')
        # Use RegEx to parse the ServerToken string from the JavaScript variable
        match = re.search(r'(?:window\.Pan\.st\.st\.st[0-9]+\s=\s\")(\w+)(?:\")', response.text)
        # The JavaScript calls the ServerToken a "cookie" so we will use that variable name
        # The "data" field is the MD5 calculation of "cookie" + "TID"
        if not match:
            raise Exception('Failed to login. Please double-check the credentials and the server URL.')
        return match.group(1)

    def logout(self):
        self.session.post(url=f'{self.session_metadata["base_url"]}/php/logout.php?', verify=False)

    def token_generator(self) -> str:
        """
        The PHP Security Token (Data String) is generated with the TID (counter) and a special session "cookie"
        :return: hash token
        """
        data_code = f'{self.session_metadata["cookie"]}{str(self.session_metadata["tid"])}'
        data_hash = hashlib.md5(data_code.encode())  # Use the hashlib library function to calculate the MD5
        data_string = data_hash.hexdigest()  # Convert the hash to a proper hex string
        return data_string

    def get_policy_optimizer_statistics(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run", "data": [
                self.token_generator(),
                "PoliciesDirect.getRuleCountInRuleUsage",
                [{"type": "security", "position": "main", "vsysName": self.machine}]
            ],
            "type": "rpc", "tid": self.session_metadata['tid']
        }

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getRuleCountInRuleUsage',
            json_cmd=json_cmd)

    def policy_optimizer_no_apps(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [
                self.token_generator(),
                "PoliciesDirect.getPoliciesByUsage", [
                    {
                        "type": "security",
                        "position": "main",
                        "vsysName": self.machine,
                        "isCmsSelected": False,
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

    def policy_optimizer_get_unused_apps(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [
                self.token_generator(),
                "PoliciesDirect.getPoliciesByUsage",
                [
                    {
                        "type": "security",
                        "position": "main",
                        "vsysName": self.machine,
                        "serialNumber": "",
                        "isCmsSelected": False,
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

    def policy_optimizer_get_rules(
        self, timeframe: str, usage: str, exclude: bool, position: str, rule_type: str
    ) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
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
                        "pageContext": "rule_usage"
                    }
                ]
            ], "type": "rpc",
            "tid": self.session_metadata['tid']}

        return self.session_post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json_cmd=json_cmd)

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


def get_policy_optimizer_statistics_command(client: Client) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    outputs_stats = {}
    raw_response = client.get_policy_optimizer_statistics()

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


def policy_optimizer_no_apps_command(client: Client) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    raw_response = client.policy_optimizer_no_apps()

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


def policy_optimizer_get_unused_apps_command(client: Client) -> CommandResults:
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    raw_response = client.policy_optimizer_get_unused_apps()

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
    timeframe = args.get('timeframe')
    usage = args.get('usage')
    exclude = argToBoolean(args.get('exclude'))
    position = args.get('position') or 'post'
    rule_type = args.get('rule_type') or 'security'

    position = position if client.is_cms_selected else 'main'  # firewall instance only has position main

    raw_response = client.policy_optimizer_get_rules(
        timeframe=timeframe, usage=usage, exclude=exclude, position=position, rule_type=rule_type  # type: ignore
    )

    stats = raw_response.get('result') or {}
    if (stats.get('@status') or '') == 'error':
        raise Exception(f'Operation Failed with: {stats}')

    rules = (stats.get('result') or {}).get('entry') or []
    if rules:
        headers = ['@name', '@uuid', 'action', 'description', 'source', 'destination']
        table = tableToMarkdown(
            name=f'PolicyOptimizer {usage}-{rule_type}-rules:', t=rules, headers=headers, removeNull=True
        )
    else:
        table = f'No {usage} {rule_type} rules where found.'

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

    raw_response = client.policy_optimizer_app_and_usage(rule_uuid)

    stats = raw_response['result']
    if '@status' in stats and stats['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(stats)}')

    stats = stats['result']
    if '@count' in stats and stats['@count'] == '0':
        return CommandResults(readable_output=f'Rule with UUID:{rule_uuid} does not use apps.', raw_response=raw_response)

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
    Gets the DAG
    """
    dag = str(args.get('dag'))
    raw_response = client.policy_optimizer_get_dag(dag)
    result = raw_response['result']
    if '@status' in result and result['@status'] == 'error':
        raise Exception(f'Operation Failed with: {str(result)}')

    try:
        result = result['result']['dyn-addr-grp']['entry'][0]['member-list']['entry']
    except KeyError:
        raise Exception(f'Dynamic Address Group: {dag} was not found.')

    return CommandResults(
        outputs_prefix='PanOS.PolicyOptimizer.DAG',
        outputs_key_field='Stats',
        outputs=result,
        readable_output=tableToMarkdown(name='Policy Optimizer Dynamic Address Group:', t=result, removeNull=True),
        raw_response=raw_response
    )


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f'Command being called is: {command}')
    client: Client = None  # type: ignore
    try:
        client = Client(url=params.get('server_url'), username=params['credentials']['identifier'],
                        password=params['credentials']['password'], vsys=params.get('vsys'),
                        device_group=params.get('device_group'), verify=not params.get('insecure'), tid=50)
        client.session_metadata['cookie'] = client.login()  # Login to PAN-OS and return the GUI cookie value

        if command == 'test-module':
            return_results('ok')  # if login was successful, instance configuration is ok.
        elif command == 'pan-os-po-get-stats':
            return_results(get_policy_optimizer_statistics_command(client))
        elif command == 'pan-os-po-no-apps':
            return_results(policy_optimizer_no_apps_command(client))
        elif command == 'pan-os-po-unused-apps':
            return_results(policy_optimizer_get_unused_apps_command(client))
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
