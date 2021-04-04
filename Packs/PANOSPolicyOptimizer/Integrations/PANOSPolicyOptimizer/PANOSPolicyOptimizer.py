import hashlib

import demistomock as demisto

from CommonServerPython import *


class Client:
    """
    Client to use in the APN-OS Policy Optimizer integration.
    """

    def __init__(self, url: str, username: str, password: str, vsys: str, verify: bool, tid: int):
        # The TID is used to track individual commands send to the firewall/Panorama during a PHP session, and
        # is also used to generate the security token (Data String) that is used to validate each command.
        # Setting tid as a global variable with an arbitrary value of 50
        self.session_metadata = {'panorama': url, 'base_url': url, 'username': username,
                                 'password': password, 'tid': tid}
        self.vsys = vsys
        self.verify = verify
        handle_proxy()
        # Use Session() in order to maintain cookies for persisting the login PHP session cookie
        self.session = requests.Session()

    def login(self) -> str:
        # This is the data sent to Panorama from the Login screen to complete the login and get a PHPSESSID cookie
        login_data = {'prot': 'https:',
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
            #   window.Pan.st.st.st539091 = "8PR8ML4A67PUMD3NU00L3G67M4958B996F61Q97T"
            response = self.session.post(url=f'{self.session_metadata["base_url"]}/', verify=self.verify)
        except Exception as err:
            raise Exception(f'Failed to login. Please double-check the credentials and the server URL. {str(err)}')
        # Use RegEx to parse the ServerToken string from the JavaScript variable
        match = re.search(r'(?:window\.Pan\.st\.st\.st[0-9]+\s=\s\")(\w+)(?:\")', response.text)
        # The JavaScript calls the ServerToken a "cookie" so we will use that variable name
        # The "data" field is the MD5 calculation of "cookie" + "TID"
        return match.group(1)

    def logout(self):
        self.session.post(url=f'{self.session_metadata["base_url"]}/php/logout.php?', verify=False)

    def token_generator(self) -> str:
        """
        The PHP Security Token (Data String) is generated with the TID (counter) and a special session "cookie"
        :return: hash token
        """
        data_code = f'{self.session_metadata["cookie"]}{str(self.session_metadata["tid"])}'
        # Use the hashlib library function to calculate the MD5
        data_hash = hashlib.md5(data_code.encode())
        # Convert the hash to a proper hex string
        data_string = data_hash.hexdigest()
        return data_string

    def get_policy_optimizer_statistics(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run", "data": [
                self.token_generator(),
                "PoliciesDirect.getRuleCountInRuleUsage",
                [{"type": "security", "position": "main", "vsysName": self.vsys}]
            ],
            "type": "rpc", "tid": self.session_metadata['tid']
        }

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getRuleCountInRuleUsage',
            json=json_cmd)

        return json.loads(response.text)

    def policy_optimizer_no_apps(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [self.token_generator(),
                     "PoliciesDirect.getPoliciesByUsage", [
                         {"type": "security", "position": "main",
                          "vsysName": self.vsys, "serialNumber": "",
                          "isCmsSelected": False, "isMultiVsys": False,
                          "showGrouped": False,
                          "usageAttributes": {"timeframeTag": "30",
                                              "application/member": "any",
                                              "apps-seen-count": "geq \'1\'",
                                              "action": "allow"},
                          "pageContext": "app_usage", "field": "$.bytes",
                          "direction": "DESC"}]], "type": "rpc",
            "tid": self.session_metadata['tid']}

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json=json_cmd)

        return json.loads(response.text)

    def policy_optimizer_get_unused_apps(self) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [self.token_generator(),
                     "PoliciesDirect.getPoliciesByUsage",
                     [{"type": "security", "position": "main",
                       "vsysName": self.VSYS, "serialNumber": "",
                       "isCmsSelected": False, "isMultiVsys": False,
                       "showGrouped": False,
                       "usageAttributes": {"timeframeTag": "30",
                                           "application/member": "unused",
                                           "action": "allow"},
                       "pageContext": "app_usage", "field": "$.bytes",
                       "direction": "DESC"}]], "type": "rpc",
            "tid": self.session_metadata['tid']}

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json=json_cmd)

        return json.loads(response.text)

    def policy_optimizer_get_rules_command(self, timeframe, usage: bool, exclude: bool) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {
            "action": "PanDirect", "method": "run",
            "data": [self.token_generator(),
                     "PoliciesDirect.getPoliciesByUsage",
                     [{"type": "security", "position": "main",
                       "vsysName": self.vsys, "serialNumber": "",
                       "isCmsSelected": False, "isMultiVsys": False,
                       "showGrouped": False,
                       "usageAttributes": {"timeframe": timeframe,
                                           "usage": usage, "exclude": exclude,
                                           "exclude-reset-text": "90"},
                       "pageContext": "rule_usage"}]], "type": "rpc",
            "tid": self.session_metadata['tid']}

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
            json=json_cmd)

        return json.loads(response.text)

    # def getUnusedIn30daysRules(self):
    #     self.session_metadata['tid'] += 1  # Increment TID
    #     json_cmd = {"action": "PanDirect", "method": "run",
    #                 "data": [self.token_generator(),
    #                          "PoliciesDirect.getPoliciesByUsage",
    #                          [{"type": "security", "position": "main",
    #                            "vsysName": self.vsys, "serialNumber": "",
    #                            "isCmsSelected": False, "isMultiVsys": False,
    #                            "showGrouped": False,
    #                            "usageAttributes": {"timeframe": "30",
    #                                                "usage": "Unused",
    #                                                "exclude": False,
    #                                                "exclude-reset-text": "30"},
    #                            "pageContext": "rule_usage"}]], "type": "rpc",
    #                 "tid": self.session_metadata['tid']}
    #
    #     response = self.session.post(
    #         url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage',
    #         json=json_cmd)
    #
    #     return json.loads(response.text)

    def policy_optimizer_app_and_usage(self, rule_uuid) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {"action": "PanDirect", "method": "run",
                    "data": [self.token_generator(),
                             "PoliciesDirect.getAppDetails",
                             [{"type": "security", "vsysName": self.vsys,
                               "position": "main", "ruleUuidList": [rule_uuid],
                               "summary": "no",
                               "resultfields":
                                   "<member>apps-seen</member>"
                                   "<member>last-app-seen-since-count"
                                   "</member><member>days-no-new-app-count</member>",
                               "appsSeenTimeframe": "any",
                               "trafficTimeframe": 30}]],
                    "type": "rpc", "tid": self.session_metadata['tid']}

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getAppDetails',
            json=json_cmd)

        return json.loads(response.text)

    def policy_optimizer_get_dag(self, dag: str) -> dict:
        self.session_metadata['tid'] += 1  # Increment TID
        json_cmd = {"action": "PanDirect", "method": "execute",
                    "data": [self.token_generator(), "AddressGroup.showDynamicAddressGroup", {
                        "id": dag, "vsysName": self.vsys}], "type": "rpc", "tid": self.session_metadata['tid']}

        response = self.session.post(
            url=f'{self.session_metadata["base_url"]}/php/utils/router.php/AddressGroup.showDynamicAddressGroup',
            json=json_cmd)

        return json.loads(response.text)


def get_policy_optimizer_statistics_command(client: Client):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    res_sta = {}
    stats = client.get_policy_optimizer_statistics()

    result = stats['result']['result']
    # we need to spin the keys and values and put them into dict so they'll look better in the context
    for i in result['entry']:
        res_sta[i['@name']] = i['text']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Statistics", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.Stats(val.Stats == obj.Stats)": res_sta}
    })


def policy_optimizer_no_apps_command(client: Client):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = client.policy_optimizer_no_apps()

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer No App Specified", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.NoApps(val.Stats == obj.Stats)": result}
    })


def policy_optimizer_get_unused_apps_command(client: Client):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = client.policy_optimizer_get_unused_apps()

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Unused Apps", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.UnusedApps(val.Stats == obj.Stats)": result}
    })


def policy_optimizer_get_rules_command(client: Client, args: dict):
    """
    Gets the unused rules Statistics as seen from the User Interface
    """
    timeframe = args.get('timeframe')
    usage = argToBoolean(args.get('usage'))
    exclude = argToBoolean(args.get('exclude'))
    stats = client.policy_optimizer_get_rules(timeframe, usage, exclude)
    demisto.info(json.dumps(stats, indent=2))
    result = stats['result']['result']['entry']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer " + usage + " Rules", result),
        'EntryContext': {"PanOS.PolicyOptimizer." + usage + "Rules(val.Stats == obj.Stats)": result}
    })


def policy_optimizer_app_and_usage_command(client: Client, args: dict):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    context_res = {}
    rule_uuid = args.get('rule_uuid')
    stats = client.policy_optimizer_app_and_usage(rule_uuid)
    result = stats['result']['result']['rules']['entry'][0]['apps-seen']['entry']
    rule_name = stats['result']['result']['rules']['entry'][0]['@name']
    context_res[rule_name] = result
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Apps and Usage", result),
        'EntryContext': {"PanOS.PolicyOptimizer.AppsAndUsage(val.Stats == obj.Stats)": context_res}
    })


def policy_optimizer_get_dag_command(client: Client, args: dict):
    """
    Gets the DAG
    """
    dag = args.get('dag')
    result = client.policy_optimizer_get_dag(dag)['result']['result']['dyn-addr-grp']['entry'][0]['member-list']['entry']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Dynamic Address Group", result),
        'EntryContext': {"PanOS.DAG(val.Stats == obj.Stats)": result}
    })


def main():
    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()

        if not demisto.params().get('port'):
            raise Exception('Set a port for the instance')
        url = f'{params.get("server").rstrip("/:")}:{params.get("port")}'

        demisto.debug(f'Command being called is: {command}')
        client = Client(url=url, username=params['credentials']['identifier'],
                        password=params['credentials']['password'], vsys=params.get('vsys', 'vsys1'),
                        verify=not params.get('insecure'), tid=50)
        client.session_metadata['cookie'] = client.login()  # Login to PAN-OS and return the GUI cookie value

        if command == 'test-module':
            return_results('ok')  # if login was successful, instance configuration is ok.
        elif command == 'pan-os-po-get-stats':
            get_policy_optimizer_statistics_command(client)
        elif command == 'pan-os-po-no-apps':
            policy_optimizer_no_apps_command(client)
        elif command == 'pan-os-po-unused-apps':
            policy_optimizer_get_unused_apps_command(client)
        elif command == 'pan-os-po-get-rules':
            policy_optimizer_get_rules_command(client, args)
        elif command == 'pan-os-po-app-and-usage':
            policy_optimizer_app_and_usage_command(client, args)
        elif command == 'pan-os-get-dag':
            policy_optimizer_get_dag_command(client, args)
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')

    except Exception as err:
        return_error(f'{str(err)}.\n Trace:{traceback.format_exc()}')

    finally:
        client.logout()  # Logout of PAN-OS


if __name__ in ("__builtin__", "builtins", '__main__'):
    main()
