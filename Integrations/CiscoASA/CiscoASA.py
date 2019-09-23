import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
from requests.auth import HTTPBasicAuth
import socket

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARIABLES'''


'''Client'''
class Client:
    def __init__(self, url, username, password, verify, proxies):
        self.base_url = url
        self.username = username
        self.password = password
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix
        res = requests.request(
                method,
                full_url,
                verify=self.verify,
                params=params,
                json=data,
                auth = (self.username, self.password)
                )
        if res.status_code not in [200, 204, 201]:
            raise ValueError('Error in API call to url [%s]. Status Code: [%d]. Reason: %s' % (full_url,
                                                                                               res.status_code,
                                                                                               res.text))

        if res.status_code == 201:
            return res.headers.get('Location')
        try:
            return res.json()
        except Exception:
            raise ValueError(
                "Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))


    def get_all_rules(self, specific_interface=None, rule_type='All', rule_id=None):
        """
        :param rule_type:
        :return: rules
        Returns all rules in Cisco ASA of the specified type/interface/rule id
        """
        rules = []
        ## Get global rules
        if specific_interface is None and rule_type in ['All', 'Global']:
            res = self.http_request('GET', '/api/access/global/rules')
            items = res.get('items', [])
            for item in items:
                item['interface_type'] = "Global"
            rules.extend(items)

        ## Get in rules
        if rule_type in ['All', 'In']:
            res = self.http_request('GET', '/api/access/in')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self.http_request('GET', '/api/access/in/{}/rules'.format(interface))
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "In"
                rules.extend(items)


        ## Get out rules
        if rule_type in ['All', 'Out']:
            res = self.http_request('GET', '/api/access/out')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self.http_request('GET', '/api/access/out/{}/rules'.format(interface))
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "Out"
                print(items)
                rules.extend(items)

        return rules

    def get_rule(self, rule_id, interface_name, interface_type):
        if interface_type == "Global":
            rule =  self.http_request('GET', '/api/access/global/rules/{}'.format(rule_id))
        if interface_type == "In":
            rule = self.http_request('GET', '/api/access/in/{}/rules/{}'.format(interface_name, rule_id))
        if interface_type == 'Out':
            rule = self.http_request('GET', '/api/access/out/{}/rules/{}'.format(interface_name, rule_id))
        rule['interface'] = interface_name
        rule['interface_type'] = interface_type
        return rule


    def create_rule_in_api(self,interface_type, interface_name, rule_body):
        if interface_type == "Global":
            loc = self.http_request('POST', '/api/access/global/rules', data=rule_body)
        if interface_type == 'In':
            loc =  self.http_request('POST', '/api/access/in/{}/rules'.format(interface_name), data=rule_body)
        if interface_type == 'Out':
            loc =  self.http_request('POST', '/api/access/out/{}/rules'.format(interface_name), data=rule_body)
        rule = self.http_request('GET', loc[loc.find('/api'):])
        rule['interface'] = interface_name
        rule['interface_type'] = interface_type
        return rule

'''HELPER COMMANDS'''


@logger
def raw_to_rules(raw_rules):
    """
    :param raw_rules:
    :return:
    Gets raw rules as received from API and extracts only the relevant fields
    """
    rules = []
    for rule in raw_rules:
        rules.append({"SourceIP": rule.get('sourceAddress',{}).get('value'),
                "DestIP": rule.get('destinationAddress',{}).get('value'),
                "IsActive": rule.get('active'),
                "Interface": rule.get("interface"),
                "InterfaceType": rule.get("interface_type"),
                "Remarks": rule.get('remarks'),
                "Position": rule.get('position'),
                "ID": rule.get('objectId'),
                'Permit': rule.get('permit')
               })
    return rules


def is_ipv4(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False


'''COMMANDS'''


@logger
def list_rules_command(client: Client, args):
    """
    :param client:
    :param args: Interface_name - get rules from a specific interface.
                Interface_type - get rules from a specific type of interface.
    :return: hr - human readable, outputs - context, raw

    Returns all rules.
    """
    interface = args.get('interface_name')
    interface_type = args.get('interface_type', 'All')

    try:
        raw_rules = client.get_all_rules(interface, interface_type) # demisto.getRules() #
        rules = raw_to_rules(raw_rules)
        outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
        hr = tableToMarkdown("Rules:", rules,["ID", "SourceIP", "DestIP", "Permit", "Interface", "InterfaceType",
                                              "IsActive", "Position"])
        return hr, outputs, raw_rules


    except Exception as e:
        if "404" in str(e) and interface:
            raise ValueError("Could not find interface")
        else:
            raise e


@logger
def test_command(client: Client):
    client.http_request("GET", "/api/aaa/authorization")


@logger
def backup_command(client: Client, args):
    location = "disk0:/"+args.get("backup_name")
    passphrase = args.get("passphrase")
    data = {'location': location}
    if passphrase:
        data['passphrase'] = passphrase

    client.http_request("POST","/api/backup", data=data)
    return "Created backup successfully in:\nlocation: {}\nPassphrase: {}".format(location, passphrase), {}, ""


@logger
def restore_command(client: Client, args):
    location = "disk0:/"+args.get("backup_name")
    passphrase = args.get("passphrase")



@logger
def rule_by_id_command(client: Client, args):
    rule_id = args.get('rule_id')
    interface = args.get('interface_name')
    interface_type = args.get('interface_type')

    raw_rules = client.get_rule(rule_id,interface,interface_type)
    rules = raw_to_rules([raw_rules])

    outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
    hr = tableToMarkdown("Rule {}:".format(rule_id), rules, ["ID", "SourceIP", "DestIP",
                                                             "Permit", "Interface", "InterfaceType", "IsActive",
                                                             "Position"])
    return hr, outputs, raw_rules


@logger
def create_rule_command(client: Client, args):
    source = args.get('source')
    dest = args.get('destination')
    permit = args.get('permit')
    interface = args.get ('interface_name')
    interface_type = args.get('interface_type')

    remarks = argToList(args.get('remarks'), ',')
    position = args.get('position')
    log_level = args.get('logging_level')
    active = args.get('active', 'True')

    rule_body = {}
    rule_body['sourceService'] = {"kind": "NetworkProtocol",
                                  "value": "ip"}
    ## Set up source
    if is_ipv4(source):
        rule_body["sourceAddress"] = {"kind": "IPv4Address",
                                       "value": source}
    if source == 'any':
        rule_body["sourceAddress"] = {"kind": "AnyIPAddress",
                                      "value": "any4"}
    if '/' in source:
        rule_body["sourceAddress"] = {"kind": "IPv4Network",
                                      "value": source}
    if not rule_body.get('sourceAddress'):
        raise ValueError("Source is not a valid IPv4 address/network/any.")

    ## Set up dest
    rule_body['destinationService'] = {"kind": "NetworkProtocol",
                                       "value": "ip"}

    if is_ipv4(dest):
        rule_body["destinationAddress"] = {"kind": "IPv4Address",
                                       "value": dest}
    if dest == 'any':
        rule_body["destinationAddress"] = {"kind": "AnyIPAddress",
                                      "value": "any4"}
    if '/' in dest:
        rule_body["destinationAddress"] = {"kind": "IPv4Network",
                                      "value": dest}

    if not rule_body.get('destinationAddress'):
        raise ValueError("Destination is not a valid IPv4 address/network/any.")

    ## everything else
    rule_body['permit'] = True if permit == 'True' else False
    rule_body['remarks'] = remarks
    rule_body['active'] = True if active == 'True' else False
    if position:
        rule_body['position'] = position
    if log_level:
        rule_body['ruleLogging'] = {'logStatus': log_level}

    try:
        raw_rule = client.create_rule_in_api(interface_type, interface, rule_body)
        rules = raw_to_rules([raw_rule])

        outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
        hr = tableToMarkdown("Created new rule. ID: {}".format(raw_rule.get('objectId'),),
                             rules, ["ID", "SourceIP", "DestIP", "Permit", "Interface", "InterfaceType", "IsActive",
                                     "Position"])
        return hr, outputs, raw_rule
    except Exception as e:
        if 'DUPLICATE' in str(e):
            raise ValueError("You are trying to create a rule that already exists.")
        if '[500]' in str(e):
            raise ValueError("Could not find interface: {}.".format(interface))
        else:
            raise e


@logger
def delete_rule_command(client: Client, args):
    rule_id = args.get('rule_id')
    interface = args.get('interface_name')
    interface_type = args.get('interface_type')



'''MAIN'''

def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxies = handle_proxy()

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['server'][:-1] \
        if (demisto.params()['server'] and demisto.params()['server'].endswith('/')) else demisto.params()['server']

    commands = {
        'cisco-asa-list-rules': list_rules_command,
        'cisco-asa-backup': backup_command,
        'cisco-asa-get-rule-by-id': rule_by_id_command,
        'cisco-asa-create-rule': create_rule_command,
        'cisco-asa-restore': restore_command
    }

    LOG('Command being called is %s' % (demisto.command()))
    try:
        client = Client(server_url, username, password, verify_certificate, proxies)

        if demisto.command() == 'test-module':
            test_command(client)
            demisto.results('ok')
        elif demisto.command() in commands.keys():
            hr, outputs, raw_rules = commands[demisto.command()](client, demisto.args())
            return_outputs(hr, outputs, raw_rules)

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(demisto.command(), e))
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
