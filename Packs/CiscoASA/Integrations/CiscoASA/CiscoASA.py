from typing import Optional

import urllib3
import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES'''

OBJECT_TYPES_DICT = {
    'IPv4': 'IPv4Address',
    'IP-Network': 'IPv4Network'
}

'''Client'''


class Client(BaseClient):
    isASAv = False
    auth_token = ""

    def login(self, isASAv) -> None:
        if isASAv:
            self.isASAv = True
            res = self._http_request('POST', '/api/tokenservices', resp_type='response')
            auth_token = res.headers._store.get('x-auth-token')[1]
            self._headers['X-Auth-Token'] = auth_token
            self.auth_token = auth_token

    def logoff(self):
        try:
            if self.isASAv and self.auth_token:
                self._http_request('DELETE', f'/api/tokenservices/{self.auth_token}', resp_type='response')
        except Exception as e:
            # if failed to logoof just write to log. no need to raise error
            demisto.debug(f'Logoff error: {str(e)}')

    def get_all_rules(self, specific_interface: Optional[str] = None, rule_type: str = 'All') -> list:
        """
        Args:
             specific_interface): the name of the interface
             rule_type: All/Global/In

        Returns:
             all rules in Cisco ASA of the specified type/interface
        """
        rules = []  # type: list
        # Get global rules
        if specific_interface is None and rule_type in ['All', 'Global']:
            res = self._http_request('GET', '/api/access/global/rules')
            items = res.get('items', [])
            for item in items:
                item['interface_type'] = "Global"
            rules.extend(items)

        # Get in rules
        if rule_type in ['All', 'In']:
            res = self._http_request('GET', '/api/access/in')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self._http_request('GET', f'/api/access/in/{interface}/rules')
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "In"
                rules.extend(items)

        # Get out rules
        if rule_type in ['All', 'Out']:
            res = self._http_request('GET', '/api/access/out')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self._http_request('GET', f'/api/access/out/{interface}/rules')
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "Out"
                rules.extend(items)

        return rules

    def rule_action(self, rule_id: str, interface_name: str, interface_type: str, command: str = 'GET',
                    data: dict = None) -> dict:
        """

        Args:
            rule_id: The Rule ID.
            interface_name: the name of the interface.
            interface_type: The type of interface.
            command: What
            data:

        Returns:
            Does the command on the rule.
            Delete - delete rule
            GET - rule info
            PATCH - edit rule
        """
        resp_type = {"GET": "json",
                     "DELETE": "text",
                     "PATCH": "response"
                     }
        if interface_type == "Global":
            rule = self._http_request(command, f'/api/access/global/rules/{rule_id}', resp_type=resp_type[command],
                                      json_data=data)
        if interface_type == "In":
            rule = self._http_request(command, f'/api/access/in/{interface_name}/rules/{rule_id}',
                                      resp_type=resp_type[command], json_data=data)
        if interface_type == 'Out':
            rule = self._http_request(command, f'/api/access/out/{interface_name}/rules/{rule_id}',
                                      resp_type=resp_type[command], json_data=data)
        if command == 'GET':
            rule['interface'] = interface_name
            rule['interface_type'] = interface_type
        return rule

    def create_rule_request(self, interface_type: str, interface_name: str, rule_body: dict) -> dict:
        """

        Args:
            interface_type:
            interface_name:
            rule_body: The information about the rule.

        Returns:
            The new created rule's information.

        """
        if interface_type == "Global":
            res = self._http_request("POST", '/api/access/global/rules', json_data=rule_body, resp_type="response")
        if interface_type == 'In':
            res = self._http_request("POST", '/api/access/in/{}/rules'.format(interface_name), json_data=rule_body,
                                     resp_type="response")
        if interface_type == 'Out':
            res = self._http_request("POST", '/api/access/out/{}/rules'.format(interface_name), json_data=rule_body,
                                     resp_type="response")
        loc = res.headers.get("Location", "")
        rule = self._http_request('GET', loc[loc.find('/api'):])
        rule['interface'] = interface_name
        rule['interface_type'] = interface_type
        return rule

    def test_command_request(self):
        self._http_request("GET", "/api/aaa/authorization")

    def backup(self, data: dict):
        self._http_request("POST", "/api/backup", json_data=data, resp_type="response")

    def restore(self, data: dict):
        self._http_request("POST", "/api/restore", json_data=data, resp_type='response')

    def get_network_obejcts(self):
        obj_res = self._http_request('GET', '/api/objects/networkobjects')
        return obj_res.get('items', [])

    def create_object(self, obj_name, obj_type, obj_value):
        data = {
            "kind": "object#NetworkObj",
            "name": obj_name,
            "host": {
                "kind": OBJECT_TYPES_DICT.get(obj_type),
                "value": obj_value
            }
        }
        try:
            return self._http_request('POST', '/api/objects/networkobjects', json_data=data, ok_codes=(200, 201, 204),
                                      resp_type='response')
        except Exception:
            raise

    def list_interfaces(self):
        interfaces = list()  # type: ignore
        for type in ['global', 'in', 'out']:
            resp = self._http_request('GET', f'/api/access/{type}')
            interfaces.extend(resp.get('items', []))
        return interfaces


'''HELPER COMMANDS'''


@logger
def set_up_ip_kind(dict_body: dict, field_to_add: str, data: str) -> None:
    """

    Args:
        dict_body: The dict to add the data to.
        field_to_add: the name of the field to add to json.
        data: the string to check its kind and insert to dict.

    Returns:
        Takes the data, checks what kind of source/dest it is (IP, network, any or network object) and inserts to the
        dict the field_to_add as key and the source/dest as value in the correct format.
    """
    if is_ip_valid(data):
        dict_body[field_to_add] = {"kind": "IPv4Address",
                                   "value": data}
    elif data == 'any':
        dict_body[field_to_add] = {"kind": "AnyIPAddress",
                                   "value": "any4"}
    elif '/' in data:
        dict_body[field_to_add] = {"kind": "IPv4Network",
                                   "value": data}
    else:
        dict_body[field_to_add] = {"kind": "objectRef#NetworkObj",
                                   "objectId": data}


@logger
def raw_to_rules(raw_rules):
    """
    :param raw_rules:
    :return:
    Gets raw rules as received from API and extracts only the relevant fields
    """
    rules = list()
    for rule in raw_rules:
        source_services = rule.get('sourceService', {})

        if isinstance(source_services, list):
            source_services_list = [v['value'] for v in source_services]
        else:
            source_services_list = source_services.get('value')

        dest_services = rule.get('destinationService', {})
        if isinstance(dest_services, list):
            dest_services_list = [v['value'] for v in dest_services]
        else:
            dest_services_list = dest_services.get('value')
        rules.append({"Source": rule.get('sourceAddress', {}).get('value'),
                      "SourceService": source_services_list,
                      "Dest": rule.get('destinationAddress', {}).get('value'),
                      "DestService": dest_services_list,
                      "IsActive": rule.get('active'),
                      "Interface": rule.get("interface"),
                      "InterfaceType": rule.get("interface_type"),
                      "Remarks": rule.get('remarks'),
                      "Position": rule.get('position'),
                      "ID": rule.get('objectId'),
                      'Permit': rule.get('permit')
                      })
        if not rules[-1].get('Source'):
            rules[-1]['Source'] = rule.get('sourceAddress', {}).get('objectId')
        if not rules[-1].get('Dest'):
            rules[-1]['Dest'] = rule.get('destinationAddress', {}).get('objectId')

    return rules


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
        raw_rules = client.get_all_rules(interface, interface_type)  # demisto.getRules() #
        rules = raw_to_rules(raw_rules)
        outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
        hr = tableToMarkdown("Rules:", rules, ["ID", "Source", "Dest", "Permit", "Interface", "InterfaceType",
                                               "IsActive", "Position", "SourceService", "destService"])
        return hr, outputs, raw_rules

    except Exception as e:
        if "404" in str(e) and interface:
            raise ValueError("Could not find interface")
        else:
            raise e


@logger
def backup_command(client: Client, args):
    """

    Args:
        client:
        args:

    Returns:
        Creates a backup. Returns a message if backup was created successfully.

    """
    location = "disk0:/" + args.get("backup_name")
    passphrase = args.get("passphrase")
    data = {'location': location}
    if passphrase:
        data['passphrase'] = passphrase

    client.backup(data)
    return f"Created backup successfully in:\nLocation: {location}\nPassphrase: {passphrase}", {}, ""


@logger
def restore_command(client: Client, args):
    location = "disk0:/" + args.get("backup_name")
    passphrase = args.get("passphrase")
    data = {'location': location}
    if passphrase:
        data['passphrase'] = passphrase

    client.restore(data)
    return "Restored backup successfully.", {}, ""


@logger
def rule_by_id_command(client: Client, args):
    rule_id = args.get('rule_id')
    interface_type = args.get('interface_type')
    interface = args.get('interface_name')

    if interface_type != "Global" and not interface:
        raise ValueError("Please state the name of the interface when it's not a global interface.")
    interface = "" if interface_type == "Global" else interface

    raw_rules = client.rule_action(rule_id, interface, interface_type, 'GET')
    rules = raw_to_rules([raw_rules])

    outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
    hr = tableToMarkdown("Rule {}:".format(rule_id), rules, ["ID", "Source", "Dest", "Permit", "Interface",
                                                             "InterfaceType", "IsActive", "Position", "SourceService",
                                                             "destService"])
    return hr, outputs, raw_rules


@logger
def create_rule_command(client: Client, args):
    source = args.get('source')
    dest = args.get('destination')
    permit = args.get('permit')
    interface = args.get('interface_name')
    interface_type = args.get('interface_type')
    service = args.get('service', 'ip')

    interface = "" if interface_type == "Global" else interface
    if interface_type != "Global" and not interface:
        raise ValueError("For In/Out interfaces, an interface name is mandatory.")

    remarks = argToList(args.get('remarks'), ',')
    position = args.get('position')
    log_level = args.get('logging_level')
    active = args.get('active', 'True')

    rule_body = {}  # type: dict
    rule_body['sourceService'] = {"kind": "NetworkProtocol",
                                  "value": service}

    # Set up source
    set_up_ip_kind(rule_body, "sourceAddress", source)

    # Set up dest
    rule_body['destinationService'] = {"kind": "NetworkProtocol",
                                       "value": service}

    set_up_ip_kind(rule_body, "destinationAddress", dest)

    # everything else
    rule_body['permit'] = True if permit == 'True' else False
    rule_body['remarks'] = remarks
    rule_body['active'] = True if active == 'True' else False
    if position:
        rule_body['position'] = position
    if log_level:
        rule_body['ruleLogging'] = {'logStatus': log_level}

    try:
        raw_rule = client.create_rule_request(interface_type, interface, rule_body)
        rules = raw_to_rules([raw_rule])

        outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
        hr = tableToMarkdown("Created new rule. ID: {}".format(raw_rule.get('objectId'),),
                             rules, ["ID", "Source", "Dest", "Permit", "Interface", "InterfaceType", "IsActive",
                                     "Position", "SourceService", "destService"])
        return hr, outputs, raw_rule
    except Exception as e:
        if 'DUPLICATE' in str(e):
            raise ValueError("You are trying to create a rule that already exists.")
        if '[500]' in str(e):
            raise ValueError("Could not find interface: {}.".format(interface))
        else:
            raise ValueError(f"Could not create rule. Error {str(e)}")


@logger
def delete_rule_command(client: Client, args):
    rule_id = args.get('rule_id')
    interface = args.get('interface_name')
    interface_type = args.get('interface_type')
    if interface_type != "Global" and not interface:
        raise ValueError("Please state the name of the interface when it's not a global interface.")

    try:
        client.rule_action(rule_id, interface, interface_type, 'DELETE')
    except Exception as e:
        if 'Not Found' in str(e):
            raise ValueError(f"Rule {rule_id} does not exist in interface {interface} of type {interface_type}.")
        else:
            raise ValueError(f"Could not delete rule. Error {str(e)}")

    return f"Rule {rule_id} deleted successfully.", {}, ""


@logger
def edit_rule_command(client: Client, args):
    interface = args.get('interface_name')
    interface_type = args.get('interface_type')
    rule_id = args.get('rule_id')

    if interface_type != "Global" and not interface:
        raise ValueError("Please state the name of the interface when it's not a global interface.")

    interface = "" if interface_type == "Global" else interface

    remarks = argToList(args.get('remarks'), ',')
    position = args.get('position')
    log_level = args.get('logging_level')
    active = args.get('active', 'True')
    source = args.get('source')
    dest = args.get('destination')
    permit = args.get('permit')
    service = args.get("service")

    rule_body = {}  # type: dict

    # Set up source
    if source:
        set_up_ip_kind(rule_body, "sourceAddress", source)

    if service:
        rule_body['sourceService'] = {"kind": "NetworkProtocol",
                                      "value": service}
    # Set up dest
    if dest:
        set_up_ip_kind(rule_body, "destinationAddress", dest)

    if service:
        rule_body['destinationService'] = {"kind": "NetworkProtocol",
                                           "value": service}

    # everything else
    if permit:
        rule_body['permit'] = True if permit == 'True' else False
    if remarks:
        rule_body['remarks'] = remarks
    if active:
        rule_body['active'] = True if active == 'True' else False
    if position:
        rule_body['position'] = position
    if log_level:
        rule_body['ruleLogging'] = {'logStatus': log_level}

    try:
        rule = client.rule_action(rule_id, interface, interface_type, "PATCH", rule_body)
        try:
            raw_rule = client.rule_action(rule_id, interface, interface_type, 'GET')
        except Exception:
            location = rule.headers._store.get('location')[1]  # type: ignore
            rule_id = location[location.rfind('/') + 1:]
            raw_rule = client.rule_action(rule_id, interface, interface_type, 'GET')

        rules = raw_to_rules([raw_rule])

        outputs = {'CiscoASA.Rules(val.ID && val.ID == obj.ID)': rules}
        hr = tableToMarkdown(f"Edited rule {raw_rule.get('objectId')}",
                             rules, ["ID", "Source", "Dest", "Permit", "Interface", "InterfaceType", "IsActive",
                                     "Position", "SourceService", "destService"])
        return hr, outputs, raw_rule
    except Exception as e:
        if 'DUPLICATE' in str(e):
            raise ValueError("You are trying to create a rule that already exists.")
        if '[500]' in str(e):
            raise ValueError("Could not find interface: {}.".format(interface))
        else:
            raise


@logger
def list_objects_command(client: Client, args: dict):
    objects = client.get_network_obejcts()
    obj_names = argToList(args.get('object_name'))
    obj_ids = argToList(args.get('object_id'))
    formated_objects = []
    for object in objects:
        if (not obj_names and not obj_ids) or object.get('name') in obj_names or object.get('objectId') in obj_ids:
            object.pop('selfLink')
            object.pop('kind')
            formated_obj = camelize(object)
            formated_obj['ID'] = formated_obj.pop('Objectid')
            formated_objects.append(formated_obj)
    ec = {'CiscoASA.NetworkObject(val.ID && val.ID == obj.ID)': formated_objects}
    hr = tableToMarkdown("Network Objects", formated_objects, headers=['ID', 'Name', 'Host', 'Description'])
    return hr, ec, formated_objects


@logger
def create_object_command(client: Client, args: dict):
    obj_type = args.get('object_type')
    obj_name = args.get('object_name')
    obj_value = args.get('object_value')
    if obj_type not in OBJECT_TYPES_DICT.keys():
        raise ValueError("Please enter an object type from the given dropdown list.")
    client.create_object(obj_name, obj_type, obj_value)
    return list_objects_command(client, {'object_name': obj_name})


@logger
def list_interfaces_command(client: Client, args: dict):
    raw_interfaces = client.list_interfaces()
    interface_list = []
    for interface in raw_interfaces:

        temp_interface = {'Type': interface.get('direction', '').capitalize(),
                          'ID': interface.get('interface', {}).get('objectId', '-1'),
                          'Name': interface.get('interface', {}).get('name')}
        interface_list.append(temp_interface)
    ec = {'CiscoASA.Interface(val.ID && val.ID== obj.ID)': interface_list}
    hr = tableToMarkdown('Interfaces', interface_list, ['Type', 'ID', 'Name'])
    return hr, ec, raw_interfaces


@logger
def test_command(client: Client):
    """
    Args:
        client:

    Returns:
        Runs a random GET API request just to see if successful.
    """

    client.test_command_request()


'''MAIN'''


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    isASAv = demisto.params().get('isASAv', False)
    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['server'][:-1] \
        if (demisto.params()['server'] and demisto.params()['server'].endswith('/')) else demisto.params()['server']

    commands = {
        'cisco-asa-list-rules': list_rules_command,
        'cisco-asa-backup': backup_command,
        'cisco-asa-get-rule-by-id': rule_by_id_command,
        'cisco-asa-create-rule': create_rule_command,
        'cisco-asa-delete-rule': delete_rule_command,
        'cisco-asa-edit-rule': edit_rule_command,
        'cisco-asa-list-network-objects': list_objects_command,
        'cisco-asa-create-network-object': create_object_command,
        'cisco-asa-list-interfaces': list_interfaces_command
    }

    LOG(f'Command being called is {demisto.command()}')
    client = Client(server_url, auth=(username, password), verify=verify_certificate, proxy=proxy, headers={})
    try:
        client.login(isASAv)

        if demisto.command() == 'test-module':
            test_command(client)
            demisto.results('ok')
        elif demisto.command() in commands.keys():
            hr, outputs, raw_rules = commands[demisto.command()](client, demisto.args())
            return_outputs(hr, outputs, raw_rules)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e}", error=traceback.format_exc())
        raise

    finally:
        client.logoff()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
