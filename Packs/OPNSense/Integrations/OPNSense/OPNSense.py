"""OPNSense integration for Cortex XSOAR (aka Demisto)

blabla
license

SecInfra © 20xy
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


from typing import Any, Dict
from pyopnsense2 import core_core
from pyopnsense2 import core_diagnostics
from pyopnsense2 import core_firmware
from pyopnsense2 import core_firewall
from pyopnsense2 import plugins_firewall
import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('proxy', False):
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
        try:
            del os.environ[key]
        except KeyError:
            pass

''' CONSTANTS '''

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, params):
        # alias util
        self.fw_alias_util = core_firewall.firewall_alias_util(params)
        # alias
        self.fw_alias = core_firewall.firewall_alias(params)
        # category
        self.fw_categ = core_firewall.firewall_category(params)
        # fw rules
        self.fw_filter = plugins_firewall.firewall_filter(params)
        # fw base
        self.fw_base = plugins_firewall.firewall_filter_base(params)
        # interfaces
        self.diag_interfaces = core_diagnostics.diagnostics_interface(params)
        # logs
        self.diag_firewall = core_diagnostics.diagnostics_firewall(params)
        # core system
        self.core_system = core_core.core_system(params)
        # core firmware
        self.core_firmware = core_firmware.Core_Firmware(params)

    def test_module(self):
        return self.fw_alias_util.aliases()

    # core_system in core_core and

    def system_reboot(self):
        return self.core_system.reboot()

    def firmware_info(self):
        return self.core_firmware.info()

    def firmware_status(self):
        return self.core_firmware.status()

    def firmware_upgradestatus(self):
        return self.core_firmware.upgradestatus()

    def firmware_update(self):
        return self.core_firmware.update()

    def firmware_upgrade(self):
        return self.core_firmware.upgrade()

    # diagnostics_interface and diagnostics_firewall in core_diagnostics

    def interfaces_list(self):
        return self.diag_interfaces.getInterfaceNames()

    def log_search(self, limit):
        return self.diag_firewall.log(args={'limit': limit})

    def states_search(self):
        return self.diag_firewall.queryStates()

    def state_del(self, state_id):
        return self.diag_firewall.delState(args={'stateid': state_id})

    # firewall_filter_base and firewall_filter in plugins_firewall

    def firewall_savepoint(self):
        return self.fw_filter.savepoint()

    def firewall_apply(self, rollback=None):
        if rollback:
            return self.fw_filter.apply(args={'rollback_revision': rollback})
        return self.fw_filter.apply()

    def firewall_cancelRollback(self, rollback):
        return self.fw_filter.cancelRollback(args={'rollback_revision': rollback})

    def firewall_revert(self, rollback):
        return self.fw_filter.revert(args={'revision': rollback})

    def firewall_addRule(self, args):
        return self.fw_filter.addRule(args)

    def firewall_delRule(self, args):
        return self.fw_filter.delRule(args)

    def firewall_setRule(self, uuid, args):
        args['uuid'] = uuid
        return self.fw_filter.setRule(args)

    def firewall_getRule(self, args):
        return self.fw_filter.getRule(args)

    def firewall_searchRule(self, args=None):
        return self.fw_filter.searchRule(args)

    # firewall_category in core_firewall

    def category_list(self):
        return self.fw_categ.searchItem({'rowCount': -1})['rows']

    def category_addItem(self, args):
        return self.fw_categ.addItem(args)

    def category_delItem(self, args):
        return self.fw_categ.delItem(args)

    def category_getItem(self, args):
        return self.fw_categ.getItem(args)

    def category_setItem(self, uuid, args):
        args['uuid'] = uuid
        return self.fw_categ.setItem(args)

    # firewall_alias_util and firewall_alias in core_firewall

    def alias_util_aliases(self):
        return self.fw_alias_util.aliases()

    def alias_util_add(self, args):
        return self.fw_alias_util.add(args)

    def alias_util_del(self, args):
        return self.fw_alias_util.delete(args)

    def alias_getItem(self, args):
        return self.fw_alias.getItem(args)

    def alias_addItem(self, args):
        return self.fw_alias.addItem(args)

    def alias_delItem(self, args):
        return self.fw_alias.delItem(args)

    def alias_setItem(self, uuid, args):
        args['uuid'] = uuid
        return self.fw_alias.setItem(args)

    def alias_getuuid(self, args):
        return self.fw_alias.getAliasUUID(args)

    def alias_reconfigure(self):
        return self.fw_alias.reconfigure()


''' HELPER FUNCTIONS '''


def with_keys(d, keys):
    return {x: d[x] for x in d if x in keys}


def output_format(res, output_type=None, readable=None):
    if res:
        if isinstance(res, list):
            keys = res[0].keys()
        else:
            keys = res.keys()
        key_list = []
        for key in keys:
            key_list.append(key)
        if not output_type:
            output_type = key_list[0].split(".")[0]
        result = []
        if not readable:
            readable = output_type
        result.append(CommandResults(outputs_prefix='OPNSense.' + output_type,
                      outputs_key_field=key_list,
                      outputs=res,
                      raw_response=res,
                      readable_output=tableToMarkdown(name='OPNSense ' + readable, t=res, headers=key_list)))
        return result
    else:
        return "No result"


def rule_reformat_result(data):
    result = {"rule": {}}  # type: Dict[str, Any]
    for key in data['rule'].keys():
        if key in ['enabled', 'sequence', 'quick', 'source_net', 'source_not', 'source_port', 'destination_net',
                   'destination_not', 'destination_port', 'log', 'description']:
            result['rule'][key] = data['rule'][key]
        elif key in ['action', 'interface', 'direction', 'ipprotocol', 'protocol', 'gateway']:
            tmpvalue = ''
            for subkey in data['rule'][key].keys():
                if data['rule'][key][subkey]['selected'] == 1:
                    tmpvalue = subkey
                    break
                elif data['rule'][key][subkey]['selected'] == 0:
                    pass
                else:
                    return_error("something is wrong here")
            result['rule'][key] = tmpvalue
        else:
            result['rule'][key] = 'REPLACED'
    return result


def alias_reformat_result(data):
    result = {"alias": {}}  # type: Dict[str, Any]
    for key in data['alias'].keys():
        if key in ['enabled', 'name', 'counters', 'updatefreq', 'description']:
            result['alias'][key] = data['alias'][key]
        elif key in ['content', 'type', 'proto', 'interface']:
            tmpvalue = ''
            for subkey in data['alias'][key].keys():
                if data['alias'][key][subkey]['selected'] == 1:
                    tmpvalue = subkey
                    break
                elif data['alias'][key][subkey]['selected'] == 0:
                    pass
                else:
                    return_error("something is wrong here")
            result['alias'][key] = tmpvalue
        else:
            result['alias'][key] = 'REPLACED'
    return result


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    result = client.test_module()
    if 'error' not in result and 'exception' not in result:
        return 'ok'
    return 'Test Failed!'


# Alias commands

def alias_apply_command(client):
    result = client.alias_reconfigure()
    readable_output = f'## {result}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OPNSense.Alias',
        outputs_key_field='',
        outputs=json.dumps(result)
    )


def alias_list_command(client):
    result = client.alias_util_aliases()
    readable_output = f'## {result}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OPNSense.Alias',
        outputs_key_field='',
        outputs=json.dumps(result)
    )


def alias_add_command(client, args):
    content = argToList(args.get('content'))
    format_content = '\n'.join(content)
    params = {
        "alias": {
            "enabled": args.get('enabled', '1'),
            "name": args.get('name'),
            "type": args.get('type'),
            "proto": args.get('proto', ''),
            "updatefreq": args.get('updatefreq', ''),
            "content": format_content,
            "counters": args.get('counters', ''),
            "description": args.get('description', '')
        }
    }
    result = client.alias_addItem(params)
    if args.get('auto_commit'):
        client.alias_reconfigure()
    output = output_format(result, 'Alias', 'Alias uuid : ' + str(result['uuid']) + ' created')
    return output


def alias_mod_command(client, args):
    uuid = args.get('uuid')
    content = argToList(args.get('content'))
    format_content = '\n'.join(content)
    data = client.alias_getItem({'uuid': uuid})
    original = alias_reformat_result(data)
    original['alias']['content'] = format_content
    modified = {"alias": {}}  # type: Dict[str, Any]
    for key in original['alias'].keys():
        newvalue = args.get(key)
        if newvalue is None:
            modified['alias'][key] = original['alias'][key]
        else:
            modified['alias'][key] = newvalue
    result = client.alias_setItem(uuid, modified)
    if args.get('auto_commit'):
        client.alias_reconfigure()
    output = output_format(result, 'Alias', 'Alias uuid : ' + str(uuid) + ' modified')
    return output


def alias_mod_additem_command(client, args):
    name = args.get('name')
    entry = args.get('entry')
    params = {
        'aliasName': name,
        'address': entry
    }
    result = client.alias_util_add(params)
    if args.get('auto_commit'):
        client.alias_reconfigure()
    output = output_format(result, 'Alias', 'Alias : ' + str(name) + ' modified')
    return output


def alias_mod_delitem_command(client, args):
    name = args.get('name')
    entry = args.get('entry')
    params = {
        'aliasName': name,
        'address': entry
    }
    result = client.alias_util_del(params)
    if args.get('auto_commit'):
        client.alias_reconfigure()
    output = output_format(result, 'Alias', 'Alias : ' + str(name) + ' modified')
    return output


def alias_del_command(client, args):
    params = {"uuid": args.get('uuid')}
    result = client.alias_delItem(params)
    if args.get('auto_commit'):
        client.alias_reconfigure()
    output = output_format(result, 'Alias', 'Alias uuid : ' + str(args.get('uuid')) + ' deleted')
    return output


def alias_get_command(client, args):
    name = args.get('name')
    uuid = args.get('uuid')
    if name is None and uuid is None:
        return_error('You must at least define the name or the uuid argument')
    elif uuid is None and name is not None:
        uuid = client.alias_getuuid({'name': name})['uuid']
    data = client.alias_getItem({'uuid': uuid})
    result = alias_reformat_result(data)
    output = output_format(result['alias'], 'Alias', 'Alias uuid : ' + str(uuid) + ' description')
    return output


def alias_getuuid_command(client, args):
    name = args.get('name')
    result = client.alias_getuuid({'name': name})['uuid']
    readable_output = f'## {result}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OPNSense.Alias',
        outputs_key_field='',
        outputs=json.dumps(result)
    )


# Diagnostics commands

def interfaces_list_command(client):
    result = client.interfaces_list()
    output = output_format(result, 'Interfaces', 'Interfaces list:')
    return output


def logs_search_command(client: Client, args) -> CommandResults:
    limit = args.get('limit')
    ip = args.get('ip')
    interface = args.get('interface')
    results = client.log_search(limit)
    if interface:
        if ip:
            sresult = [x for x in results if x['interface'] == interface if (x['dst'] == ip or x['src'] == ip)]
        else:
            sresult = [x for x in results if x['interface'] == interface]
    elif ip:
        sresult = [x for x in results if (x['dst'] == ip or x['src'] == ip)]
    if interface or ip:
        res = sresult
    else:
        res = results
    if res:
        pretty = []
        for result in res:
            display = {'interface', 'src', 'srcport', 'dst', 'dstport', 'action', '__timestamp__', 'protoname', 'label'}
            pretty.append(with_keys(result, display))
        return output_format(pretty, 'Logs', readable='firewall logs')
    else:
        return CommandResults(readable_output='Nothing found')


# States commands

def states_search_command(client: Client, args) -> CommandResults:
    ip = args.get('ip')
    results = client.states_search()
    if ip:
        sresult = [x for x in results['rows'] if (x['dst_addr'] == ip or x['src_addr'] == ip)]
        result = output_format(sresult, 'States', readable='firewall states')
    elif results:
        result = output_format(results['rows'], 'States', readable='firewall states')
    else:
        return CommandResults(readable_output='Nothing found')
    return result


def state_del_command(client: Client, args) -> CommandResults:
    state_id = args.get('state_id')
    results = client.state_del(state_id)
    return results


# Categories commands


def category_list_command(client):
    result = client.category_list()
    output = output_format(result, 'Category', 'Categories list:')
    return output


def category_add_command(client, args):
    params = {
        "category": {
            "auto": args.get('auto', '0'),
            "name": args.get('name'),
            "color": args.get('color', '')
        }
    }
    result = client.category_addItem(params)
    output = output_format(result, 'Category', 'Category uuid : ' + result['uuid'] + ' created:')
    return output


def category_del_command(client, args):
    uuid = args.get('uuid')
    params = {"uuid": uuid}
    result = client.category_delItem(params)
    output = output_format(result, 'Category', 'Category uuid : ' + uuid + ' deleted')
    return output


def category_get_command(client, args):
    uuid = args.get('uuid')
    result = client.category_getItem({'uuid': uuid})
    result = client.category_getItem({'uuid': uuid})['category']
    output = output_format(result, 'Category', 'Category uuid : ' + uuid + ' description')
    return output


def category_mod_command(client, args):
    uuid = args.get('uuid')
    original = client.category_getItem({'uuid': uuid})
    modified = {"category": {}}  # type: Dict[str, Any]
    for key in original['category'].keys():
        newvalue = args.get(key)
        if newvalue is None:
            modified['category'][key] = original['category'][key]
        else:
            modified['category'][key] = newvalue
    result = client.category_setItem(uuid, modified)
    output = output_format(result, 'Category', 'Category uuid : ' + uuid + ' modified:')
    return output


# Firewall rule commands

def fw_rule_list_command(client):
    result = client.firewall_searchRule()
    output = output_format(result['rows'], 'Rule', 'Rules list: ')
    return output


def fw_rule_get_command(client, args):
    uuid = args.get('uuid')
    data = client.firewall_getRule({'uuid': uuid})
    result = rule_reformat_result(data)
    output = output_format(result['rule'], 'Rule', 'Rule uuid : ' + uuid + ' description')
    return output


def fw_rule_del_command(client, args):
    uuid = args.get('uuid')
    params = {"uuid": uuid}
    result = client.firewall_delRule(params)
    if args.get('auto_commit'):
        client.firewall_apply()
    output = output_format(result, 'Rule', 'Rule uuid : ' + uuid + ' deleted')
    return output


def fw_rule_add_command(client, args):
    params = {
        "rule":
            {
                "sequence": args.get('sequence'),
                "action": args.get('action'),
                "enabled": args.get('enabled'),
                "quick": args.get('quick'),
                "interface": args.get('interface', ''),
                "direction": args.get('direction'),
                "ipprotocol": args.get('ipprotocol', ''),
                "source_net": args.get('source_net'),
                "source_not": args.get('source_not'),
                "source_port": args.get('source_port'),
                "destination_net": args.get('destination_net'),
                "destination_not": args.get('destination_not'),
                "destination_port": args.get('destination_port'),
                "log": args.get('log'),
                "description": args.get('description'),

            }
    }
    result = client.firewall_addRule(params)
    if str(result['result']) == 'failed':
        return_error(result['validations'])
    if args.get('auto_commit'):
        client.firewall_apply()
    output = output_format(result, 'Rule', 'Rule successfully added with ID : ' + str(result['uuid']))
    return output


def fw_rule_mod_command(client, args):
    uuid = args.get('uuid')
    data = client.firewall_getRule({'uuid': uuid})
    original = rule_reformat_result(data)
    modified = {"rule": {}}  # type: Dict[str, Any]
    for key in original['rule'].keys():
        newvalue = args.get(key)
        if newvalue is None:
            modified['rule'][key] = original['rule'][key]
        else:
            modified['rule'][key] = newvalue
    result = client.firewall_setRule(uuid, modified)
    if args.get('auto_commit'):
        client.firewall_apply()
    output = output_format(result, 'Rule', 'Rule uuid : ' + uuid + ' modified:')
    return output


def fw_rule_apply_command(client, args):
    revision = args.get('rollback_revision', None)
    result = client.firewall_apply(revision)
    output = output_format(result, 'Rule', 'Rules applyied')
    return output


def fw_rule_savepoint_command(client):
    result = client.firewall_savepoint()
    output = output_format(result, 'Rule', 'Rules Save point')
    return output


def fw_rule_cancelRollback_command(client, args):
    revision = args.get('rollback_revision')
    result = client.firewall_cancelRollback(revision)
    return result


def fw_rule_revert_command(client, args):
    revision = args.get('rollback_revision')
    result = client.firewall_revert(revision)
    output = output_format(result, 'Rule', 'Rules reverted')
    return output


# Firmware and System commands

def device_reboot_command(client):
    result = client.system_reboot()
    output = output_format(result, 'Device', 'Device Reboot')
    return output


def firmware_info_command(client):
    result = client.firmware_info()
    output = output_format(result, 'Firmware', 'Firmware info')
    return output


def firmware_status_command(client):
    result = client.firmware_status()
    output = output_format(result['product'], 'Firmware', 'Firmware status')
    return output


def firmware_upgradestatus_command(client):
    result = client.firmware_upgradestatus()
    output = output_format(result, 'Firmware', 'Firmware Upgrade status')
    return output


def firmware_update_command(client):
    result = client.firmware_update()
    output = output_format(result, 'Firmware', 'Firmware update')
    return output


def firmware_upgrade_command(client):
    result = client.firmware_upgrade()
    output = output_format(result, 'Firmware', 'Firmware upgrade')
    return output


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command_list_noarg = {
        'opnsense-interfaces-list': interfaces_list_command,
        'opnsense-alias-apply': alias_apply_command,
        'opnsense-alias-list': alias_list_command,
        'opnsense-category-list': category_list_command,
        'opnsense-rule-list': fw_rule_list_command,
        'opnsense-rule-savepoint': fw_rule_savepoint_command,
        'opnsense-firmware-info': firmware_info_command,
        'opnsense-firmware-status': firmware_status_command,
        'opnsense-firmware-upgradestatus': firmware_upgradestatus_command,
        'opnsense-firmware-update': firmware_update_command,
        'opnsense-firmware-upgrade': firmware_upgrade_command,
        'opnsense-device-reboot': device_reboot_command,
    }

    command_list = {
        'opnsense-alias-add': alias_add_command,
        'opnsense-alias-del': alias_del_command,
        'opnsense-alias-mod': alias_mod_command,
        'opnsense-alias-mod-additem': alias_mod_additem_command,
        'opnsense-alias-mod-delitem': alias_mod_delitem_command,
        'opnsense-alias-get': alias_get_command,
        'opnsense-alias-get-uuid': alias_getuuid_command,
        'opnsense-category-add': category_add_command,
        'opnsense-category-del': category_del_command,
        'opnsense-category-get': category_get_command,
        'opnsense-category-mod': category_mod_command,
        'opnsense-rule-apply': fw_rule_apply_command,
        'opnsense-rule-revert': fw_rule_revert_command,
        'opnsense-rule-get': fw_rule_get_command,
        'opnsense-rule-del': fw_rule_del_command,
        'opnsense-rule-add': fw_rule_add_command,
        'opnsense-rule-mod': fw_rule_mod_command,
        'opnsense-logs-search': logs_search_command,
        'opnsense-states-search': states_search_command,
        'opnsense-state-del': state_del_command,
    }

    params = {
        'base_url': urljoin(demisto.params()['url'], '/api'),
        'auth': (
            demisto.params().get('apikey'),
            demisto.params().get('apisecret')),
        'verify_cert': not demisto.params().get('insecure', False),
        'proxy': demisto.params().get('proxy', False),
        'timeout': 60
    }

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(params)
        cmd = demisto.command()

        if cmd == 'test-module':
            return_results(test_module(client))
        elif cmd in command_list_noarg.keys():
            return_results(command_list_noarg[cmd](client))
        elif cmd in command_list.keys():
            return_results(command_list[cmd](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

