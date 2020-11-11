import json
import traceback
from typing import Dict, cast

import ansible_runner
import demistomock as demisto  # noqa: F401
import ssh_agent_setup
from CommonServerPython import *  # noqa: F401


# Dict to Markdown Converter adapted from https://github.com/PolBaladas/torsimany/
def dict2md(json_block, depth=0):
    markdown = ""
    if isinstance(json_block, dict):
        markdown = parseDict(json_block, depth)
    if isinstance(json_block, list):
        markdown = parseList(json_block, depth)
    return markdown


def parseDict(d, depth):
    markdown = ""
    for k in d:
        if isinstance(d[k], (dict, list)):
            markdown += addHeader(k, depth)
            markdown += dict2md(d[k], depth + 1)
        else:
            markdown += buildValueChain(k, d[k], depth)
    return markdown


def parseList(rawlist, depth):
    markdown = ""
    for value in rawlist:
        if not isinstance(value, (dict, list)):
            index = rawlist.index(value)
            markdown += buildValueChain(index, value, depth)
        else:
            markdown += parseDict(value, depth)
    return markdown


def buildHeaderChain(depth):
    list_tag = '* '
    htag = '#'

    chain = list_tag * (bool(depth)) + htag * (depth + 1) + \
        ' value ' + (htag * (depth + 1) + '\n')
    return chain


def buildValueChain(key, value, depth):
    tab = "  "
    list_tag = '* '

    chain = tab * (bool(depth - 1)) + list_tag + \
        str(key) + ": " + str(value) + "\n"
    return chain


def addHeader(value, depth):
    chain = buildHeaderChain(depth)
    chain = chain.replace('value', value.title())
    return chain


# Remove ansible branding from results
def rec_ansible_key_strip(obj):
    if isinstance(obj, dict):
        return {key.replace('ansible_', ''): rec_ansible_key_strip(val) for key, val in obj.items()}
    return obj


# COMMAND FUNCTIONS


def generic_ansible(integration_name, command, args: Dict[str, Any]) -> CommandResults:

    readable_output = ""
    sshkey = ""
    fork_count = 1   # default to executing against 1 host at a time

    if args.get('concurrency'):
        fork_count = cast(int, args.get('concurrency'))

    inventory: Dict[str, dict] = {}
    inventory['all'] = {}
    inventory['all']['hosts'] = {}

    if type(args['host']) is list:
        # host arg can be a array of multiple hosts
        hosts = args['host']
    else:
        # host arg could also be csv
        hosts = [host.strip() for host in args['host'].split(',')]

    for host in hosts:
        new_host = {}
        new_host['ansible_host'] = host

        if ":" in host:
            address = host.split(':')
            new_host['ansible_port'] = address[1]
            new_host['ansible_host'] = address[0]
        else:
            new_host['ansible_host'] = host
            if demisto.params().get('port'):
                new_host['ansible_port'] = demisto.params().get('port')
        # Cisco NXOS

        # Different credential options
        # SSH Key saved in credential manager selection
        sshkey = ""
        if demisto.params().get('creds', {}).get('credentials').get('sshkey'):
            username = demisto.params().get('creds', {}).get('credentials').get('user')
            sshkey = demisto.params().get('creds', {}).get('credentials').get('sshkey')

            new_host['ansible_user'] = username

        # Password saved in credential manager selection
        elif demisto.params().get('creds', {}).get('credentials').get('password'):
            username = demisto.params().get('creds', {}).get('credentials').get('user')
            password = demisto.params().get('creds', {}).get('credentials').get('password')

            new_host['ansible_user'] = username
            new_host['ansible_password'] = password

        # username/password individually entered
        else:
            username = demisto.params().get('creds', {}).get('identifier')
            password = demisto.params().get('creds', {}).get('password')

            new_host['ansible_user'] = username
            new_host['ansible_password'] = password

        new_host['ansible_connection'] = 'network_cli'
        new_host['ansible_network_os'] = 'nxos'
        new_host['ansible_become'] = 'yes'
        new_host['ansible_become_method'] = 'enable'
        inventory['all']['hosts'][host] = new_host
    module_args = ""
    # build module args list
    for arg_key, arg_value in args.items():
        # skip hardcoded host arg, as it doesn't related to module
        if arg_key == 'host':
            continue

        module_args += "%s=\"%s\" " % (arg_key, arg_value)

    r = ansible_runner.run(inventory=inventory, host_pattern='all', module=command, quiet=True,
                           omit_event_data=True, ssh_key=sshkey, module_args=module_args, forks=fork_count)

    results = []
    for each_host_event in r.events:
        # Troubleshooting
        # demisto.log("%s: %s\n" % (each_host_event['event'], each_host_event))
        if each_host_event['event'] in ["runner_on_ok", "runner_on_unreachable", "runner_on_failed"]:

            # parse results

            result = json.loads('{' + each_host_event['stdout'].split('{', 1)[1])
            host = each_host_event['stdout'].split('|', 1)[0].strip()
            status = each_host_event['stdout'].replace('=>', '|').split('|', 3)[1]

            # if successful build outputs
            if each_host_event['event'] == "runner_on_ok":
                if 'fact' in command:
                    result = result['ansible_facts']
                else:
                    if result.get(command) is not None:
                        result = result[command]
                    else:
                        result.pop("ansible_facts", None)

                result = rec_ansible_key_strip(result)

                if host != "localhost":
                    readable_output += "# %s - %s\n" % (host, status)
                else:
                    # This is integration is not host based
                    readable_output += "# %s\n" % status

                readable_output += dict2md(result)

                # add host and status to result
                result['host'] = host
                result['status'] = status

                results.append(result)
            if each_host_event['event'] == "runner_on_unreachable":
                msg = "Host %s unreachable\nError Details: %s" % (host, result)
                return_error(msg)

            if each_host_event['event'] == "runner_on_failed":
                msg = "Host %s failed running command\nError Details: %s" % (host, result)
                return_error(msg)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=integration_name + '.' + command,
        outputs_key_field='',
        outputs=results
    )


# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'nxos_aaa_server':
            return_results(generic_ansible('cisconx-os', 'nxos_aaa_server', demisto.args()))
        elif demisto.command() == 'nxos_aaa_server_host':
            return_results(generic_ansible('cisconx-os', 'nxos_aaa_server_host', demisto.args()))
        elif demisto.command() == 'nxos_acl':
            return_results(generic_ansible('cisconx-os', 'nxos_acl', demisto.args()))
        elif demisto.command() == 'nxos_acl_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_acl_interface', demisto.args()))
        elif demisto.command() == 'nxos_banner':
            return_results(generic_ansible('cisconx-os', 'nxos_banner', demisto.args()))
        elif demisto.command() == 'nxos_bfd_global':
            return_results(generic_ansible('cisconx-os', 'nxos_bfd_global', demisto.args()))
        elif demisto.command() == 'nxos_bfd_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_bfd_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_bgp':
            return_results(generic_ansible('cisconx-os', 'nxos_bgp', demisto.args()))
        elif demisto.command() == 'nxos_bgp_af':
            return_results(generic_ansible('cisconx-os', 'nxos_bgp_af', demisto.args()))
        elif demisto.command() == 'nxos_bgp_neighbor':
            return_results(generic_ansible('cisconx-os', 'nxos_bgp_neighbor', demisto.args()))
        elif demisto.command() == 'nxos_bgp_neighbor_af':
            return_results(generic_ansible('cisconx-os', 'nxos_bgp_neighbor_af', demisto.args()))
        elif demisto.command() == 'nxos_command':
            return_results(generic_ansible('cisconx-os', 'nxos_command', demisto.args()))
        elif demisto.command() == 'nxos_config':
            return_results(generic_ansible('cisconx-os', 'nxos_config', demisto.args()))
        elif demisto.command() == 'nxos_evpn_global':
            return_results(generic_ansible('cisconx-os', 'nxos_evpn_global', demisto.args()))
        elif demisto.command() == 'nxos_evpn_vni':
            return_results(generic_ansible('cisconx-os', 'nxos_evpn_vni', demisto.args()))
        elif demisto.command() == 'nxos_facts':
            return_results(generic_ansible('cisconx-os', 'nxos_facts', demisto.args()))
        elif demisto.command() == 'nxos_feature':
            return_results(generic_ansible('cisconx-os', 'nxos_feature', demisto.args()))
        elif demisto.command() == 'nxos_gir':
            return_results(generic_ansible('cisconx-os', 'nxos_gir', demisto.args()))
        elif demisto.command() == 'nxos_gir_profile_management':
            return_results(generic_ansible('cisconx-os', 'nxos_gir_profile_management', demisto.args()))
        elif demisto.command() == 'nxos_hsrp':
            return_results(generic_ansible('cisconx-os', 'nxos_hsrp', demisto.args()))
        elif demisto.command() == 'nxos_igmp':
            return_results(generic_ansible('cisconx-os', 'nxos_igmp', demisto.args()))
        elif demisto.command() == 'nxos_igmp_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_igmp_interface', demisto.args()))
        elif demisto.command() == 'nxos_igmp_snooping':
            return_results(generic_ansible('cisconx-os', 'nxos_igmp_snooping', demisto.args()))
        elif demisto.command() == 'nxos_install_os':
            return_results(generic_ansible('cisconx-os', 'nxos_install_os', demisto.args()))
        elif demisto.command() == 'nxos_interface_ospf':
            return_results(generic_ansible('cisconx-os', 'nxos_interface_ospf', demisto.args()))
        elif demisto.command() == 'nxos_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_l2_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_l2_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_l3_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_l3_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_lacp':
            return_results(generic_ansible('cisconx-os', 'nxos_lacp', demisto.args()))
        elif demisto.command() == 'nxos_lacp_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_lacp_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_lag_interfaces':
            return_results(generic_ansible('cisconx-os', 'nxos_lag_interfaces', demisto.args()))
        elif demisto.command() == 'nxos_lldp':
            return_results(generic_ansible('cisconx-os', 'nxos_lldp', demisto.args()))
        elif demisto.command() == 'nxos_lldp_global':
            return_results(generic_ansible('cisconx-os', 'nxos_lldp_global', demisto.args()))
        elif demisto.command() == 'nxos_logging':
            return_results(generic_ansible('cisconx-os', 'nxos_logging', demisto.args()))
        elif demisto.command() == 'nxos_ntp':
            return_results(generic_ansible('cisconx-os', 'nxos_ntp', demisto.args()))
        elif demisto.command() == 'nxos_ntp_auth':
            return_results(generic_ansible('cisconx-os', 'nxos_ntp_auth', demisto.args()))
        elif demisto.command() == 'nxos_ntp_options':
            return_results(generic_ansible('cisconx-os', 'nxos_ntp_options', demisto.args()))
        elif demisto.command() == 'nxos_nxapi':
            return_results(generic_ansible('cisconx-os', 'nxos_nxapi', demisto.args()))
        elif demisto.command() == 'nxos_ospf':
            return_results(generic_ansible('cisconx-os', 'nxos_ospf', demisto.args()))
        elif demisto.command() == 'nxos_ospf_vrf':
            return_results(generic_ansible('cisconx-os', 'nxos_ospf_vrf', demisto.args()))
        elif demisto.command() == 'nxos_overlay_global':
            return_results(generic_ansible('cisconx-os', 'nxos_overlay_global', demisto.args()))
        elif demisto.command() == 'nxos_pim':
            return_results(generic_ansible('cisconx-os', 'nxos_pim', demisto.args()))
        elif demisto.command() == 'nxos_pim_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_pim_interface', demisto.args()))
        elif demisto.command() == 'nxos_pim_rp_address':
            return_results(generic_ansible('cisconx-os', 'nxos_pim_rp_address', demisto.args()))
        elif demisto.command() == 'nxos_ping':
            return_results(generic_ansible('cisconx-os', 'nxos_ping', demisto.args()))
        elif demisto.command() == 'nxos_reboot':
            return_results(generic_ansible('cisconx-os', 'nxos_reboot', demisto.args()))
        elif demisto.command() == 'nxos_rollback':
            return_results(generic_ansible('cisconx-os', 'nxos_rollback', demisto.args()))
        elif demisto.command() == 'nxos_rpm':
            return_results(generic_ansible('cisconx-os', 'nxos_rpm', demisto.args()))
        elif demisto.command() == 'nxos_smu':
            return_results(generic_ansible('cisconx-os', 'nxos_smu', demisto.args()))
        elif demisto.command() == 'nxos_snapshot':
            return_results(generic_ansible('cisconx-os', 'nxos_snapshot', demisto.args()))
        elif demisto.command() == 'nxos_snmp_community':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_community', demisto.args()))
        elif demisto.command() == 'nxos_snmp_contact':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_contact', demisto.args()))
        elif demisto.command() == 'nxos_snmp_host':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_host', demisto.args()))
        elif demisto.command() == 'nxos_snmp_location':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_location', demisto.args()))
        elif demisto.command() == 'nxos_snmp_traps':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_traps', demisto.args()))
        elif demisto.command() == 'nxos_snmp_user':
            return_results(generic_ansible('cisconx-os', 'nxos_snmp_user', demisto.args()))
        elif demisto.command() == 'nxos_static_route':
            return_results(generic_ansible('cisconx-os', 'nxos_static_route', demisto.args()))
        elif demisto.command() == 'nxos_system':
            return_results(generic_ansible('cisconx-os', 'nxos_system', demisto.args()))
        elif demisto.command() == 'nxos_telemetry':
            return_results(generic_ansible('cisconx-os', 'nxos_telemetry', demisto.args()))
        elif demisto.command() == 'nxos_udld':
            return_results(generic_ansible('cisconx-os', 'nxos_udld', demisto.args()))
        elif demisto.command() == 'nxos_udld_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_udld_interface', demisto.args()))
        elif demisto.command() == 'nxos_user':
            return_results(generic_ansible('cisconx-os', 'nxos_user', demisto.args()))
        elif demisto.command() == 'nxos_vlans':
            return_results(generic_ansible('cisconx-os', 'nxos_vlans', demisto.args()))
        elif demisto.command() == 'nxos_vpc':
            return_results(generic_ansible('cisconx-os', 'nxos_vpc', demisto.args()))
        elif demisto.command() == 'nxos_vpc_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_vpc_interface', demisto.args()))
        elif demisto.command() == 'nxos_vrf':
            return_results(generic_ansible('cisconx-os', 'nxos_vrf', demisto.args()))
        elif demisto.command() == 'nxos_vrf_af':
            return_results(generic_ansible('cisconx-os', 'nxos_vrf_af', demisto.args()))
        elif demisto.command() == 'nxos_vrf_interface':
            return_results(generic_ansible('cisconx-os', 'nxos_vrf_interface', demisto.args()))
        elif demisto.command() == 'nxos_vrrp':
            return_results(generic_ansible('cisconx-os', 'nxos_vrrp', demisto.args()))
        elif demisto.command() == 'nxos_vtp_domain':
            return_results(generic_ansible('cisconx-os', 'nxos_vtp_domain', demisto.args()))
        elif demisto.command() == 'nxos_vtp_password':
            return_results(generic_ansible('cisconx-os', 'nxos_vtp_password', demisto.args()))
        elif demisto.command() == 'nxos_vtp_version':
            return_results(generic_ansible('cisconx-os', 'nxos_vtp_version', demisto.args()))
        elif demisto.command() == 'nxos_vxlan_vtep':
            return_results(generic_ansible('cisconx-os', 'nxos_vxlan_vtep', demisto.args()))
        elif demisto.command() == 'nxos_vxlan_vtep_vni':
            return_results(generic_ansible('cisconx-os', 'nxos_vxlan_vtep_vni', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
