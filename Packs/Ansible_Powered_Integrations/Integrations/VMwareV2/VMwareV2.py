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

    inventory['all']['hosts']['localhost'] = {}
    inventory['all']['hosts']['localhost']['ansible_connection'] = 'local'

    module_args = ""
    # build module args list
    for arg_key, arg_value in args.items():
        # skip hardcoded host arg, as it doesn't related to module
        if arg_key == 'host':
            continue

        module_args += "%s=\"%s\" " % (arg_key, arg_value)
    # If this isn't host based, then all the integratation parms will be used as command args
    for arg_key, arg_value in demisto.params().items():
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
    # This is integration is not host based and always runs against localhost
    results = results[0]

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
        elif demisto.command() == 'vmware_about_info':
            return_results(generic_ansible('vmwarev2', 'vmware_about_info', demisto.args()))
        elif demisto.command() == 'vmware_category':
            return_results(generic_ansible('vmwarev2', 'vmware_category', demisto.args()))
        elif demisto.command() == 'vmware_category_info':
            return_results(generic_ansible('vmwarev2', 'vmware_category_info', demisto.args()))
        elif demisto.command() == 'vmware_cfg_backup':
            return_results(generic_ansible('vmwarev2', 'vmware_cfg_backup', demisto.args()))
        elif demisto.command() == 'vmware_cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster', demisto.args()))
        elif demisto.command() == 'vmware_cluster_drs':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_drs', demisto.args()))
        elif demisto.command() == 'vmware_cluster_ha':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_ha', demisto.args()))
        elif demisto.command() == 'vmware_cluster_info':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_info', demisto.args()))
        elif demisto.command() == 'vmware_cluster_vsan':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_vsan', demisto.args()))
        elif demisto.command() == 'vmware_content_deploy_template':
            return_results(generic_ansible('vmwarev2', 'vmware_content_deploy_template', demisto.args()))
        elif demisto.command() == 'vmware_content_library_info':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_info', demisto.args()))
        elif demisto.command() == 'vmware_content_library_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_manager', demisto.args()))
        elif demisto.command() == 'vmware_datacenter':
            return_results(generic_ansible('vmwarev2', 'vmware_datacenter', demisto.args()))
        elif demisto.command() == 'vmware_datastore_cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_cluster', demisto.args()))
        elif demisto.command() == 'vmware_datastore_info':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_info', demisto.args()))
        elif demisto.command() == 'vmware_datastore_maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_maintenancemode', demisto.args()))
        elif demisto.command() == 'vmware_dns_config':
            return_results(generic_ansible('vmwarev2', 'vmware_dns_config', demisto.args()))
        elif demisto.command() == 'vmware_drs_group':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group', demisto.args()))
        elif demisto.command() == 'vmware_drs_group_info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group_info', demisto.args()))
        elif demisto.command() == 'vmware_drs_rule_info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_rule_info', demisto.args()))
        elif demisto.command() == 'vmware_dvs_host':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_host', demisto.args()))
        elif demisto.command() == 'vmware_dvs_portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup', demisto.args()))
        elif demisto.command() == 'vmware_dvs_portgroup_find':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_find', demisto.args()))
        elif demisto.command() == 'vmware_dvs_portgroup_info':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_info', demisto.args()))
        elif demisto.command() == 'vmware_dvswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch', demisto.args()))
        elif demisto.command() == 'vmware_dvswitch_lacp':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_lacp', demisto.args()))
        elif demisto.command() == 'vmware_dvswitch_nioc':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_nioc', demisto.args()))
        elif demisto.command() == 'vmware_dvswitch_pvlans':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_pvlans', demisto.args()))
        elif demisto.command() == 'vmware_dvswitch_uplink_pg':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_uplink_pg', demisto.args()))
        elif demisto.command() == 'vmware_evc_mode':
            return_results(generic_ansible('vmwarev2', 'vmware_evc_mode', demisto.args()))
        elif demisto.command() == 'vmware_folder_info':
            return_results(generic_ansible('vmwarev2', 'vmware_folder_info', demisto.args()))
        elif demisto.command() == 'vmware_guest':
            return_results(generic_ansible('vmwarev2', 'vmware_guest', demisto.args()))
        elif demisto.command() == 'vmware_guest_boot_info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_info', demisto.args()))
        elif demisto.command() == 'vmware_guest_boot_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_manager', demisto.args()))
        elif demisto.command() == 'vmware_guest_custom_attribute_defs':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attribute_defs', demisto.args()))
        elif demisto.command() == 'vmware_guest_custom_attributes':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attributes', demisto.args()))
        elif demisto.command() == 'vmware_guest_customization_info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_customization_info', demisto.args()))
        elif demisto.command() == 'vmware_guest_disk':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk', demisto.args()))
        elif demisto.command() == 'vmware_guest_disk_info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk_info', demisto.args()))
        elif demisto.command() == 'vmware_guest_find':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_find', demisto.args()))
        elif demisto.command() == 'vmware_guest_info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_info', demisto.args()))
        elif demisto.command() == 'vmware_guest_move':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_move', demisto.args()))
        elif demisto.command() == 'vmware_guest_network':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_network', demisto.args()))
        elif demisto.command() == 'vmware_guest_powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_powerstate', demisto.args()))
        elif demisto.command() == 'vmware_guest_screenshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_screenshot', demisto.args()))
        elif demisto.command() == 'vmware_guest_sendkey':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_sendkey', demisto.args()))
        elif demisto.command() == 'vmware_guest_snapshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot', demisto.args()))
        elif demisto.command() == 'vmware_guest_snapshot_info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot_info', demisto.args()))
        elif demisto.command() == 'vmware_guest_tools_upgrade':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_upgrade', demisto.args()))
        elif demisto.command() == 'vmware_guest_tools_wait':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_wait', demisto.args()))
        elif demisto.command() == 'vmware_guest_video':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_video', demisto.args()))
        elif demisto.command() == 'vmware_guest_vnc':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_vnc', demisto.args()))
        elif demisto.command() == 'vmware_host':
            return_results(generic_ansible('vmwarev2', 'vmware_host', demisto.args()))
        elif demisto.command() == 'vmware_host_acceptance':
            return_results(generic_ansible('vmwarev2', 'vmware_host_acceptance', demisto.args()))
        elif demisto.command() == 'vmware_host_active_directory':
            return_results(generic_ansible('vmwarev2', 'vmware_host_active_directory', demisto.args()))
        elif demisto.command() == 'vmware_host_capability_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_capability_info', demisto.args()))
        elif demisto.command() == 'vmware_host_config_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_info', demisto.args()))
        elif demisto.command() == 'vmware_host_config_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_manager', demisto.args()))
        elif demisto.command() == 'vmware_host_datastore':
            return_results(generic_ansible('vmwarev2', 'vmware_host_datastore', demisto.args()))
        elif demisto.command() == 'vmware_host_dns_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_dns_info', demisto.args()))
        elif demisto.command() == 'vmware_host_facts':
            return_results(generic_ansible('vmwarev2', 'vmware_host_facts', demisto.args()))
        elif demisto.command() == 'vmware_host_feature_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_feature_info', demisto.args()))
        elif demisto.command() == 'vmware_host_firewall_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_info', demisto.args()))
        elif demisto.command() == 'vmware_host_firewall_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_manager', demisto.args()))
        elif demisto.command() == 'vmware_host_hyperthreading':
            return_results(generic_ansible('vmwarev2', 'vmware_host_hyperthreading', demisto.args()))
        elif demisto.command() == 'vmware_host_ipv6':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ipv6', demisto.args()))
        elif demisto.command() == 'vmware_host_kernel_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_kernel_manager', demisto.args()))
        elif demisto.command() == 'vmware_host_lockdown':
            return_results(generic_ansible('vmwarev2', 'vmware_host_lockdown', demisto.args()))
        elif demisto.command() == 'vmware_host_ntp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp', demisto.args()))
        elif demisto.command() == 'vmware_host_ntp_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp_info', demisto.args()))
        elif demisto.command() == 'vmware_host_package_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_package_info', demisto.args()))
        elif demisto.command() == 'vmware_host_powermgmt_policy':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powermgmt_policy', demisto.args()))
        elif demisto.command() == 'vmware_host_powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powerstate', demisto.args()))
        elif demisto.command() == 'vmware_host_scanhba':
            return_results(generic_ansible('vmwarev2', 'vmware_host_scanhba', demisto.args()))
        elif demisto.command() == 'vmware_host_service_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_info', demisto.args()))
        elif demisto.command() == 'vmware_host_service_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_manager', demisto.args()))
        elif demisto.command() == 'vmware_host_snmp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_snmp', demisto.args()))
        elif demisto.command() == 'vmware_host_ssl_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ssl_info', demisto.args()))
        elif demisto.command() == 'vmware_host_vmhba_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmhba_info', demisto.args()))
        elif demisto.command() == 'vmware_host_vmnic_info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmnic_info', demisto.args()))
        elif demisto.command() == 'vmware_local_role_info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_info', demisto.args()))
        elif demisto.command() == 'vmware_local_role_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_manager', demisto.args()))
        elif demisto.command() == 'vmware_local_user_info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_info', demisto.args()))
        elif demisto.command() == 'vmware_local_user_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_manager', demisto.args()))
        elif demisto.command() == 'vmware_maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_maintenancemode', demisto.args()))
        elif demisto.command() == 'vmware_migrate_vmk':
            return_results(generic_ansible('vmwarev2', 'vmware_migrate_vmk', demisto.args()))
        elif demisto.command() == 'vmware_object_role_permission':
            return_results(generic_ansible('vmwarev2', 'vmware_object_role_permission', demisto.args()))
        elif demisto.command() == 'vmware_portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup', demisto.args()))
        elif demisto.command() == 'vmware_portgroup_info':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup_info', demisto.args()))
        elif demisto.command() == 'vmware_resource_pool':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool', demisto.args()))
        elif demisto.command() == 'vmware_resource_pool_info':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool_info', demisto.args()))
        elif demisto.command() == 'vmware_tag':
            return_results(generic_ansible('vmwarev2', 'vmware_tag', demisto.args()))
        elif demisto.command() == 'vmware_tag_info':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_info', demisto.args()))
        elif demisto.command() == 'vmware_tag_manager':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_manager', demisto.args()))
        elif demisto.command() == 'vmware_target_canonical_info':
            return_results(generic_ansible('vmwarev2', 'vmware_target_canonical_info', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_settings':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_settings', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_statistics':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_statistics', demisto.args()))
        elif demisto.command() == 'vmware_vm_host_drs_rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_host_drs_rule', demisto.args()))
        elif demisto.command() == 'vmware_vm_info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_info', demisto.args()))
        elif demisto.command() == 'vmware_vm_shell':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_shell', demisto.args()))
        elif demisto.command() == 'vmware_vm_storage_policy_info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_storage_policy_info', demisto.args()))
        elif demisto.command() == 'vmware_vm_vm_drs_rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vm_drs_rule', demisto.args()))
        elif demisto.command() == 'vmware_vm_vss_dvs_migrate':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vss_dvs_migrate', demisto.args()))
        elif demisto.command() == 'vmware_vmkernel':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel', demisto.args()))
        elif demisto.command() == 'vmware_vmkernel_info':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_info', demisto.args()))
        elif demisto.command() == 'vmware_vmkernel_ip_config':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_ip_config', demisto.args()))
        elif demisto.command() == 'vmware_vmotion':
            return_results(generic_ansible('vmwarev2', 'vmware_vmotion', demisto.args()))
        elif demisto.command() == 'vmware_vsan_cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_vsan_cluster', demisto.args()))
        elif demisto.command() == 'vmware_vspan_session':
            return_results(generic_ansible('vmwarev2', 'vmware_vspan_session', demisto.args()))
        elif demisto.command() == 'vmware_vswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch', demisto.args()))
        elif demisto.command() == 'vmware_vswitch_info':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch_info', demisto.args()))
        elif demisto.command() == 'vmware_vsphere_file':
            return_results(generic_ansible('vmwarev2', 'vsphere_file', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_extension':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_extension_info':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension_info', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_folder':
            return_results(generic_ansible('vmwarev2', 'vcenter_folder', demisto.args()))
        elif demisto.command() == 'vmware_vcenter_license':
            return_results(generic_ansible('vmwarev2', 'vcenter_license', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
