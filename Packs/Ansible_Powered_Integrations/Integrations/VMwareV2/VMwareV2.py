import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import traceback
from typing import Dict, cast

import ansible_runner
import ssh_agent_setup


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
        elif demisto.command() == 'vmware-about-info':
            return_results(generic_ansible('vmwarev2', 'vmware_about_info', demisto.args()))
        elif demisto.command() == 'vmware-category':
            return_results(generic_ansible('vmwarev2', 'vmware_category', demisto.args()))
        elif demisto.command() == 'vmware-category-info':
            return_results(generic_ansible('vmwarev2', 'vmware_category_info', demisto.args()))
        elif demisto.command() == 'vmware-cfg-backup':
            return_results(generic_ansible('vmwarev2', 'vmware_cfg_backup', demisto.args()))
        elif demisto.command() == 'vmware-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster', demisto.args()))
        elif demisto.command() == 'vmware-cluster-drs':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_drs', demisto.args()))
        elif demisto.command() == 'vmware-cluster-ha':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_ha', demisto.args()))
        elif demisto.command() == 'vmware-cluster-info':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_info', demisto.args()))
        elif demisto.command() == 'vmware-cluster-vsan':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_vsan', demisto.args()))
        elif demisto.command() == 'vmware-content-deploy-template':
            return_results(generic_ansible('vmwarev2', 'vmware_content_deploy_template', demisto.args()))
        elif demisto.command() == 'vmware-content-library-info':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_info', demisto.args()))
        elif demisto.command() == 'vmware-content-library-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_manager', demisto.args()))
        elif demisto.command() == 'vmware-datacenter':
            return_results(generic_ansible('vmwarev2', 'vmware_datacenter', demisto.args()))
        elif demisto.command() == 'vmware-datastore-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_cluster', demisto.args()))
        elif demisto.command() == 'vmware-datastore-info':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_info', demisto.args()))
        elif demisto.command() == 'vmware-datastore-maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_maintenancemode', demisto.args()))
        elif demisto.command() == 'vmware-dns-config':
            return_results(generic_ansible('vmwarev2', 'vmware_dns_config', demisto.args()))
        elif demisto.command() == 'vmware-drs-group':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group', demisto.args()))
        elif demisto.command() == 'vmware-drs-group-info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group_info', demisto.args()))
        elif demisto.command() == 'vmware-drs-rule-info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_rule_info', demisto.args()))
        elif demisto.command() == 'vmware-dvs-host':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_host', demisto.args()))
        elif demisto.command() == 'vmware-dvs-portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup', demisto.args()))
        elif demisto.command() == 'vmware-dvs-portgroup-find':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_find', demisto.args()))
        elif demisto.command() == 'vmware-dvs-portgroup-info':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_info', demisto.args()))
        elif demisto.command() == 'vmware-dvswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch', demisto.args()))
        elif demisto.command() == 'vmware-dvswitch-lacp':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_lacp', demisto.args()))
        elif demisto.command() == 'vmware-dvswitch-nioc':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_nioc', demisto.args()))
        elif demisto.command() == 'vmware-dvswitch-pvlans':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_pvlans', demisto.args()))
        elif demisto.command() == 'vmware-dvswitch-uplink-pg':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_uplink_pg', demisto.args()))
        elif demisto.command() == 'vmware-evc-mode':
            return_results(generic_ansible('vmwarev2', 'vmware_evc_mode', demisto.args()))
        elif demisto.command() == 'vmware-folder-info':
            return_results(generic_ansible('vmwarev2', 'vmware_folder_info', demisto.args()))
        elif demisto.command() == 'vmware-guest':
            return_results(generic_ansible('vmwarev2', 'vmware_guest', demisto.args()))
        elif demisto.command() == 'vmware-guest-boot-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_info', demisto.args()))
        elif demisto.command() == 'vmware-guest-boot-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_manager', demisto.args()))
        elif demisto.command() == 'vmware-guest-custom-attribute-defs':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attribute_defs', demisto.args()))
        elif demisto.command() == 'vmware-guest-custom-attributes':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attributes', demisto.args()))
        elif demisto.command() == 'vmware-guest-customization-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_customization_info', demisto.args()))
        elif demisto.command() == 'vmware-guest-disk':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk', demisto.args()))
        elif demisto.command() == 'vmware-guest-disk-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk_info', demisto.args()))
        elif demisto.command() == 'vmware-guest-find':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_find', demisto.args()))
        elif demisto.command() == 'vmware-guest-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_info', demisto.args()))
        elif demisto.command() == 'vmware-guest-move':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_move', demisto.args()))
        elif demisto.command() == 'vmware-guest-network':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_network', demisto.args()))
        elif demisto.command() == 'vmware-guest-powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_powerstate', demisto.args()))
        elif demisto.command() == 'vmware-guest-screenshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_screenshot', demisto.args()))
        elif demisto.command() == 'vmware-guest-sendkey':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_sendkey', demisto.args()))
        elif demisto.command() == 'vmware-guest-snapshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot', demisto.args()))
        elif demisto.command() == 'vmware-guest-snapshot-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot_info', demisto.args()))
        elif demisto.command() == 'vmware-guest-tools-upgrade':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_upgrade', demisto.args()))
        elif demisto.command() == 'vmware-guest-tools-wait':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_wait', demisto.args()))
        elif demisto.command() == 'vmware-guest-video':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_video', demisto.args()))
        elif demisto.command() == 'vmware-guest-vnc':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_vnc', demisto.args()))
        elif demisto.command() == 'vmware-host':
            return_results(generic_ansible('vmwarev2', 'vmware_host', demisto.args()))
        elif demisto.command() == 'vmware-host-acceptance':
            return_results(generic_ansible('vmwarev2', 'vmware_host_acceptance', demisto.args()))
        elif demisto.command() == 'vmware-host-active-directory':
            return_results(generic_ansible('vmwarev2', 'vmware_host_active_directory', demisto.args()))
        elif demisto.command() == 'vmware-host-capability-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_capability_info', demisto.args()))
        elif demisto.command() == 'vmware-host-config-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_info', demisto.args()))
        elif demisto.command() == 'vmware-host-config-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_manager', demisto.args()))
        elif demisto.command() == 'vmware-host-datastore':
            return_results(generic_ansible('vmwarev2', 'vmware_host_datastore', demisto.args()))
        elif demisto.command() == 'vmware-host-dns-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_dns_info', demisto.args()))
        elif demisto.command() == 'vmware-host-facts':
            return_results(generic_ansible('vmwarev2', 'vmware_host_facts', demisto.args()))
        elif demisto.command() == 'vmware-host-feature-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_feature_info', demisto.args()))
        elif demisto.command() == 'vmware-host-firewall-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_info', demisto.args()))
        elif demisto.command() == 'vmware-host-firewall-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_manager', demisto.args()))
        elif demisto.command() == 'vmware-host-hyperthreading':
            return_results(generic_ansible('vmwarev2', 'vmware_host_hyperthreading', demisto.args()))
        elif demisto.command() == 'vmware-host-ipv6':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ipv6', demisto.args()))
        elif demisto.command() == 'vmware-host-kernel-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_kernel_manager', demisto.args()))
        elif demisto.command() == 'vmware-host-lockdown':
            return_results(generic_ansible('vmwarev2', 'vmware_host_lockdown', demisto.args()))
        elif demisto.command() == 'vmware-host-ntp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp', demisto.args()))
        elif demisto.command() == 'vmware-host-ntp-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp_info', demisto.args()))
        elif demisto.command() == 'vmware-host-package-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_package_info', demisto.args()))
        elif demisto.command() == 'vmware-host-powermgmt-policy':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powermgmt_policy', demisto.args()))
        elif demisto.command() == 'vmware-host-powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powerstate', demisto.args()))
        elif demisto.command() == 'vmware-host-scanhba':
            return_results(generic_ansible('vmwarev2', 'vmware_host_scanhba', demisto.args()))
        elif demisto.command() == 'vmware-host-service-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_info', demisto.args()))
        elif demisto.command() == 'vmware-host-service-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_manager', demisto.args()))
        elif demisto.command() == 'vmware-host-snmp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_snmp', demisto.args()))
        elif demisto.command() == 'vmware-host-ssl-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ssl_info', demisto.args()))
        elif demisto.command() == 'vmware-host-vmhba-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmhba_info', demisto.args()))
        elif demisto.command() == 'vmware-host-vmnic-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmnic_info', demisto.args()))
        elif demisto.command() == 'vmware-local-role-info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_info', demisto.args()))
        elif demisto.command() == 'vmware-local-role-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_manager', demisto.args()))
        elif demisto.command() == 'vmware-local-user-info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_info', demisto.args()))
        elif demisto.command() == 'vmware-local-user-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_manager', demisto.args()))
        elif demisto.command() == 'vmware-maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_maintenancemode', demisto.args()))
        elif demisto.command() == 'vmware-migrate-vmk':
            return_results(generic_ansible('vmwarev2', 'vmware_migrate_vmk', demisto.args()))
        elif demisto.command() == 'vmware-object-role-permission':
            return_results(generic_ansible('vmwarev2', 'vmware_object_role_permission', demisto.args()))
        elif demisto.command() == 'vmware-portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup', demisto.args()))
        elif demisto.command() == 'vmware-portgroup-info':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup_info', demisto.args()))
        elif demisto.command() == 'vmware-resource-pool':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool', demisto.args()))
        elif demisto.command() == 'vmware-resource-pool-info':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool_info', demisto.args()))
        elif demisto.command() == 'vmware-tag':
            return_results(generic_ansible('vmwarev2', 'vmware_tag', demisto.args()))
        elif demisto.command() == 'vmware-tag-info':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_info', demisto.args()))
        elif demisto.command() == 'vmware-tag-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_manager', demisto.args()))
        elif demisto.command() == 'vmware-target-canonical-info':
            return_results(generic_ansible('vmwarev2', 'vmware_target_canonical_info', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-settings':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_settings', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-statistics':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_statistics', demisto.args()))
        elif demisto.command() == 'vmware-vm-host-drs-rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_host_drs_rule', demisto.args()))
        elif demisto.command() == 'vmware-vm-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_info', demisto.args()))
        elif demisto.command() == 'vmware-vm-shell':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_shell', demisto.args()))
        elif demisto.command() == 'vmware-vm-storage-policy-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_storage_policy_info', demisto.args()))
        elif demisto.command() == 'vmware-vm-vm-drs-rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vm_drs_rule', demisto.args()))
        elif demisto.command() == 'vmware-vm-vss-dvs-migrate':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vss_dvs_migrate', demisto.args()))
        elif demisto.command() == 'vmware-vmkernel':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel', demisto.args()))
        elif demisto.command() == 'vmware-vmkernel-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_info', demisto.args()))
        elif demisto.command() == 'vmware-vmkernel-ip-config':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_ip_config', demisto.args()))
        elif demisto.command() == 'vmware-vmotion':
            return_results(generic_ansible('vmwarev2', 'vmware_vmotion', demisto.args()))
        elif demisto.command() == 'vmware-vsan-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_vsan_cluster', demisto.args()))
        elif demisto.command() == 'vmware-vspan-session':
            return_results(generic_ansible('vmwarev2', 'vmware_vspan_session', demisto.args()))
        elif demisto.command() == 'vmware-vswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch', demisto.args()))
        elif demisto.command() == 'vmware-vswitch-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch_info', demisto.args()))
        elif demisto.command() == 'vmware-vsphere-file':
            return_results(generic_ansible('vmwarev2', 'vsphere_file', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-extension':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-extension-info':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension_info', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-folder':
            return_results(generic_ansible('vmwarev2', 'vcenter_folder', demisto.args()))
        elif demisto.command() == 'vmware-vcenter-license':
            return_results(generic_ansible('vmwarev2', 'vcenter_license', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
