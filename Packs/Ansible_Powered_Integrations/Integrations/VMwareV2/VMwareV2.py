import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'local'

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    # Common Inputs
    command = demisto.command()
    args = demisto.args()
    int_params = demisto.params()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'vmware-about-info':
            return_results(generic_ansible('vmwarev2', 'vmware_about_info', args, int_params))
        elif demisto.command() == 'vmware-category':
            return_results(generic_ansible('vmwarev2', 'vmware_category', args, int_params))
        elif demisto.command() == 'vmware-category-info':
            return_results(generic_ansible('vmwarev2', 'vmware_category_info', args, int_params))
        elif demisto.command() == 'vmware-cfg-backup':
            return_results(generic_ansible('vmwarev2', 'vmware_cfg_backup', args, int_params))
        elif demisto.command() == 'vmware-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster', args, int_params))
        elif demisto.command() == 'vmware-cluster-drs':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_drs', args, int_params))
        elif demisto.command() == 'vmware-cluster-ha':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_ha', args, int_params))
        elif demisto.command() == 'vmware-cluster-info':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_info', args, int_params))
        elif demisto.command() == 'vmware-cluster-vsan':
            return_results(generic_ansible('vmwarev2', 'vmware_cluster_vsan', args, int_params))
        elif demisto.command() == 'vmware-content-deploy-template':
            return_results(generic_ansible('vmwarev2', 'vmware_content_deploy_template', args, int_params))
        elif demisto.command() == 'vmware-content-library-info':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_info', args, int_params))
        elif demisto.command() == 'vmware-content-library-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_content_library_manager', args, int_params))
        elif demisto.command() == 'vmware-datacenter':
            return_results(generic_ansible('vmwarev2', 'vmware_datacenter', args, int_params))
        elif demisto.command() == 'vmware-datastore-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_cluster', args, int_params))
        elif demisto.command() == 'vmware-datastore-info':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_info', args, int_params))
        elif demisto.command() == 'vmware-datastore-maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_datastore_maintenancemode', args, int_params))
        elif demisto.command() == 'vmware-dns-config':
            return_results(generic_ansible('vmwarev2', 'vmware_dns_config', args, int_params))
        elif demisto.command() == 'vmware-drs-group':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group', args, int_params))
        elif demisto.command() == 'vmware-drs-group-info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_group_info', args, int_params))
        elif demisto.command() == 'vmware-drs-rule-info':
            return_results(generic_ansible('vmwarev2', 'vmware_drs_rule_info', args, int_params))
        elif demisto.command() == 'vmware-dvs-host':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_host', args, int_params))
        elif demisto.command() == 'vmware-dvs-portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup', args, int_params))
        elif demisto.command() == 'vmware-dvs-portgroup-find':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_find', args, int_params))
        elif demisto.command() == 'vmware-dvs-portgroup-info':
            return_results(generic_ansible('vmwarev2', 'vmware_dvs_portgroup_info', args, int_params))
        elif demisto.command() == 'vmware-dvswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch', args, int_params))
        elif demisto.command() == 'vmware-dvswitch-lacp':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_lacp', args, int_params))
        elif demisto.command() == 'vmware-dvswitch-nioc':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_nioc', args, int_params))
        elif demisto.command() == 'vmware-dvswitch-pvlans':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_pvlans', args, int_params))
        elif demisto.command() == 'vmware-dvswitch-uplink-pg':
            return_results(generic_ansible('vmwarev2', 'vmware_dvswitch_uplink_pg', args, int_params))
        elif demisto.command() == 'vmware-evc-mode':
            return_results(generic_ansible('vmwarev2', 'vmware_evc_mode', args, int_params))
        elif demisto.command() == 'vmware-folder-info':
            return_results(generic_ansible('vmwarev2', 'vmware_folder_info', args, int_params))
        elif demisto.command() == 'vmware-guest':
            return_results(generic_ansible('vmwarev2', 'vmware_guest', args, int_params))
        elif demisto.command() == 'vmware-guest-boot-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_info', args, int_params))
        elif demisto.command() == 'vmware-guest-boot-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_boot_manager', args, int_params))
        elif demisto.command() == 'vmware-guest-custom-attribute-defs':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attribute_defs', args, int_params))
        elif demisto.command() == 'vmware-guest-custom-attributes':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_custom_attributes', args, int_params))
        elif demisto.command() == 'vmware-guest-customization-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_customization_info', args, int_params))
        elif demisto.command() == 'vmware-guest-disk':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk', args, int_params))
        elif demisto.command() == 'vmware-guest-disk-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_disk_info', args, int_params))
        elif demisto.command() == 'vmware-guest-find':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_find', args, int_params))
        elif demisto.command() == 'vmware-guest-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_info', args, int_params))
        elif demisto.command() == 'vmware-guest-move':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_move', args, int_params))
        elif demisto.command() == 'vmware-guest-network':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_network', args, int_params))
        elif demisto.command() == 'vmware-guest-powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_powerstate', args, int_params))
        elif demisto.command() == 'vmware-guest-screenshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_screenshot', args, int_params))
        elif demisto.command() == 'vmware-guest-sendkey':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_sendkey', args, int_params))
        elif demisto.command() == 'vmware-guest-snapshot':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot', args, int_params))
        elif demisto.command() == 'vmware-guest-snapshot-info':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_snapshot_info', args, int_params))
        elif demisto.command() == 'vmware-guest-tools-upgrade':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_upgrade', args, int_params))
        elif demisto.command() == 'vmware-guest-tools-wait':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_tools_wait', args, int_params))
        elif demisto.command() == 'vmware-guest-video':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_video', args, int_params))
        elif demisto.command() == 'vmware-guest-vnc':
            return_results(generic_ansible('vmwarev2', 'vmware_guest_vnc', args, int_params))
        elif demisto.command() == 'vmware-host':
            return_results(generic_ansible('vmwarev2', 'vmware_host', args, int_params))
        elif demisto.command() == 'vmware-host-acceptance':
            return_results(generic_ansible('vmwarev2', 'vmware_host_acceptance', args, int_params))
        elif demisto.command() == 'vmware-host-active-directory':
            return_results(generic_ansible('vmwarev2', 'vmware_host_active_directory', args, int_params))
        elif demisto.command() == 'vmware-host-capability-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_capability_info', args, int_params))
        elif demisto.command() == 'vmware-host-config-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_info', args, int_params))
        elif demisto.command() == 'vmware-host-config-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_config_manager', args, int_params))
        elif demisto.command() == 'vmware-host-datastore':
            return_results(generic_ansible('vmwarev2', 'vmware_host_datastore', args, int_params))
        elif demisto.command() == 'vmware-host-dns-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_dns_info', args, int_params))
        elif demisto.command() == 'vmware-host-facts':
            return_results(generic_ansible('vmwarev2', 'vmware_host_facts', args, int_params))
        elif demisto.command() == 'vmware-host-feature-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_feature_info', args, int_params))
        elif demisto.command() == 'vmware-host-firewall-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_info', args, int_params))
        elif demisto.command() == 'vmware-host-firewall-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_firewall_manager', args, int_params))
        elif demisto.command() == 'vmware-host-hyperthreading':
            return_results(generic_ansible('vmwarev2', 'vmware_host_hyperthreading', args, int_params))
        elif demisto.command() == 'vmware-host-ipv6':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ipv6', args, int_params))
        elif demisto.command() == 'vmware-host-kernel-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_kernel_manager', args, int_params))
        elif demisto.command() == 'vmware-host-lockdown':
            return_results(generic_ansible('vmwarev2', 'vmware_host_lockdown', args, int_params))
        elif demisto.command() == 'vmware-host-ntp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp', args, int_params))
        elif demisto.command() == 'vmware-host-ntp-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ntp_info', args, int_params))
        elif demisto.command() == 'vmware-host-package-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_package_info', args, int_params))
        elif demisto.command() == 'vmware-host-powermgmt-policy':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powermgmt_policy', args, int_params))
        elif demisto.command() == 'vmware-host-powerstate':
            return_results(generic_ansible('vmwarev2', 'vmware_host_powerstate', args, int_params))
        elif demisto.command() == 'vmware-host-scanhba':
            return_results(generic_ansible('vmwarev2', 'vmware_host_scanhba', args, int_params))
        elif demisto.command() == 'vmware-host-service-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_info', args, int_params))
        elif demisto.command() == 'vmware-host-service-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_host_service_manager', args, int_params))
        elif demisto.command() == 'vmware-host-snmp':
            return_results(generic_ansible('vmwarev2', 'vmware_host_snmp', args, int_params))
        elif demisto.command() == 'vmware-host-ssl-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_ssl_info', args, int_params))
        elif demisto.command() == 'vmware-host-vmhba-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmhba_info', args, int_params))
        elif demisto.command() == 'vmware-host-vmnic-info':
            return_results(generic_ansible('vmwarev2', 'vmware_host_vmnic_info', args, int_params))
        elif demisto.command() == 'vmware-local-role-info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_info', args, int_params))
        elif demisto.command() == 'vmware-local-role-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_role_manager', args, int_params))
        elif demisto.command() == 'vmware-local-user-info':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_info', args, int_params))
        elif demisto.command() == 'vmware-local-user-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_local_user_manager', args, int_params))
        elif demisto.command() == 'vmware-maintenancemode':
            return_results(generic_ansible('vmwarev2', 'vmware_maintenancemode', args, int_params))
        elif demisto.command() == 'vmware-migrate-vmk':
            return_results(generic_ansible('vmwarev2', 'vmware_migrate_vmk', args, int_params))
        elif demisto.command() == 'vmware-object-role-permission':
            return_results(generic_ansible('vmwarev2', 'vmware_object_role_permission', args, int_params))
        elif demisto.command() == 'vmware-portgroup':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup', args, int_params))
        elif demisto.command() == 'vmware-portgroup-info':
            return_results(generic_ansible('vmwarev2', 'vmware_portgroup_info', args, int_params))
        elif demisto.command() == 'vmware-resource-pool':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool', args, int_params))
        elif demisto.command() == 'vmware-resource-pool-info':
            return_results(generic_ansible('vmwarev2', 'vmware_resource_pool_info', args, int_params))
        elif demisto.command() == 'vmware-tag':
            return_results(generic_ansible('vmwarev2', 'vmware_tag', args, int_params))
        elif demisto.command() == 'vmware-tag-info':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_info', args, int_params))
        elif demisto.command() == 'vmware-tag-manager':
            return_results(generic_ansible('vmwarev2', 'vmware_tag_manager', args, int_params))
        elif demisto.command() == 'vmware-target-canonical-info':
            return_results(generic_ansible('vmwarev2', 'vmware_target_canonical_info', args, int_params))
        elif demisto.command() == 'vmware-vcenter-settings':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_settings', args, int_params))
        elif demisto.command() == 'vmware-vcenter-statistics':
            return_results(generic_ansible('vmwarev2', 'vmware_vcenter_statistics', args, int_params))
        elif demisto.command() == 'vmware-vm-host-drs-rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_host_drs_rule', args, int_params))
        elif demisto.command() == 'vmware-vm-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_info', args, int_params))
        elif demisto.command() == 'vmware-vm-shell':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_shell', args, int_params))
        elif demisto.command() == 'vmware-vm-storage-policy-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_storage_policy_info', args, int_params))
        elif demisto.command() == 'vmware-vm-vm-drs-rule':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vm_drs_rule', args, int_params))
        elif demisto.command() == 'vmware-vm-vss-dvs-migrate':
            return_results(generic_ansible('vmwarev2', 'vmware_vm_vss_dvs_migrate', args, int_params))
        elif demisto.command() == 'vmware-vmkernel':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel', args, int_params))
        elif demisto.command() == 'vmware-vmkernel-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_info', args, int_params))
        elif demisto.command() == 'vmware-vmkernel-ip-config':
            return_results(generic_ansible('vmwarev2', 'vmware_vmkernel_ip_config', args, int_params))
        elif demisto.command() == 'vmware-vmotion':
            return_results(generic_ansible('vmwarev2', 'vmware_vmotion', args, int_params))
        elif demisto.command() == 'vmware-vsan-cluster':
            return_results(generic_ansible('vmwarev2', 'vmware_vsan_cluster', args, int_params))
        elif demisto.command() == 'vmware-vspan-session':
            return_results(generic_ansible('vmwarev2', 'vmware_vspan_session', args, int_params))
        elif demisto.command() == 'vmware-vswitch':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch', args, int_params))
        elif demisto.command() == 'vmware-vswitch-info':
            return_results(generic_ansible('vmwarev2', 'vmware_vswitch_info', args, int_params))
        elif demisto.command() == 'vmware-vsphere-file':
            return_results(generic_ansible('vmwarev2', 'vsphere_file', args, int_params))
        elif demisto.command() == 'vmware-vcenter-extension':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension', args, int_params))
        elif demisto.command() == 'vmware-vcenter-extension-info':
            return_results(generic_ansible('vmwarev2', 'vcenter_extension_info', args, int_params))
        elif demisto.command() == 'vmware-vcenter-folder':
            return_results(generic_ansible('vmwarev2', 'vcenter_folder', args, int_params))
        elif demisto.command() == 'vmware-vcenter-license':
            return_results(generic_ansible('vmwarev2', 'vcenter_license', args, int_params))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
