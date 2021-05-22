import json
import traceback
import ansible_runner
import ssh_agent_setup
from typing import Dict, cast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type =  'winrm'

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
        elif demisto.command() == 'win-gather-facts':
            return_results(generic_ansible('microsoftwindows', 'gather_facts', demisto.args()))
        elif demisto.command() == 'win-acl':
            return_results(generic_ansible('microsoftwindows', 'win_acl', demisto.args()))
        elif demisto.command() == 'win-acl-inheritance':
            return_results(generic_ansible('microsoftwindows', 'win_acl_inheritance', demisto.args()))
        elif demisto.command() == 'win-audit-policy-system':
            return_results(generic_ansible('microsoftwindows', 'win_audit_policy_system', demisto.args()))
        elif demisto.command() == 'win-audit-rule':
            return_results(generic_ansible('microsoftwindows', 'win_audit_rule', demisto.args()))
        elif demisto.command() == 'win-certificate-store':
            return_results(generic_ansible('microsoftwindows', 'win_certificate_store', demisto.args()))
        elif demisto.command() == 'win-chocolatey':
            return_results(generic_ansible('microsoftwindows', 'win_chocolatey', demisto.args()))
        elif demisto.command() == 'win-chocolatey-config':
            return_results(generic_ansible('microsoftwindows', 'win_chocolatey_config', demisto.args()))
        elif demisto.command() == 'win-chocolatey-facts':
            return_results(generic_ansible('microsoftwindows', 'win_chocolatey_facts', demisto.args()))
        elif demisto.command() == 'win-chocolatey-feature':
            return_results(generic_ansible('microsoftwindows', 'win_chocolatey_feature', demisto.args()))
        elif demisto.command() == 'win-chocolatey-source':
            return_results(generic_ansible('microsoftwindows', 'win_chocolatey_source', demisto.args()))
        elif demisto.command() == 'win-copy':
            return_results(generic_ansible('microsoftwindows', 'win_copy', demisto.args()))
        elif demisto.command() == 'win-credential':
            return_results(generic_ansible('microsoftwindows', 'win_credential', demisto.args()))
        elif demisto.command() == 'win-defrag':
            return_results(generic_ansible('microsoftwindows', 'win_defrag', demisto.args()))
        elif demisto.command() == 'win-disk-facts':
            return_results(generic_ansible('microsoftwindows', 'win_disk_facts', demisto.args()))
        elif demisto.command() == 'win-disk-image':
            return_results(generic_ansible('microsoftwindows', 'win_disk_image', demisto.args()))
        elif demisto.command() == 'win-dns-client':
            return_results(generic_ansible('microsoftwindows', 'win_dns_client', demisto.args()))
        elif demisto.command() == 'win-dns-record':
            return_results(generic_ansible('microsoftwindows', 'win_dns_record', demisto.args()))
        elif demisto.command() == 'win-domain':
            return_results(generic_ansible('microsoftwindows', 'win_domain', demisto.args()))
        elif demisto.command() == 'win-domain-computer':
            return_results(generic_ansible('microsoftwindows', 'win_domain_computer', demisto.args()))
        elif demisto.command() == 'win-domain-controller':
            return_results(generic_ansible('microsoftwindows', 'win_domain_controller', demisto.args()))
        elif demisto.command() == 'win-domain-group':
            return_results(generic_ansible('microsoftwindows', 'win_domain_group', demisto.args()))
        elif demisto.command() == 'win-domain-group-membership':
            return_results(generic_ansible('microsoftwindows', 'win_domain_group_membership', demisto.args()))
        elif demisto.command() == 'win-domain-membership':
            return_results(generic_ansible('microsoftwindows', 'win_domain_membership', demisto.args()))
        elif demisto.command() == 'win-domain-user':
            return_results(generic_ansible('microsoftwindows', 'win_domain_user', demisto.args()))
        elif demisto.command() == 'win-dotnet-ngen':
            return_results(generic_ansible('microsoftwindows', 'win_dotnet_ngen', demisto.args()))
        elif demisto.command() == 'win-dsc':
            return_results(generic_ansible('microsoftwindows', 'win_dsc', demisto.args()))
        elif demisto.command() == 'win-environment':
            return_results(generic_ansible('microsoftwindows', 'win_environment', demisto.args()))
        elif demisto.command() == 'win-eventlog':
            return_results(generic_ansible('microsoftwindows', 'win_eventlog', demisto.args()))
        elif demisto.command() == 'win-eventlog-entry':
            return_results(generic_ansible('microsoftwindows', 'win_eventlog_entry', demisto.args()))
        elif demisto.command() == 'win-feature':
            return_results(generic_ansible('microsoftwindows', 'win_feature', demisto.args()))
        elif demisto.command() == 'win-file':
            return_results(generic_ansible('microsoftwindows', 'win_file', demisto.args()))
        elif demisto.command() == 'win-file-version':
            return_results(generic_ansible('microsoftwindows', 'win_file_version', demisto.args()))
        elif demisto.command() == 'win-find':
            return_results(generic_ansible('microsoftwindows', 'win_find', demisto.args()))
        elif demisto.command() == 'win-firewall':
            return_results(generic_ansible('microsoftwindows', 'win_firewall', demisto.args()))
        elif demisto.command() == 'win-firewall-rule':
            return_results(generic_ansible('microsoftwindows', 'win_firewall_rule', demisto.args()))
        elif demisto.command() == 'win-format':
            return_results(generic_ansible('microsoftwindows', 'win_format', demisto.args()))
        elif demisto.command() == 'win-get-url':
            return_results(generic_ansible('microsoftwindows', 'win_get_url', demisto.args()))
        elif demisto.command() == 'win-group':
            return_results(generic_ansible('microsoftwindows', 'win_group', demisto.args()))
        elif demisto.command() == 'win-group-membership':
            return_results(generic_ansible('microsoftwindows', 'win_group_membership', demisto.args()))
        elif demisto.command() == 'win-hostname':
            return_results(generic_ansible('microsoftwindows', 'win_hostname', demisto.args()))
        elif demisto.command() == 'win-hosts':
            return_results(generic_ansible('microsoftwindows', 'win_hosts', demisto.args()))
        elif demisto.command() == 'win-hotfix':
            return_results(generic_ansible('microsoftwindows', 'win_hotfix', demisto.args()))
        elif demisto.command() == 'win-http-proxy':
            return_results(generic_ansible('microsoftwindows', 'win_http_proxy', demisto.args()))
        elif demisto.command() == 'win-iis-virtualdirectory':
            return_results(generic_ansible('microsoftwindows', 'win_iis_virtualdirectory', demisto.args()))
        elif demisto.command() == 'win-iis-webapplication':
            return_results(generic_ansible('microsoftwindows', 'win_iis_webapplication', demisto.args()))
        elif demisto.command() == 'win-iis-webapppool':
            return_results(generic_ansible('microsoftwindows', 'win_iis_webapppool', demisto.args()))
        elif demisto.command() == 'win-iis-webbinding':
            return_results(generic_ansible('microsoftwindows', 'win_iis_webbinding', demisto.args()))
        elif demisto.command() == 'win-iis-website':
            return_results(generic_ansible('microsoftwindows', 'win_iis_website', demisto.args()))
        elif demisto.command() == 'win-inet-proxy':
            return_results(generic_ansible('microsoftwindows', 'win_inet_proxy', demisto.args()))
        elif demisto.command() == 'win-lineinfile':
            return_results(generic_ansible('microsoftwindows', 'win_lineinfile', demisto.args()))
        elif demisto.command() == 'win-mapped-drive':
            return_results(generic_ansible('microsoftwindows', 'win_mapped_drive', demisto.args()))
        elif demisto.command() == 'win-msg':
            return_results(generic_ansible('microsoftwindows', 'win_msg', demisto.args()))
        elif demisto.command() == 'win-netbios':
            return_results(generic_ansible('microsoftwindows', 'win_netbios', demisto.args()))
        elif demisto.command() == 'win-nssm':
            return_results(generic_ansible('microsoftwindows', 'win_nssm', demisto.args()))
        elif demisto.command() == 'win-optional-feature':
            return_results(generic_ansible('microsoftwindows', 'win_optional_feature', demisto.args()))
        elif demisto.command() == 'win-owner':
            return_results(generic_ansible('microsoftwindows', 'win_owner', demisto.args()))
        elif demisto.command() == 'win-package':
            return_results(generic_ansible('microsoftwindows', 'win_package', demisto.args()))
        elif demisto.command() == 'win-pagefile':
            return_results(generic_ansible('microsoftwindows', 'win_pagefile', demisto.args()))
        elif demisto.command() == 'win-partition':
            return_results(generic_ansible('microsoftwindows', 'win_partition', demisto.args()))
        elif demisto.command() == 'win-path':
            return_results(generic_ansible('microsoftwindows', 'win_path', demisto.args()))
        elif demisto.command() == 'win-pester':
            return_results(generic_ansible('microsoftwindows', 'win_pester', demisto.args()))
        elif demisto.command() == 'win-ping':
            return_results(generic_ansible('microsoftwindows', 'win_ping', demisto.args()))
        elif demisto.command() == 'win-power-plan':
            return_results(generic_ansible('microsoftwindows', 'win_power_plan', demisto.args()))
        elif demisto.command() == 'win-product-facts':
            return_results(generic_ansible('microsoftwindows', 'win_product_facts', demisto.args()))
        elif demisto.command() == 'win-psexec':
            return_results(generic_ansible('microsoftwindows', 'win_psexec', demisto.args()))
        elif demisto.command() == 'win-psmodule':
            return_results(generic_ansible('microsoftwindows', 'win_psmodule', demisto.args()))
        elif demisto.command() == 'win-psrepository':
            return_results(generic_ansible('microsoftwindows', 'win_psrepository', demisto.args()))
        elif demisto.command() == 'win-rabbitmq-plugin':
            return_results(generic_ansible('microsoftwindows', 'win_rabbitmq_plugin', demisto.args()))
        elif demisto.command() == 'win-rds-cap':
            return_results(generic_ansible('microsoftwindows', 'win_rds_cap', demisto.args()))
        elif demisto.command() == 'win-rds-rap':
            return_results(generic_ansible('microsoftwindows', 'win_rds_rap', demisto.args()))
        elif demisto.command() == 'win-rds-settings':
            return_results(generic_ansible('microsoftwindows', 'win_rds_settings', demisto.args()))
        elif demisto.command() == 'win-reboot':
            return_results(generic_ansible('microsoftwindows', 'win_reboot', demisto.args()))
        elif demisto.command() == 'win-reg-stat':
            return_results(generic_ansible('microsoftwindows', 'win_reg_stat', demisto.args()))
        elif demisto.command() == 'win-regedit':
            return_results(generic_ansible('microsoftwindows', 'win_regedit', demisto.args()))
        elif demisto.command() == 'win-region':
            return_results(generic_ansible('microsoftwindows', 'win_region', demisto.args()))
        elif demisto.command() == 'win-regmerge':
            return_results(generic_ansible('microsoftwindows', 'win_regmerge', demisto.args()))
        elif demisto.command() == 'win-robocopy':
            return_results(generic_ansible('microsoftwindows', 'win_robocopy', demisto.args()))
        elif demisto.command() == 'win-route':
            return_results(generic_ansible('microsoftwindows', 'win_route', demisto.args()))
        elif demisto.command() == 'win-say':
            return_results(generic_ansible('microsoftwindows', 'win_say', demisto.args()))
        elif demisto.command() == 'win-scheduled-task':
            return_results(generic_ansible('microsoftwindows', 'win_scheduled_task', demisto.args()))
        elif demisto.command() == 'win-scheduled-task-stat':
            return_results(generic_ansible('microsoftwindows', 'win_scheduled_task_stat', demisto.args()))
        elif demisto.command() == 'win-security-policy':
            return_results(generic_ansible('microsoftwindows', 'win_security_policy', demisto.args()))
        elif demisto.command() == 'win-service':
            return_results(generic_ansible('microsoftwindows', 'win_service', demisto.args()))
        elif demisto.command() == 'win-share':
            return_results(generic_ansible('microsoftwindows', 'win_share', demisto.args()))
        elif demisto.command() == 'win-shortcut':
            return_results(generic_ansible('microsoftwindows', 'win_shortcut', demisto.args()))
        elif demisto.command() == 'win-snmp':
            return_results(generic_ansible('microsoftwindows', 'win_snmp', demisto.args()))
        elif demisto.command() == 'win-stat':
            return_results(generic_ansible('microsoftwindows', 'win_stat', demisto.args()))
        elif demisto.command() == 'win-tempfile':
            return_results(generic_ansible('microsoftwindows', 'win_tempfile', demisto.args()))
        elif demisto.command() == 'win-template':
            return_results(generic_ansible('microsoftwindows', 'win_template', demisto.args()))
        elif demisto.command() == 'win-timezone':
            return_results(generic_ansible('microsoftwindows', 'win_timezone', demisto.args()))
        elif demisto.command() == 'win-toast':
            return_results(generic_ansible('microsoftwindows', 'win_toast', demisto.args()))
        elif demisto.command() == 'win-unzip':
            return_results(generic_ansible('microsoftwindows', 'win_unzip', demisto.args()))
        elif demisto.command() == 'win-updates':
            return_results(generic_ansible('microsoftwindows', 'win_updates', demisto.args()))
        elif demisto.command() == 'win-uri':
            return_results(generic_ansible('microsoftwindows', 'win_uri', demisto.args()))
        elif demisto.command() == 'win-user':
            return_results(generic_ansible('microsoftwindows', 'win_user', demisto.args()))
        elif demisto.command() == 'win-user-profile':
            return_results(generic_ansible('microsoftwindows', 'win_user_profile', demisto.args()))
        elif demisto.command() == 'win-user-right':
            return_results(generic_ansible('microsoftwindows', 'win_user_right', demisto.args()))
        elif demisto.command() == 'win-wait-for':
            return_results(generic_ansible('microsoftwindows', 'win_wait_for', demisto.args()))
        elif demisto.command() == 'win-wait-for-process':
            return_results(generic_ansible('microsoftwindows', 'win_wait_for_process', demisto.args()))
        elif demisto.command() == 'win-wakeonlan':
            return_results(generic_ansible('microsoftwindows', 'win_wakeonlan', demisto.args()))
        elif demisto.command() == 'win-webpicmd':
            return_results(generic_ansible('microsoftwindows', 'win_webpicmd', demisto.args()))
        elif demisto.command() == 'win-whoami':
            return_results(generic_ansible('microsoftwindows', 'win_whoami', demisto.args()))
        elif demisto.command() == 'win-xml':
            return_results(generic_ansible('microsoftwindows', 'win_xml', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()