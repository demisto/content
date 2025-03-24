import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = "winrm"

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
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(
                "This integration does not support testing from this screen. \
                           Please refer to the documentation for details on how to perform \
                           configuration tests."
            )
        elif command == "win-gather-facts":
            return_results(generic_ansible("MicrosoftWindows", "gather_facts", args, int_params, host_type))
        elif command == "win-acl":
            return_results(generic_ansible("MicrosoftWindows", "win_acl", args, int_params, host_type))
        elif command == "win-acl-inheritance":
            return_results(generic_ansible("MicrosoftWindows", "win_acl_inheritance", args, int_params, host_type))
        elif command == "win-audit-policy-system":
            return_results(generic_ansible("MicrosoftWindows", "win_audit_policy_system", args, int_params, host_type))
        elif command == "win-audit-rule":
            return_results(generic_ansible("MicrosoftWindows", "win_audit_rule", args, int_params, host_type))
        elif command == "win-certificate-store":
            return_results(generic_ansible("MicrosoftWindows", "win_certificate_store", args, int_params, host_type))
        elif command == "win-chocolatey":
            return_results(generic_ansible("MicrosoftWindows", "win_chocolatey", args, int_params, host_type))
        elif command == "win-chocolatey-config":
            return_results(generic_ansible("MicrosoftWindows", "win_chocolatey_config", args, int_params, host_type))
        elif command == "win-chocolatey-facts":
            return_results(generic_ansible("MicrosoftWindows", "win_chocolatey_facts", args, int_params, host_type))
        elif command == "win-chocolatey-feature":
            return_results(generic_ansible("MicrosoftWindows", "win_chocolatey_feature", args, int_params, host_type))
        elif command == "win-chocolatey-source":
            return_results(generic_ansible("MicrosoftWindows", "win_chocolatey_source", args, int_params, host_type))
        elif command == "win-copy":
            return_results(generic_ansible("MicrosoftWindows", "win_copy", args, int_params, host_type))
        elif command == "win-credential":
            return_results(generic_ansible("MicrosoftWindows", "win_credential", args, int_params, host_type))
        elif command == "win-defrag":
            return_results(generic_ansible("MicrosoftWindows", "win_defrag", args, int_params, host_type))
        elif command == "win-disk-facts":
            return_results(generic_ansible("MicrosoftWindows", "win_disk_facts", args, int_params, host_type))
        elif command == "win-disk-image":
            return_results(generic_ansible("MicrosoftWindows", "win_disk_image", args, int_params, host_type))
        elif command == "win-dns-client":
            return_results(generic_ansible("MicrosoftWindows", "win_dns_client", args, int_params, host_type))
        elif command == "win-dns-record":
            return_results(generic_ansible("MicrosoftWindows", "win_dns_record", args, int_params, host_type))
        elif command == "win-domain":
            return_results(generic_ansible("MicrosoftWindows", "win_domain", args, int_params, host_type))
        elif command == "win-domain-computer":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_computer", args, int_params, host_type))
        elif command == "win-domain-controller":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_controller", args, int_params, host_type))
        elif command == "win-domain-group":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_group", args, int_params, host_type))
        elif command == "win-domain-group-membership":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_group_membership", args, int_params, host_type))
        elif command == "win-domain-membership":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_membership", args, int_params, host_type))
        elif command == "win-domain-user":
            return_results(generic_ansible("MicrosoftWindows", "win_domain_user", args, int_params, host_type))
        elif command == "win-dotnet-ngen":
            return_results(generic_ansible("MicrosoftWindows", "win_dotnet_ngen", args, int_params, host_type))
        elif command == "win-dsc":
            return_results(generic_ansible("MicrosoftWindows", "win_dsc", args, int_params, host_type))
        elif command == "win-environment":
            return_results(generic_ansible("MicrosoftWindows", "win_environment", args, int_params, host_type))
        elif command == "win-eventlog":
            return_results(generic_ansible("MicrosoftWindows", "win_eventlog", args, int_params, host_type))
        elif command == "win-eventlog-entry":
            return_results(generic_ansible("MicrosoftWindows", "win_eventlog_entry", args, int_params, host_type))
        elif command == "win-feature":
            return_results(generic_ansible("MicrosoftWindows", "win_feature", args, int_params, host_type))
        elif command == "win-file":
            return_results(generic_ansible("MicrosoftWindows", "win_file", args, int_params, host_type))
        elif command == "win-file-version":
            return_results(generic_ansible("MicrosoftWindows", "win_file_version", args, int_params, host_type))
        elif command == "win-find":
            return_results(generic_ansible("MicrosoftWindows", "win_find", args, int_params, host_type))
        elif command == "win-firewall":
            return_results(generic_ansible("MicrosoftWindows", "win_firewall", args, int_params, host_type))
        elif command == "win-firewall-rule":
            return_results(generic_ansible("MicrosoftWindows", "win_firewall_rule", args, int_params, host_type))
        elif command == "win-format":
            return_results(generic_ansible("MicrosoftWindows", "win_format", args, int_params, host_type))
        elif command == "win-get-url":
            return_results(generic_ansible("MicrosoftWindows", "win_get_url", args, int_params, host_type))
        elif command == "win-group":
            return_results(generic_ansible("MicrosoftWindows", "win_group", args, int_params, host_type))
        elif command == "win-group-membership":
            return_results(generic_ansible("MicrosoftWindows", "win_group_membership", args, int_params, host_type))
        elif command == "win-hostname":
            return_results(generic_ansible("MicrosoftWindows", "win_hostname", args, int_params, host_type))
        elif command == "win-hosts":
            return_results(generic_ansible("MicrosoftWindows", "win_hosts", args, int_params, host_type))
        elif command == "win-hotfix":
            return_results(generic_ansible("MicrosoftWindows", "win_hotfix", args, int_params, host_type))
        elif command == "win-http-proxy":
            return_results(generic_ansible("MicrosoftWindows", "win_http_proxy", args, int_params, host_type))
        elif command == "win-iis-virtualdirectory":
            return_results(generic_ansible("MicrosoftWindows", "win_iis_virtualdirectory", args, int_params, host_type))
        elif command == "win-iis-webapplication":
            return_results(generic_ansible("MicrosoftWindows", "win_iis_webapplication", args, int_params, host_type))
        elif command == "win-iis-webapppool":
            return_results(generic_ansible("MicrosoftWindows", "win_iis_webapppool", args, int_params, host_type))
        elif command == "win-iis-webbinding":
            return_results(generic_ansible("MicrosoftWindows", "win_iis_webbinding", args, int_params, host_type))
        elif command == "win-iis-website":
            return_results(generic_ansible("MicrosoftWindows", "win_iis_website", args, int_params, host_type))
        elif command == "win-inet-proxy":
            return_results(generic_ansible("MicrosoftWindows", "win_inet_proxy", args, int_params, host_type))
        elif command == "win-lineinfile":
            return_results(generic_ansible("MicrosoftWindows", "win_lineinfile", args, int_params, host_type))
        elif command == "win-mapped-drive":
            return_results(generic_ansible("MicrosoftWindows", "win_mapped_drive", args, int_params, host_type))
        elif command == "win-msg":
            return_results(generic_ansible("MicrosoftWindows", "win_msg", args, int_params, host_type))
        elif command == "win-netbios":
            return_results(generic_ansible("MicrosoftWindows", "win_netbios", args, int_params, host_type))
        elif command == "win-nssm":
            return_results(generic_ansible("MicrosoftWindows", "win_nssm", args, int_params, host_type))
        elif command == "win-optional-feature":
            return_results(generic_ansible("MicrosoftWindows", "win_optional_feature", args, int_params, host_type))
        elif command == "win-owner":
            return_results(generic_ansible("MicrosoftWindows", "win_owner", args, int_params, host_type))
        elif command == "win-package":
            return_results(generic_ansible("MicrosoftWindows", "win_package", args, int_params, host_type))
        elif command == "win-pagefile":
            return_results(generic_ansible("MicrosoftWindows", "win_pagefile", args, int_params, host_type))
        elif command == "win-partition":
            return_results(generic_ansible("MicrosoftWindows", "win_partition", args, int_params, host_type))
        elif command == "win-path":
            return_results(generic_ansible("MicrosoftWindows", "win_path", args, int_params, host_type))
        elif command == "win-pester":
            return_results(generic_ansible("MicrosoftWindows", "win_pester", args, int_params, host_type))
        elif command == "win-ping":
            return_results(generic_ansible("MicrosoftWindows", "win_ping", args, int_params, host_type))
        elif command == "win-power-plan":
            return_results(generic_ansible("MicrosoftWindows", "win_power_plan", args, int_params, host_type))
        elif command == "win-product-facts":
            return_results(generic_ansible("MicrosoftWindows", "win_product_facts", args, int_params, host_type))
        elif command == "win-psexec":
            return_results(generic_ansible("MicrosoftWindows", "win_psexec", args, int_params, host_type))
        elif command == "win-psmodule":
            return_results(generic_ansible("MicrosoftWindows", "win_psmodule", args, int_params, host_type))
        elif command == "win-psrepository":
            return_results(generic_ansible("MicrosoftWindows", "win_psrepository", args, int_params, host_type))
        elif command == "win-rabbitmq-plugin":
            return_results(generic_ansible("MicrosoftWindows", "win_rabbitmq_plugin", args, int_params, host_type))
        elif command == "win-rds-cap":
            return_results(generic_ansible("MicrosoftWindows", "win_rds_cap", args, int_params, host_type))
        elif command == "win-rds-rap":
            return_results(generic_ansible("MicrosoftWindows", "win_rds_rap", args, int_params, host_type))
        elif command == "win-rds-settings":
            return_results(generic_ansible("MicrosoftWindows", "win_rds_settings", args, int_params, host_type))
        elif command == "win-reboot":
            return_results(generic_ansible("MicrosoftWindows", "win_reboot", args, int_params, host_type))
        elif command == "win-reg-stat":
            return_results(generic_ansible("MicrosoftWindows", "win_reg_stat", args, int_params, host_type))
        elif command == "win-regedit":
            return_results(generic_ansible("MicrosoftWindows", "win_regedit", args, int_params, host_type))
        elif command == "win-region":
            return_results(generic_ansible("MicrosoftWindows", "win_region", args, int_params, host_type))
        elif command == "win-regmerge":
            return_results(generic_ansible("MicrosoftWindows", "win_regmerge", args, int_params, host_type))
        elif command == "win-robocopy":
            return_results(generic_ansible("MicrosoftWindows", "win_robocopy", args, int_params, host_type))
        elif command == "win-route":
            return_results(generic_ansible("MicrosoftWindows", "win_route", args, int_params, host_type))
        elif command == "win-say":
            return_results(generic_ansible("MicrosoftWindows", "win_say", args, int_params, host_type))
        elif command == "win-scheduled-task":
            return_results(generic_ansible("MicrosoftWindows", "win_scheduled_task", args, int_params, host_type))
        elif command == "win-scheduled-task-stat":
            return_results(generic_ansible("MicrosoftWindows", "win_scheduled_task_stat", args, int_params, host_type))
        elif command == "win-security-policy":
            return_results(generic_ansible("MicrosoftWindows", "win_security_policy", args, int_params, host_type))
        elif command == "win-service":
            return_results(generic_ansible("MicrosoftWindows", "win_service", args, int_params, host_type))
        elif command == "win-share":
            return_results(generic_ansible("MicrosoftWindows", "win_share", args, int_params, host_type))
        elif command == "win-shortcut":
            return_results(generic_ansible("MicrosoftWindows", "win_shortcut", args, int_params, host_type))
        elif command == "win-snmp":
            return_results(generic_ansible("MicrosoftWindows", "win_snmp", args, int_params, host_type))
        elif command == "win-stat":
            return_results(generic_ansible("MicrosoftWindows", "win_stat", args, int_params, host_type))
        elif command == "win-tempfile":
            return_results(generic_ansible("MicrosoftWindows", "win_tempfile", args, int_params, host_type))
        elif command == "win-template":
            return_results(generic_ansible("MicrosoftWindows", "win_template", args, int_params, host_type))
        elif command == "win-timezone":
            return_results(generic_ansible("MicrosoftWindows", "win_timezone", args, int_params, host_type))
        elif command == "win-toast":
            return_results(generic_ansible("MicrosoftWindows", "win_toast", args, int_params, host_type))
        elif command == "win-unzip":
            return_results(generic_ansible("MicrosoftWindows", "win_unzip", args, int_params, host_type))
        elif command == "win-updates":
            return_results(generic_ansible("MicrosoftWindows", "win_updates", args, int_params, host_type))
        elif command == "win-uri":
            return_results(generic_ansible("MicrosoftWindows", "win_uri", args, int_params, host_type))
        elif command == "win-user":
            return_results(generic_ansible("MicrosoftWindows", "win_user", args, int_params, host_type))
        elif command == "win-user-profile":
            return_results(generic_ansible("MicrosoftWindows", "win_user_profile", args, int_params, host_type))
        elif command == "win-user-right":
            return_results(generic_ansible("MicrosoftWindows", "win_user_right", args, int_params, host_type))
        elif command == "win-wait-for":
            return_results(generic_ansible("MicrosoftWindows", "win_wait_for", args, int_params, host_type))
        elif command == "win-wait-for-process":
            return_results(generic_ansible("MicrosoftWindows", "win_wait_for_process", args, int_params, host_type))
        elif command == "win-wakeonlan":
            return_results(generic_ansible("MicrosoftWindows", "win_wakeonlan", args, int_params, host_type))
        elif command == "win-webpicmd":
            return_results(generic_ansible("MicrosoftWindows", "win_webpicmd", args, int_params, host_type))
        elif command == "win-whoami":
            return_results(generic_ansible("MicrosoftWindows", "win_whoami", args, int_params, host_type))
        elif command == "win-xml":
            return_results(generic_ansible("MicrosoftWindows", "win_xml", args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


# ENTRY POINT


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
