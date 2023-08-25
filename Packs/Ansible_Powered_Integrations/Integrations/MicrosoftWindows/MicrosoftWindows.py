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
        # Windows

        # Different credential options
        # Password saved in credential manager selection
        if demisto.params().get('creds', {}).get('credentials').get('password'):
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

        new_host['ansible_connection'] = "winrm"
        new_host['ansible_winrm_transport'] = "ntlm"
        new_host['ansible_winrm_server_cert_validation'] = "ignore"

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
