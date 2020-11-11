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
        # Linux

        # Different credential options
        # SSH Key saved in credential manager selection
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
        elif demisto.command() == 'linux_alternatives':
            return_results(generic_ansible('linux', 'alternatives', demisto.args()))
        elif demisto.command() == 'linux_at':
            return_results(generic_ansible('linux', 'at', demisto.args()))
        elif demisto.command() == 'linux_authorized_key':
            return_results(generic_ansible('linux', 'authorized_key', demisto.args()))
        elif demisto.command() == 'linux_capabilities':
            return_results(generic_ansible('linux', 'capabilities', demisto.args()))
        elif demisto.command() == 'linux_cron':
            return_results(generic_ansible('linux', 'cron', demisto.args()))
        elif demisto.command() == 'linux_cronvar':
            return_results(generic_ansible('linux', 'cronvar', demisto.args()))
        elif demisto.command() == 'linux_dconf':
            return_results(generic_ansible('linux', 'dconf', demisto.args()))
        elif demisto.command() == 'linux_debconf':
            return_results(generic_ansible('linux', 'debconf', demisto.args()))
        elif demisto.command() == 'linux_filesystem':
            return_results(generic_ansible('linux', 'filesystem', demisto.args()))
        elif demisto.command() == 'linux_firewalld':
            return_results(generic_ansible('linux', 'firewalld', demisto.args()))
        elif demisto.command() == 'linux_gather_facts':
            return_results(generic_ansible('linux', 'gather_facts', demisto.args()))
        elif demisto.command() == 'linux_gconftool2':
            return_results(generic_ansible('linux', 'gconftool2', demisto.args()))
        elif demisto.command() == 'linux_getent':
            return_results(generic_ansible('linux', 'getent', demisto.args()))
        elif demisto.command() == 'linux_group':
            return_results(generic_ansible('linux', 'group', demisto.args()))
        elif demisto.command() == 'linux_hostname':
            return_results(generic_ansible('linux', 'hostname', demisto.args()))
        elif demisto.command() == 'linux_interfaces_file':
            return_results(generic_ansible('linux', 'interfaces_file', demisto.args()))
        elif demisto.command() == 'linux_iptables':
            return_results(generic_ansible('linux', 'iptables', demisto.args()))
        elif demisto.command() == 'linux_java_cert':
            return_results(generic_ansible('linux', 'java_cert', demisto.args()))
        elif demisto.command() == 'linux_java_keystore':
            return_results(generic_ansible('linux', 'java_keystore', demisto.args()))
        elif demisto.command() == 'linux_kernel_blacklist':
            return_results(generic_ansible('linux', 'kernel_blacklist', demisto.args()))
        elif demisto.command() == 'linux_known_hosts':
            return_results(generic_ansible('linux', 'known_hosts', demisto.args()))
        elif demisto.command() == 'linux_listen_ports_facts':
            return_results(generic_ansible('linux', 'listen_ports_facts', demisto.args()))
        elif demisto.command() == 'linux_locale_gen':
            return_results(generic_ansible('linux', 'locale_gen', demisto.args()))
        elif demisto.command() == 'linux_modprobe':
            return_results(generic_ansible('linux', 'modprobe', demisto.args()))
        elif demisto.command() == 'linux_mount':
            return_results(generic_ansible('linux', 'mount', demisto.args()))
        elif demisto.command() == 'linux_open_iscsi':
            return_results(generic_ansible('linux', 'open_iscsi', demisto.args()))
        elif demisto.command() == 'linux_pam_limits':
            return_results(generic_ansible('linux', 'pam_limits', demisto.args()))
        elif demisto.command() == 'linux_pamd':
            return_results(generic_ansible('linux', 'pamd', demisto.args()))
        elif demisto.command() == 'linux_parted':
            return_results(generic_ansible('linux', 'parted', demisto.args()))
        elif demisto.command() == 'linux_pids':
            return_results(generic_ansible('linux', 'pids', demisto.args()))
        elif demisto.command() == 'linux_ping':
            return_results(generic_ansible('linux', 'ping', demisto.args()))
        elif demisto.command() == 'linux_python_requirements_info':
            return_results(generic_ansible('linux', 'python_requirements_info', demisto.args()))
        elif demisto.command() == 'linux_reboot':
            return_results(generic_ansible('linux', 'reboot', demisto.args()))
        elif demisto.command() == 'linux_seboolean':
            return_results(generic_ansible('linux', 'seboolean', demisto.args()))
        elif demisto.command() == 'linux_sefcontext':
            return_results(generic_ansible('linux', 'sefcontext', demisto.args()))
        elif demisto.command() == 'linux_selinux':
            return_results(generic_ansible('linux', 'selinux', demisto.args()))
        elif demisto.command() == 'linux_selinux_permissive':
            return_results(generic_ansible('linux', 'selinux_permissive', demisto.args()))
        elif demisto.command() == 'linux_selogin':
            return_results(generic_ansible('linux', 'selogin', demisto.args()))
        elif demisto.command() == 'linux_seport':
            return_results(generic_ansible('linux', 'seport', demisto.args()))
        elif demisto.command() == 'linux_service':
            return_results(generic_ansible('linux', 'service', demisto.args()))
        elif demisto.command() == 'linux_service_facts':
            return_results(generic_ansible('linux', 'service_facts', demisto.args()))
        elif demisto.command() == 'linux_setup':
            return_results(generic_ansible('linux', 'setup', demisto.args()))
        elif demisto.command() == 'linux_sysctl':
            return_results(generic_ansible('linux', 'sysctl', demisto.args()))
        elif demisto.command() == 'linux_systemd':
            return_results(generic_ansible('linux', 'systemd', demisto.args()))
        elif demisto.command() == 'linux_sysvinit':
            return_results(generic_ansible('linux', 'sysvinit', demisto.args()))
        elif demisto.command() == 'linux_timezone':
            return_results(generic_ansible('linux', 'timezone', demisto.args()))
        elif demisto.command() == 'linux_ufw':
            return_results(generic_ansible('linux', 'ufw', demisto.args()))
        elif demisto.command() == 'linux_user':
            return_results(generic_ansible('linux', 'user', demisto.args()))
        elif demisto.command() == 'linux_xfs_quota':
            return_results(generic_ansible('linux', 'xfs_quota', demisto.args()))
        elif demisto.command() == 'linux_htpasswd':
            return_results(generic_ansible('linux', 'htpasswd', demisto.args()))
        elif demisto.command() == 'linux_supervisorctl':
            return_results(generic_ansible('linux', 'supervisorctl', demisto.args()))
        elif demisto.command() == 'linux_openssh_cert':
            return_results(generic_ansible('linux', 'openssh_cert', demisto.args()))
        elif demisto.command() == 'linux_openssh_keypair':
            return_results(generic_ansible('linux', 'openssh_keypair', demisto.args()))
        elif demisto.command() == 'linux_acl':
            return_results(generic_ansible('linux', 'acl', demisto.args()))
        elif demisto.command() == 'linux_archive':
            return_results(generic_ansible('linux', 'archive', demisto.args()))
        elif demisto.command() == 'linux_assemble':
            return_results(generic_ansible('linux', 'assemble', demisto.args()))
        elif demisto.command() == 'linux_blockinfile':
            return_results(generic_ansible('linux', 'blockinfile', demisto.args()))
        elif demisto.command() == 'linux_file':
            return_results(generic_ansible('linux', 'file', demisto.args()))
        elif demisto.command() == 'linux_find':
            return_results(generic_ansible('linux', 'find', demisto.args()))
        elif demisto.command() == 'linux_ini_file':
            return_results(generic_ansible('linux', 'ini_file', demisto.args()))
        elif demisto.command() == 'linux_iso_extract':
            return_results(generic_ansible('linux', 'iso_extract', demisto.args()))
        elif demisto.command() == 'linux_lineinfile':
            return_results(generic_ansible('linux', 'lineinfile', demisto.args()))
        elif demisto.command() == 'linux_replace':
            return_results(generic_ansible('linux', 'replace', demisto.args()))
        elif demisto.command() == 'linux_stat':
            return_results(generic_ansible('linux', 'stat', demisto.args()))
        elif demisto.command() == 'linux_synchronize':
            return_results(generic_ansible('linux', 'synchronize', demisto.args()))
        elif demisto.command() == 'linux_tempfile':
            return_results(generic_ansible('linux', 'tempfile', demisto.args()))
        elif demisto.command() == 'linux_unarchive':
            return_results(generic_ansible('linux', 'unarchive', demisto.args()))
        elif demisto.command() == 'linux_xml':
            return_results(generic_ansible('linux', 'xml', demisto.args()))
        elif demisto.command() == 'linux_expect':
            return_results(generic_ansible('linux', 'expect', demisto.args()))
        elif demisto.command() == 'linux_bower':
            return_results(generic_ansible('linux', 'bower', demisto.args()))
        elif demisto.command() == 'linux_bundler':
            return_results(generic_ansible('linux', 'bundler', demisto.args()))
        elif demisto.command() == 'linux_composer':
            return_results(generic_ansible('linux', 'composer', demisto.args()))
        elif demisto.command() == 'linux_cpanm':
            return_results(generic_ansible('linux', 'cpanm', demisto.args()))
        elif demisto.command() == 'linux_gem':
            return_results(generic_ansible('linux', 'gem', demisto.args()))
        elif demisto.command() == 'linux_maven_artifact':
            return_results(generic_ansible('linux', 'maven_artifact', demisto.args()))
        elif demisto.command() == 'linux_npm':
            return_results(generic_ansible('linux', 'npm', demisto.args()))
        elif demisto.command() == 'linux_pear':
            return_results(generic_ansible('linux', 'pear', demisto.args()))
        elif demisto.command() == 'linux_pip':
            return_results(generic_ansible('linux', 'pip', demisto.args()))
        elif demisto.command() == 'linux_pip_package_info':
            return_results(generic_ansible('linux', 'pip_package_info', demisto.args()))
        elif demisto.command() == 'linux_yarn':
            return_results(generic_ansible('linux', 'yarn', demisto.args()))
        elif demisto.command() == 'linux_apk':
            return_results(generic_ansible('linux', 'apk', demisto.args()))
        elif demisto.command() == 'linux_apt':
            return_results(generic_ansible('linux', 'apt', demisto.args()))
        elif demisto.command() == 'linux_apt_key':
            return_results(generic_ansible('linux', 'apt_key', demisto.args()))
        elif demisto.command() == 'linux_apt_repo':
            return_results(generic_ansible('linux', 'apt_repo', demisto.args()))
        elif demisto.command() == 'linux_apt_repository':
            return_results(generic_ansible('linux', 'apt_repository', demisto.args()))
        elif demisto.command() == 'linux_apt_rpm':
            return_results(generic_ansible('linux', 'apt_rpm', demisto.args()))
        elif demisto.command() == 'linux_dpkg_selections':
            return_results(generic_ansible('linux', 'dpkg_selections', demisto.args()))
        elif demisto.command() == 'linux_flatpak':
            return_results(generic_ansible('linux', 'flatpak', demisto.args()))
        elif demisto.command() == 'linux_flatpak_remote':
            return_results(generic_ansible('linux', 'flatpak_remote', demisto.args()))
        elif demisto.command() == 'linux_homebrew':
            return_results(generic_ansible('linux', 'homebrew', demisto.args()))
        elif demisto.command() == 'linux_homebrew_cask':
            return_results(generic_ansible('linux', 'homebrew_cask', demisto.args()))
        elif demisto.command() == 'linux_homebrew_tap':
            return_results(generic_ansible('linux', 'homebrew_tap', demisto.args()))
        elif demisto.command() == 'linux_layman':
            return_results(generic_ansible('linux', 'layman', demisto.args()))
        elif demisto.command() == 'linux_package':
            return_results(generic_ansible('linux', 'package', demisto.args()))
        elif demisto.command() == 'linux_package_facts':
            return_results(generic_ansible('linux', 'package_facts', demisto.args()))
        elif demisto.command() == 'linux_yum':
            return_results(generic_ansible('linux', 'yum', demisto.args()))
        elif demisto.command() == 'linux_yum_repository':
            return_results(generic_ansible('linux', 'yum_repository', demisto.args()))
        elif demisto.command() == 'linux_zypper':
            return_results(generic_ansible('linux', 'zypper', demisto.args()))
        elif demisto.command() == 'linux_zypper_repository':
            return_results(generic_ansible('linux', 'zypper_repository', demisto.args()))
        elif demisto.command() == 'linux_snap':
            return_results(generic_ansible('linux', 'snap', demisto.args()))
        elif demisto.command() == 'linux_redhat_subscription':
            return_results(generic_ansible('linux', 'redhat_subscription', demisto.args()))
        elif demisto.command() == 'linux_rhn_channel':
            return_results(generic_ansible('linux', 'rhn_channel', demisto.args()))
        elif demisto.command() == 'linux_rhn_register':
            return_results(generic_ansible('linux', 'rhn_register', demisto.args()))
        elif demisto.command() == 'linux_rhsm_release':
            return_results(generic_ansible('linux', 'rhsm_release', demisto.args()))
        elif demisto.command() == 'linux_rhsm_repository':
            return_results(generic_ansible('linux', 'rhsm_repository', demisto.args()))
        elif demisto.command() == 'linux_rpm_key':
            return_results(generic_ansible('linux', 'rpm_key', demisto.args()))
        elif demisto.command() == 'linux_get_url':
            return_results(generic_ansible('linux', 'get_url', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
