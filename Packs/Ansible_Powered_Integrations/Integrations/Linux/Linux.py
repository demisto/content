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
        elif demisto.command() == 'linux-alternatives':
            return_results(generic_ansible('linux', 'alternatives', demisto.args()))
        elif demisto.command() == 'linux-at':
            return_results(generic_ansible('linux', 'at', demisto.args()))
        elif demisto.command() == 'linux-authorized-key':
            return_results(generic_ansible('linux', 'authorized_key', demisto.args()))
        elif demisto.command() == 'linux-capabilities':
            return_results(generic_ansible('linux', 'capabilities', demisto.args()))
        elif demisto.command() == 'linux-cron':
            return_results(generic_ansible('linux', 'cron', demisto.args()))
        elif demisto.command() == 'linux-cronvar':
            return_results(generic_ansible('linux', 'cronvar', demisto.args()))
        elif demisto.command() == 'linux-dconf':
            return_results(generic_ansible('linux', 'dconf', demisto.args()))
        elif demisto.command() == 'linux-debconf':
            return_results(generic_ansible('linux', 'debconf', demisto.args()))
        elif demisto.command() == 'linux-filesystem':
            return_results(generic_ansible('linux', 'filesystem', demisto.args()))
        elif demisto.command() == 'linux-firewalld':
            return_results(generic_ansible('linux', 'firewalld', demisto.args()))
        elif demisto.command() == 'linux-gather-facts':
            return_results(generic_ansible('linux', 'gather_facts', demisto.args()))
        elif demisto.command() == 'linux-gconftool2':
            return_results(generic_ansible('linux', 'gconftool2', demisto.args()))
        elif demisto.command() == 'linux-getent':
            return_results(generic_ansible('linux', 'getent', demisto.args()))
        elif demisto.command() == 'linux-group':
            return_results(generic_ansible('linux', 'group', demisto.args()))
        elif demisto.command() == 'linux-hostname':
            return_results(generic_ansible('linux', 'hostname', demisto.args()))
        elif demisto.command() == 'linux-interfaces-file':
            return_results(generic_ansible('linux', 'interfaces_file', demisto.args()))
        elif demisto.command() == 'linux-iptables':
            return_results(generic_ansible('linux', 'iptables', demisto.args()))
        elif demisto.command() == 'linux-java-cert':
            return_results(generic_ansible('linux', 'java_cert', demisto.args()))
        elif demisto.command() == 'linux-java-keystore':
            return_results(generic_ansible('linux', 'java_keystore', demisto.args()))
        elif demisto.command() == 'linux-kernel-blacklist':
            return_results(generic_ansible('linux', 'kernel_blacklist', demisto.args()))
        elif demisto.command() == 'linux-known-hosts':
            return_results(generic_ansible('linux', 'known_hosts', demisto.args()))
        elif demisto.command() == 'linux-listen-ports-facts':
            return_results(generic_ansible('linux', 'listen_ports_facts', demisto.args()))
        elif demisto.command() == 'linux-locale-gen':
            return_results(generic_ansible('linux', 'locale_gen', demisto.args()))
        elif demisto.command() == 'linux-modprobe':
            return_results(generic_ansible('linux', 'modprobe', demisto.args()))
        elif demisto.command() == 'linux-mount':
            return_results(generic_ansible('linux', 'mount', demisto.args()))
        elif demisto.command() == 'linux-open-iscsi':
            return_results(generic_ansible('linux', 'open_iscsi', demisto.args()))
        elif demisto.command() == 'linux-pam-limits':
            return_results(generic_ansible('linux', 'pam_limits', demisto.args()))
        elif demisto.command() == 'linux-pamd':
            return_results(generic_ansible('linux', 'pamd', demisto.args()))
        elif demisto.command() == 'linux-parted':
            return_results(generic_ansible('linux', 'parted', demisto.args()))
        elif demisto.command() == 'linux-pids':
            return_results(generic_ansible('linux', 'pids', demisto.args()))
        elif demisto.command() == 'linux-ping':
            return_results(generic_ansible('linux', 'ping', demisto.args()))
        elif demisto.command() == 'linux-python-requirements-info':
            return_results(generic_ansible('linux', 'python_requirements_info', demisto.args()))
        elif demisto.command() == 'linux-reboot':
            return_results(generic_ansible('linux', 'reboot', demisto.args()))
        elif demisto.command() == 'linux-seboolean':
            return_results(generic_ansible('linux', 'seboolean', demisto.args()))
        elif demisto.command() == 'linux-sefcontext':
            return_results(generic_ansible('linux', 'sefcontext', demisto.args()))
        elif demisto.command() == 'linux-selinux':
            return_results(generic_ansible('linux', 'selinux', demisto.args()))
        elif demisto.command() == 'linux-selinux-permissive':
            return_results(generic_ansible('linux', 'selinux_permissive', demisto.args()))
        elif demisto.command() == 'linux-selogin':
            return_results(generic_ansible('linux', 'selogin', demisto.args()))
        elif demisto.command() == 'linux-seport':
            return_results(generic_ansible('linux', 'seport', demisto.args()))
        elif demisto.command() == 'linux-service':
            return_results(generic_ansible('linux', 'service', demisto.args()))
        elif demisto.command() == 'linux-service-facts':
            return_results(generic_ansible('linux', 'service_facts', demisto.args()))
        elif demisto.command() == 'linux-setup':
            return_results(generic_ansible('linux', 'setup', demisto.args()))
        elif demisto.command() == 'linux-sysctl':
            return_results(generic_ansible('linux', 'sysctl', demisto.args()))
        elif demisto.command() == 'linux-systemd':
            return_results(generic_ansible('linux', 'systemd', demisto.args()))
        elif demisto.command() == 'linux-sysvinit':
            return_results(generic_ansible('linux', 'sysvinit', demisto.args()))
        elif demisto.command() == 'linux-timezone':
            return_results(generic_ansible('linux', 'timezone', demisto.args()))
        elif demisto.command() == 'linux-ufw':
            return_results(generic_ansible('linux', 'ufw', demisto.args()))
        elif demisto.command() == 'linux-user':
            return_results(generic_ansible('linux', 'user', demisto.args()))
        elif demisto.command() == 'linux-xfs-quota':
            return_results(generic_ansible('linux', 'xfs_quota', demisto.args()))
        elif demisto.command() == 'linux-htpasswd':
            return_results(generic_ansible('linux', 'htpasswd', demisto.args()))
        elif demisto.command() == 'linux-supervisorctl':
            return_results(generic_ansible('linux', 'supervisorctl', demisto.args()))
        elif demisto.command() == 'linux-openssh-cert':
            return_results(generic_ansible('linux', 'openssh_cert', demisto.args()))
        elif demisto.command() == 'linux-openssh-keypair':
            return_results(generic_ansible('linux', 'openssh_keypair', demisto.args()))
        elif demisto.command() == 'linux-acl':
            return_results(generic_ansible('linux', 'acl', demisto.args()))
        elif demisto.command() == 'linux-archive':
            return_results(generic_ansible('linux', 'archive', demisto.args()))
        elif demisto.command() == 'linux-assemble':
            return_results(generic_ansible('linux', 'assemble', demisto.args()))
        elif demisto.command() == 'linux-blockinfile':
            return_results(generic_ansible('linux', 'blockinfile', demisto.args()))
        elif demisto.command() == 'linux-file':
            return_results(generic_ansible('linux', 'file', demisto.args()))
        elif demisto.command() == 'linux-find':
            return_results(generic_ansible('linux', 'find', demisto.args()))
        elif demisto.command() == 'linux-ini-file':
            return_results(generic_ansible('linux', 'ini_file', demisto.args()))
        elif demisto.command() == 'linux-iso-extract':
            return_results(generic_ansible('linux', 'iso_extract', demisto.args()))
        elif demisto.command() == 'linux-lineinfile':
            return_results(generic_ansible('linux', 'lineinfile', demisto.args()))
        elif demisto.command() == 'linux-replace':
            return_results(generic_ansible('linux', 'replace', demisto.args()))
        elif demisto.command() == 'linux-stat':
            return_results(generic_ansible('linux', 'stat', demisto.args()))
        elif demisto.command() == 'linux-synchronize':
            return_results(generic_ansible('linux', 'synchronize', demisto.args()))
        elif demisto.command() == 'linux-tempfile':
            return_results(generic_ansible('linux', 'tempfile', demisto.args()))
        elif demisto.command() == 'linux-unarchive':
            return_results(generic_ansible('linux', 'unarchive', demisto.args()))
        elif demisto.command() == 'linux-xml':
            return_results(generic_ansible('linux', 'xml', demisto.args()))
        elif demisto.command() == 'linux-expect':
            return_results(generic_ansible('linux', 'expect', demisto.args()))
        elif demisto.command() == 'linux-bower':
            return_results(generic_ansible('linux', 'bower', demisto.args()))
        elif demisto.command() == 'linux-bundler':
            return_results(generic_ansible('linux', 'bundler', demisto.args()))
        elif demisto.command() == 'linux-composer':
            return_results(generic_ansible('linux', 'composer', demisto.args()))
        elif demisto.command() == 'linux-cpanm':
            return_results(generic_ansible('linux', 'cpanm', demisto.args()))
        elif demisto.command() == 'linux-gem':
            return_results(generic_ansible('linux', 'gem', demisto.args()))
        elif demisto.command() == 'linux-maven-artifact':
            return_results(generic_ansible('linux', 'maven_artifact', demisto.args()))
        elif demisto.command() == 'linux-npm':
            return_results(generic_ansible('linux', 'npm', demisto.args()))
        elif demisto.command() == 'linux-pear':
            return_results(generic_ansible('linux', 'pear', demisto.args()))
        elif demisto.command() == 'linux-pip':
            return_results(generic_ansible('linux', 'pip', demisto.args()))
        elif demisto.command() == 'linux-pip-package-info':
            return_results(generic_ansible('linux', 'pip_package_info', demisto.args()))
        elif demisto.command() == 'linux-yarn':
            return_results(generic_ansible('linux', 'yarn', demisto.args()))
        elif demisto.command() == 'linux-apk':
            return_results(generic_ansible('linux', 'apk', demisto.args()))
        elif demisto.command() == 'linux-apt':
            return_results(generic_ansible('linux', 'apt', demisto.args()))
        elif demisto.command() == 'linux-apt-key':
            return_results(generic_ansible('linux', 'apt_key', demisto.args()))
        elif demisto.command() == 'linux-apt-repo':
            return_results(generic_ansible('linux', 'apt_repo', demisto.args()))
        elif demisto.command() == 'linux-apt-repository':
            return_results(generic_ansible('linux', 'apt_repository', demisto.args()))
        elif demisto.command() == 'linux-apt-rpm':
            return_results(generic_ansible('linux', 'apt_rpm', demisto.args()))
        elif demisto.command() == 'linux-dpkg-selections':
            return_results(generic_ansible('linux', 'dpkg_selections', demisto.args()))
        elif demisto.command() == 'linux-flatpak':
            return_results(generic_ansible('linux', 'flatpak', demisto.args()))
        elif demisto.command() == 'linux-flatpak-remote':
            return_results(generic_ansible('linux', 'flatpak_remote', demisto.args()))
        elif demisto.command() == 'linux-homebrew':
            return_results(generic_ansible('linux', 'homebrew', demisto.args()))
        elif demisto.command() == 'linux-homebrew-cask':
            return_results(generic_ansible('linux', 'homebrew_cask', demisto.args()))
        elif demisto.command() == 'linux-homebrew-tap':
            return_results(generic_ansible('linux', 'homebrew_tap', demisto.args()))
        elif demisto.command() == 'linux-layman':
            return_results(generic_ansible('linux', 'layman', demisto.args()))
        elif demisto.command() == 'linux-package':
            return_results(generic_ansible('linux', 'package', demisto.args()))
        elif demisto.command() == 'linux-package-facts':
            return_results(generic_ansible('linux', 'package_facts', demisto.args()))
        elif demisto.command() == 'linux-yum':
            return_results(generic_ansible('linux', 'yum', demisto.args()))
        elif demisto.command() == 'linux-yum-repository':
            return_results(generic_ansible('linux', 'yum_repository', demisto.args()))
        elif demisto.command() == 'linux-zypper':
            return_results(generic_ansible('linux', 'zypper', demisto.args()))
        elif demisto.command() == 'linux-zypper-repository':
            return_results(generic_ansible('linux', 'zypper_repository', demisto.args()))
        elif demisto.command() == 'linux-snap':
            return_results(generic_ansible('linux', 'snap', demisto.args()))
        elif demisto.command() == 'linux-redhat-subscription':
            return_results(generic_ansible('linux', 'redhat_subscription', demisto.args()))
        elif demisto.command() == 'linux-rhn-channel':
            return_results(generic_ansible('linux', 'rhn_channel', demisto.args()))
        elif demisto.command() == 'linux-rhn-register':
            return_results(generic_ansible('linux', 'rhn_register', demisto.args()))
        elif demisto.command() == 'linux-rhsm-release':
            return_results(generic_ansible('linux', 'rhsm_release', demisto.args()))
        elif demisto.command() == 'linux-rhsm-repository':
            return_results(generic_ansible('linux', 'rhsm_repository', demisto.args()))
        elif demisto.command() == 'linux-rpm-key':
            return_results(generic_ansible('linux', 'rpm_key', demisto.args()))
        elif demisto.command() == 'linux-get-url':
            return_results(generic_ansible('linux', 'get_url', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
