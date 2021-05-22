import json
import traceback
import ansible_runner
import ssh_agent_setup
from typing import Dict, cast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type =  'ssh'

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