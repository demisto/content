import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'ssh'

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

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('This integration does not support testing from this screen. \
                           Please refer to the documentation for details on how to perform \
                           configuration tests.')
        elif command == 'linux-alternatives':
            return_results(generic_ansible('linux', 'alternatives', args, int_params, host_type))
        elif command == 'linux-at':
            return_results(generic_ansible('linux', 'at', args, int_params, host_type))
        elif command == 'linux-authorized-key':
            return_results(generic_ansible('linux', 'authorized_key', args, int_params, host_type))
        elif command == 'linux-capabilities':
            return_results(generic_ansible('linux', 'capabilities', args, int_params, host_type))
        elif command == 'linux-cron':
            return_results(generic_ansible('linux', 'cron', args, int_params, host_type))
        elif command == 'linux-cronvar':
            return_results(generic_ansible('linux', 'cronvar', args, int_params, host_type))
        elif command == 'linux-dconf':
            return_results(generic_ansible('linux', 'dconf', args, int_params, host_type))
        elif command == 'linux-debconf':
            return_results(generic_ansible('linux', 'debconf', args, int_params, host_type))
        elif command == 'linux-filesystem':
            return_results(generic_ansible('linux', 'filesystem', args, int_params, host_type))
        elif command == 'linux-firewalld':
            return_results(generic_ansible('linux', 'firewalld', args, int_params, host_type))
        elif command == 'linux-gather-facts':
            return_results(generic_ansible('linux', 'gather_facts', args, int_params, host_type))
        elif command == 'linux-gconftool2':
            return_results(generic_ansible('linux', 'gconftool2', args, int_params, host_type))
        elif command == 'linux-getent':
            return_results(generic_ansible('linux', 'getent', args, int_params, host_type))
        elif command == 'linux-group':
            return_results(generic_ansible('linux', 'group', args, int_params, host_type))
        elif command == 'linux-hostname':
            return_results(generic_ansible('linux', 'hostname', args, int_params, host_type))
        elif command == 'linux-interfaces-file':
            return_results(generic_ansible('linux', 'interfaces_file', args, int_params, host_type))
        elif command == 'linux-iptables':
            return_results(generic_ansible('linux', 'iptables', args, int_params, host_type))
        elif command == 'linux-java-cert':
            return_results(generic_ansible('linux', 'java_cert', args, int_params, host_type))
        elif command == 'linux-java-keystore':
            return_results(generic_ansible('linux', 'java_keystore', args, int_params, host_type))
        elif command == 'linux-kernel-blacklist':
            return_results(generic_ansible('linux', 'kernel_blacklist', args, int_params, host_type))
        elif command == 'linux-known-hosts':
            return_results(generic_ansible('linux', 'known_hosts', args, int_params, host_type))
        elif command == 'linux-listen-ports-facts':
            return_results(generic_ansible('linux', 'listen_ports_facts', args, int_params, host_type))
        elif command == 'linux-locale-gen':
            return_results(generic_ansible('linux', 'locale_gen', args, int_params, host_type))
        elif command == 'linux-modprobe':
            return_results(generic_ansible('linux', 'modprobe', args, int_params, host_type))
        elif command == 'linux-mount':
            return_results(generic_ansible('linux', 'mount', args, int_params, host_type))
        elif command == 'linux-open-iscsi':
            return_results(generic_ansible('linux', 'open_iscsi', args, int_params, host_type))
        elif command == 'linux-pam-limits':
            return_results(generic_ansible('linux', 'pam_limits', args, int_params, host_type))
        elif command == 'linux-pamd':
            return_results(generic_ansible('linux', 'pamd', args, int_params, host_type))
        elif command == 'linux-parted':
            return_results(generic_ansible('linux', 'parted', args, int_params, host_type))
        elif command == 'linux-pids':
            return_results(generic_ansible('linux', 'pids', args, int_params, host_type))
        elif command == 'linux-ping':
            return_results(generic_ansible('linux', 'ping', args, int_params, host_type))
        elif command == 'linux-python-requirements-info':
            return_results(generic_ansible('linux', 'python_requirements_info', args, int_params, host_type))
        elif command == 'linux-reboot':
            return_results(generic_ansible('linux', 'reboot', args, int_params, host_type))
        elif command == 'linux-seboolean':
            return_results(generic_ansible('linux', 'seboolean', args, int_params, host_type))
        elif command == 'linux-sefcontext':
            return_results(generic_ansible('linux', 'sefcontext', args, int_params, host_type))
        elif command == 'linux-selinux':
            return_results(generic_ansible('linux', 'selinux', args, int_params, host_type))
        elif command == 'linux-selinux-permissive':
            return_results(generic_ansible('linux', 'selinux_permissive', args, int_params, host_type))
        elif command == 'linux-selogin':
            return_results(generic_ansible('linux', 'selogin', args, int_params, host_type))
        elif command == 'linux-seport':
            return_results(generic_ansible('linux', 'seport', args, int_params, host_type))
        elif command == 'linux-service':
            return_results(generic_ansible('linux', 'service', args, int_params, host_type))
        elif command == 'linux-service-facts':
            return_results(generic_ansible('linux', 'service_facts', args, int_params, host_type))
        elif command == 'linux-setup':
            return_results(generic_ansible('linux', 'setup', args, int_params, host_type))
        elif command == 'linux-sysctl':
            return_results(generic_ansible('linux', 'sysctl', args, int_params, host_type))
        elif command == 'linux-systemd':
            return_results(generic_ansible('linux', 'systemd', args, int_params, host_type))
        elif command == 'linux-sysvinit':
            return_results(generic_ansible('linux', 'sysvinit', args, int_params, host_type))
        elif command == 'linux-timezone':
            return_results(generic_ansible('linux', 'timezone', args, int_params, host_type))
        elif command == 'linux-ufw':
            return_results(generic_ansible('linux', 'ufw', args, int_params, host_type))
        elif command == 'linux-user':
            return_results(generic_ansible('linux', 'user', args, int_params, host_type))
        elif command == 'linux-xfs-quota':
            return_results(generic_ansible('linux', 'xfs_quota', args, int_params, host_type))
        elif command == 'linux-htpasswd':
            return_results(generic_ansible('linux', 'htpasswd', args, int_params, host_type))
        elif command == 'linux-supervisorctl':
            return_results(generic_ansible('linux', 'supervisorctl', args, int_params, host_type))
        elif command == 'linux-openssh-cert':
            return_results(generic_ansible('linux', 'openssh_cert', args, int_params, host_type))
        elif command == 'linux-openssh-keypair':
            return_results(generic_ansible('linux', 'openssh_keypair', args, int_params, host_type))
        elif command == 'linux-acl':
            return_results(generic_ansible('linux', 'acl', args, int_params, host_type))
        elif command == 'linux-archive':
            return_results(generic_ansible('linux', 'archive', args, int_params, host_type))
        elif command == 'linux-assemble':
            return_results(generic_ansible('linux', 'assemble', args, int_params, host_type))
        elif command == 'linux-blockinfile':
            return_results(generic_ansible('linux', 'blockinfile', args, int_params, host_type))
        elif command == 'linux-file':
            return_results(generic_ansible('linux', 'file', args, int_params, host_type))
        elif command == 'linux-find':
            return_results(generic_ansible('linux', 'find', args, int_params, host_type))
        elif command == 'linux-ini-file':
            return_results(generic_ansible('linux', 'ini_file', args, int_params, host_type))
        elif command == 'linux-iso-extract':
            return_results(generic_ansible('linux', 'iso_extract', args, int_params, host_type))
        elif command == 'linux-lineinfile':
            return_results(generic_ansible('linux', 'lineinfile', args, int_params, host_type))
        elif command == 'linux-replace':
            return_results(generic_ansible('linux', 'replace', args, int_params, host_type))
        elif command == 'linux-stat':
            return_results(generic_ansible('linux', 'stat', args, int_params, host_type))
        elif command == 'linux-synchronize':
            return_results(generic_ansible('linux', 'synchronize', args, int_params, host_type))
        elif command == 'linux-tempfile':
            return_results(generic_ansible('linux', 'tempfile', args, int_params, host_type))
        elif command == 'linux-unarchive':
            return_results(generic_ansible('linux', 'unarchive', args, int_params, host_type))
        elif command == 'linux-xml':
            return_results(generic_ansible('linux', 'xml', args, int_params, host_type))
        elif command == 'linux-expect':
            return_results(generic_ansible('linux', 'expect', args, int_params, host_type))
        elif command == 'linux-bower':
            return_results(generic_ansible('linux', 'bower', args, int_params, host_type))
        elif command == 'linux-bundler':
            return_results(generic_ansible('linux', 'bundler', args, int_params, host_type))
        elif command == 'linux-composer':
            return_results(generic_ansible('linux', 'composer', args, int_params, host_type))
        elif command == 'linux-cpanm':
            return_results(generic_ansible('linux', 'cpanm', args, int_params, host_type))
        elif command == 'linux-gem':
            return_results(generic_ansible('linux', 'gem', args, int_params, host_type))
        elif command == 'linux-maven-artifact':
            return_results(generic_ansible('linux', 'maven_artifact', args, int_params, host_type))
        elif command == 'linux-npm':
            return_results(generic_ansible('linux', 'npm', args, int_params, host_type))
        elif command == 'linux-pear':
            return_results(generic_ansible('linux', 'pear', args, int_params, host_type))
        elif command == 'linux-pip':
            return_results(generic_ansible('linux', 'pip', args, int_params, host_type))
        elif command == 'linux-pip-package-info':
            return_results(generic_ansible('linux', 'pip_package_info', args, int_params, host_type))
        elif command == 'linux-yarn':
            return_results(generic_ansible('linux', 'yarn', args, int_params, host_type))
        elif command == 'linux-apk':
            return_results(generic_ansible('linux', 'apk', args, int_params, host_type))
        elif command == 'linux-apt':
            return_results(generic_ansible('linux', 'apt', args, int_params, host_type))
        elif command == 'linux-apt-key':
            return_results(generic_ansible('linux', 'apt_key', args, int_params, host_type))
        elif command == 'linux-apt-repo':
            return_results(generic_ansible('linux', 'apt_repo', args, int_params, host_type))
        elif command == 'linux-apt-repository':
            return_results(generic_ansible('linux', 'apt_repository', args, int_params, host_type))
        elif command == 'linux-apt-rpm':
            return_results(generic_ansible('linux', 'apt_rpm', args, int_params, host_type))
        elif command == 'linux-dpkg-selections':
            return_results(generic_ansible('linux', 'dpkg_selections', args, int_params, host_type))
        elif command == 'linux-flatpak':
            return_results(generic_ansible('linux', 'flatpak', args, int_params, host_type))
        elif command == 'linux-flatpak-remote':
            return_results(generic_ansible('linux', 'flatpak_remote', args, int_params, host_type))
        elif command == 'linux-homebrew':
            return_results(generic_ansible('linux', 'homebrew', args, int_params, host_type))
        elif command == 'linux-homebrew-cask':
            return_results(generic_ansible('linux', 'homebrew_cask', args, int_params, host_type))
        elif command == 'linux-homebrew-tap':
            return_results(generic_ansible('linux', 'homebrew_tap', args, int_params, host_type))
        elif command == 'linux-layman':
            return_results(generic_ansible('linux', 'layman', args, int_params, host_type))
        elif command == 'linux-package':
            return_results(generic_ansible('linux', 'package', args, int_params, host_type))
        elif command == 'linux-package-facts':
            return_results(generic_ansible('linux', 'package_facts', args, int_params, host_type))
        elif command == 'linux-yum':
            return_results(generic_ansible('linux', 'yum', args, int_params, host_type))
        elif command == 'linux-yum-repository':
            return_results(generic_ansible('linux', 'yum_repository', args, int_params, host_type))
        elif command == 'linux-zypper':
            return_results(generic_ansible('linux', 'zypper', args, int_params, host_type))
        elif command == 'linux-zypper-repository':
            return_results(generic_ansible('linux', 'zypper_repository', args, int_params, host_type))
        elif command == 'linux-snap':
            return_results(generic_ansible('linux', 'snap', args, int_params, host_type))
        elif command == 'linux-redhat-subscription':
            return_results(generic_ansible('linux', 'redhat_subscription', args, int_params, host_type))
        elif command == 'linux-rhn-channel':
            return_results(generic_ansible('linux', 'rhn_channel', args, int_params, host_type))
        elif command == 'linux-rhn-register':
            return_results(generic_ansible('linux', 'rhn_register', args, int_params, host_type))
        elif command == 'linux-rhsm-release':
            return_results(generic_ansible('linux', 'rhsm_release', args, int_params, host_type))
        elif command == 'linux-rhsm-repository':
            return_results(generic_ansible('linux', 'rhsm_repository', args, int_params, host_type))
        elif command == 'linux-rpm-key':
            return_results(generic_ansible('linux', 'rpm_key', args, int_params, host_type))
        elif command == 'linux-get-url':
            return_results(generic_ansible('linux', 'get_url', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
