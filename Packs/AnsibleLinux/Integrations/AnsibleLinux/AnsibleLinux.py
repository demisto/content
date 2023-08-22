import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

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
            return_results(generic_ansible('Linux', 'alternatives', args, int_params, host_type))
        elif command == 'linux-at':
            return_results(generic_ansible('Linux', 'at', args, int_params, host_type))
        elif command == 'linux-authorized-key':
            return_results(generic_ansible('Linux', 'authorized_key', args, int_params, host_type))
        elif command == 'linux-capabilities':
            return_results(generic_ansible('Linux', 'capabilities', args, int_params, host_type))
        elif command == 'linux-cron':
            return_results(generic_ansible('Linux', 'cron', args, int_params, host_type))
        elif command == 'linux-cronvar':
            return_results(generic_ansible('Linux', 'cronvar', args, int_params, host_type))
        elif command == 'linux-dconf':
            return_results(generic_ansible('Linux', 'dconf', args, int_params, host_type))
        elif command == 'linux-debconf':
            return_results(generic_ansible('Linux', 'debconf', args, int_params, host_type))
        elif command == 'linux-filesystem':
            return_results(generic_ansible('Linux', 'filesystem', args, int_params, host_type))
        elif command == 'linux-firewalld':
            return_results(generic_ansible('Linux', 'firewalld', args, int_params, host_type))
        elif command == 'linux-gather-facts':
            return_results(generic_ansible('Linux', 'gather_facts', args, int_params, host_type))
        elif command == 'linux-gconftool2':
            return_results(generic_ansible('Linux', 'gconftool2', args, int_params, host_type))
        elif command == 'linux-getent':
            return_results(generic_ansible('Linux', 'getent', args, int_params, host_type))
        elif command == 'linux-group':
            return_results(generic_ansible('Linux', 'group', args, int_params, host_type))
        elif command == 'linux-hostname':
            return_results(generic_ansible('Linux', 'hostname', args, int_params, host_type))
        elif command == 'linux-interfaces-file':
            return_results(generic_ansible('Linux', 'interfaces_file', args, int_params, host_type))
        elif command == 'linux-iptables':
            return_results(generic_ansible('Linux', 'iptables', args, int_params, host_type))
        elif command == 'linux-java-cert':
            return_results(generic_ansible('Linux', 'java_cert', args, int_params, host_type))
        elif command == 'linux-java-keystore':
            return_results(generic_ansible('Linux', 'java_keystore', args, int_params, host_type))
        elif command == 'linux-kernel-blacklist':
            return_results(generic_ansible('Linux', 'kernel_blacklist', args, int_params, host_type))
        elif command == 'linux-known-hosts':
            return_results(generic_ansible('Linux', 'known_hosts', args, int_params, host_type))
        elif command == 'linux-listen-ports-facts':
            return_results(generic_ansible('Linux', 'listen_ports_facts', args, int_params, host_type))
        elif command == 'linux-locale-gen':
            return_results(generic_ansible('Linux', 'locale_gen', args, int_params, host_type))
        elif command == 'linux-modprobe':
            return_results(generic_ansible('Linux', 'modprobe', args, int_params, host_type))
        elif command == 'linux-mount':
            return_results(generic_ansible('Linux', 'mount', args, int_params, host_type))
        elif command == 'linux-open-iscsi':
            return_results(generic_ansible('Linux', 'open_iscsi', args, int_params, host_type))
        elif command == 'linux-pam-limits':
            return_results(generic_ansible('Linux', 'pam_limits', args, int_params, host_type))
        elif command == 'linux-pamd':
            return_results(generic_ansible('Linux', 'pamd', args, int_params, host_type))
        elif command == 'linux-parted':
            return_results(generic_ansible('Linux', 'parted', args, int_params, host_type))
        elif command == 'linux-pids':
            return_results(generic_ansible('Linux', 'pids', args, int_params, host_type))
        elif command == 'linux-ping':
            return_results(generic_ansible('Linux', 'ping', args, int_params, host_type))
        elif command == 'linux-python-requirements-info':
            return_results(generic_ansible('Linux', 'python_requirements_info', args, int_params, host_type))
        elif command == 'linux-reboot':
            return_results(generic_ansible('Linux', 'reboot', args, int_params, host_type))
        elif command == 'linux-seboolean':
            return_results(generic_ansible('Linux', 'seboolean', args, int_params, host_type))
        elif command == 'linux-sefcontext':
            return_results(generic_ansible('Linux', 'sefcontext', args, int_params, host_type))
        elif command == 'linux-selinux':
            return_results(generic_ansible('Linux', 'selinux', args, int_params, host_type))
        elif command == 'linux-selinux-permissive':
            return_results(generic_ansible('Linux', 'selinux_permissive', args, int_params, host_type))
        elif command == 'linux-selogin':
            return_results(generic_ansible('Linux', 'selogin', args, int_params, host_type))
        elif command == 'linux-seport':
            return_results(generic_ansible('Linux', 'seport', args, int_params, host_type))
        elif command == 'linux-service':
            return_results(generic_ansible('Linux', 'service', args, int_params, host_type))
        elif command == 'linux-service-facts':
            return_results(generic_ansible('Linux', 'service_facts', args, int_params, host_type))
        elif command == 'linux-setup':
            return_results(generic_ansible('Linux', 'setup', args, int_params, host_type))
        elif command == 'linux-sysctl':
            return_results(generic_ansible('Linux', 'sysctl', args, int_params, host_type))
        elif command == 'linux-systemd':
            return_results(generic_ansible('Linux', 'systemd', args, int_params, host_type))
        elif command == 'linux-sysvinit':
            return_results(generic_ansible('Linux', 'sysvinit', args, int_params, host_type))
        elif command == 'linux-timezone':
            return_results(generic_ansible('Linux', 'timezone', args, int_params, host_type))
        elif command == 'linux-ufw':
            return_results(generic_ansible('Linux', 'ufw', args, int_params, host_type))
        elif command == 'linux-user':
            return_results(generic_ansible('Linux', 'user', args, int_params, host_type))
        elif command == 'linux-xfs-quota':
            return_results(generic_ansible('Linux', 'xfs_quota', args, int_params, host_type))
        elif command == 'linux-htpasswd':
            return_results(generic_ansible('Linux', 'htpasswd', args, int_params, host_type))
        elif command == 'linux-supervisorctl':
            return_results(generic_ansible('Linux', 'supervisorctl', args, int_params, host_type))
        elif command == 'linux-openssh-cert':
            return_results(generic_ansible('Linux', 'openssh_cert', args, int_params, host_type))
        elif command == 'linux-openssh-keypair':
            return_results(generic_ansible('Linux', 'openssh_keypair', args, int_params, host_type))
        elif command == 'linux-acl':
            return_results(generic_ansible('Linux', 'acl', args, int_params, host_type))
        elif command == 'linux-archive':
            return_results(generic_ansible('Linux', 'archive', args, int_params, host_type))
        elif command == 'linux-assemble':
            return_results(generic_ansible('Linux', 'assemble', args, int_params, host_type))
        elif command == 'linux-blockinfile':
            return_results(generic_ansible('Linux', 'blockinfile', args, int_params, host_type))
        elif command == 'linux-file':
            return_results(generic_ansible('Linux', 'file', args, int_params, host_type))
        elif command == 'linux-find':
            return_results(generic_ansible('Linux', 'find', args, int_params, host_type))
        elif command == 'linux-ini-file':
            return_results(generic_ansible('Linux', 'ini_file', args, int_params, host_type))
        elif command == 'linux-iso-extract':
            return_results(generic_ansible('Linux', 'iso_extract', args, int_params, host_type))
        elif command == 'linux-lineinfile':
            return_results(generic_ansible('Linux', 'lineinfile', args, int_params, host_type))
        elif command == 'linux-replace':
            return_results(generic_ansible('Linux', 'replace', args, int_params, host_type))
        elif command == 'linux-stat':
            return_results(generic_ansible('Linux', 'stat', args, int_params, host_type))
        elif command == 'linux-synchronize':
            return_results(generic_ansible('Linux', 'synchronize', args, int_params, host_type))
        elif command == 'linux-tempfile':
            return_results(generic_ansible('Linux', 'tempfile', args, int_params, host_type))
        elif command == 'linux-unarchive':
            return_results(generic_ansible('Linux', 'unarchive', args, int_params, host_type))
        elif command == 'linux-xml':
            return_results(generic_ansible('Linux', 'xml', args, int_params, host_type))
        elif command == 'linux-expect':
            return_results(generic_ansible('Linux', 'expect', args, int_params, host_type))
        elif command == 'linux-bower':
            return_results(generic_ansible('Linux', 'bower', args, int_params, host_type))
        elif command == 'linux-bundler':
            return_results(generic_ansible('Linux', 'bundler', args, int_params, host_type))
        elif command == 'linux-composer':
            return_results(generic_ansible('Linux', 'composer', args, int_params, host_type))
        elif command == 'linux-cpanm':
            return_results(generic_ansible('Linux', 'cpanm', args, int_params, host_type))
        elif command == 'linux-gem':
            return_results(generic_ansible('Linux', 'gem', args, int_params, host_type))
        elif command == 'linux-maven-artifact':
            return_results(generic_ansible('Linux', 'maven_artifact', args, int_params, host_type))
        elif command == 'linux-npm':
            return_results(generic_ansible('Linux', 'npm', args, int_params, host_type))
        elif command == 'linux-pear':
            return_results(generic_ansible('Linux', 'pear', args, int_params, host_type))
        elif command == 'linux-pip':
            return_results(generic_ansible('Linux', 'pip', args, int_params, host_type))
        elif command == 'linux-pip-package-info':
            return_results(generic_ansible('Linux', 'pip_package_info', args, int_params, host_type))
        elif command == 'linux-yarn':
            return_results(generic_ansible('Linux', 'yarn', args, int_params, host_type))
        elif command == 'linux-apk':
            return_results(generic_ansible('Linux', 'apk', args, int_params, host_type))
        elif command == 'linux-apt':
            return_results(generic_ansible('Linux', 'apt', args, int_params, host_type))
        elif command == 'linux-apt-key':
            return_results(generic_ansible('Linux', 'apt_key', args, int_params, host_type))
        elif command == 'linux-apt-repo':
            return_results(generic_ansible('Linux', 'apt_repo', args, int_params, host_type))
        elif command == 'linux-apt-repository':
            return_results(generic_ansible('Linux', 'apt_repository', args, int_params, host_type))
        elif command == 'linux-apt-rpm':
            return_results(generic_ansible('Linux', 'apt_rpm', args, int_params, host_type))
        elif command == 'linux-dpkg-selections':
            return_results(generic_ansible('Linux', 'dpkg_selections', args, int_params, host_type))
        elif command == 'linux-flatpak':
            return_results(generic_ansible('Linux', 'flatpak', args, int_params, host_type))
        elif command == 'linux-flatpak-remote':
            return_results(generic_ansible('Linux', 'flatpak_remote', args, int_params, host_type))
        elif command == 'linux-homebrew':
            return_results(generic_ansible('Linux', 'homebrew', args, int_params, host_type))
        elif command == 'linux-homebrew-cask':
            return_results(generic_ansible('Linux', 'homebrew_cask', args, int_params, host_type))
        elif command == 'linux-homebrew-tap':
            return_results(generic_ansible('Linux', 'homebrew_tap', args, int_params, host_type))
        elif command == 'linux-layman':
            return_results(generic_ansible('Linux', 'layman', args, int_params, host_type))
        elif command == 'linux-package':
            return_results(generic_ansible('Linux', 'package', args, int_params, host_type))
        elif command == 'linux-package-facts':
            return_results(generic_ansible('Linux', 'package_facts', args, int_params, host_type))
        elif command == 'linux-yum':
            return_results(generic_ansible('Linux', 'yum', args, int_params, host_type))
        elif command == 'linux-yum-repository':
            return_results(generic_ansible('Linux', 'yum_repository', args, int_params, host_type))
        elif command == 'linux-zypper':
            return_results(generic_ansible('Linux', 'zypper', args, int_params, host_type))
        elif command == 'linux-zypper-repository':
            return_results(generic_ansible('Linux', 'zypper_repository', args, int_params, host_type))
        elif command == 'linux-snap':
            return_results(generic_ansible('Linux', 'snap', args, int_params, host_type))
        elif command == 'linux-redhat-subscription':
            return_results(generic_ansible('Linux', 'redhat_subscription', args, int_params, host_type))
        elif command == 'linux-rhn-channel':
            return_results(generic_ansible('Linux', 'rhn_channel', args, int_params, host_type))
        elif command == 'linux-rhn-register':
            return_results(generic_ansible('Linux', 'rhn_register', args, int_params, host_type))
        elif command == 'linux-rhsm-release':
            return_results(generic_ansible('Linux', 'rhsm_release', args, int_params, host_type))
        elif command == 'linux-rhsm-repository':
            return_results(generic_ansible('Linux', 'rhsm_repository', args, int_params, host_type))
        elif command == 'linux-rpm-key':
            return_results(generic_ansible('Linux', 'rpm_key', args, int_params, host_type))
        elif command == 'linux-get-url':
            return_results(generic_ansible('Linux', 'get_url', args, int_params, host_type))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
