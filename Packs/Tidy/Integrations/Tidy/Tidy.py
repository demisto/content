import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" Developer notes

This integration based on:
    1. Ansible-runner library - https://ansible-runner.readthedocs.io/en/latest/
"""


from typing import Any
from collections.abc import Callable

from ansible_runner import Runner, run
from paramiko import (AuthenticationException, AutoAddPolicy, SSHClient,
                      SSHException)
from urllib3 import disable_warnings

# Disable insecure warnings
disable_warnings()

''' CONSTANTS '''

DemistoResult = dict[str, Any]
IMAGE_PLAYBOOKS_PATH = '/home/demisto/ansible'


class Envs:
    pyenv = "pyenv"
    goenv = "goenv"
    nodenv = "nodenv"


''' CLIENT CLASS '''


class TidyClient:
    def __init__(self, hostname: str, user: str, password: str = "", ssh_key: str = ""):
        self.hostname = hostname
        self.username = user
        self.password = password
        self.ssh_key = ssh_key

    def test(self) -> None:
        """

        Returns:

        """
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try:
            ssh.connect(hostname=self.hostname, username=self.username, password=self.password)
            ssh.close()
        except AuthenticationException as e:
            raise DemistoException(f"Authentication details isn't valid.\nFull error: {e}")
        except OSError as e:
            raise DemistoException(f"SSH socket isn't enabled in endpoint.\nFull error: {e}")
        except SSHException as e:
            raise DemistoException(f"Hostname \"{self.hostname}\" isn't valid!.\nFull error: {e}")

    def _execute(self, playbook_name: str, extra_vars=None) -> Runner:
        """ Execute synchronized ansible-playbook.

        Notes:
            Current availble playbooks:
                1. install_environments.
                2. blockinfile.
                3. exec.
                4. git-clone.
                5. git-config.
                6. github-ssh-key.
                7. homebrew.
                8. zsh.

        Args:
            playbook_name: Playbook name to be execute (Locate in docker image path "/ansible")
            extra_vars: Extra variables to pass the playbook.

        Returns:
            Runner: ansible-runner Runner object.
        """
        if extra_vars is None:
            extra_vars = {}
        inventory = f"{self.username}@{self.hostname} ansible_host=\"{self.hostname}\" " \
                    f"ansible_user=\"{self.username}\" ansible_password=\"{self.password}\" " \
                    f"ansible_become_password=\"{self.password}\" ansible_connection=ssh"

        runner = run(
            private_data_dir=IMAGE_PLAYBOOKS_PATH,
            playbook=f'playbook-{playbook_name}.yml',
            inventory=inventory,
            verbosity=2,
            extravars=extra_vars,
            json_mode=False,
            quiet=True)

        return runner

    def osx_command_line_tools(self) -> Runner:
        """ Execute osx-command-line-tools playbook, Available envs defined by Envs object.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="osx-command-line-tools")

    def install_environments(self, env: str, versions: list[str], global_versions: list[str]) -> Runner:
        """ Execute install-environments playbook, Available envs defined by Envs object.

        Args:
            env: pyenv,goenv,nodenv
            versions: Versions to be installed.
            global_versions: Versions to define as globals in enviorment.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="install-environments",
                             extra_vars={
                                 "env": env,
                                 "versions": versions,
                                 "global_versions": global_versions
                             })

    def homebrew(self, apps: list[str], cask_apps: list[str], homebrew_taps: list[str]) -> Runner:
        """ Execute homebrew playbook.

        Args:
            apps: List of homebrew packages (https://formulae.brew.sh/)
            cask_apps: List of homebrew cask packages (https://formulae.brew.sh/cask/)
            homebrew_taps: List of homebrew taps to install.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(
            playbook_name="homebrew",
            extra_vars={
                "homebrew_installed_packages": apps,
                "homebrew_cask_apps": cask_apps,
                "homebrew_taps": homebrew_taps
            })

    def github_ssh_key(self, access_token: str) -> Runner:
        """ Execute github-ssh-key playbook.

        Args:
            access_token: GitHub access token with public keys admin permissions.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="github-ssh-key",
                             extra_vars={
                                 "access_token": access_token
                             })

    def git_clone(self, repo: str, dest: str, force: str, update: str) -> Runner:
        """ Execute git-clone playbook.

        Args:
            repo: Repository to be cloned (SSH/HTTPS).
            dest: The path of where the repository should be checked out.
            force: If yes, any modified files in the working repository will be discarded.
            update: If no, do not retrieve new revisions from the origin repository.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(
            playbook_name="git-clone",
            extra_vars={
                "repo": repo,
                "dest": dest,
                "force": force,
                "update": update
            })

    def git_config(self, key: str, value: str, scope: str) -> Runner:
        """ Execute git-config playbook.

        Args:
            key: Git config key to set.
            value: Git key: value to set.
            scope: Specify which scope to read/set values from.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(
            playbook_name="git-config",
            extra_vars={
                "key": key,
                "value": value,
                "scope": scope
            })

    def zsh(self) -> Runner:
        """ Execute zsh playbook.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="zsh")

    def python_env(self) -> Runner:
        """ Execute python environment playbook.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="python-env")

    def block_in_file(self, path: str, block: str, marker: str, create: str) -> Runner:
        """ Execute blockinfile playbook.

        Args:
            path: The file to modify.
            block: The text to insert inside the marker lines.
            marker: Marker to manage block if needed to change in the future.
            create: Create a new file if it does not exist.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="blockinfile",
                             extra_vars={
                                 "path": path,
                                 "block": block,
                                 "marker": marker,
                                 "create": create
                             })

    def exec(self, command: str, working_dir: str) -> Runner:
        """ Execute exec playbook.

        Args:
            command: Bash command to execute.
            working_dir: Change directory before executing command.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="exec",
                             extra_vars={
                                 "command": command,
                                 "dir": working_dir
                             })

    def demisto_server(self) -> Runner:
        """ Execute demisto-server playbook.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="demisto-server")

    def demisto_web_client(self) -> Runner:
        """ Execute web-client playbook.

        Returns:
            Runner: ansible-runner Runner object.
        """
        return self._execute(playbook_name="demisto-web-client")


''' HELPER FUNCTIONS '''


def parse_response(response: Runner, human_readable_name: str, installed_software: str,
                   additional_vars=None) -> DemistoResult:
    """ Parse ansible-runner Runner object to demisto

    Args:
        response: ansible-runner Runner object.
        human_readable_name: Table header.
        installed_software: SW installed in hostname
        additional_vars:

    Returns:
         DemistoResult: Demisto structured response.
    """
    stdout = f'\n\n### Stdout:\n```\n{"".join(response.stdout.readlines())}\n```'

    result = {
        'Status': response.status,
        'ReturnCode': response.rc,
        'Canceled': response.canceled,
        'Errored': response.errored,
        'TimedOut': response.timed_out,
        'Stats': response.stats,
        'InstalledSoftware': installed_software,
        'AdditionalInfo': additional_vars
    }

    human_readable = tableToMarkdown(human_readable_name, result, removeNull=True) + stdout
    if response.status == 'failed' or response.rc != 0:
        demisto.results({
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': result,
            'ReadableContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': stdout,
            'EntryContext': {'Tidy.Install': result}
        })
        raise DemistoException(f'Installing {installed_software} has failed with return code {response.rc}, '
                               f'See stdout.')

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {'Tidy.Install': result}
    }


''' COMMAND FUNCTIONS '''


def test_module(client: TidyClient, **_) -> str:
    """Check endpoint configuration is right, Could detect the following:
        1. Hostname isn't accessible from network.
        2. User or password isn't right.
        3. SSH socket isn't enabled in host.

        Args:
            client: TidyClient.

        Raises:
            DemistoException: If test isn't finished successfully.
    """
    client.test()

    return 'ok'


def tidy_osx_command_line_tools_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install OSX command line tools

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.osx_command_line_tools()

    return parse_response(response=runner,
                          human_readable_name="OSx command line tools",
                          installed_software="command line tools",
                          additional_vars={})


def tidy_pyenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install Python versions, Using Pyenv.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    versions = kwargs.get('versions')
    global_versions = kwargs.get('globals')
    runner: Runner = client.install_environments(env=Envs.pyenv,
                                                 versions=argToList(versions),
                                                 global_versions=argToList(global_versions))

    return parse_response(response=runner,
                          human_readable_name="PyEnv installation",
                          installed_software="Pyenv",
                          additional_vars={'versions': versions, 'globals': global_versions})


def tidy_goenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install GoLang versions, Using Goenv.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    versions = kwargs.get('versions')
    global_versions = kwargs.get('globals')
    runner: Runner = client.install_environments(env=Envs.goenv,
                                                 versions=argToList(versions),
                                                 global_versions=argToList(global_versions))

    return parse_response(response=runner,
                          human_readable_name="GoEnv Installation",
                          installed_software="GoEnv",
                          additional_vars={'versions': versions, 'globals': global_versions})


def tidy_nodenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install Node.js versions, Using nodenv.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    versions = kwargs.get('versions')
    global_versions = kwargs.get('globals')
    runner: Runner = client.install_environments(env=Envs.nodenv,
                                                 versions=argToList(versions),
                                                 global_versions=argToList(global_versions))

    return parse_response(response=runner,
                          human_readable_name="NodeEnv Installation",
                          installed_software="NodeEnv",
                          additional_vars={'versions': versions, 'globals': global_versions})


def tidy_homebrew_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install and configure homebrew, Install additional homebrew/-cask packages.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    apps = kwargs.get('apps', '')
    cask_apps = kwargs.get('cask_apps', '')
    homebrew_taps = kwargs.get('homebrew_taps', '')
    raw_response = client.homebrew(apps=argToList(apps),
                                   cask_apps=argToList(cask_apps), homebrew_taps=argToList(argToList(homebrew_taps)))

    return parse_response(response=raw_response,
                          human_readable_name="HomeBrew Command Results",
                          installed_software=','.join([apps, cask_apps, homebrew_taps]),
                          additional_vars={})


def tidy_github_ssh_key_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Generate private/public key, Configure ssh client, and deploy keys to your GitHub account.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.github_ssh_key(access_token=kwargs.get("access_token", ""))

    return parse_response(response=runner,
                          human_readable_name="Github SSH Key Creation Results",
                          installed_software="Github SSH Key",
                          additional_vars={})


def tidy_git_clone_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Clone git repository to destination.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    repo = kwargs.get("repo", "")
    dest = kwargs.get("dest", "")
    force = kwargs.get("force", "")
    update = kwargs.get("update", "")
    runner: Runner = client.git_clone(repo=repo,
                                      dest=dest,
                                      force=force,
                                      update=update)

    return parse_response(response=runner,
                          human_readable_name="Cloning Github Repository Results",
                          installed_software="Git Repository",
                          additional_vars={'repo': repo, 'Destination': dest, 'Force': force, 'Update': update})


def tidy_git_config_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Configure git cli.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    key = kwargs.get("key", "")
    value = kwargs.get("value", "")
    scope = kwargs.get("scope", "")
    runner: Runner = client.git_config(key=key,
                                       value=value,
                                       scope=scope)

    return parse_response(response=runner,
                          human_readable_name="Git Config Modification Results",
                          installed_software="Git Configuration",
                          additional_vars={'Configuration Key': key,
                                           'Configuration Value': value,
                                           'Configuration Scope': scope})


def tidy_zsh_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install zsh, oh-my-zsh, p10k.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.zsh()
    return parse_response(response=runner,
                          human_readable_name="Oh My Zsh Installation Results",
                          installed_software='OhMyZsh',
                          additional_vars={})


def tidy_block_in_file_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Insert/update/remove a block of multi-line text surrounded by customizable marker lines.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    path = kwargs.get("path", "")
    block = kwargs.get("block", "")
    marker = kwargs.get("marker", "")
    create = kwargs.get("create", "")
    runner: Runner = client.block_in_file(path=path,
                                          block=block,
                                          marker=marker,
                                          create=create)

    return parse_response(response=runner,
                          human_readable_name="Adding Block In File Results",
                          installed_software="Block In File",
                          additional_vars={"FilePath": path, 'Block': block, 'Marker': marker, 'Create': create})


def tidy_exec_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Run command in host.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    command = kwargs.get("command", "")
    working_dir = kwargs.get("chdir", "")
    runner: Runner = client.exec(command=command,
                                 working_dir=working_dir)

    return parse_response(response=runner,
                          human_readable_name="Exec Results",
                          installed_software="Execution",
                          additional_vars={'Command': command, 'WorkingDirectory': working_dir})


def tidy_demisto_server_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install demisto server.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    command = kwargs.get("command")
    runner: Runner = client.demisto_server()

    return parse_response(response=runner,
                          human_readable_name="Exec Results",
                          installed_software="Execution",
                          additional_vars={'Command': command})


def tidy_demisto_web_client_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install demisto web-client.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    command = kwargs.get("command")
    runner: Runner = client.demisto_web_client()

    return parse_response(response=runner,
                          human_readable_name="Exec Results",
                          installed_software="Execution",
                          additional_vars={'Command': command})


def tidy_python_env_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install Python environment.

    Args:
        client: Tidy client object.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.python_env()

    return parse_response(response=runner,
                          human_readable_name="Exec Results",
                          installed_software="Execution",
                          additional_vars={})


''' MAIN FUNCTION '''


def main() -> None:
    # Commands definition
    command = demisto.command()
    commands: dict[str, Callable] = {
        "test-module": test_module,
        "tidy-pyenv": tidy_pyenv_command,
        "tidy-goenv": tidy_goenv_command,
        "tidy-nodenv": tidy_nodenv_command,
        "tidy-homebrew": tidy_homebrew_command,
        "tidy-github-ssh-key": tidy_github_ssh_key_command,
        "tidy-git-clone": tidy_git_clone_command,
        "tidy-git-config": tidy_git_config_command,
        "tidy-zsh": tidy_zsh_command,
        "tidy-block-in-file": tidy_block_in_file_command,
        "tidy-exec": tidy_exec_command,
        "tidy-osx-command-line-tools": tidy_osx_command_line_tools_command,
        "tidy-python-env": tidy_python_env_command,
        "tidy-demisto-server": tidy_demisto_server_command,
        "tidy-demisto-web-client": tidy_demisto_web_client_command,
    }

    # Tidy client configuration
    hostname = demisto.getArg("hostname") or demisto.getParam("hostname")
    user = demisto.getArg("user") or demisto.params().get('user_creds', {}).get('identifier') or demisto.params().get("user")
    password = demisto.getArg("password") or demisto.params().get(
        'user_creds', {}).get('password') or demisto.params().get("password")
    ssh_key = demisto.getParam("ssh_key")
    client = TidyClient(
        hostname=hostname,
        user=user,
        password=password,
        ssh_key=ssh_key if ssh_key else ''
    )

    # Command execution
    try:
        demisto.debug(f'Command being called is {command}')
        demisto.results(commands[command](client, **demisto.args()))
    # Log exceptions and return errors
    except DemistoException as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
