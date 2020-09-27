""" Developer notes

This integration based on:
    1. Ansible-runner libary - https://ansible-runner.readthedocs.io/en/latest/
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from ansible_runner import run, Runner
from paramiko import AutoAddPolicy, AuthenticationException, SSHClient, SSHException
from socket import error

from urllib3 import disable_warnings
import traceback
from typing import Any, Dict, List, Callable

# Disable insecure warnings
disable_warnings()

''' CONSTANTS '''

DemistoResult = Dict[str, Any]


class AnyEnvs:
    pyenv = "pyenv"
    goenv = "goenv"
    nodenv = "nodenv"


''' CLIENT CLASS '''


class TidyClient:
    def __init__(self, hostname: str, user: str, password: str = ""):
        self.hostname = hostname
        self.username = user
        self.password = password

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
        except error as e:
            raise DemistoException(f"SSH socket isn't enabled in endpoint.\nFull error: {e}")
        except SSHException as e:
            raise DemistoException(f"Hostname \"{self.hostname}\" isn't valid!.\nFull error: {e}")

    def _execute(self, playbook_name: str, extra_vars=None) -> Runner:
        """ Execute synchronized ansible-playbook.

        Notes:
            Current availble playbooks:
                1. anyenv.
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
            Runner: anible-runner Runner object.
        """
        if extra_vars is None:
            extra_vars = {}
        runner = run(
            private_data_dir='/ansible',
            playbook=f'playbook-{playbook_name}.yml',
            inventory=f"demisto ansible_host=\"{self.hostname}\" ansible_user=\"{self.username}\""
                      f" ansible_ssh_pass=\"{self.password}\" ansible_connection=ssh",
            verbosity=2,
            extravars=extra_vars,
            json_mode=False)

        return runner

    def anyenv(self, env: str, versions: List[str], global_versions: List[str]) -> Runner:
        """ Execute anyenv playbook, Availble envs defined by AnyEnvs object.

        Args:
            env: pyenv,goenv,nodenv
            versions: Versions to be installed.
            global_versions: Versions to define as globals in enviorment.

        Returns:
            Runner: anible-runner Runner object.
        """
        return self._execute(playbook_name="anyenv",
                             extra_vars={
                                 "env": env,
                                 "versions": versions,
                                 "global_versions": global_versions
                             })

    def homebrew(self, apps: List[str], cask_apps: List[str]) -> Runner:
        """ Execute homebrew playbook.

        Args:
            apps: List of homebrew packages (https://formulae.brew.sh/)
            cask_apps: List of homebrew cask packages (https://formulae.brew.sh/cask/)

        Returns:
            Runner: anible-runner Runner object.
        """
        return self._execute(
            playbook_name="homebrew",
            extra_vars={
                "homebrew_installed_packages": apps,
                "homebrew_cask_apps": cask_apps
            })

    def github_ssh_key(self, github_access_token: str) -> Runner:
        """ Execute github-ssh-key playbook.

        Args:
            github_access_token: GitHub access token with public keys admin permissions.

        Returns:
            Runner: anible-runner Runner object.
        """
        return self._execute(playbook_name="github-ssh-key",
                             extra_vars={
                                 "github_access_token": github_access_token
                             })

    def git_clone(self, repo: str, dest: str, force: str, update: str) -> Runner:
        """ Execute git-clone playbook.

        Args:
            repo: Repository to be cloned (SSH/HTTPS).
            dest: The path of where the repository should be checked out.
            force: If yes, any modified files in the working repository will be discarded.
            update: If no, do not retrieve new revisions from the origin repository.

        Returns:
            Runner: anible-runner Runner object.
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
            Runner: anible-runner Runner object.
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
            Runner: anible-runner Runner object.
        """
        return self._execute(playbook_name="zsh")

    def block_in_file(self, path: str, block: str, marker: str, create: str) -> Runner:
        """ Execute blockinfile playbook.

        Args:
            path: The file to modify.
            block: The text to insert inside the marker lines.
            marker: Marker to manage block if needed to change in the future.
            create: Create a new file if it does not exist.

        Returns:
            Runner: anible-runner Runner object.
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
            Runner: anible-runner Runner object.
        """
        return self._execute(playbook_name="exec",
                             extra_vars={
                                 "command": command,
                                 "dir": working_dir
                             })


''' HELPER FUNCTIONS '''


def parse_response(response: Runner, human_readable_name: str, installed_software: str, additional_vars=None) -> DemistoResult:
    """ Parse anible-runner Runner object to demisto

    Args:
        response: anible-runner Runner object.
        human_readable_name: Table header.
        installed_software: SW installed in hostname
        additional_vars:

    Returns:
         DemistoResult: Demisto structured response.
    """
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
    stdout = f'\n\n### Stdout:\n```\n{"".join(response.stdout.readlines())}\n```'
    human_readable = tableToMarkdown(human_readable_name, result, removeNull=True) + stdout

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': 'result',
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {'Ansible.Install': 'result'}
    }


''' COMMAND FUNCTIONS '''


def test_module(client: TidyClient, **kwargs) -> DemistoResult:
    """Check endpoint configuration is right, Could detect the following:
        1. Hostname isn't accessible from network.
        2. User or password isn't right.
        3. SSH socket isn't enabled in host.

        Args:
            client: TidyClient.

        Raises:
            DemistoException: If test isn't finished succesfully.
    """
    client.test()

    return 'ok', {}, {}


def tidy_pyenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install Python versions, Using Pyenv.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.anyenv(env=AnyEnvs.pyenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_goenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install GoLang versions, Using Goenv.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.anyenv(env=AnyEnvs.goenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_nodenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install Node.js versions, Using nodenv.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.anyenv(env=AnyEnvs.nodenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_homebrew_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install and configure homebrew, Install additional homebrew/-cask packages.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    raw_response = client.homebrew(apps=argToList(kwargs.get('apps')),
                                   cask_apps=argToList(kwargs.get('cask_apps')))

    return parse_response(response=raw_response,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})



def tidy_github_ssh_key_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Generate private/public key, Configure ssh client, and deploy keys to your GitHub account.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.github_ssh_key(github_access_token=kwargs.get("access_token"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_git_clone_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Clone git repository to destination.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.git_clone(repo=kwargs.get("repo"),
                                      dest=kwargs.get("dest"),
                                      force=kwargs.get("force"),
                                      update=kwargs.get("update"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_git_config_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Configure git cli.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.git_config(key=kwargs.get("key"),
                                       value=kwargs.get("value"),
                                       scope=kwargs.get("scope"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_zsh_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Install zsh, oh-my-zsh, p10k.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.zsh()
    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_block_in_file_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Insert/update/remove a block of multi-line text surrounded by customizable marker lines.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.block_in_file(path=kwargs.get("path"),
                                          block=kwargs.get("block"),
                                          marker=kwargs.get("marker"),
                                          create=kwargs.get("create"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_exec_command(client: TidyClient, **kwargs) -> DemistoResult:
    """ Run command in host.

    Args:
        client: Tidy client obect.
        **kwargs: command kwargs.

    Returns:
        DemistoResults: Demisto structured response.
    """
    runner: Runner = client.exec(command=kwargs.get("command"),
                                 working_dir=kwargs.get("chdir"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


''' MAIN FUNCTION '''


def main() -> None:
    # Commands definition
    command = demisto.command()
    commands: Dict[str, Callable] = {
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
        "tidy-exec": tidy_exec_command
    }

    # Tidy client configuration
    hostname = demisto.getParam("hostname") or demisto.getArg("hostname")
    user = demisto.getParam("user") or demisto.getArg("user")
    password = demisto.getParam("password") or demisto.getArg("password")
    client = TidyClient(hostname=hostname, user=user, password=password)

    # Command execution
    try:
        demisto.debug(f'Command being called is {command}')
        demisto.results(commands[command](client, **demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
