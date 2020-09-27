import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from ansible_runner import run, Runner
from paramiko import AutoAddPolicy, AuthenticationException, SSHClient, SSHException
from socket import error

from urllib3 import disable_warnings
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast, Callable

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
        """

        Args:
            playbook_name:
            extra_vars:

        Returns:

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

    def homebrew(self, apps: List[str], cask_apps: List[str]) -> Runner:
        """

        Args:
            apps:
            cask_apps:

        Returns:

        """
        return self._execute(
            playbook_name="homebrew",
            extra_vars={
                "homebrew_installed_packages": apps,
                "homebrew_cask_apps": cask_apps
            })

    def anyenv(self, env: str, versions: List[str], global_versions: List[str]) -> Runner:
        """

        Args:
            env:
            versions:
            global_versions:

        Returns:

        """
        return self._execute(playbook_name="anyenv",
                             extra_vars={
                                 "env": env,
                                 "versions": versions,
                                 "global_versions": global_versions
                             })

    def git_clone(self, repo: str, dest: str, force: str, update: str) -> Runner:
        return self._execute(
            playbook_name="git-clone",
            extra_vars={
                "repo": repo,
                "dest": dest,
                "force": force,
                "update": update
            })

    def git_config(self, key: str, value: str, scope: str) -> Runner:
        """

        Args:
            key:
            value:
            scope:

        Returns:

        """
        return self._execute(
            playbook_name="git-config",
            extra_vars={
                "key": key,
                "value": value,
                "scope": scope
            })

    def github_ssh_key(self, github_access_token: str) -> Runner:
        """

        Args:
            github_access_token:

        Returns:

        """
        return self._execute(playbook_name="github-ssh-key",
                             extra_vars={
                                 "github_access_token": github_access_token
                             })

    def zsh(self) -> Runner:
        """

        Returns:

        """
        return self._execute(playbook_name="zsh")

    def block_in_file(self, path: str, block: str, marker: str, create: str) -> Runner:
        """

        Args:
            path:
            block:
            marker:
            create:

        Returns:

        """
        return self._execute(playbook_name="blockinfile",
                             extra_vars={
                                 "path": path,
                                 "block": block,
                                 "marker": marker,
                                 "create": create
                             })

    def exec(self, command: str, working_dir: str) -> Runner:
        """

        Args:
            command:
            working_dir:

        Returns:

        """
        return self._execute(playbook_name="exec",
                             extra_vars={
                                 "command": command,
                                 "dir": working_dir
                             })


''' HELPER FUNCTIONS '''


def parse_response(response: Runner, human_readable_name: str, installed_software: str, additional_vars=None) -> DemistoResult:
    """

    Args:
        response:
        human_readable_name:
        installed_software:
        additional_vars:

    Returns:

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
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.anyenv(env=AnyEnvs.pyenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_goenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.anyenv(env=AnyEnvs.goenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_nodenv_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.anyenv(env=AnyEnvs.nodenv,
                                   versions=argToList(kwargs.get("versions")),
                                   global_versions=argToList(kwargs.get("globals")))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_homebrew_command(client: TidyClient, **kwargs) -> DemistoResult:
    """
    """
    raw_response = client.homebrew(apps=argToList(kwargs.get('apps')),
                                   cask_apps=argToList(kwargs.get('cask_apps')))

    return parse_response(response=raw_response,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_zsh_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.zsh()
    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_github_ssh_key_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.github_ssh_key(github_access_token=kwargs.get("access_token"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})


def tidy_git_clone_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

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
    """

    Args:
        client:
        **kwargs:

    Returns:

    """
    runner: Runner = client.git_config(key=kwargs.get("key"),
                                       value=kwargs.get("value"),
                                       scope=kwargs.get("scope"))

    return parse_response(response=runner,
                          human_readable_name="",
                          installed_software="",
                          additional_vars={})



def tidy_block_in_file_command(client: TidyClient, **kwargs) -> DemistoResult:
    """

    Args:
        client:
        **kwargs:

    Returns:

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
    """

    Args:
        client:
        **kwargs:

    Returns:

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

    hostname = demisto.getParam("hostname") or demisto.getArg("hostname")
    user = demisto.getParam("user") or demisto.getArg("user")
    password = demisto.getParam("password") or demisto.getArg("password")

    demisto.debug(f'Command being called is {command}')

    # Command execution
    client = TidyClient(hostname=hostname, user=user, password=password)
    try:
        demisto.results(commands[command](client, **demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
