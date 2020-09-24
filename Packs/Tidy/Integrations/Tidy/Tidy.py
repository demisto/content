import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from ansible_runner import run
from paramiko import AutoAddPolicy, AuthenticationException, SSHClient, SSHException
from socket import error

from urllib3 import disable_warnings
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast, Callable

# Disable insecure warnings
disable_warnings()

''' CONSTANTS '''

DemistoResult = Tuple[str, dict, dict]

''' CLIENT CLASS '''


class TidyClient:
    def __init__(self, hostname: str, user: str, password: str = ""):
        self.hostname = hostname
        self.username = user
        self.password = password

    def test(self):
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

    def _execute(self, extra_vars: Dict[str, str]):
        runner = run(
            private_data_dir='/ansible',
            playbook='playbook.yml',
            inventory=f"demisto ansible_host=\"{self.hostname}\" ansible_user=\"{self.username}\""
                      f" ansible_ssh_pass=\"{self.password}\" ansible_connection=ssh",
            verbosity=2,
            extravars=extra_vars,
            json_mode=False)

        return runner

    def homebrew(self):
        pass

    def python(self, env: str, python_versions: List[str], global_python_versions: List[str], pyenv_setting_path: str):
        return self._execute({
            "env": env,
            "pyenv_python_versions": python_versions,
            "pyenv_global": global_python_versions,
            "pyenv_setting_path": pyenv_setting_path
        })

    def golang(self, version: str):
        return self._execute({
            "golang_version": version
        })

    def git(self):
        pass

    def github_ssh_key(self):
        pass

    def env_vars(self):
        pass

    def zsh(self):
        pass


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: TidyClient, **kwargs):
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


def tidy_homebrew_command(client: TidyClient, **kwargs):
    pass


def tidy_python_command(client: TidyClient, **kwargs) -> DemistoResult:
    raw_response = client.python(env=kwargs.get('env'),
                                 python_versions=argToList(kwargs.get("python_versions")),
                                 global_python_versions=argToList(kwargs.get("global_python_versions")),
                                 pyenv_setting_path=kwargs.get("pyenv_setting_path"))
    entry_context = {}
    human_readable = ""

    return human_readable, entry_context, raw_response


def tidy_golang_command(client: TidyClient, **kwargs):
    raw_response = client.golang(version=kwargs.get("version"))
    entry_context = {}
    human_readable = ""

    return human_readable, entry_context, raw_response


def tidy_git_command(client: TidyClient):
    pass


def tidy_github_ssh_key_command(client: TidyClient):
    pass


def tidy_env_vars_command(client: TidyClient):
    pass


def tidy_zsh_command(client: TidyClient):
    pass


''' MAIN FUNCTION '''


def main() -> None:
    # Commands definition
    command = demisto.command()
    commands: Dict[str, Callable] = {
        "test-module": test_module,
        "tidy-python": tidy_python_command,
        "tidy-golang": tidy_golang_command,
        "tidy-git": tidy_git_command,
        "tidy-homebrew": tidy_homebrew_command,
        "tidy-github-ssh-key": tidy_github_ssh_key_command,
        "tidy-env-vars": tidy_env_vars_command,
        "tidy-zsh": tidy_zsh_command,
    }

    # Enpoint definition
    proxy = demisto.params().get('proxy', False)

    hostname = demisto.getParam("hostname") or demisto.getArg("hostname")
    user = demisto.getParam("user") or demisto.getArg("user")
    password = demisto.getParam("password") or demisto.getArg("password")

    demisto.debug(f'Command being called is {command}')

    # Command execution
    client = TidyClient(hostname=hostname, user=user, password=password)
    try:
        return_results(commands[command](client, **demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
