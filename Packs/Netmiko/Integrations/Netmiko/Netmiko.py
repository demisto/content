import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''


import io
import json
import re
import sys
from datetime import datetime
from time import sleep

from netmiko import Netmiko
from netmiko.ssh_dispatcher import platforms
from paramiko import PKey

''' HELPER FUNCTIONS '''


class Client:
    def __init__(self, platform, hostname, username, password, port, ssh_key=None):
        self.platform = platform
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.ssh_key = ssh_key
        self.net_connect = None

    def connect(self):
        try:
            if self.ssh_key:
                with open("ssh_key", "w") as fp:
                    fp.write(self.ssh_key)
                self.net_connect = Netmiko(device_type=self.platform, host=self.hostname, port=self.port,
                                           use_keys=True, key_file="ssh_key", username=self.username, passphrase=self.password)
            else:
                self.net_connect = Netmiko(device_type=self.platform, host=self.hostname,
                                           port=self.port, username=self.username, password=self.password)
        except Exception as err:
            return_error(err)

    def disconnect(self):
        try:
            if self.net_connect:
                self.net_connect.disconnect()
        except Exception as err:
            return_error(err)

    def cmds(self, exitRequired, exitChar, commands, enable, isConfig):
        try:
            output = {"Hostname": self.hostname, "Platform": self.platform, "Commands": []}
            self.connect()
            sleep(2)
            if enable:
                self.net_connect.enable()
            if isConfig:
                output['Commands'].append({"Hostname": self.hostname, "DateTime(UTC)": datetime.utcnow(
                ).isoformat(), "Config": self.net_connect.send_config_set(commands)})
            if not isConfig:
                for cmd in commands:
                    prompt = self.net_connect.find_prompt()
                    c = {"Hostname": self.hostname, "DateTime(UTC)": datetime.utcnow().isoformat(
                    ), "Command": cmd, "Output": f"{prompt} {self.net_connect.send_command_timing(cmd)}"}
                    output['Commands'].append(c)

        except Exception as err:
            return_error(err)
        finally:
            self.disconnect()
        return output


def test_command(client):
    client.connect()
    client.disconnect()
    demisto.results('ok')
    sys.exit(0)


def cmds_command(client):

    # Parse the commands
    cmds = demisto.args().get('cmds')
    if type(cmds) != list:
        try:
            cmds = cmds.split('\n')
        except Exception as err:
            return_error(f"The 'cmds' input needs to be a JSON array or carriage return separated text - {err}")
    cmds[:] = [x for x in cmds if len(x) > 0]

    # Parse the remaining arguments
    isConfig = True if demisto.args().get('isConfig', 'false') == 'true' else False
    enable = True if demisto.params().get('require_enable', 'false') == 'true' else False
    require_exit = True if demisto.args().get('require_exit', 'false') == 'true' else False
    exit_argument = demisto.args().get('exit_argument')
    raw_print = True if demisto.args().get('raw_print', 'false') == 'true' else False
    disable_context = True if demisto.args().get('disable_context', 'false') == 'true' else False
    override_host = demisto.args().get('override_host', None)
    override_port = demisto.args().get('override_port', None)
    override_platform = demisto.args().get('override_platform', None)
    override_username = demisto.args().get('override_username', None)
    override_password = demisto.args().get('override_password', None)

    client.hostname = override_host if override_host else client.hostname
    client.port = override_port if override_port else client.port
    client.platform = override_platform if override_platform else client.platform
    client.username = override_username if override_username else client.username
    client.password = override_password if override_password else client.password

    # Execute the commands
    output = client.cmds(require_exit, exit_argument, cmds, enable, isConfig)
    raw_print_list = list()

    # Output the results
    if raw_print:
        md = str()
        try:
            for command in output.get('Commands'):
                raw_print_list.append(command.get('Output'))
            md = "\n".join(raw_print_list)
        except Exception as err:
            md = "Error parsing raw print output"
            demisto.error(f"Error with raw print output - {err}")

    else:
        md = tableToMarkdown(f'Command(s) against {client.hostname} ({client.platform}):', output.get('Commands', []))
    outputs_key_field = None
    outputs_prefix = None
    outputs = None
    if not disable_context:
        outputs_prefix = "Netmiko"
        outputs_key_field = 'DateTime(UTC)'
        outputs = output.get('Commands')

    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=md
    )
    return_results(command_results)


def main():

    platform = demisto.params().get('platform')
    hostname = demisto.params().get('hostname')
    port = int(demisto.params().get('port'))
    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')
    ssh_key = demisto.params().get('credentials', {}).get('credentials', {}).get('sshkey')

    client = Client(platform, hostname, username, password, port, ssh_key=ssh_key)

    if demisto.command() == 'test-module':
        test_command(client)
    elif demisto.command() == 'netmiko-cmds':
        cmds_command(client)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
