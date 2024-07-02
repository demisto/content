import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

# Logging only needed for netmiko debugging
# import logging
import io
import paramiko
import sys
from datetime import datetime
from netmiko import ConnectHandler

# value for Netmiko last_read parameter
LAST_READ_TIMEOUT = 15.0

''' HELPER FUNCTIONS '''

# Return only specific keys from dictionary


def include_keys(dictionary, keys):
    key_set = set(keys) & set(dictionary.keys())
    return {key: dictionary[key] for key in key_set}


class Client:  # pragma: no cover
    def __init__(self, platform, hostname, username, password, port, keys, timeout):
        self.platform = platform
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = int(timeout)
        self.port = port
        self.keys = keys
        self.net_connect = ConnectHandler

    def connect(self):
        if self.keys:
            try:
                self.net_connect = ConnectHandler(device_type=self.platform, host=self.hostname, port=self.port,
                                                  pkey=self.keys, username=self.username, read_timeout_override=self.timeout)
            except Exception as err:
                return_error(err)
        else:
            try:
                self.net_connect = ConnectHandler(device_type=self.platform, host=self.hostname, port=self.port,
                                                  use_keys=False, username=self.username, password=self.password,
                                                  read_timeout_override=self.timeout)
            except Exception as err:
                return_error(err)

    def disconnect(self):
        try:
            if self.net_connect:
                self.net_connect.disconnect()
        except Exception as err:
            return_error(err)

    def cmds(self, require_exit, exit_argument, commands, enable, isConfig):
        try:
            output = {"Hostname": self.hostname, "Platform": self.platform, "Commands": []}
            self.connect()
            if enable:
                self.net_connect.enable()
            if isConfig:
                output['Commands'].append({"Hostname": self.hostname, "DateTimeUTC": datetime.utcnow(
                ).isoformat(), "Config": self.net_connect.send_config_set(commands, read_timeout=self.timeout)})
            if not isConfig:
                for cmd in commands:
                    prompt = self.net_connect.find_prompt()

                    pre_out = self.net_connect.send_command_timing(
                        cmd, read_timeout=self.timeout, strip_prompt=False, last_read=LAST_READ_TIMEOUT)

                    pattern_to_keep = re.escape(prompt)

                    out = re.sub(pattern_to_keep, '', pre_out, count=len(re.findall(pattern_to_keep, pre_out))).strip()

                    c = {"Hostname": self.hostname, "DateTimeUTC": datetime.utcnow().isoformat(), "Command": cmd,
                         "Output": f"{prompt} {out}"}
                    output['Commands'].append(c)

        except Exception as err:
            return_error(err)
        finally:
            self.disconnect()
        return output


def test_command(client):  # pragma: no cover
    client.connect()
    client.disconnect()
    demisto.results('ok')
    sys.exit(0)


def cmds_command(client, args):

    # Parse the commands
    cmds = args.get('cmds')
    if not isinstance(cmds, list):  # pragma: no cover
        try:
            cmds = cmds.split('\n')
        except Exception as err:
            return_error("The 'cmds' input needs to be a JSON array or carriage return (SHIFT+ENTER) separated"
                         + f"text - {err}")
    cmds[:] = [x for x in cmds if len(x) > 0]

    # Parse the remaining arguments
    isConfig = args.get("isConfig", "false") == "true"
    enable = args.get("require_enable", "false") == "true"
    require_exit = args.get("require_exit", "false") == "true"
    exit_argument = args.get('exit_argument', None)
    raw_print = args.get("raw_print", "false") == "true"
    disable_context = args.get("disable_context", "false") == "true"
    override_host = args.get('override_host', None)
    override_port = args.get('override_port', None)
    override_platform = args.get('override_platform', None)
    override_username = args.get('override_username', None)
    override_password = args.get('override_password', None)

    client.hostname = override_host if override_host else client.hostname
    client.port = override_port if override_port else client.port
    client.platform = override_platform if override_platform else client.platform
    client.username = override_username if override_username else client.username
    client.password = override_password if override_password else client.password

    # Execute the commands
    output = client.cmds(require_exit, exit_argument, cmds, enable, isConfig)
    raw_print_list = []

    # Output the results
    if raw_print:
        md = ""
        try:
            for command in output.get('Commands'):
                raw_print_list.append(command.get('Output'))
            md = "\n".join(raw_print_list)
        except Exception as err:
            md = "Error parsing raw print output"
            demisto.error(f"Error with raw print output - {err}")

    else:
        hdrs = ["Hostname", "DateTimeUTC", "Command", "Output"]
        data = []

        # Single command
        if len(cmds) == 1:
            data.append(output["Commands"][0])

        # Multiple commands
        else:
            for item in output["Commands"]:
                data.append(include_keys(item, hdrs))

        md = tableToMarkdown(f'Command(s) against {client.hostname} ({client.platform}):', data, headers=hdrs)
    outputs_key_field = None
    outputs_prefix = None
    outputs = None
    if not disable_context:
        outputs_prefix = "Netmiko"
        outputs_key_field = 'DateTimeUTC'
        outputs = output

    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=md
    )

    return command_results


def main():  # pragma: no cover
    # Uncomment the logging.getLogger line to turn on netmiko debugging (shown in integration-instance.log when debug mode is on)
    # Be sure to uncomment the import logging command at the top of the integration
    # Helpful in troubleshooting incorrect command outputs from remote devices

    # logging.getLogger("netmiko").setLevel(logging.DEBUG)
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    platform = params.get('platform')
    hostname = params.get('hostname')
    port = params.get('port')
    try:
        port = int(port)
    except Exception as err:
        return_error(f"Please ensure the port number is a number - {err}")
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    ssh_key = params.get('credentials', {}).get('credentials', {}).get('sshkey')
    timeout = params.get('TimeoutOverride', 60)

    keys = None
    if ssh_key:
        if password:
            try:
                keys = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key), password=password)
            except Exception as err:
                return_error(f"There was an error - {err} - Did you provide the correct password?")
        else:
            keys = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))

    client = Client(platform, hostname, username, password, port, keys, timeout)

    if command == 'test-module':
        test_command(client)
    elif command == 'netmiko-cmds':
        results = cmds_command(client, args)
        return_results(results)


if __name__ in ['__main__', 'builtin', 'builtins']:  # pragma: no cover
    main()
