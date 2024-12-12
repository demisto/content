import re
from json import JSONDecodeError

from CommonServerPython import *  # noqa: F403
from CommonServerUserPython import *  # noqa: F403
import ansible_runner  # pylint: disable=E0401
import json
from typing import Dict, cast, List, Union, Any

# Dict to Markdown Converter adapted from https://github.com/PolBaladas/torsimany/


def dict2md(json_block: Union[Dict[str, Union[dict, list]], List[Union[str, dict, list, float]], float],
            depth: int = 0):
    markdown = ""

    if isinstance(json_block, dict):
        markdown = parse_dict(json_block, depth)
    if isinstance(json_block, list):
        markdown += parse_list(json_block, depth)
    return markdown


def parse_dict(d: Dict[str, Union[dict, list]], depth: int):
    markdown = ""

    # In the case of a dict of dicts/lists, we want to show the "leaves" of the tree first.
    # This will improve readability by avoiding the scenario where "leaves" are shown in between
    # "branches", resulting in their relation to the header to become unclear to the reader.

    for k in d:
        if not isinstance(d[k], (dict, list)):
            markdown += build_value_chain(k, d.get(k), depth + 1)

    for k in d:
        if isinstance(d[k], (dict, list)):
            markdown += add_header(k, depth + 1)
            markdown += dict2md(d[k], depth + 1)
    return markdown


def parse_list(rawlist: List[Union[str, dict, list, float]], depth: int):
    markdown = ""
    default_header_value = "list"
    for value in rawlist:
        if not isinstance(value, (dict, list)):
            index = rawlist.index(value)
            item_depth = depth + 1  # since a header was added previously items should be idented one
            markdown += build_value_chain(index, value, item_depth)
        else:
            # It makes list  more readable to have a header of some sort
            header_value = find_header_in_dict(value)
            if header_value is None:
                header_value = default_header_value
            markdown += add_header(header_value, depth)
            if isinstance(value, dict):
                markdown += parse_dict(value, depth)
            if isinstance(value, list):
                markdown += parse_list(value, depth)
    return markdown


def find_header_in_dict(rawdict: Union[Dict[Any, Any], List[Any]]):
    header = None
    # Finds a suitible value to use as a header
    if not isinstance(rawdict, dict):
        return header  # Not a dict, nothing to do

    id_search = [val for key, val in rawdict.items() if 'id' in key]
    name_search = [val for key, val in rawdict.items() if 'name' in key]

    if id_search:
        header = id_search[0]
    if name_search:
        header = name_search[0]

    return header


def build_header_chain(depth: int):
    list_tag = '* '
    htag = '#'
    tab = "  "

    chain = (tab * depth) + list_tag * (bool(depth)) + htag * (depth + 1) + ' value\n'
    return chain


def build_value_chain(key: Union[int, str], value: Union[str, int, float, Dict[Any, Any], List[Any], None], depth: int):
    tab = '  '
    list_tag = '* '

    chain = (tab * depth) + list_tag + str(key) + ": " + str(value) + "\n"
    return chain


def add_header(value: str, depth: int):
    chain = build_header_chain(depth)
    chain = chain.replace('value', value.title())
    return chain


# Remove ansible branding from results
def rec_ansible_key_strip(obj: Dict[Any, Any]):
    if isinstance(obj, dict):
        return {key.replace('ansible_', ''): rec_ansible_key_strip(val) for key, val in obj.items()}
    return obj


# Convert to TitleCase, like .title() but only letters/numbers.
def title_case(st: str):
    output = ''.join(x for x in st.title() if x.isalnum())
    return output


def generate_ansible_inventory(args: Dict[str, Any], int_params: Dict[str, Any], host_type: str = "local"):
    host_types = ['ssh', 'winrm', 'nxos', 'ios', 'local']
    if host_type not in host_types:
        raise ValueError("Invalid host type. Expected one of: %s" % host_types)

    sshkey = ""

    inventory: Dict[str, dict] = {}
    inventory['all'] = {}
    inventory['all']['hosts'] = {}

    # local
    if host_type == 'local':
        inventory['all']['hosts']['localhost'] = {}
        inventory['all']['hosts']['localhost']['ansible_connection'] = 'local'

    # All other host types are remote
    elif host_type in ['ssh', 'winrm', 'nxos', 'ios']:
        hosts = args.get('host')
        if type(hosts) is str:
            # host arg could be csv
            hosts = [host.strip() for host in hosts.split(',')]  # type: ignore[union-attr]

        for host in hosts:  # type: ignore[union-attr]
            new_host = {}
            new_host['ansible_host'] = host

            if ":" in host:
                address = host.split(':')
                new_host['ansible_port'] = address[1]
                new_host['ansible_host'] = address[0]
            else:
                new_host['ansible_host'] = host
                if int_params.get('port'):
                    new_host['ansible_port'] = int_params.get('port')

            # Common SSH based auth options
            if host_type in ['ssh', 'nxos', 'ios']:
                # SSH Key saved in credential manager selection
                if int_params.get('creds', {}).get('credentials').get('sshkey'):
                    username = int_params.get('creds', {}).get('credentials').get('user')
                    sshkey = int_params.get('creds', {}).get('credentials').get('sshkey')

                    new_host['ansible_user'] = username

                # Password saved in credential manager selection
                elif int_params.get('creds', {}).get('credentials').get('password'):
                    username = int_params.get('creds', {}).get('credentials').get('user')
                    password = int_params.get('creds', {}).get('credentials').get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # username/password individually entered
                else:
                    username = int_params.get('creds', {}).get('identifier')
                    password = int_params.get('creds', {}).get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # ssh specific become options
                if host_type == 'ssh':
                    new_host['ansible_become'] = int_params.get('become')
                    new_host['ansible_become_method'] = int_params.get('become_method')
                    if int_params.get('become_user'):
                        new_host['ansible_become_user'] = int_params.get('become_user')
                    if int_params.get('become_password'):
                        new_host['ansible_become_pass'] = int_params.get('become_password')

                # ios specific
                if host_type == 'ios':
                    new_host['ansible_connection'] = 'network_cli'
                    new_host['ansible_network_os'] = 'ios'
                    new_host['ansible_become'] = 'yes'
                    new_host['ansible_become_method'] = 'enable'
                    new_host['ansible_become_password'] = int_params.get('enable_password')
                    inventory['all']['hosts'][host] = new_host

                # nxos specific
                elif host_type == 'nxos':
                    new_host['ansible_connection'] = 'network_cli'
                    new_host['ansible_network_os'] = 'nxos'
                    new_host['ansible_become'] = 'yes'
                    new_host['ansible_become_method'] = 'enable'
                    inventory['all']['hosts'][host] = new_host

            # winrm
            elif host_type == 'winrm':
                # Only two credential options
                # Password saved in credential manager selection
                if int_params.get('creds', {}).get('credentials').get('password'):
                    username = int_params.get('creds', {}).get('credentials').get('user')
                    password = int_params.get('creds', {}).get('credentials').get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # username/password individually entered
                else:
                    username = int_params.get('creds', {}).get('identifier')
                    password = int_params.get('creds', {}).get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                new_host['ansible_connection'] = "winrm"
                new_host['ansible_winrm_transport'] = "ntlm"
                new_host['ansible_winrm_server_cert_validation'] = "ignore"

            inventory['all']['hosts'][host] = new_host

    return inventory, sshkey


def clean_ansi_codes(input_str: str) -> str:
    """
    Remove ANSI escape codes from the provided string.

    Parameters:
    - input_str (str): The input string containing ANSI escape codes.

    Returns:
    - str: The cleaned string without ANSI escape codes.
    """
    return re.sub(r'\x1b\[.*?m', '', input_str)


def generic_ansible(integration_name: str, command: str,
                    args: Dict[str, Any], int_params: Dict[str, Any], host_type: str,
                    creds_mapping: Dict[str, str] = None) -> CommandResults:
    """Run a Ansible module and return the results as a CommandResult.

    Keyword arguments:
    integration_name -- the name of the XSOAR integration. Used for context output structure
    command -- the ansible module to run
    args -- the XSOAR command args. Literally the demisto.args(). The args provided need to match the
            ansible module args, as well as include the arg "host" if the module is one that connects
            to a host.
    int_params -- the integration parameters. These will contain args that are integration wide.
                  They will passed to the the ansible module as args, with exception of credentials,
                  these will be used to build the ansible inventory.
    host_type -- the type of host that is being managed. The following host types are supported:
                 * ssh -- Linux or Unix variant managed over ssh
                 * winrm -- Windows
                 * nxos -- Cisco NX-OS based network device
                 * ios -- Cisco IOS based network device
                 * local  -- this indicates that the command should be executed locally.
                             Mostly used by modules that connect out to cloud services.
    creds_mapping -- A mapping for the 'creds' param names to expected ansible param names
    """

    readable_output = ""
    sshkey = ""
    fork_count = 1  # default to executing against 1 host at a time

    if args.get('concurrency'):
        fork_count = cast(int, args.get('concurrency'))

    # generate ansible host inventory
    inventory, sshkey = generate_ansible_inventory(args=args, host_type=host_type, int_params=int_params)

    module_args = ""
    # build module args list
    for arg_key, arg_value in args.items():
        # skip hardcoded host arg, as it doesn't related to module
        if arg_key == 'host':
            continue
        # special condition for if there is a collision between the host argument used for ansible inventory
        # and the host argument used by a module
        if arg_key == 'ansible-module-host':
            arg_key = 'host'

        module_args += "%s=\"%s\" " % (arg_key, arg_value)

        # If this isn't host based, then all the integration params will be used as command args
    if host_type == 'local':
        for arg_key, arg_value in int_params.items():

            # if given creds param and a cred mapping - use the naming mapping to correct the arg names
            if arg_key == 'creds' and creds_mapping:
                if arg_value.get('identifier') and 'identifier' in creds_mapping:
                    module_args += "%s=\"%s\" " % (creds_mapping.get('identifier'), arg_value.get('identifier'))

                if arg_value.get('password') and 'password' in creds_mapping:
                    module_args += "%s=\"%s\" " % (creds_mapping.get('password'), arg_value.get('password'))

            else:
                module_args += "%s=\"%s\" " % (arg_key, arg_value)

    r = ansible_runner.run(inventory=inventory, host_pattern='all', module=command, quiet=True,
                           omit_event_data=True, ssh_key=sshkey, module_args=module_args, forks=fork_count)

    results = []
    outputs_key_field = ''
    for each_host_event in r.events:
        # Troubleshooting
        # demisto.log("%s: %s\n" % (each_host_event['event'], each_host_event))
        if each_host_event['event'] in ["runner_on_ok", "runner_on_unreachable", "runner_on_failed"]:

            # parse results
            raw_str_to_parse = '{' + each_host_event['stdout'].split('{', 1)[1]
            str_to_parse = clean_ansi_codes(input_str=raw_str_to_parse)
            try:
                result = json.loads(str_to_parse)
            except JSONDecodeError as e:  # pragma: no cover
                demisto.debug(e)
                demisto.debug('failed to parse response as JSON, will try to clean it from special characters and parse again')
                ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
                str_to_parse = ansi_escape.sub('', str_to_parse)
                result = json.loads(str_to_parse)
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

                # add host and status to result if it is a dict. Some ansible modules return a list
                if (type(result) is dict) and (host != 'localhost'):
                    result['host'] = host
                    outputs_key_field = 'host'  # updates previous outputs that share this key, neat!

                if type(result) is dict:
                    result['status'] = status.strip()

                results.append(result)
            msg = ""
            if each_host_event['event'] == "runner_on_unreachable":
                msg = "Host %s unreachable\nError Details: %s" % (host, result.get('msg'))

            if each_host_event['event'] == "runner_on_failed":
                msg = "Host %s failed running command\nError Details: %s" % (host, result.get('msg'))

            if each_host_event['event'] in ["runner_on_failed", "runner_on_unreachable"]:
                return_error(msg)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=integration_name + '.' + title_case(command),
        outputs_key_field=outputs_key_field,
        outputs=results
    )
