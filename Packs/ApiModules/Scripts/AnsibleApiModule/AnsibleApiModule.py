from CommonServerPython import *  # noqa: F403
from CommonServerUserPython import *  # noqa: F403
import ansible_runner  # noqa: E401
import json
from typing import Dict, cast

import demistomock as demisto  # noqa: F401

# Dict to Markdown Converter adapted from https://github.com/PolBaladas/torsimany/


def dict2md(json_block, depth=0):
    markdown = ""
    if isinstance(json_block, dict):
        markdown = parseDict(json_block, depth)
    if isinstance(json_block, list):
        markdown = parseList(json_block, depth)
    return markdown


def parseDict(d, depth):
    markdown = ""
    for k in d:
        if isinstance(d[k], (dict, list)):
            markdown += addHeader(k, depth)
            markdown += dict2md(d[k], depth + 1)
        else:
            markdown += buildValueChain(k, d[k], depth)
    return markdown


def parseList(rawlist, depth):
    markdown = ""
    for value in rawlist:
        if not isinstance(value, (dict, list)):
            index = rawlist.index(value)
            markdown += buildValueChain(index, value, depth)
        else:
            header_value = find_header_in_dict(value)
            if header_value is None:
                header_value = "list"

            markdown += addHeader(header_value, depth)
            markdown += parseDict(value, depth)
    return markdown


def find_header_in_dict(rawdict):
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


def buildHeaderChain(depth):
    list_tag = '* '
    htag = '#'

    chain = list_tag * (bool(depth)) + htag * (depth + 1) + \
        ' value ' + (htag * (depth + 1) + '\n')
    return chain


def buildValueChain(key, value, depth):
    tab = "  "
    list_tag = '* '

    chain = tab * (bool(depth - 1)) + list_tag + \
        str(key) + ": " + str(value) + "\n"
    return chain


def addHeader(value, depth):
    chain = buildHeaderChain(depth)
    chain = chain.replace('value', value.title())
    return chain


# Remove ansible branding from results
def rec_ansible_key_strip(obj):
    if isinstance(obj, dict):
        return {key.replace('ansible_', ''): rec_ansible_key_strip(val) for key, val in obj.items()}
    return obj


def generate_ansible_inventory(args: Dict[str, Any], host_type: str = "local"):
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
        if type(args['host']) is list:
            # host arg can be a array of multiple hosts
            hosts = args['host']
        else:
            # host arg could also be csv
            hosts = [host.strip() for host in args['host'].split(',')]

        for host in hosts:
            new_host = {}
            new_host['ansible_host'] = host

            if ":" in host:
                address = host.split(':')
                new_host['ansible_port'] = address[1]
                new_host['ansible_host'] = address[0]
            else:
                new_host['ansible_host'] = host
                if demisto.params().get('port'):
                    new_host['ansible_port'] = demisto.params().get('port')

            # Common SSH based auth options
            if host_type in ['ssh', 'nxos', 'ios']:
                # SSH Key saved in credential manager selection
                if demisto.params().get('creds', {}).get('credentials').get('sshkey'):
                    username = demisto.params().get('creds', {}).get('credentials').get('user')
                    sshkey = demisto.params().get('creds', {}).get('credentials').get('sshkey')

                    new_host['ansible_user'] = username

                # Password saved in credential manager selection
                elif demisto.params().get('creds', {}).get('credentials').get('password'):
                    username = demisto.params().get('creds', {}).get('credentials').get('user')
                    password = demisto.params().get('creds', {}).get('credentials').get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # username/password individually entered
                else:
                    username = demisto.params().get('creds', {}).get('identifier')
                    password = demisto.params().get('creds', {}).get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # ios specific
                if host_type == 'ios':
                    new_host['ansible_connection'] = 'network_cli'
                    new_host['ansible_network_os'] = 'ios'
                    new_host['ansible_become'] = 'yes'
                    new_host['ansible_become_method'] = 'enable'
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
                if demisto.params().get('creds', {}).get('credentials').get('password'):
                    username = demisto.params().get('creds', {}).get('credentials').get('user')
                    password = demisto.params().get('creds', {}).get('credentials').get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                # username/password individually entered
                else:
                    username = demisto.params().get('creds', {}).get('identifier')
                    password = demisto.params().get('creds', {}).get('password')

                    new_host['ansible_user'] = username
                    new_host['ansible_password'] = password

                new_host['ansible_connection'] = "winrm"
                new_host['ansible_winrm_transport'] = "ntlm"
                new_host['ansible_winrm_server_cert_validation'] = "ignore"

        inventory['all']['hosts'][host] = new_host

    return inventory, sshkey


host_type: str  # Global defined within the integration module. Defined here because https://github.com/python/mypy/issues/5732


def generic_ansible(integration_name, command, args: Dict[str, Any]) -> CommandResults:

    readable_output = ""
    sshkey = ""
    fork_count = 1   # default to executing against 1 host at a time
    global host_type

    if args.get('concurrency'):
        fork_count = cast(int, args.get('concurrency'))

    # generate ansible host inventory
    inventory, sshkey = generate_ansible_inventory(args=args, host_type=host_type)

    module_args = ""
    # build module args list
    for arg_key, arg_value in args.items():
        # skip hardcoded host arg, as it doesn't related to module
        if arg_key == 'host':
            continue

        module_args += "%s=\"%s\" " % (arg_key, arg_value)

        # If this isn't host based, then all the integratation parms will be used as command args
    if host_type == 'local':
        for arg_key, arg_value in demisto.params().items():
            module_args += "%s=\"%s\" " % (arg_key, arg_value)

    r = ansible_runner.run(inventory=inventory, host_pattern='all', module=command, quiet=True,
                           omit_event_data=True, ssh_key=sshkey, module_args=module_args, forks=fork_count)

    results = []
    for each_host_event in r.events:
        # Troubleshooting
        # demisto.log("%s: %s\n" % (each_host_event['event'], each_host_event))
        if each_host_event['event'] in ["runner_on_ok", "runner_on_unreachable", "runner_on_failed"]:

            # parse results

            result = json.loads('{' + each_host_event['stdout'].split('{', 1)[1])
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
                if type(result) == dict:
                    result['host'] = host
                    result['status'] = status.strip()

                results.append(result)
            if each_host_event['event'] == "runner_on_unreachable":
                msg = "Host %s unreachable\nError Details: %s" % (host, result)
                return_error(msg)

            if each_host_event['event'] == "runner_on_failed":
                msg = "Host %s failed running command\nError Details: %s" % (host, result)
                return_error(msg)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=integration_name + '.' + command,
        outputs_key_field='',
        outputs=results
    )
