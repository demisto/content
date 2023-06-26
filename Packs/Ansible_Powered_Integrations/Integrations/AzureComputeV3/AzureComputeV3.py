import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import traceback
from typing import Dict, cast

import ansible_runner
import ssh_agent_setup


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
            markdown += parseDict(value, depth)
    return markdown


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


# COMMAND FUNCTIONS


def generic_ansible(integration_name, command, args: Dict[str, Any]) -> CommandResults:

    readable_output = ""
    sshkey = ""
    fork_count = 1   # default to executing against 1 host at a time

    if args.get('concurrency'):
        fork_count = cast(int, args.get('concurrency'))

    inventory: Dict[str, dict] = {}
    inventory['all'] = {}
    inventory['all']['hosts'] = {}

    inventory['all']['hosts']['localhost'] = {}
    inventory['all']['hosts']['localhost']['ansible_connection'] = 'local'

    module_args = ""
    # build module args list
    for arg_key, arg_value in args.items():
        # skip hardcoded host arg, as it doesn't related to module
        if arg_key == 'host':
            continue

        module_args += "%s=\"%s\" " % (arg_key, arg_value)
    # If this isn't host based, then all the integratation parms will be used as command args
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

                # add host and status to result
                result['host'] = host
                result['status'] = status

                results.append(result)
            if each_host_event['event'] == "runner_on_unreachable":
                msg = "Host %s unreachable\nError Details: %s" % (host, result)
                return_error(msg)

            if each_host_event['event'] == "runner_on_failed":
                msg = "Host %s failed running command\nError Details: %s" % (host, result)
                return_error(msg)
    # This is integration is not host based and always runs against localhost
    results = results[0]

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=integration_name + '.' + command,
        outputs_key_field='',
        outputs=results
    )


# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'azure-rm-autoscale':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_autoscale', demisto.args()))
        elif demisto.command() == 'azure-rm-autoscale-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_autoscale_info', demisto.args()))
        elif demisto.command() == 'azure-rm-availabilityset':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_availabilityset', demisto.args()))
        elif demisto.command() == 'azure-rm-availabilityset-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_availabilityset_info', demisto.args()))
        elif demisto.command() == 'azure-rm-deployment':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_deployment', demisto.args()))
        elif demisto.command() == 'azure-rm-deployment-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_deployment_info', demisto.args()))
        elif demisto.command() == 'azure-rm-functionapp':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_functionapp', demisto.args()))
        elif demisto.command() == 'azure-rm-functionapp-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_functionapp_info', demisto.args()))
        elif demisto.command() == 'azure-rm-gallery':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_gallery', demisto.args()))
        elif demisto.command() == 'azure-rm-gallery-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_gallery_info', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimage':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimage', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimage-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimage_info', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimageversion':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimageversion', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimageversion-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimageversion_info', demisto.args()))
        elif demisto.command() == 'azure-rm-image':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_image', demisto.args()))
        elif demisto.command() == 'azure-rm-image-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_image_info', demisto.args()))
        elif demisto.command() == 'azure-rm-loadbalancer':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_loadbalancer', demisto.args()))
        elif demisto.command() == 'azure-rm-loadbalancer-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_loadbalancer_info', demisto.args()))
        elif demisto.command() == 'azure-rm-manageddisk':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_manageddisk', demisto.args()))
        elif demisto.command() == 'azure-rm-manageddisk-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_manageddisk_info', demisto.args()))
        elif demisto.command() == 'azure-rm-resource':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resource', demisto.args()))
        elif demisto.command() == 'azure-rm-resource-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resource_info', demisto.args()))
        elif demisto.command() == 'azure-rm-resourcegroup':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resourcegroup', demisto.args()))
        elif demisto.command() == 'azure-rm-resourcegroup-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resourcegroup_info', demisto.args()))
        elif demisto.command() == 'azure-rm-snapshot':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_snapshot', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachine':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachine', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachine-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachine_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineextension':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineextension', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineextension-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineextension_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineimage-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineimage_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescaleset':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescaleset', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescaleset-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescaleset_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetextension':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetextension', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetextension-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetextension_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetinstance':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetinstance', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetinstance-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetinstance_info', demisto.args()))
        elif demisto.command() == 'azure-rm-webapp':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webapp', demisto.args()))
        elif demisto.command() == 'azure-rm-webapp-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webapp_info', demisto.args()))
        elif demisto.command() == 'azure-rm-webappslot':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webappslot', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
