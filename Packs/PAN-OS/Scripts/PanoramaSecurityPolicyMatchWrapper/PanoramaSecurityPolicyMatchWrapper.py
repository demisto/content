import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback

''' STANDALONE FUNCTION '''


def create_script_output(result):
    human_readable_arr = set()
    context = []

    for res in result:
        if isinstance(res, str):
            human_readable_arr.add(res)
        elif isinstance(res, dict):
            if target := res.get('DeviceSerial'):
                table_name = f'Matching Security Policies in `{target}` FW:'
            else:
                table_name = 'Matching Security Policies:'

            table = tableToMarkdown(table_name, res)
            human_readable_arr.add(table)
            context.append(res)

    human_readable = '\n\n'.join(human_readable_arr)

    return human_readable, context


def panorama_security_policy_match(args):
    res = []
    result = demisto.executeCommand('panorama-security-policy-match', args=args)
    if 'The query did not match a Security policy' in result[0].get('Contents'):
        res = [f'The query for source: {args.get("source")}, destination: '
               f'{args.get("destination")} did not match a Security policy.']
    elif entry_context := result[0]['EntryContext']:
        policy_match = entry_context.get(
            'Panorama.SecurityPolicyMatch(val.Query == obj.Query && val.Device == obj.Device)')
        for entry in policy_match:
            if rules := entry.get('Rules'):
                res.append(rules)
    elif is_error(result):
        res = [f'For the following arguments: {args}, panorama-security-policy-match command failed to run: '
               f'Error: {get_error(result)}']
    else:
        res = result[0].get("Contents")
    return res


def wrapper_panorama_security_policy_match(destinations: list, sources: list, destination_ports: list, args: dict):
    results = []
    for source in sources:
        args['source'] = source
        for destination in destinations:
            args['destination'] = destination

            if destination_ports:
                for port in destination_ports:
                    args['destination-port'] = port
                    res = panorama_security_policy_match(args)
                    results.extend(res)
            else:
                res = panorama_security_policy_match(args)
                results.extend(res)

    return results


def wrapper_command(args: Dict[str, Any]):
    destinations = argToList(args.get('destination'))
    sources = argToList(args.get('source'))
    destination_ports = argToList(args.get('destination_port'))
    source_user = args.get('source_user')
    vsys = args.get('vsys')
    target = args.get('target')
    protocol = args.get('protocol')
    to_ = args.get('to')
    from_ = args.get('from')
    category = args.get('category')
    application = args.get('application')
    limit = arg_to_number(args.get('limit', 500))

    vsys_num = len(argToList(vsys)) if vsys else 1
    target_num = len(argToList(target)) if target else 1
    ports_num = len(destination_ports) if destination_ports else 1

    if ports_num * len(destinations) * len(sources) * target_num * vsys_num > limit:    # type: ignore[operator]
        raise Exception(f'Provided arguments will cause more than {limit} API Requests. '
                        'If you wish to exceed the API limit, increase limit argument.')

    args = {
        'source-user': source_user,
        'vsys': vsys,
        'target': target,
        'protocol': protocol,
        'to': to_,
        'from': from_,
        'category': category,
        'application': application
    }

    command_args = assign_params(**args)

    result = wrapper_panorama_security_policy_match(destinations, sources, destination_ports, command_args)

    human_readable, context = create_script_output(result)

    return CommandResults(readable_output=human_readable,
                          outputs_key_field=['Action', 'Name', 'Category', 'Destination', 'From', 'Source', 'To',
                                             'DeviceSerial', 'Application'],
                          outputs=context,
                          outputs_prefix='Panorama.SecurityPolicyMatch.Rules')


def main():  # pragma: no cover
    try:
        return_results(wrapper_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute PanoramaSecurityPolicyMatchWrapper. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
