import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def panorama_security_policy_match(args):
    try:
        result = demisto.executeCommand('panorama-security-policy-match', args=args)
        return result
    except Exception as e:
        raise Exception(f'Failed to run panorama-security-policy-match command. Error: {str(e)}')


def wrapper_panorama_security_policy_match(destinations: list, sources: list, args: dict):
    results = []
    for source in sources:
        args['source'] = source
        for destination in destinations:
            args['destination'] = destination

            res = panorama_security_policy_match(args)
            try:
                if 'The query did not match a Security policy' in res[0].get('Contents'):
                    res[0]['Contents'] = f'The query for source: {source}, destination: {destination} ' \
                                         f'did not match a Security policy.'
            except Exception:
                pass
            results.append(res)

    return results


def wrapper_command(args: Dict[str, Any]):

    destinations = argToList(args.get('destinations'))
    sources = argToList(args.get('sources'))
    destination_port = args.get('destination_port')
    source_user = args.get('source_user')
    vsys = args.get('vsys')
    target = args.get('target')
    protocol = args.get('protocol')
    to_ = args.get('to')
    from_ = args.get('from')
    category = args.get('category')
    application = args.get('application')

    args = {
        'destination-port': destination_port,
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

    result = wrapper_panorama_security_policy_match(destinations, sources, command_args)

    return result


''' MAIN FUNCTION '''


def main():
    try:
        return_results(wrapper_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute PanoramaSecurityPolicyMatchWrapper. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
