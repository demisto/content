import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""MatchIPinCIDRIndicators

"""

from typing import Dict, Any
import ipaddress
import traceback


''' STANDALONE FUNCTION '''


''' COMMAND FUNCTION '''


def match_ip_in_cidr_indicators(args: Dict[str, Any]) -> CommandResults:

    ip = args.get('ip', None)
    if not ip:
        raise ValueError('ip not provided')

    tags = argToList(args.get('tags', []))

    keys = ['id', 'value', 'CustomFields', 'type', 'score', 'firstSeen', 'lastSeen',
            'expiration', 'expirationStatus', 'sourceBrands', 'sourceInstances']

    tagquery = f' and tags:({" OR ".join(tags)})' if tags else None

    ranges = []
    for r in range(32, 7, -1):
        ranges.append(str(ipaddress.ip_network(f'{ip}/{r}', strict=False)))

    joinexpr = '\" or value:\"'.join(ranges)
    query = f'type:CIDR {tagquery} and ( value:"{joinexpr}")'

    indicators = demisto.executeCommand("findIndicators", {"query": query, 'size': 32})
    outputs = list()
    if not isinstance(indicators, list) or len(indicators) < 1 or 'Contents' not in indicators[0]:
        raise ValueError('No content')

    longest_match = 0
    found_ind: Dict = {}
    for i in indicators[0]['Contents']:
        if 'value' not in i:
            continue
        pfx = ipaddress.ip_network(i['value']).prefixlen
        if pfx > longest_match:
            longest_match = pfx
            found_ind = i

    oi = dict()
    for k in found_ind.keys():
        if k in keys:
            oi[k] = i[k]
    outputs.append(oi)

    return CommandResults(
        outputs_prefix='MatchingCIDRIndicator',
        outputs_key_field='value',
        outputs=outputs
    )
    # need to add IgnoreAutoExtract


''' MAIN FUNCTION '''


def main():
    try:
        return_results(match_ip_in_cidr_indicators(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MatchIPinCIDRIndicators. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
