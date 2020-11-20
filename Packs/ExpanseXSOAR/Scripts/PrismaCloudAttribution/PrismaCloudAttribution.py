import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""PrismaCloudAttribution

"""


from typing import Dict, List, Any, Tuple, Iterable, Union
import traceback

IPADDRESS_KEYS = ['publicIpAddress', 'natIP', 'publicIp']
FQDN_KEYS = ['publicDnsName', 'dnsname', 'domainName', 'name']

''' STANDALONE FUNCTION '''


def recursive_find(keys: Union[List[str], str], value: List[Dict[Any, Any]]) -> Iterable[Any]:
    if not isinstance(keys, list):
        keys = [keys]
    for k, v in (value.items() if isinstance(value, dict) else
                 enumerate(value) if isinstance(value, list) else []):
        if k in keys:
            yield v
        elif isinstance(v, (dict, list)):
            for result in recursive_find(keys, v):
                yield result


def handle_data(data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    out_dict: Dict = {}
    if 'ip' in fields:
        out_dict["ip"] = i if (i := list(set(recursive_find(IPADDRESS_KEYS, data)))) else None
    if 'fqdn' in fields:
        out_dict["fqdn"] = f if (f := list(set([l for l in recursive_find(FQDN_KEYS, data) if l.count('.') > 0]))) else None
    return out_dict


''' COMMAND FUNCTION '''


def attribution_command(args: Dict[str, Any]) -> CommandResults:

    assets = argToList(args.get('assets', []))
    demisto.debug(f"Assets: {assets!r}")
    fields = argToList(
        args.get('fields', 'id,cloudType,resourceName,resourceType,regionId,accountId,accountName,hasAlert,service,ip,fqdn'))
    demisto.debug(f"Fields: {fields!r}")

    asset_dict: Dict = {}

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        if 'rrn' not in asset:
            continue
        rrn = asset['rrn']
        asset_dict[rrn] = {'rrn': rrn}
        for k in asset.keys():
            if k == 'name' and 'resourceName' in fields:
                asset_dict[rrn]['resourceName'] = asset['name']
            elif k == 'data' and isinstance(asset[k], dict):
                asset_dict[rrn].update(handle_data([asset[k]], fields))
            elif k in fields:
                asset_dict[rrn][k] = asset[k]

    return CommandResults(
        outputs=list(asset_dict.values()),
        outputs_prefix="PrismaCloud.Attribution",
        outputs_key_field="rrn"
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(attribution_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute PrismaCloudAttribution. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
