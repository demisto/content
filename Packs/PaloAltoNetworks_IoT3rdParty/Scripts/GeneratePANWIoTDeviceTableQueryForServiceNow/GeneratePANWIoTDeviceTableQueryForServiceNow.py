import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    device_list = demisto.args().get('devices')

    query_strs = []
    query_str = 'mac_addressIN'
    DEFAULT_VALUE_SIZE = 100  # each query contains 100 deviceid
    res = {}
    output_description = f'Total data length is {len(device_list)}'

    for i, entry in enumerate(device_list):
        query_str += entry['deviceid'] + ','
        if ((i + 1) % DEFAULT_VALUE_SIZE == 0 or i == (len(device_list) - 1)):
            query_strs.append(query_str[0:len(query_str) - 1])
            query_str = 'mac_addressIN'
    res['query'] = query_strs
    output_description = f'{output_description} total number of query is {len(query_strs)}'

    results = CommandResults(
        readable_output=output_description,
        outputs_prefix="PanwIot3rdParty.Query",
        outputs=res
    )
    return results


if __name__ in ['__main__', 'builtin', 'builtins']:
    res = main()
    return_results(res)
