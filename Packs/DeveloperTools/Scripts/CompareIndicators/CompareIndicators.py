import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Tuple, Iterable

from netaddr import IPSet, IPRange
import re

CIDR_RE = re.compile(ipv4cidrRegex)
IP_RE = re.compile(ipv4Regex)


def extract_list_from_args(args: dict, list_key: str) -> List[str]:
    ioc_list = argToList(args.get(list_key, []))
    try:
        if len(ioc_list) == 1:
            fp = demisto.getFilePath(ioc_list[0])
            if isinstance(fp, dict) and 'path' in fp:
                with open(fp['path']) as f:
                    ioc_list = f.read().splitlines()
    finally:
        return ioc_list


def ip_groups_to_ranges(ip_range_groups: Iterable) -> set:
    """Collapse ip groups to ranges.

    Args:
        ip_range_groups (Iterable): a list of lists containing connected IPs

    Returns:
        Set. a set of Ranges.
    """
    ip_ranges = set()
    for group in ip_range_groups:
        # handle single ips
        if len(group) == 1:
            ip_ranges.add(str(group[0]))
            continue

        ip_ranges.add(str(group))

    return ip_ranges


def collect_ips(ioc_list: List[str]) -> Tuple[IPSet, set]:
    ip_set = IPSet()
    non_ip_group = set()
    for ioc in ioc_list:
        if '-' in ioc:
            # handle ip ranges
            ip_range = ioc.split('-')
            if len(ip_range) == 2 and IP_RE.fullmatch(ip_range[0]) and IP_RE.fullmatch(ip_range[1]):
                ip_set.add(IPRange(ip_range[0], ip_range[1]))
            else:
                non_ip_group.add(ioc)
        elif CIDR_RE.findall(ioc) or IP_RE.match(ioc):
            ip_set.add(ioc.strip('\n'))
        else:
            non_ip_group.add(ioc)
    return ip_set, non_ip_group


def collect_unique_indicators_from_lists(ioc_list_1: List[str], ioc_list_2: List[str]) -> Tuple[list, list]:
    ip_set_1, non_ip_set_1 = collect_ips(ioc_list_1)
    ip_set_2, non_ip_set_2 = collect_ips(ioc_list_2)
    ip_diff1 = ip_set_1.difference(ip_set_2)
    ip_diff2 = ip_set_2.difference(ip_set_1)
    diff1 = ip_groups_to_ranges(ip_diff1.iter_ipranges())
    diff2 = ip_groups_to_ranges(ip_diff2.iter_ipranges())
    diff1.update(non_ip_set_1.difference(non_ip_set_2))
    diff2.update(non_ip_set_2.difference(non_ip_set_1))
    return list(diff1), list(diff2)


def main():
    args = demisto.args()
    ioc_list1 = extract_list_from_args(args, 'base_list')
    ioc_list2 = extract_list_from_args(args, 'compare_to_list')
    diff1, diff2 = collect_unique_indicators_from_lists(ioc_list1, ioc_list2)
    outputs = {
        'BaseList': diff1,
        'CompareList': diff2
    }
    return_results(CommandResults(outputs=outputs, outputs_prefix='IndicatorCompare'))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
