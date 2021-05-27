import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import ipaddress

"""
This short script searches for CIDR indicators, then checks if any of the provided IP indicators are within them.

If they are, they get tagged with the value of add_tag, which can then be searched on (-tags:added_tag)

This automation is dynamic, so if the list of CIDR blocks changes the IP indicators are re-evaluated.

This should be run attached as a feed triggered or scheduled job.
"""


def cidr_match(indicator, cidr_indicator_list):
    """
    Given a list of CIDR indicators and a single IP indicator, compare if the indicator is
    in the list of CIDR blocks

    Returns true if it DOES match
    """
    ip_addr = ipaddress.ip_address(indicator)
    for cidr_indicator_data in cidr_indicator_list:
        value = cidr_indicator_data.get("value")
        net = ipaddress.ip_network(value)
        if ip_addr in net:
            return value

    return False


def find_tag(indicator, tag_name):
    """
    Searches an indicator object for the given tag_name
    If it doesn't exist, return False
    Otehrwise, return true
    """
    if "CustomFields" in indicator:
        if "tags" in indicator.get("CustomFields"):
            tags = indicator.get("CustomFields").get("tags")
            if tag_name not in tags:
                return False
            else:
                return True
        else:
            return False
    else:
        return False


def main():
    query = demisto.args().get("indicator_query")
    whitelist_query = demisto.args().get("cidr_whitelist_query")
    add_tag = demisto.args().get("add_tag")

    res = demisto.executeCommand("findIndicators", {'query': query, 'size': 15000})
    indicators = res[0]['Contents']

    res = demisto.executeCommand("findIndicators", {'query': whitelist_query, 'size': 15000})
    whitelist_indicators = res[0]['Contents']

    tagged = []
    untagged = []

    for indicator_data in indicators:
        value = indicator_data.get("value")
        match = cidr_match(value, whitelist_indicators)
        # If IP exists in the whitelist query
        if match:
            new_tags = add_tag
            # If the tag doesn't already exist...
            if not find_tag(indicator_data, add_tag):
                tagged.append({
                    "indicator": value,
                    "added_tags": new_tags,
                    "matched": f"{match}"
                })
                res = demisto.executeCommand("setIndicator", {'value': value, 'tags': add_tag})
        # If the IP doesn't exist in the whitelist query, but it is tagged, we need to remove the tag.
        else:
            if find_tag(indicator_data, add_tag):
                untagged.append({
                    "indicator": value,
                    "removed_tag": add_tag,
                    "matched": f"{match}"
                })
                res = demisto.executeCommand("removeIndicatorField",
                                             {'field': "tags", 'fieldValue': add_tag, "indicatorsValues": value})

    tagged_table = tableToMarkdown(f"{len(tagged)} CIDR Whitelisted Indicators - Tagged", tagged)
    untagged_table = tableToMarkdown(f"{len(untagged)} Indicators no longer in CIDR whitelist - untagged", untagged)
    md = ""
    md = md + tagged_table
    md = md + untagged_table
    output = {
        "Tagged": tagged,
        "Untagged": untagged
    }
    return_results(
        CommandResults(
            readable_output=md,
            outputs_prefix="CIDRIndicatorMatch",
            outputs=output
        )
    )
    # Return for test suite
    return output


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
