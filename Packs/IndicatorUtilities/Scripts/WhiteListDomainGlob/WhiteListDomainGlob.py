import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re
from urllib.parse import urlparse


def glob_match(indicator, glob_indicator_list):
    """
    Given a list of domain indicators and a list of DomainGlob indicators, check indicators match DomainGlob
    and if they do, return True.
    """
    if re.match("https?://", indicator):
        # If it's a URL, grab the hostname to check against glob
        parsed_url = urlparse(indicator)
        indicator = parsed_url.hostname

    for glob_indicator in glob_indicator_list:
        glob_indicator = glob_indicator.get("value")
        if "*" in glob_indicator:
            # Check if the domain exactly matches the domain glob with the leading . stripped
            domain_only_glob = glob_indicator.replace("*.", "")
            domain_only_glob = re.escape(domain_only_glob)
            if re.match(domain_only_glob, indicator):
                return domain_only_glob

            # First replace wildcard with regex .*
            glob_indicator_re = re.sub(r"(\*)", ".*", glob_indicator)
            # then escape the entire string - this also escapes .*
            glob_indicator_re = re.escape(glob_indicator_re)
            # Finally, unescape the wildcard
            glob_indicator_re = glob_indicator_re.replace(r"\.\*", ".*")
            # Add the final component - useful if URL
            glob_indicator_re = glob_indicator_re + r"(\/.*)?$"
            if re.match(glob_indicator_re, indicator):
                return glob_indicator

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
    whitelist_query = demisto.args().get("glob_whitelist_query")
    add_tag = demisto.args().get("add_tag")
    size = int(demisto.args().get("size", 30000))

    res = demisto.executeCommand("findIndicators", {'query': query, 'size': size})
    indicators = res[0]['Contents']

    res = demisto.executeCommand("findIndicators", {'query': whitelist_query, 'size': size})
    whitelist_indicators = res[0]['Contents']

    tagged = []
    untagged = []

    for indicator_data in indicators:
        value = indicator_data.get("value")
        match = glob_match(value, whitelist_indicators)
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
                demisto.executeCommand("setIndicator", {'value': value, 'tags': add_tag})
        # If the IP doesn't exist in the whitelist query, but it is tagged, we need to remove the tag.
        else:
            if find_tag(indicator_data, add_tag):
                untagged.append({
                    "indicator": value,
                    "removed_tag": add_tag,
                    "matched": f"{match}"
                })
                demisto.executeCommand("removeIndicatorField",
                                       {'field': "tags", 'fieldValue': add_tag, "indicatorsValues": value})

    tagged_table = tableToMarkdown(f"{len(tagged)} Domain Whitelisted Indicators - Tagged", tagged)
    untagged_table = tableToMarkdown(f"{len(untagged)} Indicators no longer in DomainGlob whitelist - untagged", untagged)
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
            outputs_prefix="DomainGlobIndicatorMatch",
            outputs=output
        )
    )
    # Return for test suite
    return output


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
