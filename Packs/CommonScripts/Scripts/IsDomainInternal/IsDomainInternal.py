import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_domain_internal(domain: str, internal_domains: List[str]) -> bool:
    parts = domain.split(".")
    for i in range(len(parts), 0, -1):
        sub = ".".join(parts[-i:])
        if sub in internal_domains:
            return True
    return False


def main():
    args = demisto.args()
    internal_domains_list_name = args.get("InternalDomainsListName", "InternalDomains")
    domains_to_check = argToList(args.get("Domains", ()))

    # Get the list of internal domains from the XSOAR list:
    internal_domains = demisto.executeCommand("getList", {"listName": internal_domains_list_name})[0]['Contents']
    if "Item not found" in internal_domains:
        return_error(f"The list name {internal_domains_list_name} does not exist.")

    # Split internal domains from XSOAR list to be a list:
    if internal_domains:
        try:
            internal_domains = internal_domains.split("\n")
        except Exception as ex:
            return_error(
                f"Could not parse the internal domains list. Please make sure that the list contains domain names,"
                f" separated by new lines.\nThe exact error is: {ex}")
    else:
        return_results(f"No internal domains were found under {internal_domains_list_name}.")
        return

    # Create list of domain names with internal property
    domain_list = [{"Name": domain, "Internal": is_domain_internal(domain, internal_domains)} for domain in
                   domains_to_check]

    for domain in domain_list:

        args_exists_check = {
            "indicator": domain.get("Name")
        }

        # Check if indicator exists:
        is_exist_res = demisto.executeCommand("CheckIndicatorValue", args_exists_check)
        indicator_exists = is_exist_res[0]["Contents"][0]["Exists"]

        args_create_or_set_indicator = {
            "value": domain.get("Name"),
            "type": "Domain",
            "internal": domain.get("Internal")
        }

        # If indicator doesn't exist, create it and continuously poll for its creation (which happens asynchronously):
        if indicator_exists:
            # If indicator exists, update it with the correct Internal property:
            # Note: theoretically the custom field mapping of the Domain indicator should already map Domain.Internal
            # context to the "Internal" indicator field.
            # However, the mapping occurs only AFTER the indicator reputation script, which DOES NOT run before this
            # script completes, so in order to successfully set the Internal property of the domain name,
            # we need to ensure creation and then edit the indicator ourselves.
            demisto.executeCommand("setIndicator", args_create_or_set_indicator)
        else:
            demisto.executeCommand("createNewIndicator", args_create_or_set_indicator)

    # Create entry context and human-readable results
    entry_context = {"Domain(val.Name == obj.Name)": domain_list}
    md_table = tableToMarkdown(name="Domain Names", t=sorted(domain_list, key=lambda x: not x['Internal']),
                               headers=["Name", "Internal"])
    entry_to_return = {
        "Type": entryTypes['note'],
        "Contents": domain_list,
        "ContentsFormat": "text",
        "HumanReadable": md_table,
        "EntryContext": entry_context,
        "Tags": ['Internal_Domain_Check_Results']
    }

    # Return results
    return_results(entry_to_return)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
