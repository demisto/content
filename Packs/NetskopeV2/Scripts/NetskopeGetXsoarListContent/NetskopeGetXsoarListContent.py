import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Netskope's v1 hash-list API has no read-back endpoint, so this reads (and creates if missing) an
# XSOAR-side List used to track what's currently believed to be in a given Netskope hash list
# between playbook runs.
#
# getList/setList/createList are real core XSOAR commands (confirmed via
# Packs/CommonScripts/Scripts/AddKeyToList/AddKeyToList.py, which uses the exact same calls) -
# this script exists only to do the "look up a List by a runtime-computed name" step in Python,
# since turning a dynamic string into a context key name isn't reliably expressible in plain
# playbook YAML templating.


def get_or_create_list_content(list_name: str) -> str:
    res = demisto.executeCommand("getList", {"listName": list_name})
    # Checking the entry's actual error status (not string-matching Contents) - "list not found"
    # comes back as a real error entry, and its exact text varies (e.g. includes the list name).
    if not is_error(res):
        contents = res[0].get("Contents", "")
        return contents if isinstance(contents, str) else ""

    # List doesn't exist yet - create it empty so a later setList call has something to update.
    demisto.executeCommand("createList", {"listName": list_name, "listData": ""})
    return ""


def main():
    list_name = demisto.args().get("listName")
    if not list_name:
        return_error("listName is required")

    content = get_or_create_list_content(list_name)

    return_results(
        CommandResults(
            readable_output=content or "(list is currently empty)",
            outputs_prefix="XsoarList",
            outputs_key_field="name",
            outputs={"name": list_name, "content": content},
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
