import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# setList can fail with an Elasticsearch optimistic-concurrency "version conflict" (409) if
# something else writes to the same List between when this playbook's earlier getList ran and
# when this save happens - seen repeatedly in practice while iterating on the same list in quick
# succession. Since that's a transient condition (the conflicting writer's transaction has usually
# already completed a moment later), retry a few times with a short delay before giving up.

MAX_ATTEMPTS = 4
RETRY_DELAY_SECONDS = 3


def set_list_with_retry(list_name: str, list_data: str) -> None:
    last_error = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        res = demisto.executeCommand("setList", {"listName": list_name, "listData": list_data})
        if not is_error(res):
            return

        last_error = get_error(res)
        if "version conflict" not in last_error.lower() or attempt == MAX_ATTEMPTS:
            raise DemistoException(f"Failed to save list {list_name}: {last_error}")

        demisto.debug(f"setList version conflict on attempt {attempt}/{MAX_ATTEMPTS} for {list_name}, retrying: {last_error}")
        time.sleep(RETRY_DELAY_SECONDS)

    raise DemistoException(f"Failed to save list {list_name} after {MAX_ATTEMPTS} attempts: {last_error}")


def main():
    list_name = demisto.args().get("listName")
    if not list_name:
        return_error("listName is required")
    list_data = demisto.args().get("listData", "")

    set_list_with_retry(list_name, list_data)

    return_results(
        CommandResults(
            readable_output=f'Saved list "{list_name}".',
            outputs_prefix="XsoarList",
            outputs_key_field="name",
            outputs={"name": list_name, "content": list_data},
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
