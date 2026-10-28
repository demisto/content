import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    items = argToList(args.get("items")) or []
    id_field = args.get("id_field", "id")
    seen_list_name = args.get("seen_list")
    domain_filter_list = args.get("domain_filter_list")
    domain_match_field = args.get("domain_match_field", "username")
    allowlist_name = args.get("allowlist")
    allowlist_match_field = args.get("allowlist_match_field", "username")

    def _get_list(name):
        if not name:
            return set()
        try:
            res = demisto.executeCommand("getList", {"listName": name})
            content = res[0].get("Contents", "") if res else ""
            return {line.strip() for line in (content or "").replace(",", "\n").splitlines() if line.strip()}
        except Exception:
            return set()

    seen = _get_list(seen_list_name)
    customer_domains = _get_list(domain_filter_list) if domain_filter_list else None
    allowlist = _get_list(allowlist_name) if allowlist_name else set()

    new_items = []
    new_ids = []
    for it in items:
        iid = str(it.get(id_field, "")).strip()
        if not iid or iid in seen:
            continue
        match_val = str(it.get(allowlist_match_field, "")).lower()
        if any(a.lower() in match_val for a in allowlist):
            continue
        if customer_domains is not None:
            uval = str(it.get(domain_match_field, "")).lower()
            if not any(d.lower() in uval for d in customer_domains):
                continue
        new_items.append(it)
        new_ids.append(iid)

    if new_ids and seen_list_name:
        merged = "\n".join(sorted(seen | set(new_ids)))
        demisto.executeCommand("setList", {"listName": seen_list_name, "listData": merged})

    return_results({"NewAccounts": new_items})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
