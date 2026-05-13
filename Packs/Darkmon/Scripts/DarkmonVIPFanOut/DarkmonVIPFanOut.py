import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def _get_seen(seen_list_name):
    try:
        res = demisto.executeCommand("getList", {"listName": seen_list_name})
        content = res[0].get("Contents", "") if res else ""
        return {line.strip() for line in (content or "").splitlines() if line.strip()}
    except Exception:
        return set()


def _put_seen(seen_list_name, seen):
    demisto.executeCommand("setList", {"listName": seen_list_name, "listData": "\n".join(sorted(seen))})


def main():
    args = demisto.args()
    emails = argToList(args.get("emails")) or []
    seen_list_name = args.get("seen_list")
    incident_type = args.get("incident_type", "Darkmon VIP Email Leak")

    seen = _get_seen(seen_list_name)
    new_seen = set(seen)
    created = 0

    for email in emails:
        for leak_type in ("accounts", "combo-lists", "public-breaches"):
            try:
                res = demisto.executeCommand("dmontip-get-boardemails", {"type": leak_type, "email": email, "size": "100"})
                ctx = res[0].get("EntryContext", {}) if res else {}
                singular = {"accounts": "Account", "combo-lists": "ComboList", "public-breaches": "PublicBreach"}[leak_type]
                items = ctx.get(f"Darkmon.BoardLeak.{singular}") or []
            except Exception as e:
                demisto.error(f"VIP fetch failed for {email}/{leak_type}: {e}")
                continue
            for it in items:
                composite = f"{email}::{leak_type}::{it.get('id')}"
                if composite in new_seen:
                    continue
                new_seen.add(composite)
                demisto.executeCommand(
                    "createNewIncident",
                    {
                        "name": f"Darkmon VIP leak: {email} ({leak_type})",
                        "type": incident_type,
                        "customFields": {
                            "darkmonprotectedemail": email,
                            "darkmonleaktype": leak_type,
                            "darkmonleakid": str(it.get("id", "")),
                            "darkmonsourcename": str(it.get("source", "")),
                        },
                    },
                )
                created += 1

    if seen_list_name and new_seen != seen:
        _put_seen(seen_list_name, new_seen)

    return_results({"VIPCreated": created})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
