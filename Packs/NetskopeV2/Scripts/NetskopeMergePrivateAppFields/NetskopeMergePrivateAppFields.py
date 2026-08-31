import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_current_app(app_id: str) -> dict:
    # netskopev2-list-private-apps has no filter/get-by-id, so fetch everything and find the
    # match here - same EntryContext-based parsing as NetskopeResolvePrivateAppId (Contents
    # reflects raw_response for this command, not outputs).
    res = demisto.executeCommand("netskopev2-list-private-apps", {})
    if is_error(res):
        raise DemistoException(f"Failed to list private apps: {get_error(res)}")

    apps: list = []
    for entry in res:
        entry_context = entry.get("EntryContext") or {}
        for key, value in entry_context.items():
            if not key.startswith("Netskope.PrivateApp"):
                continue
            if isinstance(value, list):
                apps.extend(value)
            elif isinstance(value, dict):
                apps.append(value)

    for app in apps:
        if str(app.get("app_id")) == str(app_id):
            return app
    raise DemistoException(f'Could not find a private app with app_id "{app_id}" to read current host/protocols/tags from.')


def merge_hosts(current_host: str, hosts_to_add: list) -> str:
    existing = [h.strip() for h in (current_host or "").split(",") if h.strip()]
    seen = {h.lower() for h in existing}
    merged = list(existing)
    for h in hosts_to_add:
        if h.lower() not in seen:
            merged.append(h)
            seen.add(h.lower())
    return ",".join(merged)


def remove_hosts(current_host: str, hosts_to_remove: list) -> str:
    to_remove = {h.lower() for h in hosts_to_remove}
    existing = [h.strip() for h in (current_host or "").split(",") if h.strip()]
    return ",".join(h for h in existing if h.lower() not in to_remove)


def merge_protocols(current_protocols: list, ports_to_add: list, protocol_type: str) -> list:
    # netskopev2-list-private-apps returns each protocol with extra read-only fields (id,
    # service_id, created_at, updated_at) and calls the transport field "transport" - but the
    # write API (create/update/replace) only accepts {"type", "port"}. Confirmed against the live
    # API: passing the raw read-shape objects back on write silently applies nothing. Normalize
    # every existing entry to the write shape before appending new ones.
    merged = []
    seen_ports = set()
    for p in current_protocols or []:
        port = str(p.get("port"))
        proto_type = p.get("type") or p.get("transport") or protocol_type
        if port not in seen_ports:
            merged.append({"type": proto_type, "port": port})
            seen_ports.add(port)
    for port in ports_to_add:
        if port not in seen_ports:
            merged.append({"type": protocol_type, "port": port})
            seen_ports.add(port)
    return merged


def remove_ports(current_protocols: list, ports_to_remove: list) -> list:
    to_remove = set(ports_to_remove)
    remaining = []
    for p in current_protocols or []:
        port = str(p.get("port"))
        if port in to_remove:
            continue
        remaining.append({"type": p.get("type") or p.get("transport"), "port": port})
    return remaining


def merge_tags(current_tags: list, tags_to_add: list) -> list:
    existing = [t.get("tag_name") for t in (current_tags or []) if t.get("tag_name")]
    seen = {t.lower() for t in existing}
    merged = list(existing)
    for t in tags_to_add:
        if t.lower() not in seen:
            merged.append(t)
            seen.add(t.lower())
    return merged


def remove_tag_names(tag_names: list, tags_to_remove: list) -> list:
    to_remove = {t.lower() for t in tags_to_remove}
    return [t for t in tag_names if t.lower() not in to_remove]


def main():
    args = demisto.args()
    app_id = args.get("app_id")
    hosts_to_add = [h.strip() for h in argToList(args.get("hosts_to_add")) if h.strip()]
    ports_to_add = [p.strip() for p in argToList(args.get("ports_to_add")) if p.strip()]
    hosts_to_remove = [h.strip() for h in argToList(args.get("hosts_to_remove")) if h.strip()]
    ports_to_remove = [p.strip() for p in argToList(args.get("ports_to_remove")) if p.strip()]
    tags_to_add = [t.strip() for t in argToList(args.get("tags_to_add")) if t.strip()]
    tags_to_remove = [t.strip() for t in argToList(args.get("tags_to_remove")) if t.strip()]
    protocol_type = (args.get("protocol_type") or "tcp").strip().lower()

    # Pass through the direct-replace values unchanged unless there's something to add/remove -
    # this keeps "nothing provided at all" behaving exactly as before (PATCH leaves the field
    # untouched when it's not included in the request body).
    final_host = args.get("host") or ""
    final_protocols_json = args.get("protocols_json") or ""
    final_tags = args.get("tags") or ""

    needs_current = hosts_to_add or ports_to_add or hosts_to_remove or ports_to_remove or tags_to_add or tags_to_remove
    if needs_current:
        if not app_id:
            raise DemistoException("app_id is required to add/remove hosts, ports, or tags")
        current = get_current_app(app_id)

        if hosts_to_add or hosts_to_remove:
            host_value = current.get("host", "")
            if hosts_to_add:
                host_value = merge_hosts(host_value, hosts_to_add)
            if hosts_to_remove:
                host_value = remove_hosts(host_value, hosts_to_remove)
            final_host = host_value

        if ports_to_add or ports_to_remove:
            protocols_value = current.get("protocols") or []
            if ports_to_add:
                protocols_value = merge_protocols(protocols_value, ports_to_add, protocol_type)
            if ports_to_remove:
                protocols_value = remove_ports(protocols_value, ports_to_remove)
            final_protocols_json = json.dumps(protocols_value)

        if tags_to_add or tags_to_remove:
            if tags_to_add:
                tag_names = merge_tags(current.get("tags") or [], tags_to_add)
            else:
                tag_names = [t.get("tag_name") for t in (current.get("tags") or []) if t.get("tag_name")]
            if tags_to_remove:
                tag_names = remove_tag_names(tag_names, tags_to_remove)
            final_tags = ",".join(tag_names)

    outputs = {"host": final_host, "protocols_json": final_protocols_json, "tags": final_tags}
    readable_output = (
        f"Merged fields for app_id {app_id!r}: host={final_host!r}, protocols_json={final_protocols_json!r}, tags={final_tags!r}"
    )

    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="MergedPrivateAppFields",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
