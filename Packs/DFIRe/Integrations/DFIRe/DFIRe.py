import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

register_module_line("DFIRe", "start", __line__())  # type: ignore[name-defined]  # pylint: disable=E0602
CONSTANT_PACK_VERSION = "1.0.0"
demisto.debug("pack id = DFIRe, pack version = 1.0.0")
"""DFIRe Integration for Cortex XSOAR / XSIAM

Integrates with DFIRe (Digital Forensics and Incident Response) platform
to manage cases and IOC indicators.

API reference: OpenAPI 3.0.3 — DFIRe API v1.2.8
Auth: Bearer API key (Authorization: Bearer dfire_ak_...)
"""

import os
from typing import Any


import urllib3


urllib3.disable_warnings()


class Client(BaseClient):
    """Client class to interact with the DFIRe API."""

    # ── Cases ────────────────────────────────────────────

    def list_cases(
        self,
        page_size: int = 50,
        page: int | None = None,
        status: str | None = None,
        severity: str | None = None,
        case_mode: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page_size": page_size}
        if page is not None:
            params["page"] = page
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if case_mode:
            params["case_mode"] = case_mode
        return self._http_request("GET", "/cases/", params=params)

    def get_case(self, case_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/cases/{case_id}/")

    def create_case(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", "/cases/", json_data=body)

    def update_case(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("PATCH", f"/cases/{case_id}/", json_data=body)

    def delete_case(self, case_id: int) -> None:
        self._http_request("DELETE", f"/cases/{case_id}/", resp_type="response")

    # ── Search ────────────────────────────────────────────

    def search(self, query: str) -> dict[str, Any]:
        return self._http_request("GET", "/search/", params={"q": query})

    # ── Case Types ────────────────────────────────────────

    def list_case_types(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/case-types/")

    # ── Case Notes ───────────────────────────────────────

    def list_case_notes(self, case_id: int) -> list[dict[str, Any]]:
        return self._http_request("GET", "/case-notes/", params={"case": case_id})

    def create_case_note(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", "/case-notes/", json_data=body)

    # ── Indicators (global) ──────────────────────────────

    def list_indicators(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        stix_type: str | None = None,
        classification: str | None = None,
        confidence: str | None = None,
        tlp: str | None = None,
        is_published: bool | None = None,
        is_revoked: bool | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        if stix_type:
            params["stix_type"] = stix_type
        if classification:
            params["classification"] = classification
        if confidence:
            params["confidence"] = confidence
        if tlp:
            params["tlp"] = tlp
        if is_published is not None:
            params["is_published"] = is_published
        if is_revoked is not None:
            params["is_revoked"] = is_revoked
        return self._http_request("GET", "/indicators/", params=params)

    def get_indicator(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/indicators/{indicator_id}/")

    def create_indicator(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", "/indicators/", json_data=body, ok_codes=(200, 201))

    def update_indicator(self, indicator_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("PATCH", f"/indicators/{indicator_id}/", json_data=body)

    def delete_indicator(self, indicator_id: int) -> None:
        self._http_request("DELETE", f"/indicators/{indicator_id}/", resp_type="response")

    # ── Item Types & Flags ─────────────────────────────────

    def list_item_types(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/item-types/")

    def list_item_flags(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/item-flags/")

    # ── Items (Evidence) ───────────────────────────────────

    def list_items(self, case_id: int | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if case_id is not None:
            params["case"] = case_id
        return self._http_request("GET", "/items/", params=params)

    def get_item(self, item_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/items/{item_id}/")

    def create_item(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", "/items/", json_data=body)

    # ── Attachments ──────────────────────────────────────

    def list_attachments(self, item_uuid: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if item_uuid:
            params["item"] = item_uuid
        return self._http_request("GET", "/attachments/", params=params)

    def get_attachment(self, attachment_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/attachments/{attachment_id}/")

    def delete_attachment(self, attachment_id: int) -> None:
        self._http_request("DELETE", f"/attachments/{attachment_id}/", resp_type="response")

    def chunked_upload_init(
        self, filename: str, size: int, case_id: int | None = None, item_uuid: str | None = None, category: str = "evidence"
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"filename": filename, "size": size, "category": category}
        if case_id is not None:
            body["case"] = case_id
        if item_uuid:
            body["item"] = item_uuid
        return self._http_request("POST", "/attachments/chunked/init/", json_data=body)

    def chunked_upload_chunk(self, session_id: str, chunk_index: int, data: bytes) -> dict[str, Any]:
        headers = dict(self._headers) if self._headers else {}
        headers["Content-Type"] = "application/octet-stream"
        headers["X-Chunk-Index"] = str(chunk_index)
        return self._http_request(
            "POST",
            f"/attachments/chunked/{session_id}/upload/",
            data=data,
            headers=headers,
            resp_type="json",
        )

    def chunked_upload_complete(self, session_id: str) -> dict[str, Any]:
        return self._http_request("POST", f"/attachments/chunked/{session_id}/complete/")

    # ── Timeline ─────────────────────────────────────────

    def list_timeline(self, case_id: int) -> dict[str, Any] | list[dict[str, Any]]:
        return self._http_request("GET", f"/cases/{case_id}/timeline/")

    def create_timeline_event(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/timeline/", json_data=body)

    # ── Users ────────────────────────────────────────────

    def list_users(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/users/")

    # ── Case Indicators ──────────────────────────────────

    def list_case_indicators(self, case_id: int) -> list[dict[str, Any]]:
        return self._http_request("GET", f"/cases/{case_id}/indicators/")

    def add_case_indicator(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/indicators/", json_data=body)

    def remove_case_indicator(self, case_id: int, association_id: int) -> None:
        self._http_request("DELETE", f"/cases/{case_id}/indicators/{association_id}/", resp_type="response")


# ── Helpers ──────────────────────────────────────────────


def build_optional_body(args: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Build a request body from args, including only non-None values."""
    body: dict[str, Any] = {}
    for field in fields:
        val = args.get(field)
        if val is not None:
            body[field] = val
    return body


# ── Command functions ────────────────────────────────────


def test_module(client: Client) -> str:
    client.list_cases(page_size=1)
    return "ok"


# Search


def search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args["query"]
    result = client.search(query)
    results = result.get("results", []) if isinstance(result, dict) else result
    headers = ["id", "type", "title", "snippet", "rank", "date"]
    return CommandResults(
        outputs_prefix="DFIRe.Search",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(f'DFIRe Search Results for "{query}"', results, headers=headers, removeNull=True),
    )


# Case Types


def case_type_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    results = client.list_case_types()
    headers = ["id", "name"]
    return CommandResults(
        outputs_prefix="DFIRe.CaseType",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Case Types", results, headers=headers, removeNull=True),
    )


# Cases


def case_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page_size = arg_to_number(args.get("limit", "50")) or 50
    page = arg_to_number(args.get("page"))
    result = client.list_cases(
        page_size=page_size,
        page=page,
        status=args.get("status"),
        severity=args.get("severity"),
        case_mode=args.get("case_mode"),
    )
    cases = result.get("results", []) if isinstance(result, dict) else result
    headers = ["id", "case_number", "title", "status", "severity", "case_mode", "case_type_name", "created_at"]
    return CommandResults(
        outputs_prefix="DFIRe.Case",
        outputs_key_field="id",
        outputs=cases,
        readable_output=tableToMarkdown("DFIRe Cases", cases, headers=headers, removeNull=True),
    )


def case_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    result = client.get_case(case_id)
    headers = [
        "id",
        "case_number",
        "title",
        "status",
        "severity",
        "case_mode",
        "case_type_name",
        "description",
        "lead_investigator",
        "current_phase_name",
        "item_count",
        "indicator_count",
        "created_at",
        "closed_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Case",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("DFIRe Case", result, headers=headers, removeNull=True),
    )


def case_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body: dict[str, Any] = {
        "title": args["title"],
        "case_type": arg_to_number(args["case_type"], required=True),
    }
    for field in ("description", "severity", "case_mode", "external_id"):
        if args.get(field):
            body[field] = args[field]
    for int_field in ("lead_investigator", "project_id"):
        val = arg_to_number(args.get(int_field))
        if val is not None:
            body[int_field] = val

    result = client.create_case(body)
    return CommandResults(
        outputs_prefix="DFIRe.Case",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Created DFIRe Case", result, headers=["id", "case_number", "title", "status"], removeNull=True
        ),
    )


def case_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    body = build_optional_body(args, ["title", "description", "status", "severity", "case_mode", "external_id"])
    val = arg_to_number(args.get("lead_investigator"))
    if val is not None:
        body["lead_investigator"] = val

    if not body:
        raise DemistoException("At least one field to update must be provided.")

    result = client.update_case(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.Case",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Updated DFIRe Case", result, headers=["id", "case_number", "title", "status"], removeNull=True
        ),
    )


def case_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    client.delete_case(case_id)
    return CommandResults(readable_output=f"Case {case_id} deleted successfully.")


# Case Notes


def case_note_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    results = client.list_case_notes(case_id)
    headers = ["id", "case", "author_name", "note", "show_on_timeline", "created_at"]
    return CommandResults(
        outputs_prefix="DFIRe.CaseNote",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Case Notes", results, headers=headers, removeNull=True),
    )


def case_note_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body: dict[str, Any] = {
        "case": arg_to_number(args["case_id"], required=True),
        "note": args["note"],
    }
    show = args.get("show_on_timeline")
    if show is not None:
        body["show_on_timeline"] = argToBoolean(show)

    result = client.create_case_note(body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseNote",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Created Case Note", result, headers=["id", "case", "note", "author_name"], removeNull=True
        ),
    )


# Indicators


def indicator_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit", "50")) or 50
    offset = arg_to_number(args.get("offset", "0")) or 0
    is_published = argToBoolean(args["is_published"]) if args.get("is_published") else None
    is_revoked = argToBoolean(args["is_revoked"]) if args.get("is_revoked") else None

    result = client.list_indicators(
        limit=limit,
        offset=offset,
        search=args.get("search"),
        stix_type=args.get("stix_type"),
        classification=args.get("classification"),
        confidence=args.get("confidence"),
        tlp=args.get("tlp"),
        is_published=is_published,
        is_revoked=is_revoked,
    )
    indicators = result.get("results", []) if isinstance(result, dict) else result
    headers = [
        "id",
        "value",
        "stix_type",
        "classification",
        "confidence",
        "tlp",
        "is_published",
        "is_revoked",
        "case_count",
        "first_seen",
        "created_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=indicators,
        readable_output=tableToMarkdown("DFIRe Indicators", indicators, headers=headers, removeNull=True),
    )


def indicator_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    result = client.get_indicator(indicator_id)
    headers = [
        "id",
        "value",
        "value_normalized",
        "stix_type",
        "classification",
        "confidence",
        "tlp",
        "tags",
        "public_notes",
        "is_published",
        "is_revoked",
        "parent",
        "case_count",
        "children_count",
        "first_seen",
        "last_seen",
        "created_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("DFIRe Indicator", result, headers=headers, removeNull=True),
    )


def indicator_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body: dict[str, Any] = {
        "value": args["value"],
        "stix_type": args["stix_type"],
    }
    for field in ("classification", "confidence", "tlp", "public_notes", "valid_until"):
        if args.get(field):
            body[field] = args[field]
    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = tags

    result = client.create_indicator(body)
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Created DFIRe Indicator", result, headers=["id", "value", "stix_type", "is_existing"], removeNull=True
        ),
    )


def indicator_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    body = build_optional_body(args, ["classification", "confidence", "tlp", "public_notes", "valid_until"])
    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = tags

    if not body:
        raise DemistoException("At least one field to update must be provided.")

    result = client.update_indicator(indicator_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Updated DFIRe Indicator", result, headers=["id", "value", "classification", "confidence", "tlp"], removeNull=True
        ),
    )


def indicator_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    client.delete_indicator(indicator_id)
    return CommandResults(readable_output=f"Indicator {indicator_id} deleted successfully.")


# Item Types & Flags


def item_type_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    results = client.list_item_types()
    headers = ["id", "name", "icon"]
    return CommandResults(
        outputs_prefix="DFIRe.ItemType",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Item Types", results, headers=headers, removeNull=True),
    )


def item_flag_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    results = client.list_item_flags()
    headers = ["id", "name", "color", "description"]
    return CommandResults(
        outputs_prefix="DFIRe.ItemFlag",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Item Flags", results, headers=headers, removeNull=True),
    )


# Items (Evidence)


def item_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args.get("case_id"))
    results = client.list_items(case_id=case_id)
    headers = ["uuid", "name", "display_title", "item_type_name", "case", "location", "attachment_count", "created_at"]
    return CommandResults(
        outputs_prefix="DFIRe.Item",
        outputs_key_field="uuid",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Evidence Items", results, headers=headers, removeNull=True),
    )


def item_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    item_id = arg_to_number(args["item_id"], required=True)
    assert item_id is not None
    result = client.get_item(item_id)
    headers = [
        "uuid",
        "name",
        "display_title",
        "item_type_name",
        "case",
        "location",
        "owner_details",
        "primary_user_details",
        "attachment_count",
        "created_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Item",
        outputs_key_field="uuid",
        outputs=result,
        readable_output=tableToMarkdown("DFIRe Evidence Item", result, headers=headers, removeNull=True),
    )


def item_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body: dict[str, Any] = {
        "case": arg_to_number(args["case_id"], required=True),
        "item_type": arg_to_number(args["item_type"], required=True),
        "location": args["location"],
    }
    if args.get("name"):
        body["name"] = args["name"]
    for int_field in ("owner_id", "primary_user_id", "collected_by", "parent_item"):
        val = args.get(int_field)
        if val is not None:
            body[int_field] = val if int_field == "parent_item" else arg_to_number(val)

    result = client.create_item(body)
    return CommandResults(
        outputs_prefix="DFIRe.Item",
        outputs_key_field="uuid",
        outputs=result,
        readable_output=tableToMarkdown(
            "Created Evidence Item", result, headers=["uuid", "name", "display_title", "case", "location"], removeNull=True
        ),
    )


# Attachments


def attachment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    item_uuid = args.get("item_uuid")
    results = client.list_attachments(item_uuid=item_uuid)
    headers = [
        "id",
        "filename",
        "mime_type",
        "size",
        "category",
        "case",
        "item",
        "hash_sha256",
        "uploaded_by_name",
        "uploaded_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Attachment",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Attachments", results, headers=headers, removeNull=True),
    )


def attachment_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    attachment_id = arg_to_number(args["attachment_id"], required=True)
    assert attachment_id is not None
    result = client.get_attachment(attachment_id)
    headers = [
        "id",
        "filename",
        "mime_type",
        "size",
        "category",
        "description",
        "case",
        "item",
        "hash_sha256",
        "status",
        "storage_location",
        "uploaded_by_name",
        "uploaded_at",
    ]
    return CommandResults(
        outputs_prefix="DFIRe.Attachment",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("DFIRe Attachment", result, headers=headers, removeNull=True),
    )


def attachment_upload_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entry_id = args["entry_id"]
    file_info = demisto.getFilePath(entry_id)
    file_path = file_info["path"]
    file_name = args.get("filename") or file_info.get("name", "upload")

    case_id = arg_to_number(args.get("case_id"))
    item_uuid = args.get("item_uuid")
    category = args.get("category", "general")

    file_size = os.path.getsize(file_path)

    # Step 1: Init session
    init_resp = client.chunked_upload_init(
        filename=file_name,
        size=file_size,
        case_id=case_id,
        item_uuid=item_uuid,
        category=category,
    )
    session_id = init_resp["session_id"]
    chunk_size = init_resp.get("chunk_size", 5 * 1024 * 1024)  # default 5MB

    # Step 2: Upload chunks
    chunk_index = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            client.chunked_upload_chunk(session_id, chunk_index, chunk)
            chunk_index += 1

    # Step 3: Complete
    result = client.chunked_upload_complete(session_id)

    return CommandResults(
        outputs_prefix="DFIRe.Attachment",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("Uploaded Attachment", result, removeNull=True),
    )


def attachment_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    attachment_id = arg_to_number(args["attachment_id"], required=True)
    assert attachment_id is not None
    client.delete_attachment(attachment_id)
    return CommandResults(readable_output=f"Attachment {attachment_id} deleted successfully.")


# Timeline


def timeline_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    result = client.list_timeline(case_id)
    events = result.get("events", []) if isinstance(result, dict) else result
    headers = ["id", "event_type", "subject", "details", "event_datetime", "created_by_name"]
    return CommandResults(
        outputs_prefix="DFIRe.TimelineEvent",
        outputs_key_field="id",
        outputs=events,
        readable_output=tableToMarkdown("DFIRe Timeline Events", events, headers=headers, removeNull=True),
    )


def timeline_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    body: dict[str, Any] = {
        "subject": args["subject"],
    }
    if args.get("details"):
        body["details"] = args["details"]
    if args.get("event_datetime"):
        body["event_datetime"] = args["event_datetime"]

    result = client.create_timeline_event(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.TimelineEvent",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("Created Timeline Event", result, removeNull=True),
    )


# Users


def user_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    results = client.list_users()
    headers = ["id", "username", "full_name", "email", "is_active", "groups"]
    return CommandResults(
        outputs_prefix="DFIRe.User",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("DFIRe Users", results, headers=headers, removeNull=True),
    )


# Case Indicators


def case_indicator_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    results = client.list_case_indicators(case_id)
    headers = ["id", "indicator.id", "indicator.value", "indicator.stix_type", "context", "source", "case_count", "created_at"]

    # Flatten nested indicator fields for the readable table
    table_data = []
    for r in results:
        row = dict(r)
        ind = row.pop("indicator", {}) or {}
        row["indicator.id"] = ind.get("id")
        row["indicator.value"] = ind.get("value")
        row["indicator.stix_type"] = ind.get("stix_type")
        table_data.append(row)

    return CommandResults(
        outputs_prefix="DFIRe.CaseIndicator",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown("Case Indicators", table_data, headers=headers, removeNull=True),
    )


def case_indicator_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    body: dict[str, Any] = {
        "value": args["value"],
        "stix_type": args["stix_type"],
    }
    for field in ("classification", "confidence", "tlp", "context", "source_reference"):
        if args.get(field):
            body[field] = args[field]
    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = tags
    decompose = args.get("decompose")
    if decompose is not None:
        body["decompose"] = argToBoolean(decompose)

    result = client.add_case_indicator(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseIndicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown("Added Indicator to Case", result, removeNull=True),
    )


def case_indicator_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    association_id = arg_to_number(args["association_id"], required=True)
    assert association_id is not None
    client.remove_case_indicator(case_id, association_id)
    return CommandResults(readable_output=f"Indicator association {association_id} removed from case {case_id}.")


# ── Command dispatch ─────────────────────────────────────

COMMANDS: dict[str, Any] = {
    "dfire-search": search_command,
    "dfire-case-type-list": case_type_list_command,
    "dfire-case-list": case_list_command,
    "dfire-case-get": case_get_command,
    "dfire-case-create": case_create_command,
    "dfire-case-update": case_update_command,
    "dfire-case-delete": case_delete_command,
    "dfire-case-note-list": case_note_list_command,
    "dfire-case-note-create": case_note_create_command,
    "dfire-indicator-list": indicator_list_command,
    "dfire-indicator-get": indicator_get_command,
    "dfire-indicator-create": indicator_create_command,
    "dfire-indicator-update": indicator_update_command,
    "dfire-indicator-delete": indicator_delete_command,
    "dfire-item-type-list": item_type_list_command,
    "dfire-item-flag-list": item_flag_list_command,
    "dfire-item-list": item_list_command,
    "dfire-item-get": item_get_command,
    "dfire-item-create": item_create_command,
    "dfire-attachment-list": attachment_list_command,
    "dfire-attachment-get": attachment_get_command,
    "dfire-attachment-upload": attachment_upload_command,
    "dfire-attachment-delete": attachment_delete_command,
    "dfire-timeline-list": timeline_list_command,
    "dfire-timeline-create": timeline_create_command,
    "dfire-user-list": user_list_command,
    "dfire-case-indicator-list": case_indicator_list_command,
    "dfire-case-indicator-add": case_indicator_add_command,
    "dfire-case-indicator-remove": case_indicator_remove_command,
}


def main():
    params = demisto.params()
    base_url = urljoin(params.get("url", "").rstrip("/"), "/api")
    api_key = params.get("apikey", "")
    if isinstance(api_key, dict):
        api_key = api_key.get("password") or api_key.get("identifier") or ""
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        proxy=proxy,
    )

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command in COMMANDS:
            return_results(COMMANDS[command](client, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

register_module_line("DFIRe", "end", __line__())  # type: ignore[name-defined]  # pylint: disable=E0602
