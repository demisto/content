import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# register_module_line("DFIRe", "start", __line__())
CONSTANT_PACK_VERSION = "1.0.0"
demisto.debug("pack id = DFIRe, pack version = 1.0.0")
"""DFIRe Integration for Cortex XSOAR / XSIAM

Integrates with DFIRe (Digital Forensics and Incident Response) platform
to manage cases and IOC indicators.

API reference: OpenAPI 3.0.3 — DFIRe API v1.2.8
Auth: Bearer API key (Authorization: Bearer dfire_ak_...)
"""

import os
from datetime import datetime, UTC
from typing import Any


class Client(BaseClient):
    """Client class to interact with the DFIRe API."""

    # ── Cases ────────────────────────────────────────────

    def list_cases(
        self,
        page_size: int = 50,
        page: int | None = None,
        status: str | None = None,
        status__in: str | None = None,
        severity: str | None = None,
        case_mode: str | None = None,
        lead_investigator: int | None = None,
        created_at__gte: str | None = None,
        created_at__lte: str | None = None,
        ordering: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page_size": page_size}
        if page is not None:
            params["page"] = page
        if status:
            params["status"] = status
        if status__in:
            params["status__in"] = status__in
        if severity:
            params["severity"] = severity
        if case_mode:
            params["case_mode"] = case_mode
        if lead_investigator is not None:
            params["lead_investigator"] = lead_investigator
        if created_at__gte:
            params["created_at__gte"] = created_at__gte
        if created_at__lte:
            params["created_at__lte"] = created_at__lte
        if ordering:
            params["ordering"] = ordering
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
        parent: int | None = None,
        ordering: str | None = None,
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
        if parent is not None:
            params["parent"] = parent
        if ordering:
            params["ordering"] = ordering
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

    def get_item(self, item_id: str) -> dict[str, Any]:
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

    # ── IOC operations ───────────────────────────────────

    def ioc_extract(self, text: str) -> dict[str, Any]:
        return self._http_request("POST", "/ioc/extract/", json_data={"text": text})

    def indicator_check(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        return self._http_request("POST", "/indicators/check/", json_data={"indicators": indicators})

    def indicator_enrich(self, indicator_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/enrich/", json_data=body)

    def indicator_enrichments(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/indicators/{indicator_id}/enrichments/")

    def indicator_publish(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/publish/", json_data={})

    def indicator_unpublish(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/unpublish/", json_data={})

    def indicator_revoke(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/revoke/", json_data={})

    def indicator_unrevoke(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/unrevoke/", json_data={})

    def indicator_decompose(self, indicator_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/decompose/", json_data={})

    def indicator_add_tags(self, indicator_id: int, tags: list[str]) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{indicator_id}/add-tags/", json_data={"tags": tags})

    def indicator_correlated(self) -> dict[str, Any]:
        return self._http_request("GET", "/indicators/correlated/")

    def indicator_bulk(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/indicators/{path}/", json_data=body)

    # ── Case AI / reports ────────────────────────────────

    def case_generate_summary(self, case_id: int) -> str:
        return self._http_request("GET", f"/cases/{case_id}/generate-summary/", resp_type="text")

    def case_chat(self, case_id: int, message: str) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/chat/", json_data={"message": message})

    def case_update_report(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/update-report/", json_data=body)

    def case_can_report_list(self, case_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/cases/{case_id}/can-reports/")

    def case_can_report_generate(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/can-reports/generate/", json_data=body)

    def case_investigation_report_get(self, case_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/cases/{case_id}/investigation-report/")

    def case_investigation_report_generate(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/investigation-report/generate/", json_data=body)

    def case_investigation_report_finalize(self, case_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/investigation-report/finalize/", json_data={})

    def case_investigation_report_ready_for_qa(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/investigation-report/ready-for-qa/", json_data=body)

    # ── Case timeline / phase ────────────────────────────

    def case_timeline_change_phase(self, case_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/timeline/change-phase/", json_data=body)

    # ── Case todos ───────────────────────────────────────

    def case_todo_assign(self, case_id: int, todo_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/todo/{todo_id}/assign/", json_data=body)

    def case_todo_note(self, case_id: int, todo_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("PUT", f"/cases/{case_id}/todo/{todo_id}/note/", json_data=body)

    def case_todo_attach_runbook(self, case_id: int, todo_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/todo/{todo_id}/attach-runbook/", json_data=body)

    def case_todo_detach_runbook(self, case_id: int, todo_id: str) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_id}/todo/{todo_id}/detach-runbook/", json_data={})

    # ── Case timers ──────────────────────────────────────

    def case_timer_list(self, case_pk: int) -> dict[str, Any]:
        return self._http_request("GET", f"/cases/{case_pk}/timers/")

    def case_timer_get(self, case_pk: int, timer_id: int) -> dict[str, Any]:
        return self._http_request("GET", f"/cases/{case_pk}/timers/{timer_id}/")

    def case_timer_complete(self, case_pk: int, timer_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_pk}/timers/{timer_id}/complete/", json_data={})

    def case_timer_reset(self, case_pk: int, timer_id: int) -> dict[str, Any]:
        return self._http_request("POST", f"/cases/{case_pk}/timers/{timer_id}/reset/", json_data={})

    # ── Convenience lookups ──────────────────────────────

    def case_get_by_number(self, case_number: str) -> dict[str, Any]:
        return self._http_request("GET", f"/case/{case_number}/")

    def item_resolve_short_id(self, short_id: str) -> dict[str, Any]:
        return self._http_request("GET", f"/item/{short_id}/")

    # ── Reference data ───────────────────────────────────

    def list_incident_categories(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/incident-categories/")

    def list_incident_phases(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/incident-phases/")

    def list_outcome_verdicts(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/outcome-verdicts/")

    def list_projects(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/projects/")

    def list_runbooks(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/runbooks/")

    def list_groups(self) -> list[dict[str, Any]]:
        return self._http_request("GET", "/groups/")


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
    status__in_list = argToList(args.get("status_in"))
    status__in = ",".join(status__in_list) if status__in_list else None
    result = client.list_cases(
        page_size=page_size,
        page=page,
        status=args.get("status"),
        status__in=status__in,
        severity=args.get("severity"),
        case_mode=args.get("case_mode"),
        lead_investigator=arg_to_number(args.get("lead_investigator")),
        created_at__gte=args.get("created_at_gte"),
        created_at__lte=args.get("created_at_lte"),
        ordering=args.get("ordering"),
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
        # Default to false so SOAR-created cases don't auto-create Slack channels;
        # users can opt in explicitly via the create_slack_channel arg.
        "create_slack_channel": argToBoolean(args.get("create_slack_channel", "false")),
    }
    for field in ("description", "notes", "severity", "case_mode", "external_id"):
        if args.get(field):
            body[field] = args[field]
    for int_field in ("lead_investigator", "project_id", "incident_category", "outcome_verdict"):
        val = arg_to_number(args.get(int_field))
        if val is not None:
            body[int_field] = val
    for list_field in ("investigators", "viewers", "investigator_ids", "viewer_ids"):
        ids = [arg_to_number(x) for x in argToList(args.get(list_field))]
        ids = [x for x in ids if x is not None]
        if ids:
            body[list_field] = ids
    if args.get("attributes"):
        body["attributes"] = safe_load_json(args["attributes"])

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
    body = build_optional_body(args, ["title", "description", "notes", "status", "severity", "case_mode", "external_id"])
    for int_field in ("lead_investigator", "incident_category", "outcome_verdict"):
        val = arg_to_number(args.get(int_field))
        if val is not None:
            body[int_field] = val
    for list_field in ("investigators", "viewers", "investigator_ids", "viewer_ids"):
        ids = [arg_to_number(x) for x in argToList(args.get(list_field))]
        ids = [x for x in ids if x is not None]
        if ids:
            body[list_field] = ids
    if args.get("attributes"):
        body["attributes"] = safe_load_json(args["attributes"])

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
        parent=arg_to_number(args.get("parent")),
        ordering=args.get("ordering"),
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
    item_id = args.get("item_id")
    if not item_id:
        raise DemistoException("`item_id` is required.")
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
    # The DFIRe API requires event_datetime; default to "now" if not supplied so
    # playbook authors don't have to compute a timestamp for the common case.
    event_datetime = args.get("event_datetime") or datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body: dict[str, Any] = {
        "subject": args["subject"],
        "event_datetime": event_datetime,
    }
    if args.get("details"):
        body["details"] = args["details"]

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
    for field in ("classification", "confidence", "tlp", "context", "source", "source_reference", "valid_until"):
        if args.get(field):
            body[field] = args[field]
    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = tags
    for bool_field in ("decompose", "publish"):
        val = args.get(bool_field)
        if val is not None:
            body[bool_field] = argToBoolean(val)

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


# IOC operations


def ioc_extract_command(client: Client, args: dict[str, Any]) -> CommandResults:
    text = args["text"]
    result = client.ioc_extract(text)
    candidates = result.get("candidates", []) if isinstance(result, dict) else result
    headers = ["value", "stix_type", "context"]
    return CommandResults(
        outputs_prefix="DFIRe.IOCExtraction",
        outputs=result,
        readable_output=tableToMarkdown("Extracted IOC Candidates", candidates, headers=headers, removeNull=True),
    )


def indicator_check_command(client: Client, args: dict[str, Any]) -> CommandResults:
    raw_indicators = args.get("indicators")
    if raw_indicators:
        indicators = safe_load_json(raw_indicators)
        if not isinstance(indicators, list):
            raise DemistoException("`indicators` must be a JSON array of {value, stix_type} objects.")
    else:
        values = argToList(args.get("values"))
        stix_type = args.get("stix_type")
        if not values or not stix_type:
            raise DemistoException("Provide either `indicators` (JSON list) or both `values` and `stix_type`.")
        indicators = [{"value": v, "stix_type": stix_type} for v in values]

    result = client.indicator_check(indicators)
    rows = result.get("results", []) if isinstance(result, dict) else result
    return CommandResults(
        outputs_prefix="DFIRe.IndicatorCheck",
        outputs=result,
        readable_output=tableToMarkdown("Indicator Check Results", rows, removeNull=True),
    )


def indicator_enrich_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    body: dict[str, Any] = {}
    providers = argToList(args.get("providers"))
    if providers:
        body["providers"] = providers
    force = args.get("force")
    if force is not None:
        body["force"] = argToBoolean(force)

    result = client.indicator_enrich(indicator_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Enriched Indicator {indicator_id}", result, removeNull=True),
    )


def indicator_enrichment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    result = client.indicator_enrichments(indicator_id)
    rows = result.get("enrichments", []) if isinstance(result, dict) else result
    return CommandResults(
        outputs_prefix="DFIRe.Enrichment",
        outputs=result,
        readable_output=tableToMarkdown(f"Enrichments for Indicator {indicator_id}", rows, removeNull=True),
    )


def _indicator_lifecycle(client_fn, args: dict[str, Any], action_label: str) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    result = client_fn(indicator_id)
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"{action_label} Indicator {indicator_id}", result, removeNull=True),
    )


def indicator_publish_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _indicator_lifecycle(client.indicator_publish, args, "Published")


def indicator_unpublish_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _indicator_lifecycle(client.indicator_unpublish, args, "Unpublished")


def indicator_revoke_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _indicator_lifecycle(client.indicator_revoke, args, "Revoked")


def indicator_unrevoke_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _indicator_lifecycle(client.indicator_unrevoke, args, "Unrevoked")


def indicator_decompose_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _indicator_lifecycle(client.indicator_decompose, args, "Decomposed")


def indicator_add_tags_command(client: Client, args: dict[str, Any]) -> CommandResults:
    indicator_id = arg_to_number(args["indicator_id"], required=True)
    assert indicator_id is not None
    tags = argToList(args["tags"])
    if not tags:
        raise DemistoException("`tags` argument is required.")
    result = client.indicator_add_tags(indicator_id, tags)
    return CommandResults(
        outputs_prefix="DFIRe.Indicator",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Tagged Indicator {indicator_id}", result, removeNull=True),
    )


def indicator_correlated_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    result = client.indicator_correlated()
    rows = result.get("results", []) if isinstance(result, dict) else result
    return CommandResults(
        outputs_prefix="DFIRe.IndicatorCorrelated",
        outputs=result,
        readable_output=tableToMarkdown("Correlated Indicators", rows, removeNull=True),
    )


def _build_bulk_body(args: dict[str, Any], extra_fields: dict[str, Any]) -> dict[str, Any]:
    ids = [arg_to_number(x) for x in argToList(args.get("indicator_ids"))]
    ids = [x for x in ids if x is not None]
    if not ids:
        raise DemistoException("`indicator_ids` argument is required.")
    body: dict[str, Any] = {"indicator_ids": ids}
    body.update({k: v for k, v in extra_fields.items() if v is not None})
    return body


def indicator_bulk_classify_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {"classification": args.get("classification")})
    if "classification" not in body:
        raise DemistoException("`classification` argument is required.")
    result = client.indicator_bulk("bulk-classify", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Classify Result", result, removeNull=True),
    )


def indicator_bulk_confidence_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {"confidence": args.get("confidence")})
    if "confidence" not in body:
        raise DemistoException("`confidence` argument is required.")
    result = client.indicator_bulk("bulk-confidence", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Confidence Result", result, removeNull=True),
    )


def indicator_bulk_tag_command(client: Client, args: dict[str, Any]) -> CommandResults:
    tags = argToList(args.get("tags"))
    if not tags:
        raise DemistoException("`tags` argument is required.")
    body = _build_bulk_body(args, {"tags": tags, "mode": args.get("mode")})
    result = client.indicator_bulk("bulk-tag", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Tag Result", result, removeNull=True),
    )


def indicator_bulk_tlp_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {"tlp": args.get("tlp")})
    if "tlp" not in body:
        raise DemistoException("`tlp` argument is required.")
    result = client.indicator_bulk("bulk-tlp", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk TLP Result", result, removeNull=True),
    )


def indicator_bulk_publish_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {})
    result = client.indicator_bulk("bulk-publish", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkPublishResponse",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Publish Result", result, removeNull=True),
    )


def indicator_bulk_revoke_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {})
    result = client.indicator_bulk("bulk-revoke", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Revoke Result", result, removeNull=True),
    )


def indicator_bulk_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = _build_bulk_body(args, {})
    result = client.indicator_bulk("bulk-delete", body)
    return CommandResults(
        outputs_prefix="DFIRe.BulkResult",
        outputs=result,
        readable_output=tableToMarkdown("Bulk Delete Result", result, removeNull=True),
    )


# Case AI / reports


def case_generate_summary_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    summary_text = client.case_generate_summary(case_id)
    output = {"case_id": case_id, "summary": summary_text}
    return CommandResults(
        outputs_prefix="DFIRe.CaseSummary",
        outputs_key_field="case_id",
        outputs=output,
        readable_output=f"### Case {case_id} Summary\n\n```\n{summary_text}\n```",
    )


def case_chat_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    message = args["message"]
    result = client.case_chat(case_id, message)
    return CommandResults(
        outputs_prefix="DFIRe.CaseChat",
        outputs=result,
        readable_output=tableToMarkdown(f"Case {case_id} Chat Response", result, removeNull=True),
    )


def case_update_report_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    report_id = arg_to_number(args["report_id"], required=True)
    assert case_id is not None
    assert report_id is not None
    body = {"id": report_id, "report_text": args["report_text"]}
    result = client.case_update_report(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseReport",
        outputs=result,
        readable_output=tableToMarkdown(f"Case {case_id} Report {report_id} Update", result, removeNull=True),
    )


def case_can_report_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    result = client.case_can_report_list(case_id)
    rows = result.get("results", []) if isinstance(result, dict) else result
    return CommandResults(
        outputs_prefix="DFIRe.CANReport",
        outputs_key_field="id",
        outputs=rows if isinstance(rows, list) else result,
        readable_output=tableToMarkdown(f"CAN Reports for Case {case_id}", rows, removeNull=True),
    )


def case_can_report_generate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    body = safe_load_json(args["body"]) if args.get("body") else {}
    result = client.case_can_report_generate(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CANReport",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Generated CAN Report for Case {case_id}", result, removeNull=True),
    )


def case_investigation_report_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    result = client.case_investigation_report_get(case_id)
    return CommandResults(
        outputs_prefix="DFIRe.InvestigationReport",
        outputs=result,
        readable_output=tableToMarkdown(f"Investigation Report for Case {case_id}", result, removeNull=True),
    )


def case_investigation_report_generate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    section_id = arg_to_number(args["section_id"], required=True)
    assert case_id is not None
    assert section_id is not None
    body: dict[str, Any] = {"section_id": section_id}
    result = client.case_investigation_report_generate(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.InvestigationReport",
        outputs=result,
        readable_output=tableToMarkdown(
            f"Generated content for section {section_id} of Case {case_id} report", result, removeNull=True
        ),
    )


def case_investigation_report_finalize_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    result = client.case_investigation_report_finalize(case_id)
    return CommandResults(
        outputs_prefix="DFIRe.InvestigationReport",
        outputs=result,
        readable_output=tableToMarkdown(f"Finalized Investigation Report for Case {case_id}", result, removeNull=True),
    )


def case_investigation_report_ready_for_qa_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    section_id = arg_to_number(args["section_id"], required=True)
    assert case_id is not None
    assert section_id is not None
    result = client.case_investigation_report_ready_for_qa(case_id, {"section_id": section_id})
    return CommandResults(
        outputs_prefix="DFIRe.InvestigationReport",
        outputs=result,
        readable_output=tableToMarkdown(
            f"Section {section_id} of Case {case_id} report marked ready for QA", result, removeNull=True
        ),
    )


# Timeline phase


def case_timeline_change_phase_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    body: dict[str, Any] = {}
    phase = arg_to_number(args.get("phase_id"))
    if phase is not None:
        body["phase_id"] = phase
    if args.get("phase_name"):
        body["phase_name"] = args["phase_name"]
    if args.get("note"):
        body["note"] = args["note"]
    result = client.case_timeline_change_phase(case_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.TimelineEvent",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Phase change on Case {case_id}", result, removeNull=True),
    )


# Case todos


def _extract_case_todos(client: Client, case_id: int) -> list[dict[str, Any]]:
    """Fetch a case and return its `todo_checklist`. The DFIRe API does not expose a
    separate GET endpoint for todos; they live on the Case resource itself."""
    case = client.get_case(case_id)
    todos = case.get("todo_checklist") if isinstance(case, dict) else None
    if isinstance(todos, list):
        return todos
    if isinstance(todos, dict):
        # Some serializers nest the list inside a results/items key.
        for key in ("results", "items", "todos"):
            inner = todos.get(key)
            if isinstance(inner, list):
                return inner
    return []


def case_todo_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todos = _extract_case_todos(client, case_id)
    headers = ["id", "title", "status", "assignee_name", "runbook_slug", "created_at"]
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=todos,
        readable_output=tableToMarkdown(f"Todos for Case {case_id}", todos, headers=headers, removeNull=True),
    )


def case_todo_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todo_id = str(args["todo_id"])
    todos = _extract_case_todos(client, case_id)
    matches = [t for t in todos if str(t.get("id")) == todo_id]
    if not matches:
        raise DemistoException(f"No todo with id {todo_id} found on case {case_id}.")
    result = matches[0]
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Todo {todo_id} (Case {case_id})", result, removeNull=True),
    )


def case_todo_assign_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todo_id = str(args["todo_id"])
    body: dict[str, Any] = {}
    assignee = arg_to_number(args.get("assignee_id"))
    if assignee is not None:
        body["assignee_id"] = assignee
    result = client.case_todo_assign(case_id, todo_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Assigned todo {todo_id} on Case {case_id}", result, removeNull=True),
    )


def case_todo_note_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todo_id = str(args["todo_id"])
    body = {"note": args["note"]}
    result = client.case_todo_note(case_id, todo_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Updated note on todo {todo_id} (Case {case_id})", result, removeNull=True),
    )


def case_todo_attach_runbook_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todo_id = str(args["todo_id"])
    body = {"runbook_slug": args["runbook_slug"]}
    result = client.case_todo_attach_runbook(case_id, todo_id, body)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Attached runbook to todo {todo_id} (Case {case_id})", result, removeNull=True),
    )


def case_todo_detach_runbook_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = arg_to_number(args["case_id"], required=True)
    assert case_id is not None
    todo_id = str(args["todo_id"])
    result = client.case_todo_detach_runbook(case_id, todo_id)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTodo",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Detached runbook from todo {todo_id} (Case {case_id})", result, removeNull=True),
    )


# Case timers


def case_timer_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_pk = arg_to_number(args["case_id"], required=True)
    assert case_pk is not None
    result = client.case_timer_list(case_pk)
    rows = result.get("results", []) if isinstance(result, dict) else result
    headers = ["id", "name", "framework", "duration_hours", "start_time", "end_time"]
    return CommandResults(
        outputs_prefix="DFIRe.CaseTimer",
        outputs_key_field="id",
        outputs=rows if isinstance(rows, list) else result,
        readable_output=tableToMarkdown(f"Timers for Case {case_pk}", rows, headers=headers, removeNull=True),
    )


def case_timer_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_pk = arg_to_number(args["case_id"], required=True)
    timer_id = arg_to_number(args["timer_id"], required=True)
    assert case_pk is not None
    assert timer_id is not None
    result = client.case_timer_get(case_pk, timer_id)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTimer",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Timer {timer_id} (Case {case_pk})", result, removeNull=True),
    )


def case_timer_complete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_pk = arg_to_number(args["case_id"], required=True)
    timer_id = arg_to_number(args["timer_id"], required=True)
    assert case_pk is not None
    assert timer_id is not None
    result = client.case_timer_complete(case_pk, timer_id)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTimer",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Completed timer {timer_id} on Case {case_pk}", result, removeNull=True),
    )


def case_timer_reset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_pk = arg_to_number(args["case_id"], required=True)
    timer_id = arg_to_number(args["timer_id"], required=True)
    assert case_pk is not None
    assert timer_id is not None
    result = client.case_timer_reset(case_pk, timer_id)
    return CommandResults(
        outputs_prefix="DFIRe.CaseTimer",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"Reset timer {timer_id} on Case {case_pk}", result, removeNull=True),
    )


# Convenience lookups


def case_get_by_number_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_number = args["case_number"]
    result = client.case_get_by_number(case_number)
    return CommandResults(
        outputs_prefix="DFIRe.Case",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(f"DFIRe Case {case_number}", result, removeNull=True),
    )


def item_resolve_short_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    short_id = args["short_id"]
    result = client.item_resolve_short_id(short_id)
    return CommandResults(
        outputs_prefix="DFIRe.Item",
        outputs_key_field="uuid",
        outputs=result,
        readable_output=tableToMarkdown(f"DFIRe Item Short-ID {short_id}", result, removeNull=True),
    )


# Reference data


def _list_reference(client_fn, prefix: str, label: str) -> CommandResults:
    result = client_fn()
    rows = result.get("results", []) if isinstance(result, dict) else result
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field="id",
        outputs=rows if isinstance(rows, list) else result,
        readable_output=tableToMarkdown(label, rows, removeNull=True),
    )


def incident_category_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_incident_categories, "DFIRe.IncidentCategory", "DFIRe Incident Categories")


def incident_phase_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_incident_phases, "DFIRe.IncidentPhase", "DFIRe Incident Phases")


def outcome_verdict_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_outcome_verdicts, "DFIRe.OutcomeVerdict", "DFIRe Outcome Verdicts")


def project_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_projects, "DFIRe.Project", "DFIRe Projects")


def runbook_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_runbooks, "DFIRe.Runbook", "DFIRe Runbooks")


def group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_reference(client.list_groups, "DFIRe.Group", "DFIRe Groups")


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
    # IOC operations
    "dfire-ioc-extract": ioc_extract_command,
    "dfire-indicator-check": indicator_check_command,
    "dfire-indicator-enrich": indicator_enrich_command,
    "dfire-indicator-enrichment-list": indicator_enrichment_list_command,
    "dfire-indicator-publish": indicator_publish_command,
    "dfire-indicator-unpublish": indicator_unpublish_command,
    "dfire-indicator-revoke": indicator_revoke_command,
    "dfire-indicator-unrevoke": indicator_unrevoke_command,
    "dfire-indicator-decompose": indicator_decompose_command,
    "dfire-indicator-add-tags": indicator_add_tags_command,
    "dfire-indicator-correlated-list": indicator_correlated_list_command,
    "dfire-indicator-bulk-classify": indicator_bulk_classify_command,
    "dfire-indicator-bulk-confidence": indicator_bulk_confidence_command,
    "dfire-indicator-bulk-tag": indicator_bulk_tag_command,
    "dfire-indicator-bulk-tlp": indicator_bulk_tlp_command,
    "dfire-indicator-bulk-publish": indicator_bulk_publish_command,
    "dfire-indicator-bulk-revoke": indicator_bulk_revoke_command,
    "dfire-indicator-bulk-delete": indicator_bulk_delete_command,
    # Case AI / reports
    "dfire-case-generate-summary": case_generate_summary_command,
    "dfire-case-chat": case_chat_command,
    "dfire-case-update-report": case_update_report_command,
    "dfire-case-can-report-list": case_can_report_list_command,
    "dfire-case-can-report-generate": case_can_report_generate_command,
    "dfire-case-investigation-report-get": case_investigation_report_get_command,
    "dfire-case-investigation-report-generate": case_investigation_report_generate_command,
    "dfire-case-investigation-report-finalize": case_investigation_report_finalize_command,
    "dfire-case-investigation-report-ready-for-qa": case_investigation_report_ready_for_qa_command,
    # Timeline phase
    "dfire-case-timeline-change-phase": case_timeline_change_phase_command,
    # Todos
    "dfire-case-todo-list": case_todo_list_command,
    "dfire-case-todo-get": case_todo_get_command,
    "dfire-case-todo-assign": case_todo_assign_command,
    "dfire-case-todo-note-set": case_todo_note_set_command,
    "dfire-case-todo-attach-runbook": case_todo_attach_runbook_command,
    "dfire-case-todo-detach-runbook": case_todo_detach_runbook_command,
    # Timers
    "dfire-case-timer-list": case_timer_list_command,
    "dfire-case-timer-get": case_timer_get_command,
    "dfire-case-timer-complete": case_timer_complete_command,
    "dfire-case-timer-reset": case_timer_reset_command,
    # Convenience lookups
    "dfire-case-get-by-number": case_get_by_number_command,
    "dfire-item-resolve-short-id": item_resolve_short_id_command,
    # Reference data
    "dfire-incident-category-list": incident_category_list_command,
    "dfire-incident-phase-list": incident_phase_list_command,
    "dfire-outcome-verdict-list": outcome_verdict_list_command,
    "dfire-project-list": project_list_command,
    "dfire-runbook-list": runbook_list_command,
    "dfire-group-list": group_list_command,
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

# register_module_line("DFIRe", "end", __line__())
