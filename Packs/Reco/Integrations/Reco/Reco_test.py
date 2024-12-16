import json
import uuid

from typing import Any

import base64

import pytest
import datetime

from Reco import (
    RecoClient,
    fetch_incidents,
    map_reco_score_to_demisto_score,
    get_max_fetch,
    get_risky_users_from_reco,
    add_risky_user_label,
    get_assets_user_has_access,
    get_sensitive_assets_by_name,
    get_sensitive_assets_by_id, get_link_to_user_overview_page, get_sensitive_assets_shared_with_public_link,
    get_3rd_parties_list, get_files_shared_with_3rd_parties, map_reco_alert_score_to_demisto_score,
    get_user_context_by_email_address, get_assets_shared_externally_command, get_files_exposed_to_email_command,
    get_private_email_list_with_access
)

from test_data.structs import (
    TableData,
    RowData,
    KeyValuePair,
    RiskLevel,
    GetTableResponse,
    GetIncidentTableResponse,
)

DUMMY_RECO_API_DNS_NAME = "https://dummy.reco.ai/api"
INCIDET_ID_UUID = "87799f2f-c012-43b6-ace2-78ec984427f3"
ALERT_ID = "ee593dc2-a50e-415e-bed0-8403c18b26ca"
INCIDENT_DESCRIPTION = "Sensitive files are accessible to anyone who has their link"
ENCODING = "utf-8"
INCIDENT_STATUS = "INCIDENT_STATE_UNMARKED"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def get_random_table_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="incident_id",
                                value=base64.b64encode(
                                    INCIDET_ID_UUID.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="incident_description",
                                value=base64.b64encode(
                                    INCIDENT_DESCRIPTION.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="risk_level",
                                value=base64.b64encode(
                                    str(RiskLevel.HIGH.value).encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="event_time",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="updated_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="status",
                                value=base64.b64encode(
                                    INCIDENT_STATUS.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_alerts_and_table_response() -> tuple[GetIncidentTableResponse, dict[str, Any]]:
    alert = {
        "alert": {
            "id": INCIDET_ID_UUID,
            "policyId": "7f174580-81b6-4349-a4ca-ca8873b48b78",
            "workspaceId": "f4be4202-4a6e-4bf7-b058-5d33a3146df7",
            "description": "1 sensitive file exposed publicly by t@acme.ai (part of ACME IL)",
            "aggregationRulesToKeys": {
                "aggregationRuleToKey": [
                    {
                        "aggregationRule": {
                            "aggregationKeyJsonataQuery": "enriched.actor.email_account"
                        },
                        "aggregationKey": {"stringKey": '"t@acme.ai"'},
                    },
                    {
                        "aggregationRule": {"aggregationDuration": "3600s"},
                        "aggregationKey": {"timeKey": "2023-05-03T10:21:04.078627293Z"},
                    },
                ]
            },
            "status": "ALERT_STATUS_NEW",
            "riskLevel": "HIGH",
            "policyViolations": [
                {
                    "id": "75123c18-5ea2-4511-b9c0-1aad67e8b2ff",
                    "policyId": "7f174580-81b6-4349-a4ca-ca8873b48b78",
                    "workspaceId": "f4be4202-4a6e-4bf7-b058-5d33a3146df7",
                    "jsonData": "eyJpZCI6ICI5MWJlZjFkZS01NjZkLTRkYWYtODhkYi0xYTQ0MDQ0Y2E1NzciLCAicGF5bG9hZCI6IHsiaWQiOiB7InRpbWUiOiAiMjAyMy0wNS0wM1QxMDoyMDo1NS43NTRaIiwgImN1c3RvbWVySWQiOiAiQzAybWNrc2htIiwgImFwcGxpY2F0aW9uTmFtZSI6ICJkcml2ZSIsICJ1bmlxdWVRdWFsaWZpZXIiOiAiMjYxOTkxMDk0ODY4MDM1NjI2MCJ9LCAiZXRhZyI6ICJcImNKTW01QmJCWWRxMl80bGVma2pkZ3p3dHpwZy9YNVNnaE9KTUNBNWo0UTJDRU1WdDl4SmFXWjhcIiIsICJraW5kIjogImFkbWluI3JlcG9ydHMjYWN0aXZpdHkiLCAiYWN0b3IiOiB7ImVtYWlsIjogImdhbEByZWNvLmFpIiwgInByb2ZpbGVJZCI6ICIxMDAwMzQzODk1NzA1MDM5MjM1NTYifSwgImV2ZW50cyI6IFt7Im5hbWUiOiAiZWRpdCIsICJ0eXBlIjogImFjY2VzcyIsICJwYXJhbWV0ZXJzIjogW3sibmFtZSI6ICJwcmltYXJ5X2V2ZW50IiwgImJvb2xWYWx1ZSI6IGZhbHNlfSwgeyJuYW1lIjogImJpbGxhYmxlIiwgImJvb2xWYWx1ZSI6IHRydWV9LCB7Im5hbWUiOiAib3duZXJfaXNfdGVhbV9kcml2ZSIsICJib29sVmFsdWUiOiBmYWxzZX0sIHsibmFtZSI6ICJvd25lciIsICJ2YWx1ZSI6ICJnYWxAcmVjby5haSJ9LCB7Im5hbWUiOiAiZG9jX2lkIiwgInZhbHVlIjogIjEtR0ZBOTZaRXN6SGh0OVJJLUdJMTB6aTRBQVFEYjJxMjRlRmIyMTVEYk5BIn0sIHsibmFtZSI6ICJkb2NfdHlwZSIsICJ2YWx1ZSI6ICJkb2N1bWVudCJ9LCB7Im5hbWUiOiAiaXNfZW5jcnlwdGVkIiwgImJvb2xWYWx1ZSI6IGZhbHNlfSwgeyJuYW1lIjogImRvY190aXRsZSIsICJ2YWx1ZSI6ICJDb3B5IG9mIHNlbnNpdGl2ZSBmaWxlIn0sIHsibmFtZSI6ICJkbHBfaW5mbyIsICJ2YWx1ZSI6ICIifSwgeyJuYW1lIjogInZpc2liaWxpdHkiLCAidmFsdWUiOiAicGVvcGxlX3dpdGhfbGluayJ9LCB7Im5hbWUiOiAib3JpZ2luYXRpbmdfYXBwX2lkIiwgInZhbHVlIjogIjIxMTYwNDM1NTYwNyJ9LCB7Im5hbWUiOiAiYWN0b3JfaXNfY29sbGFib3JhdG9yX2FjY291bnQiLCAiYm9vbFZhbHVlIjogZmFsc2V9XX0sIHsibmFtZSI6ICJjaGFuZ2VfZG9jdW1lbnRfdmlzaWJpbGl0eSIsICJ0eXBlIjogImFjbF9jaGFuZ2UiLCAicGFyYW1ldGVycyI6IFt7Im5hbWUiOiAicHJpbWFyeV9ldmVudCIsICJib29sVmFsdWUiOiB0cnVlfSwgeyJuYW1lIjogImJpbGxhYmxlIiwgImJvb2xWYWx1ZSI6IHRydWV9LCB7Im5hbWUiOiAidmlzaWJpbGl0eV9jaGFuZ2UiLCAidmFsdWUiOiAiZXh0ZXJuYWwifSwgeyJuYW1lIjogInRhcmdldF9kb21haW4iLCAidmFsdWUiOiAiYWxsIn0sIHsibmFtZSI6ICJvbGRfdmFsdWUiLCAibXVsdGlWYWx1ZSI6IFsicHJpdmF0ZSJdfSwgeyJuYW1lIjogIm5ld192YWx1ZSIsICJtdWx0aVZhbHVlIjogWyJwZW9wbGVfd2l0aF9saW5rIl19LCB7Im5hbWUiOiAib2xkX3Zpc2liaWxpdHkiLCAidmFsdWUiOiAicHJpdmF0ZSJ9LCB7Im5hbWUiOiAib3duZXJfaXNfdGVhbV9kcml2ZSIsICJib29sVmFsdWUiOiBmYWxzZX0sIHsibmFtZSI6ICJvd25lciIsICJ2YWx1ZSI6ICJnYWxAcmVjby5haSJ9LCB7Im5hbWUiOiAiZG9jX2lkIiwgInZhbHVlIjogIjEtR0ZBOTZaRXN6SGh0OVJJLUdJMTB6aTRBQVFEYjJxMjRlRmIyMTVEYk5BIn0sIHsibmFtZSI6ICJkb2NfdHlwZSIsICJ2YWx1ZSI6ICJkb2N1bWVudCJ9LCB7Im5hbWUiOiAiaXNfZW5jcnlwdGVkIiwgImJvb2xWYWx1ZSI6IGZhbHNlfSwgeyJuYW1lIjogImRvY190aXRsZSIsICJ2YWx1ZSI6ICJDb3B5IG9mIHNlbnNpdGl2ZSBmaWxlIn0sIHsibmFtZSI6ICJkbHBfaW5mbyIsICJ2YWx1ZSI6ICIifSwgeyJuYW1lIjogInZpc2liaWxpdHkiLCAidmFsdWUiOiAicGVvcGxlX3dpdGhfbGluayJ9LCB7Im5hbWUiOiAib3JpZ2luYXRpbmdfYXBwX2lkIiwgInZhbHVlIjogIjIxMTYwNDM1NTYwNyJ9LCB7Im5hbWUiOiAiYWN0b3JfaXNfY29sbGFib3JhdG9yX2FjY291bnQiLCAiYm9vbFZhbHVlIjogZmFsc2V9XX0sIHsibmFtZSI6ICJjaGFuZ2VfZG9jdW1lbnRfYWNjZXNzX3Njb3BlIiwgInR5cGUiOiAiYWNsX2NoYW5nZSIsICJwYXJhbWV0ZXJzIjogW3sibmFtZSI6ICJwcmltYXJ5X2V2ZW50IiwgImJvb2xWYWx1ZSI6IHRydWV9LCB7Im5hbWUiOiAiYmlsbGFibGUiLCAiYm9vbFZhbHVlIjogdHJ1ZX0sIHsibmFtZSI6ICJ2aXNpYmlsaXR5X2NoYW5nZSIsICJ2YWx1ZSI6ICJleHRlcm5hbCJ9LCB7Im5hbWUiOiAidGFyZ2V0X2RvbWFpbiIsICJ2YWx1ZSI6ICJhbGwifSwgeyJuYW1lIjogIm9sZF92YWx1ZSIsICJtdWx0aVZhbHVlIjogWyJub25lIl19LCB7Im5hbWUiOiAibmV3X3ZhbHVlIiwgIm11bHRpVmFsdWUiOiBbImNhbl92aWV3Il19LCB7Im5hbWUiOiAib2xkX3Zpc2liaWxpdHkiLCAidmFsdWUiOiAicHJpdmF0ZSJ9LCB7Im5hbWUiOiAib3duZXJfaXNfdGVhbV9kcml2ZSIsICJib29sVmFsdWUiOiBmYWxzZX0sIHsibmFtZSI6ICJvd25lciIsICJ2YWx1ZSI6ICJnYWxAcmVjby5haSJ9LCB7Im5hbWUiOiAiZG9jX2lkIiwgInZhbHVlIjogIjEtR0ZBOTZaRXN6SGh0OVJJLUdJMTB6aTRBQVFEYjJxMjRlRmIyMTVEYk5BIn0sIHsibmFtZSI6ICJkb2NfdHlwZSIsICJ2YWx1ZSI6ICJkb2N1bWVudCJ9LCB7Im5hbWUiOiAiaXNfZW5jcnlwdGVkIiwgImJvb2xWYWx1ZSI6IGZhbHNlfSwgeyJuYW1lIjogImRvY190aXRsZSIsICJ2YWx1ZSI6ICJDb3B5IG9mIHNlbnNpdGl2ZSBmaWxlIn0sIHsibmFtZSI6ICJkbHBfaW5mbyIsICJ2YWx1ZSI6ICIifSwgeyJuYW1lIjogInZpc2liaWxpdHkiLCAidmFsdWUiOiAicGVvcGxlX3dpdGhfbGluayJ9LCB7Im5hbWUiOiAib3JpZ2luYXRpbmdfYXBwX2lkIiwgInZhbHVlIjogIjIxMTYwNDM1NTYwNyJ9LCB7Im5hbWUiOiAiYWN0b3JfaXNfY29sbGFib3JhdG9yX2FjY291bnQiLCAiYm9vbFZhbHVlIjogZmFsc2V9XX1dLCAiaXBBZGRyZXNzIjogIjIxMi4xOTkuNDcuMTg2In0sICJlbnJpY2hlZCI6IHsiYWN0b3IiOiB7ImRvbWFpbiI6ICJAcmVjby5haSIsICJsYWJlbHMiOiBbeyJsYWJlbCI6IHsibmFtZSI6ICJMZWF2aW5nIE9yZyBVc2VyIiwgInR5cGUiOiAiTEFCRUxfVFlQRV9JTkZPUk1BVElWRSIsICJ0b29sdGlwIjogImxlYXZpbmcgZW1wbG95ZWUiLCAiY3JlYXRlZF9ieSI6IDEwLCAicmlza19sZXZlbCI6IDAsICJkZXNjcmlwdGlvbiI6ICJMZWF2aW5nIGVtcGxveWVlIn19XSwgImNhdGVnb3J5IjogImludGVybmFsX3ByaW1hcnlfZW1haWwiLCAiZnVsbF9uYW1lIjogIkdhbCBOYWthc2giLCAidXNlcl9qc29uIjogW3sidXNlciI6IHsibmFtZSI6ICJHYWwgTmFrYXNoIiwgImVtYWlsIjogImdhbEByZWNvLmFpIiwgInByb2ZpbGVfcGhvdG8iOiAiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUdObXl4YW1RT2FwZkpVaW9lVXVhcFg0elRDWXl2amJEQkNzNmUta1d3TTI9czEwMCJ9fV0sICJkZXBhcnRtZW50IjogIiIsICJlbWFpbF9hY2NvdW50IjogImdhbEByZWNvLmFpIiwgIm9yZGVyZWRfZ3JvdXBzIjogWyJSZWNvIElMIiwgIlJlY28gQWxsIiwgIkdyb3VwIFJORCIsICJyZWNvLWFsbCIsICJHcm91cCBHVE0iLCAiVGVhbSBEZXZPcHMiLCAiRm91bmRlcnMiLCAiRXZlcnlvbmUiXSwgInBfNTBfZG93bmxvYWRzIjogMCwgInBfOTBfZG93bmxvYWRzIjogMi40MDAwMDAwMDAwMDAwMDI2LCAiYXZlcmFnZV9kb3dubG9hZHMiOiAwLjk2NjY2NjY2NjY2NjY2Njd9LCAiYXNzZXQiOiB7ImxhYmVscyI6IFt7ImxhYmVsIjogeyJuYW1lIjogIkNvbmZpZGVudGlhbCBHZW5lcmFsIiwgInR5cGUiOiAiTEFCRUxfVFlQRV9CVVNJTkVTU19JTVBBQ1QiLCAidG9vbHRpcCI6ICJEYXRhIGFzc2V0cyByZWdhcmRsZXNzIG9mIHRoZWlyIHR5cGUsIGRlZmluZWQgYXMgc2Vuc2l0aXZlIGJlY2F1c2UgdGhhdCB0ZXJtcyBzdWNoIGFzIFwiY29uZmlkZW50aWFsXCIsIFwicHJpdmF0ZVwiLCBcInNlbnNpdGl2ZVwiIHdlcmUgZGV0ZWN0ZWQgaW4gdGhlIGFzc2V0IG5hbWUiLCAiY3JlYXRlZF9ieSI6IDEwLCAicmlza19sZXZlbCI6IDQwLCAiZGVzY3JpcHRpb24iOiAiRGF0YSBhc3NldHMgcmVnYXJkbGVzcyBvZiB0aGVpciB0eXBlLCBkZWZpbmVkIGFzIHNlbnNpdGl2ZSBiZWNhdXNlIHRoYXQgdGVybXMgc3VjaCBhcyBcImNvbmZpZGVudGlhbFwiLCBcInByaXZhdGVcIiwgXCJzZW5zaXRpdmVcIiB3ZXJlIGRldGVjdGVkIGluIHRoZSBhc3NldCBuYW1lIiwgImRhdGFfY2F0ZWdvcnkiOiAiQ29uZmlkZW50aWFsIC0gR2xvYmFsIn19XSwgInNvdXJjZSI6ICJHU1VJVEVfR0RSSVZFX0FVRElUX0xPR19BUEkiLCAiZmlsZV9pZCI6ICIxLUdGQTk2WkVzekhodDlSSS1HSTEwemk0QUFRRGIycTI0ZUZiMjE1RGJOQSIsICJmaWxlX3VybCI6IFt7ImFzc2V0IjogeyJsaW5rIjogImh0dHBzOi8vZHJpdmUuZ29vZ2xlLmNvbS9maWxlL2QvMS1HRkE5NlpFc3pIaHQ5UkktR0kxMHppNEFBUURiMnEyNGVGYjIxNURiTkEiLCAidmFsdWUiOiAiQ29weSBvZiBzZW5zaXRpdmUgZmlsZSJ9LCAiYXNzZXRfaWQiOiAiMS1HRkE5NlpFc3pIaHQ5UkktR0kxMHppNEFBUURiMnEyNGVGYjIxNURiTkEiLCAiZGF0YV9zb3VyY2UiOiAiR1NVSVRFX0dEUklWRV9BVURJVF9MT0dfQVBJIn1dLCAibG9jYXRpb24iOiAiZ2FsQHJlY28uYWkiLCAiZmlsZV9uYW1lIjogIkNvcHkgb2Ygc2Vuc2l0aXZlIGZpbGUiLCAiZmlsZV9zaXplIjogMCwgImZpbGVfdHlwZSI6ICJkb2N1bWVudCIsICJmaWxlX293bmVyIjogImdhbEByZWNvLmFpIiwgInZpc2liaWxpdHkiOiAiUEVSTUlTU0lPTl9UWVBFX1BFT1BMRV9XSVRIX0xJTksiLCAiZGVsZXRlX3N0YXRlIjogImFjdGl2ZSIsICJkYXRhX2NhdGVnb3JpZXMiOiBbIkNvbmZpZGVudGlhbCAtIEdsb2JhbCJdLCAibGFzdF91cGRhdGVfdGltZSI6ICIyMDIzLTA0LTIwVDE4OjMyOjMyKzAwOjAwIiwgInNlbnNpdGl2aXR5X2xldmVsIjogNDAsICJjdXJyZW50bHlfcGVybWl0dGVkX3VzZXJzIjogWyJnYWxAcmVjby5haSJdfX0sICJwb2xpY3lfaWQiOiAiN2YxNzQ1ODAtODFiNi00MzQ5LWE0Y2EtY2E4ODczYjQ4Yjc4IiwgInZpb2xhdGlvbiI6IHsiZW5yaWNoZWQuYXNzZXQuc2Vuc2l0aXZpdHlfbGV2ZWwgaW4gWzMwLCA0MCwgXCIzMFwiLCBcIjQwXCJdIG9yIGVucmljaGVkLmFzc2V0LnJpc2tfbGV2ZWwgaW4gWzMwLCA0MCwgXCIzMFwiLCBcIjQwXCJdIjogdHJ1ZSwgIiRjb3VudChwYXlsb2FkLmV2ZW50cy5wYXJhbWV0ZXJzW25hbWU9XCJ2aXNpYmlsaXR5XCIgYW5kIHZhbHVlPVwicGVvcGxlX3dpdGhfbGlua1wiXSkgPiAwIGFuZCAkY291bnQocGF5bG9hZC5ldmVudHMucGFyYW1ldGVyc1tuYW1lPVwib2xkX3Zpc2liaWxpdHlcIiBhbmQgdmFsdWU9XCJwZW9wbGVfd2l0aF9saW5rXCJdKSA8PSAwIGFuZCAkY291bnQocGF5bG9hZC5ldmVudHMucGFyYW1ldGVyc1tuYW1lPVwidmlzaWJpbGl0eV9jaGFuZ2VcIiBhbmQgdmFsdWU9XCJleHRlcm5hbFwiXSkgPiAwIjogdHJ1ZSwgIigkY291bnQocGF5bG9hZC5ldmVudHNbdHlwZT1cImFjbF9jaGFuZ2VcIl0pID4gMCAgIG9yICRjb3VudChwYXlsb2FkLmV2ZW50c1tuYW1lPVwiY2hhbmdlX2RvY3VtZW50X3Zpc2liaWxpdHlcIl0pID4gMCAgIG9yICRjb3VudChwYXlsb2FkLmV2ZW50c1tuYW1lPVwiY2hhbmdlX2RvY3VtZW50X2FjY2Vzc19zY29wZVwiXSkpIGFuZCAoICAgICAgIHBheWxvYWQuZXZlbnRzW3R5cGU9XCJhY2xfY2hhbmdlXCJdLnBhcmFtZXRlcnNbbmFtZT1cInByaW1hcnlfZXZlbnRcIl0uYm9vbFZhbHVlICAgICAgIG9yICAgICAgICBwYXlsb2FkLmV2ZW50c1tuYW1lPVwiY2hhbmdlX2RvY3VtZW50X3Zpc2liaWxpdHlcIl0ucGFyYW1ldGVyc1tuYW1lPVwicHJpbWFyeV9ldmVudFwiXS5ib29sVmFsdWUgICAgICAgb3IgICAgICAgcGF5bG9hZC5ldmVudHNbbmFtZT1cImNoYW5nZV9kb2N1bWVudF9hY2Nlc3Nfc2NvcGVcIl0ucGFyYW1ldGVyc1tuYW1lPVwicHJpbWFyeV9ldmVudFwiXS5ib29sVmFsdWUpIjogdHJ1ZX0sICJwb2xpY3lfdGFncyI6IFsiUmVjbyBSZWNvbW1lbmRlZCIsICIiXSwgInBvbGljeV90aXRsZSI6ICJTZW5zaXRpdmUgYXNzZXRzIGluIEdvb2dsZSBEcml2ZSBleHBvc2VkIHB1YmxpY2x5IiwgIndvcmtzcGFjZV9pZCI6ICJmNGJlNDIwMi00YTZlLTRiZjctYjA1OC01ZDMzYTMxNDZkZjciLCAiYWRkaXRpb25hbF9kYXRhIjogeyJ4LXJlYWwtaXAiOiAiMTAuMi4xNzIuMTAyIiwgIjphdXRob3JpdHkiOiAiZ3N1aXRlLWV4dHJhY3Rvci1zZXJ2aWNlOjUwMDUxIiwgInVzZXItYWdlbnQiOiAiZ3JwYy1nby8xLjU0LjAiLCAiY29udGVudC10eXBlIjogImFwcGxpY2F0aW9uL2dycGMiLCAieC1hbXpuLXRyYWNlLWlkIjogIlJvb3Q9MS02NDUyMzU4OC0zMzUyYjUzYzBmNTg0YzM4Njg2OTE1MDIiLCAieC1mb3J3YXJkZWQtZm9yIjogIjc0LjEyNS4yMTAuMTkwLDc0LjEyNS4yMTAuMTkwLCAxMC4yLjExMS4xNzIiLCAieC1mb3J3YXJkZWQtaG9zdCI6ICJkZW1vLnJlY28uYWkiLCAieC1mb3J3YXJkZWQtcG9ydCI6ICI0NDMiLCAieC1mb3J3YXJkZWQtcHJvdG8iOiAiaHR0cHMiLCAieC1nb29nLWNoYW5uZWwtaWQiOiAiODE0ZTA5MDktZTA0Mi00MjlmLWE3ZTYtYjIxY2ZmYWIxMzY0IiwgImdycGNnYXRld2F5LWFjY2VwdCI6ICIqLyoiLCAieC1nb29nLXJlc291cmNlLWlkIjogIlVSQzEwQ2F0ek01V2wweW8taTBtczRsYWdzVSIsICJ4LWdvb2ctcmVzb3VyY2UtdXJpIjogImh0dHBzOi8vYWRtaW4uZ29vZ2xlYXBpcy5jb20vYWRtaW4vcmVwb3J0cy92MS9hY3Rpdml0eS91c2Vycy9hbGwvYXBwbGljYXRpb25zL2RyaXZlP2FsdD1qc29uJm9yZ1VuaXRJRCZwcmV0dHlQcmludD1mYWxzZSIsICJ4LWdvb2ctY2hhbm5lbC10b2tlbiI6ICJMcndpdTF6b09RRWE1SmE1OW85ODBxQzVTakZ1Y1ZJR08ySWtjSVhaSVAyd1FDc0JPLTF0V3JIM3NvQUVCZk5MWWdaUDRua0pnOTRVZVEwZHlNQ3FITjlKLS02TUNXWktWdTk4V294QWJlNXFhRjNWeUFlT2lxVEMwcmRvNEFISiIsICJ4LWdvb2ctbWVzc2FnZS1udW1iZXIiOiAiNzkyNjM3OCIsICJ4LWdvb2ctcmVzb3VyY2Utc3RhdGUiOiAiZWRpdCIsICJncnBjZ2F0ZXdheS11c2VyLWFnZW50IjogIkFQSXMtR29vZ2xlOyAoK2h0dHBzOi8vZGV2ZWxvcGVycy5nb29nbGUuY29tL3dlYm1hc3RlcnMvQVBJcy1Hb29nbGUuaHRtbCkiLCAiZ3JwY2dhdGV3YXktY29udGVudC10eXBlIjogImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLTgiLCAieC1nb29nLWNoYW5uZWwtZXhwaXJhdGlvbiI6ICJXZWQsIDAzIE1heSAyMDIzIDEzOjA4OjQ4IEdNVCJ9LCAiZXh0cmFjdGlvbl90aW1lIjogeyJuYW5vcyI6IDc5MjM2NTEwMSwgIm1pbGxpcyI6IDE2ODMxMDkyNTY3OTIsICJzZWNvbmRzIjogMTY4MzEwOTI1NiwgInRpbWVzdGFtcCI6ICIyMDIzLTA1LTAzVDEwOjIwOjU2Ljc5MjM2NTEwMVoifSwgImV4dHJhY3Rpb25fc291cmNlIjogMTAsICJleHRyYWN0aW9uX3NvdXJjZV91cHBlcl9jYXNlIjogIkdTVUlURV9HRFJJVkVfQVVESVRfTE9HX0FQSSJ9",  # noqa
                    "createdAt": "2023-05-03T10:21:03.926534Z",
                    "policyStatusOnViolationCreation": "POLICY_STATUS_ON",
                }
            ],
            "createdAt": "2023-05-03T10:21:04.765477Z",
            "updatedAt": "2023-05-03T10:21:04.078627Z",
        }
    }
    alerts_table = GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="id",
                                value=base64.b64encode(
                                    "ZWU1OTNkYzItYTUwZS00MTVlLWJlZDAtODQwM2MxOGIyNmNh".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="description",
                                value=base64.b64encode(
                                    INCIDENT_DESCRIPTION.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="risk_level",
                                value=base64.b64encode(
                                    "HIGH".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="created_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="updated_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="status",
                                value=base64.b64encode(
                                    INCIDENT_STATUS.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )
    return alerts_table, alert


def get_random_assets_user_has_access_to_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="source",
                                value=base64.b64encode(
                                    "GDRIVE_ACCESS_LOG_AP".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_type",
                                value=base64.b64encode(
                                    "document".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="currently_permitted_users",
                                value=base64.b64encode(
                                    json.dumps(["a", "b", "c", "d", "e"]).encode(
                                        ENCODING
                                    )
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="labels",
                                value=base64.b64encode(
                                    json.dumps(["a", "b", "c", "d", "e"]).encode(
                                        ENCODING
                                    )
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="delete_state",
                                value=base64.b64encode(
                                    "active".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_size",
                                value=base64.b64encode("0".encode(ENCODING)).decode(
                                    ENCODING
                                ),
                            ),
                            KeyValuePair(
                                key="file_name",
                                value=base64.b64encode(
                                    "User Activity Report".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="visibility",
                                value=base64.b64encode(
                                    "shared_internally".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="asset_id",
                                value=base64.b64encode("1".encode(ENCODING)).decode(
                                    ENCODING
                                ),
                            ),
                            KeyValuePair(
                                key="file_owner",
                                value=base64.b64encode("a".encode(ENCODING)).decode(
                                    ENCODING
                                ),
                            ),
                        ],
                    )
                ],
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_random_risky_users_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="full_name",
                                value=base64.b64encode(
                                    "John Doe".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="identity_id",
                                value=base64.b64encode(
                                    f"{uuid.uuid4()}".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="email_account",
                                value=base64.b64encode(
                                    f"{uuid.uuid4()}@acme.com".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="risk_level",
                                value=base64.b64encode(
                                    str(RiskLevel.HIGH.value).encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="added_by",
                                value=base64.b64encode(
                                    "system".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="created_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_random_user_context_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="email_account",
                                value=base64.b64encode(
                                    "charles@corp.com".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="departments",
                                value=base64.b64encode(
                                    '["Pro"]'.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="job_titles",
                                value=base64.b64encode(
                                    '["VP Product"]'.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="category",
                                value=base64.b64encode(
                                    "external".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="groups",
                                value=base64.b64encode(
                                    '["Product"]'.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="full_name",
                                value=base64.b64encode(
                                    'Yossi'.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="labels",
                                value=base64.b64encode('["{\\"label\\": {\\"name\\": \\"VIP User\\",'
                                                       ' \\"type\\": \\"LABEL_TYPE_INFORMATIVE\\",'
                                                       ' \\"tooltip\\": \\"VIP User\\", \\"created_by\\": 10,'
                                                       ' \\"risk_level\\": 0, \\"description\\": \\"VIP User\\"}}",'
                                                       '"{\\"label\\": {\\"name\\": \\"GSuite Admin\\",'
                                                       ' \\"type\\": \\"LABEL_TYPE_INFORMATIVE\\",'
                                                       ' \\"tooltip\\": \\"GSuite Admin\\", \\"created_by\\": 10,'
                                                       ' \\"risk_level\\": 0, \\"description\\": \\"GSuite Admin\\"}}",'
                                                       '"{\\"label\\": {\\"name\\": \\"Okta Admin\\",'
                                                       ' \\"type\\": \\"LABEL_TYPE_INFORMATIVE\\",'
                                                       ' \\"tooltip\\": \\"Okta Admin\\", '
                                                       '\\"created_by\\": 10, \\"risk_level\\": 0,'
                                                       '\\"description\\": \\"Okta Admin\\"}}"]'.
                                                       encode(ENCODING)).decode(ENCODING)),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_mock_assets() -> list[dict[str, Any]]:
    return {
        "assets": [
            {
                "entityId": "1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1",
                "name": "Untitled document",
                "link": "https://drive.google.com/file/d/1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1",
                "dataSource": "GSUITE_GDRIVE_AUDIT_LOG_API",
                "type": "ASSET_TYPE_FILE",
                "attributes": {},
                "owner": "test@acme.com",
            }
        ]
    }


def test_test_module_success(requests_mock, reco_client: RecoClient) -> None:
    mock_response = {"alerts": {"tablesMetadata": [{"name": "table1"}]}}
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox?limit=1", json=mock_response
    )

    res = reco_client.validate_api_key()
    assert res == "ok"


@pytest.fixture
def reco_client() -> RecoClient:
    api_token = "dummy api key"
    return RecoClient(
        api_token=api_token, base_url=DUMMY_RECO_API_DNS_NAME, verify=True, proxy=True
    )


def test_fetch_incidents_should_succeed(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets
    )
    random_alerts_response, alert = get_alerts_and_table_response()
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{ALERT_ID}", json=alert)
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json=random_alerts_response
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        source="test",
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )
    expected_count = (random_incidents.getTableResponse.total_number_of_results
                      + random_alerts_response.getTableResponse.total_number_of_results)

    assert (len(fetched_incidents) == expected_count)
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == assets.get("assets")


def test_fetch_same_incidents(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets
    )
    random_alerts_response, alert = get_alerts_and_table_response()
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{ALERT_ID}", json=alert)
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json=random_alerts_response
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )
    expected_count = (random_incidents.getTableResponse.total_number_of_results
                      + random_alerts_response.getTableResponse.total_number_of_results)

    assert (len(fetched_incidents) == expected_count)
    last_run, incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        before=datetime.datetime.now(),
        last_run=last_run,
        max_fetch=1,
    )
    assert len(incidents) == 0


def test_fetch_incidents_without_assets_info(
    requests_mock, reco_client: RecoClient
) -> None:
    random_incidents = get_random_table_response()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json={}
    )
    random_alerts_response, alert = get_alerts_and_table_response()
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{ALERT_ID}", json=alert)
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json=random_alerts_response)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, source="GOOGLE_DRIVE", max_fetch=1
    )

    expected_count = (random_incidents.getTableResponse.total_number_of_results
                      + random_alerts_response.getTableResponse.total_number_of_results)

    assert (len(fetched_incidents) == expected_count)
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == []


def test_fetch_assets_with_empty_response(
    requests_mock, reco_client: RecoClient
) -> None:
    incident_id = uuid.uuid1()
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{incident_id}", json={}
    )
    assets = reco_client.get_incidents_assets(incident_id=incident_id)
    assert assets == []


def test_empty_response(requests_mock, reco_client: RecoClient) -> None:
    table_empty = GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(rows=[]),
            total_number_of_results=0,
            table_definition="",
            dynamic_table_definition="",
            token="",
        )
    )
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident",
        json=table_empty,
    )
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json=table_empty)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_empty_valid_response(requests_mock, reco_client: RecoClient) -> None:
    table_empty = GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(rows=[]),
            total_number_of_results=0,
            table_definition="",
            dynamic_table_definition="",
            token="",
        )
    )
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident",
        json=table_empty,
    )
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json=table_empty)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_invalid_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json={"getTableResponse": {}})
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/table", json={
        "getTableResponse": {}
    })
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        last_run={},
        max_fetch=1,
        risk_level=str(RiskLevel.HIGH),
        source="GSUITE_GDRIVE_AUDIT_LOG_API",
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_risk_level_mapper():
    risk_level_high = 40
    assert map_reco_score_to_demisto_score(risk_level_high) == 4


def test_alert_mapper():
    assert map_reco_alert_score_to_demisto_score("CRITICAL") == 4


def test_get_max_fetch_bigger():
    big_number_max_fetch = 600
    result = get_max_fetch(big_number_max_fetch)
    assert result == 500


def test_max_fetch():
    max_fetch = 200
    result = get_max_fetch(max_fetch)
    assert result == max_fetch


def test_update_reco_incident_timeline(requests_mock, reco_client: RecoClient) -> None:
    incident_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident-timeline/{str(incident_id)}",
        json={},
        status_code=200,
    )
    res = reco_client.update_reco_incident_timeline(
        incident_id=str(incident_id), comment="test"
    )
    assert res == {}


def test_update_reco_incident_timeline_error(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    incident_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident-timeline/{str(incident_id)}",
        json={},
        status_code=404,
    )
    with capfd.disabled(), pytest.raises(Exception):
        reco_client.update_reco_incident_timeline(
            incident_id=str(incident_id), comment="test"
        )


def test_resolve_visibility_event(requests_mock, reco_client: RecoClient) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=200
    )
    res = reco_client.resolve_visibility_event(
        entity_id=str(entry_id), label_name="Accessible by all"
    )
    assert res == {}


def test_resolve_visibility_event_error(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=404
    )
    with capfd.disabled(), pytest.raises(Exception):
        reco_client.resolve_visibility_event(
            entity_id=str(entry_id), label_name="Accessible by all"
        )


def test_get_risky_users(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_risky_users_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json=raw_result,
        status_code=200,
    )
    actual_result = get_risky_users_from_reco(reco_client=reco_client)
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert "@" in actual_result.outputs[0].get("email_account")


def test_get_risky_users_bad_response(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json={},
        status_code=200,
    )
    with capfd.disabled(), pytest.raises(Exception):
        get_risky_users_from_reco(reco_client=reco_client)


def test_add_risky_user_label(requests_mock, reco_client: RecoClient) -> None:
    label_id = f"{uuid.uuid1()}@gmail.com"
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/entry-label-relations", json={}, status_code=200
    )
    raw_result = get_random_risky_users_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json=raw_result,
        status_code=200,
    )
    res = add_risky_user_label(reco_client=reco_client, email_address=label_id)
    assert "labeled as risky" in res.readable_output


def test_get_assets_user_has_access_to(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200
    )
    actual_result = get_assets_user_has_access(
        reco_client=reco_client,
        email_address=f"{uuid.uuid1()}@gmail.com",
        only_sensitive=False,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_assets_user_bad_response(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json={}, status_code=200
    )
    with capfd.disabled(), pytest.raises(Exception):
        get_assets_user_has_access(
            reco_client=reco_client, email_address="test", only_sensitive=False
        )


def test_get_sensitive_assets_by_name(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200
    )
    actual_result = get_sensitive_assets_by_name(
        reco_client=reco_client, asset_name="test", regex_search=True
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_sensitive_assets_by_id(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200
    )
    actual_result = get_sensitive_assets_by_id(
        reco_client=reco_client, asset_id="asset-id"
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_link_to_user_overview_page(requests_mock, reco_client: RecoClient) -> None:
    entity_id = f"{uuid.uuid1()}@gmail.com"
    link_type = "RM_LINK_TYPE_USER"
    link_res = str(uuid.uuid1())
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
        json={"link": link_res}, status_code=200
    )
    actual_result = get_link_to_user_overview_page(
        reco_client=reco_client, entity=entity_id, link_type=link_type
    )
    assert actual_result.outputs_prefix == "Reco.Link"
    assert actual_result.outputs.get("link") == link_res


def test_get_link_to_user_overview_page_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    entity_id = f"{uuid.uuid1()}@gmail.com"
    link_type = "RM_LINK_TYPE_USER"
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
        json={}, status_code=200
    )
    with capfd.disabled(), pytest.raises(Exception):
        get_link_to_user_overview_page(reco_client=reco_client, entity=entity_id, link_type=link_type)


def test_get_exposed_publicly(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_sensitive_assets_shared_with_public_link(
        reco_client=reco_client
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_private_email_list_with_access(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table",
        json={"getTableResponse": {}},
        status_code=200
    )
    actual_result = get_private_email_list_with_access(
        reco_client=reco_client
    )
    assert len(actual_result.outputs) == 0


def test_get_assets_shared_externally_command(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200
    )
    actual_result = get_assets_shared_externally_command(
        reco_client=reco_client,
        email_address="g@example.com"
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_get_files_exposed_to_email_command(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_files_exposed_to_email_command(
        reco_client=reco_client,
        email_account="g@example.com"
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_exposed_publicly_page_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json={}, status_code=200)
    with capfd.disabled(), pytest.raises(Exception):
        get_sensitive_assets_shared_with_public_link(
            reco_client=reco_client
        )


def test_get_3rd_parties_list_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json={}, status_code=200)
    with capfd.disabled(), pytest.raises(Exception):
        get_3rd_parties_list(
            reco_client=reco_client,
            last_interaction_time_in_days=30,
        )


def test_get_3rd_parties_list(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_3rd_parties_list(
        reco_client=reco_client,
        last_interaction_time_in_days=30,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_get_files_shared_with_3rd_parties(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_files_shared_with_3rd_parties(
        reco_client=reco_client,
        domain="data",
        last_interaction_time_before_in_days=30,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_date_formatting(reco_client: RecoClient) -> None:
    date = reco_client.get_date_time_before_days_formatted(30)
    assert ".999Z" in date


def test_add_exclusion_filter(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/algo/add_values_to_data_type_exclude_analyzer", json={}, status_code=200
    )
    reco_client.add_exclusion_filter("key", ["val1", "val2"])


def test_change_alert_status(requests_mock, reco_client: RecoClient) -> None:
    alert_id = uuid.uuid1()
    status = 'ALERT_STATUS_CLOSED'
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{str(alert_id)}/status/{status}",
        json={},
        status_code=200,
    )
    res = reco_client.change_alert_status(alert_id=str(alert_id),
                                          status=status)
    assert res == {}


def test_get_user_context_by_email(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_user_context_response()
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management", json=raw_result, status_code=200
    )
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json=raw_result,
        status_code=200,
    )
    res = get_user_context_by_email_address(reco_client, "charles@corp.com")
    assert res.outputs_prefix == "Reco.User"
    assert res.outputs.get("email_account") != ""
    assert res.outputs.get("email_account") == "charles@corp.com"
