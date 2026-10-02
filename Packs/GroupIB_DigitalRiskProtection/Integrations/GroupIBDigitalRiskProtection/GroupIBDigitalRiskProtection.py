import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from ciaops import DRPPoller, Parser
from traceback import format_exc
from enum import Enum
from dateparser import parse as dateparser_parse  # type: ignore
from json import dumps as json_dumps
from typing import Any, cast
from datetime import datetime, timedelta, UTC
import base64
import time
from ciaops.exception import ConnectionException
from ciaops.const import RequestConsts
import re

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

""" CONSTANTS """


class Consts:
    """Scalar configuration constants for the Group-IB DRP integration."""

    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # The known-violations cache: a flat `dict[str, float]` in `lastRun` mapping a
    # violation id to the unix timestamp at which the instance last emitted it. A
    # violation in the cache already has an incident on this instance, so every
    # later change to it is passed through as an update, whatever the creation
    # filters say; a violation not in the cache is a candidate for a new incident
    # and has to pass them. The key is the one `CommonServerPython` uses for the
    # same purpose, so the state stays readable by XSOAR tooling.
    LAST_RUN_SEEN_INCIDENT_IDS_KEY = "found_incident_ids"
    SECONDS_IN_DAY = 86_400
    DEFAULT_DEDUP_LOOKBACK_DAYS = 365

    # `detected` older than this is not when the violation happened: DRP keeps the
    # date of the first detection across re-openings, so an incident for a
    # violation that resurfaced years later would be dated years ago.
    OCCURRED_MAX_AGE_DAYS = 365

    # Hard upper bound on the number of XSOAR incidents emitted per single
    # fetch iteration. Bounds the worker memory and the burst into the
    # incident DB even when `max_requests` and the upstream page size would
    # otherwise produce a much larger result. 0 disables the cap.
    DEFAULT_MAX_INCIDENTS_PER_FETCH = 200

    # Transport tuning for the BaseClient stack (file download only; every
    # other call goes through the ciaops session). Sourced from ciaops
    # RequestConsts so the two stacks never drift apart.
    TIMEOUT = RequestConsts.TIMEOUT
    RETRIES = RequestConsts.RETRIES
    STATUS_LIST_TO_RETRY = list(RequestConsts.STATUS_CODE_FORCELIST)

    # maxItems of the `items` array of POST /client_api/violation/add per drp-swagger.json.
    MAX_CREATE_VIOLATION_ITEMS = 100

    # Caps for inline base64 images embedded into the incident HTML field so an
    # image-heavy violation cannot push the incident past XSOAR entry limits.
    # Oversize images are skipped; their file_sha stays available via
    # gibdrp-get-violation-by-id.
    MAX_IMAGE_BYTES = 2_000_000
    MAX_IMAGES_TOTAL_BYTES_PER_INCIDENT = 5_000_000

    # DRPUpdateFeedGenerator has no built-in request throttle (unlike the TI
    # and ASM generators), so the fetch loop paces portions itself with the
    # SDK's own rate budget.
    PORTION_PACING_SECONDS = RequestConsts.RATE_LIMIT_DELAY


class Mappings:
    """Lookup tables and enumerated value sets used across parsing/rendering."""

    # `violation.status` values: the enum of drp-swagger.json (ClientViolationPageBrandInfo)
    # plus `in_response` and `resolved`, which the live API reports and the
    # specification omits. Used for parameter validation and rendered as the
    # YAML multi-select options for the `violationStatuses` integration parameter.
    SUPPORTED_VIOLATION_STATUSES: frozenset[str] = frozenset(
        {
            "found",
            "detected",
            "false_status",
            "legal",
            "on_tracking",
            "no_content",
            "on_parking",
            "active",
            "solved",
            "redirect",
            "in_response",
            "resolved",
        }
    )

    # `violationSubtype` enum of POST /client_api/violation/add per
    # drp-swagger.json. Values are case-sensitive on the wire
    # (`partnerPolicyCompliance` is camelCase).
    SUPPORTED_VIOLATION_SUBTYPES: frozenset[str] = frozenset(
        {"scam", "trademark", "phishing", "copyright", "counterfeit", "malware", "partnerPolicyCompliance"}
    )

    # `violation.approveState` value that means "waiting for the customer".
    APPROVE_STATE_UNDER_REVIEW = "under_review"

    # `violation.approveState` after the customer declined the violation. DRP does
    # nothing more with a rejected violation, so the state is final.
    APPROVE_STATE_REJECTED = "rejected"

    # `violation.status` values in which DRP has finished with the violation: the
    # take-down succeeded (`resolved`; `solved` in older API versions), the case went
    # to legal (`legal`) or the violation turned out to be false (`false_status`).
    # A violation in one of these states, or rejected by the customer, never gets a
    # new incident: it would be closed the moment it was created.
    FINISHED_VIOLATION_STATUSES: frozenset[str] = frozenset({"resolved", "solved", "legal", "false_status"})

    # `violation.approveState` after DRP accepts each customer decision.
    APPROVE_STATE_AFTER_DECISION: dict[str, str] = {"approve": "approved", "reject": "rejected"}

    # `subtypes[]` enum of GET /client_api/violation/list per drp-swagger.json,
    # keyed by the label the DRP portal shows. The specification calls subtype 7
    # `fraud`; the portal, the live API (`scam`) and customers call it Scam, so
    # that is the label. The labels are exactly the ones
    # VIOLATION_SUBTYPE_CODE_LABELS resolves the wire codes to, so a fetched
    # violation can be matched against a configured filter without a second
    # lookup table.
    VIOLATION_SUBTYPE_IDS: dict[str, int] = {
        "Counterfeit": 1,
        "Piracy": 2,
        "Partner policy compliance": 3,
        "Trademark": 4,
        "Malware": 5,
        "Phishing": 6,
        "Scam": 7,
        "No violation": 8,
    }

    # XSOAR incident severity levels behind the `incident_severity` parameter.
    # Cortex stores severity as this fixed numeric scale, so the parameter
    # offers the levels by name rather than an arbitrary number.
    INCIDENT_SEVERITY_BY_NAME: dict[str, float] = {
        "Unknown": IncidentSeverity.UNKNOWN,
        "Informational": IncidentSeverity.INFO,
        "Low": IncidentSeverity.LOW,
        "Medium": IncidentSeverity.MEDIUM,
        "High": IncidentSeverity.HIGH,
        "Critical": IncidentSeverity.CRITICAL,
    }

    # `violation.violationSubtype` values, keyed by what the API returns. The
    # live API (verified against drp.group-ib.com) reports the snake_case names
    # listed first; the letter codes are the ones drp-swagger.json documents and
    # are kept in case an older deployment still emits them. Values not in this
    # table pass through unchanged, so a label is idempotent.
    VIOLATION_SUBTYPE_CODE_LABELS: dict[str, str] = {
        "counterfeit": "Counterfeit",
        "piracy": "Piracy",
        "partner_policy_compliance": "Partner policy compliance",
        "trademark": "Trademark",
        "malware": "Malware",
        "phishing": "Phishing",
        "scam": "Scam",
        "no_violation": "No violation",
        "AK": "Counterfeit",
        "AP": "Piracy",
        "RRC": "Partner policy compliance",
        "TZ": "Trademark",
        "VPO": "Malware",
        "PH": "Phishing",
        "FR": "Scam",
        "NV": "No violation",
    }

    # `violation.stages.type` codes per drp-swagger.json
    # (ClientViolationPBIStage). Used by `transform_fields_to_grid_table` so
    # the stages grid in the layout shows readable names in addition to the
    # raw integer code returned by the API.
    STAGE_TYPE_LABELS: dict[int, str] = {
        1: "First active",
        2: "First detected",
        3: "First solved",
        4: "Enrichment",
        5: "Host info cache",
        6: "Deep vision",
        7: "Scoring",
        8: "Signaturing",
        9: "Approve required",
        10: "Approve set",
        11: "Status changed",
        12: "No content",
        13: "Screenshot",
        14: "Rejected",
        15: "Comment",
        16: "Image",
    }

    COMMON_VIOLATION_MAPPING = {
        # Start Information From Group-IB DRP
        "id": "id",  # GIB DRP ID
        "title": "violation.title",  # GIB DRP Title
        "description": "violation.description",  # GIB DRP Description
        "brand": "brand",  # GIB DRP Brand
        "company": "company",  # GIB DRP Company
        "violation_uri": "violation.uri",  # GIB DRP VIOLATION URI
        "approve_state": "violation.approveState",  # GIB DRP Approve State
        "violation_status": "violation.status",  # GIB DRP Status
        "source": "violation.source",  # GIB DRP Source
        "violation_type": "violation.violationSubtype",  # GIB DRP Type
        "tags": "violation.tags.name",  # GIB DRP Tags
        "link": "link",  # GIB DRP Link
        "typosquatting_status": "*typosquatting_status",  # GIB DRP Typosquatting Status
        # End Information From Group-IB DRP
        # Start Group-IB Dates
        "detected": "violation.detected",  # GIB DRP Detected
        "first_detected": "violation.firstDetected",  # GIB DRP First Detected
        "first_active": "violation.firstActive",  # GIB DRP First Active
        "first_solved": "violation.firstSolved",  # GIB DRP First Solved
        "dates_found_date": "violation.dates.foundDate",  # GIB DRP Found
        "dates_created_date": "violation.dates.createdDate",  # GIB DRP Created
        "dates_current_status_date": "violation.dates.currentStatusDate",  # GIB DRP Current Status Date
        # Same date under two names: the list payload uses currentStatusDate,
        # the by-id payload uses currentDate; data_pre_cleaning collapses them.
        "dates_current_date": "violation.dates.currentDate",
        "dates_approved_date": "violation.dates.approvedDate",  # GIB DRP Approved
        # End Group-IB Dates
        # Start Group-IB Images
        "images": "images",  # GIB DRP HTML Images
        # End Group-IB Images
        # Start Group-IB Tables
        "scores": {  # GIB DRP Scores Table
            "score": "violation.scores.score",
            "type": "violation.scores.type",
            "version": "violation.scores.version",
        },
        "stages": {  # GIB DRP Stages Table (take-down progression)
            "type": "violation.stages.type",
            "datetime": "violation.stages.datetime",
            "times": "violation.stages.times",
        },
        # End Group-IB Tables
    }

    TABLES_MAPPING = ["scores", "stages"]


class ViolationTypeMapping(Enum):
    WEB = 1
    MARKETPLACE = 3
    ADVERTISING = 5
    MOBILE_APPS = 2
    SOCIAL_NETWORKS = 4
    INSTANT_MESSENGERS = 6


class ViolationSubType(Enum):
    Counterfeit = 1
    Piracy = 2
    Partner_policy_compliance = 3
    Trademark = 4
    Malware = 5
    Phishing = 6
    Scam = 7
    NoViolation = 8


class Endpoints(Enum):
    VIOLATIONS = "violation/list"
    VIOLATION = "violation"
    BRANDS = "/settings/brands"
    SUBSCRIPTIONS = "/settings/subscriptions"
    RECEIVING_FILE = "/file/"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, auth: tuple[str, str], verify=True, proxy=False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

        self.poller = DRPPoller(
            username=auth[0],
            api_key=auth[1],
            api_url=base_url,
        )
        # The poller runs its own requests.Session; without this the
        # "Trust any certificate" instance setting only affects BaseClient.
        self.poller.set_verify(verify)
        self.poller.set_product(
            product_type="SOAR",
            product_name="CortexSOAR",
            product_version="unknown",
            integration_name="Group-IB Digital Risk Protection",
            integration_version="1.2.0",
        )
        self.additional_headers = {
            "Accept": "*/*",
            "User-Agent": f"SOAR/CortexSOAR_unknown/Group-IB Digital Risk Protection/{auth[0]}",
        }

    def generate_seq_update(self, first_fetch_time: str) -> int:
        demisto.debug(f"Client.generate_seq_update: first_fetch_time='{first_fetch_time}'")
        parsed_from = dateparser_parse(date_string=first_fetch_time)
        if parsed_from is None:
            raise DemistoException(
                "Inappropriate first_fetch format, "
                f"please use a format such as: 2020-01-01 or January 1 2020 or 3 days. The format given is: {first_fetch_time}"
            )
        date_from = parsed_from.strftime("%Y-%m-%d")
        demisto.debug(f"Client.generate_seq_update: date_from='{date_from}'")
        raw_seq = self.poller.get_seq_update_dict(date=date_from, collection_name=Endpoints.VIOLATIONS.value)
        demisto.debug(f"Client.generate_seq_update: raw_seq={raw_seq!r}")
        return raw_seq[Endpoints.VIOLATIONS.value]

    def _get_violation_section_number(self, name: str) -> int:
        normalized_name = name.upper()
        normalized_name = normalized_name.replace(" ", "_")

        try:
            return ViolationTypeMapping[normalized_name].value
        except KeyError:
            raise ValueError(f"Unknown violation type: {name}")

    def create_generator(
        self,
        first_fetch_time: str,
        last_run: dict,
        only_typosquatting: bool,
        violation_subtypes: list[int] | None = None,
        brands: str | None = None,
        section: str | None = None,
    ):
        """The update stream of the violations the instance is responsible for.

        Only attributes a violation never changes are pushed to the API: section, type
        and brand. Anything that changes during the life of a violation (status,
        approve state) is filtered by the caller when an incident is created, so that
        later updates of that violation still arrive and reach the incident.
        """
        last_fetch = last_run.get("last_fetch", None)
        demisto.debug(f"Client.create_generator: last_fetch={last_fetch!r}")
        use_last_fetch = isinstance(last_fetch, int) and last_fetch > 0
        sequpdate: int = last_fetch if use_last_fetch else self.generate_seq_update(first_fetch_time)
        demisto.debug(
            "Client.create_generator: sequpdate selection - "
            f"selected={sequpdate} source={'last_run.last_fetch' if use_last_fetch else 'generate_seq_update(first_fetch_time)'} "
            f"first_fetch_time={first_fetch_time!r}"
        )

        # ciaops serializes `section` verbatim into the query string, so the
        # scalar section id (not a list) is the correct wire format.
        section_id: int | None = self._get_violation_section_number(section.strip()) if section else None

        # `brands` must be a list: ciaops indexes it, so a bare string would send its first
        # character as the brand id. The whole list is passed on; the library currently forwards
        # only `brands[0]` to `brandIds[]`, which is where multi-brand filtering is lost -- the API
        # itself declares `brandIds[]` as a multi-value array.
        brands_list: list[str] | None = argToList(brands) or None
        if brands_list and len(brands_list) > 1:
            demisto.info(
                f"Filter by Brand lists {len(brands_list)} ids, but the bundled ciaops library sends only "
                f"{brands_list[0]!r}. The other ids have no effect until the library is updated."
            )

        demisto.debug(
            "Client.create_generator: "
            f"collection={Endpoints.VIOLATIONS.value} subtypes={violation_subtypes} section={section_id} "
            f"sequpdate={sequpdate} brands={brands_list}"
        )
        try:
            return self.poller.create_update_generator(
                collection_name=Endpoints.VIOLATIONS.value,
                subtypes=violation_subtypes,
                section=section_id,  # type: ignore[arg-type]  # scalar is the wire format; see comment above
                brands=brands_list,
                sequpdate=sequpdate,
                use_typo_squatting=only_typosquatting,
            )
        except ConnectionException as e:
            raise ConnectionException(
                f"Additional information: collection_name: {Endpoints.VIOLATIONS.value} "
                f"subtypes: {violation_subtypes} section: {section_id} sequpdate: {sequpdate} {str(e)}"
            ) from e

    def change_violation_status(self, feed_id: str, status: str) -> None:
        """Approve or reject a violation pending customer review.

        The mutation itself is `ciaops`' `change_status`. The precondition is re-checked here first
        because the library only writes a line to its own logger when the violation is not in a
        changeable state -- from XSOAR that is indistinguishable from success, so the analyst would
        be told the change was sent while nothing happened.

        The library requires both `status == "detected"` and `approveState == "under_review"`; the
        same pair is checked here so the message names whichever one actually blocked the change.
        """
        response = self.get_violation_by_id(feed_id)
        violation = response.raw_dict.get("violation") or {}
        violation_status = violation.get("status")
        violation_approve_state = violation.get("approveState")
        demisto.debug(
            "Client.change_violation_status: "
            f"id={feed_id} status={status} "
            f"current_status={violation_status!r} approve_state={violation_approve_state!r}"
        )
        if violation_status != "detected" or violation_approve_state != "under_review":
            raise DemistoException(
                f"Cannot change violation '{feed_id}' to '{status}': it is only changeable while "
                f"status is 'detected' and approveState is 'under_review'; this one has "
                f"status={violation_status!r} and approveState={violation_approve_state!r}."
            )
        try:
            self.poller.change_status(feed_id=feed_id, status=status)
        except ConnectionException as e:
            # The SDK retries the change-approve POST on transport errors. When the first attempt
            # did reach DRP, the retry is answered with HTTP 400 ("You can't set approve to result")
            # although the decision is already recorded - seen live. Re-read the violation and
            # accept the call when it is in the requested state; anything else is a real failure.
            target_state = {"approve": "approved", "reject": "rejected"}.get(status)
            try:
                current = self.get_violation_by_id(feed_id).raw_dict.get("violation") or {}
            except Exception:  # noqa: BLE001 - the original error is the one worth reporting
                current = {}
            if target_state and current.get("approveState") == target_state:
                demisto.debug(
                    f"Client.change_violation_status: change request for {feed_id} failed with {e!s} but the "
                    f"violation is already {target_state!r}; treating as success"
                )
                return
            raise

    def get_formatted_brands(self) -> list[dict[str, str]]:
        return self.poller.get_brands() or []

    def get_formatted_subscriptions(self) -> list[str]:
        return self.poller.get_subscriptions() or []

    def get_file(self, file_sha: str) -> tuple[bytes, str] | None:
        try:
            response = self._http_request(
                method="GET",
                url_suffix=Endpoints.RECEIVING_FILE.value + file_sha,
                timeout=Consts.TIMEOUT,
                retries=Consts.RETRIES,
                status_list_to_retry=Consts.STATUS_LIST_TO_RETRY,
                headers=self.additional_headers,
                resp_type="response",
            )
            mime_type = CommonHelpers.extract_mime_type(response.headers.get("content-type", ""))
            content_len = len(response.content) if hasattr(response, "content") and response.content is not None else 0
            status_code = getattr(response, "status_code", None)
            demisto.debug(
                "Client.get_file: downloaded file - "
                f"file_sha={file_sha} status_code={status_code} mime_type={mime_type} content_len={content_len}"
            )
            data = response.content, mime_type
        except Exception as e:
            data = None
            demisto.debug(
                "Client.get_file: Could not download or the following image is not available - "
                f"file_sha={file_sha} error_type={type(e).__name__} error={e!s}\n{format_exc()}"
            )
        return data

    def create_violations(self, urls: list[str], violation_subtype: str, brand_id: str) -> dict[str, Any]:
        """Submit new violations to the DRP portal via `violation/add`.

        Every URL is submitted as a separate item sharing the same
        `violationSubtype` and `brandId`. A URL already submitted for the same brand and
        subtype is refused by the API ("This URL already exists"), so a repeated call fails
        instead of creating a second violation.

        :return: ``{"succeeded": [...], "failed": [...]}`` as returned by the
            API (``failed`` is present only on HTTP 207 partial success).
        """
        items = [{"url": url, "violationSubtype": violation_subtype, "brandId": brand_id} for url in urls]
        demisto.debug(
            "Client.create_violations: submitting violations - "
            f"count={len(items)} violation_subtype={violation_subtype} brand_id={brand_id}"
        )
        return self.poller.add_violations(items=items)

    def get_violation_by_id(self, violation_id: str) -> Parser:
        """Fetch one violation, failing with a readable error when the id is unknown.

        The API answers an unknown id with a `null` body rather than an error; the SDK then
        builds its Parser from that None and fails with an AttributeError deep inside the
        library, which reached the War Room as `'NoneType' object has no attribute 'get'`.
        """
        try:
            results = self.poller.search_feed_by_id(violation_id)
        except AttributeError as e:
            raise DemistoException(f"Violation '{violation_id}' was not found in Group-IB DRP.") from e
        raw = getattr(results, "raw_dict", None)
        if not isinstance(raw, dict) or not raw.get("violation"):
            raise DemistoException(f"Violation '{violation_id}' was not found in Group-IB DRP.")
        return results

    def get_formatted_violation_by_id(
        self, violation_id: str, get_images: bool | None = True
    ) -> tuple[dict[Any, Any], list[dict[str, str | bytes]]]:
        results = self.get_violation_by_id(violation_id=violation_id)
        # cast: with as_json=False the SDK returns list[dict]; the ignore covers
        # its `keys` annotation, which excludes the nested templates it documents.
        parsed_portion = cast(
            "list[dict[Any, Any]]",
            results.parse_portion(keys=Mappings.COMMON_VIOLATION_MAPPING, as_json=False),  # type: ignore[arg-type]
        )
        parse_result: dict[Any, Any] = parsed_portion[0]
        updated_images = []
        if get_images:
            images = parse_result.get("images", [])
            if images and len(images) > 0:
                # The payload lists the same hash once per stage/screenshot; attach each image once.
                for image in dict.fromkeys(images):
                    image_data_and_mime_type = self.get_file(file_sha=image)
                    if image_data_and_mime_type is not None:
                        image_data, mime_type = image_data_and_mime_type
                        demisto.debug(f"Client.get_formatted_violation_by_id: image mime_type={mime_type}")
                        updated_images.append(
                            {
                                "file_sha": image,
                                "image_data": image_data,
                                "mime_type": mime_type,
                            }
                        )

        return parse_result, updated_images


""" Support functions """


class CommonHelpers:
    scores_tables_name_by_types = {
        "risk": "General Score ",
        "domain": "Domain Score ",
        "image": "Image Score ",
        "parking": "Parking Score ",
        "text": "Text Score ",
    }

    @staticmethod
    def transform_dict(input_dict: dict[str, list[str | list[Any]] | str | None]) -> list[dict[str, Any]]:
        if not input_dict:
            return [{}]

        normalized_dict: dict[str, list[Any]] = {}
        for k, v in input_dict.items():
            if isinstance(v, list):
                normalized_dict[k] = v
            elif v is None:
                normalized_dict[k] = []
            else:
                normalized_dict[k] = [v]

        max_length = max((len(v) for v in normalized_dict.values() if isinstance(v, list)), default=1)

        result = []
        for i in range(max_length):
            result.append({k: (v[i] if i < len(v) else (v[0] if v else None)) for k, v in normalized_dict.items()})

        return result

    @staticmethod
    def transform_additional_fields_to_markdown_tables(feed: dict):
        additional_tables = []
        delete_keys = []
        for key, value in feed.items():
            if key == "scores" and isinstance(value, dict):
                additional_data = CommonHelpers.transform_dict(value)
                position_score_dict = next((item for item in additional_data if item.get("type") == "position"), {})
                additional_data = [item for item in additional_data if item.get("type") != "position"]

                for item in additional_data:
                    value_type = item.get("type")
                    table_name = "Table"
                    if value_type == "risk":
                        item.update(
                            {
                                "position_score": position_score_dict.get("score"),
                                "position_version": position_score_dict.get("version"),
                            }
                        )
                    elif value_type is not None:
                        table_name = CommonHelpers.scores_tables_name_by_types.get(value_type, "Table")

                    table = CommonHelpers.get_human_readable_feed(
                        table=item,
                        name=table_name,
                    )
                    additional_tables.append(
                        CommandResults(
                            readable_output=table,
                            ignore_auto_extract=True,
                        )
                    )

                delete_keys.append(key)

            elif isinstance(value, dict):
                additional_data = CommonHelpers.transform_dict(value)
                for index, item in enumerate(additional_data):
                    table = CommonHelpers.get_human_readable_feed(table=item, name=f"{key} table {index}")
                    additional_tables.append(
                        CommandResults(
                            readable_output=table,
                            ignore_auto_extract=True,
                        )
                    )
                delete_keys.append(key)

        for key in delete_keys:
            feed.pop(key)

        return feed, additional_tables

    @staticmethod
    def get_human_readable_feed(table: dict[Any, Any], name: str):
        return tableToMarkdown(
            name=name,
            t=table,
            removeNull=True,
        )

    @staticmethod
    def get_table_data(
        feed: dict[Any, Any],
    ):
        updated_feed, additional_tables = CommonHelpers.transform_additional_fields_to_markdown_tables(feed)

        return updated_feed, additional_tables

    @staticmethod
    def violation_source_mapping(feed: dict) -> dict:
        source = feed.get("source")
        try:
            feed["source"] = ViolationTypeMapping(source).name
        except ValueError:
            demisto.debug(f"CommonHelpers.violation_source_mapping: unknown source={source!r}, falling back to UNKNOWN")
            feed["source"] = "UNKNOWN"
        return feed

    @staticmethod
    def convert_iso8601_with_timezone(date_str: str):
        """Normalize an API timestamp to `YYYY-MM-DDTHH:MM:SS+HH:MM`.

        The list endpoint writes offsets as `+0000`, the by-id endpoint writes the same
        `dates.*` values as `+00:00`, and `Z` is accepted for completeness; all three come
        out in the one format the incident date fields expect.
        """
        match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})$", date_str)
        if not match:
            raise ValueError(
                "Invalid date format. A string in the following format is expected "
                "'YYYY-MM-DDTHH:MM:SS+0000' (or '+00:00', or 'Z')."
            )
        date_part, timezone_part = match.group(1), match.group(2)
        if timezone_part == "Z":
            return f"{date_part}+00:00"
        timezone_part = timezone_part.replace(":", "")  # '+0000'
        return f"{date_part}{timezone_part[:3]}:{timezone_part[3:]}"  # '+00:00'

    # DRP fills a date it does not know with the Unix epoch. Nothing DRP tracks
    # happened in 1970, so such a value is "unknown" and must not reach a field.
    EPOCH_DATE_PREFIX = "1970-01-01"

    @staticmethod
    def normalize_api_date(date_str: str) -> str | None:
        if date_str.startswith(CommonHelpers.EPOCH_DATE_PREFIX):
            return None
        return CommonHelpers.convert_iso8601_with_timezone(date_str)

    @staticmethod
    def format_dates_in_dict(data: dict):
        date_keys = [
            "dates_created_date",
            "dates_found_date",
            "dates_approved_date",
            "dates_current_status_date",
            "datetime",
            "first_detected",
            "first_active",
            "first_solved",
            "detected",
            "stages",
        ]
        for key, value in data.items():
            if key in date_keys and value is not None:
                if isinstance(value, str):
                    data[key] = CommonHelpers.normalize_api_date(value)
                elif isinstance(value, dict):
                    CommonHelpers.format_dates_in_dict(value)
                elif isinstance(value, list):
                    data[key] = [CommonHelpers.normalize_api_date(item) for item in value]
        return data

    @staticmethod
    def all_lists_empty(data: dict[str, Any] | list[Any]) -> bool:
        all_empty = True

        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    if value:
                        all_empty = False
                elif isinstance(value, dict) and not CommonHelpers.all_lists_empty(value):
                    all_empty = False
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and not CommonHelpers.all_lists_empty(item):
                    all_empty = False

        return all_empty

    @staticmethod
    def replace_empty_values(data: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
        if isinstance(data, dict):
            return {key: CommonHelpers.replace_empty_values(value) for key, value in data.items()}

        elif isinstance(data, list):
            if not data:
                return None  # type: ignore

            if all(isinstance(item, list) and not item for item in data):
                return None  # type: ignore

            return [CommonHelpers.replace_empty_values(item) for item in data]  # type: ignore

        else:
            if data == "":
                return None
            return data

    @staticmethod
    def remove_underscore_and_lowercase_keys(dict_list: list[dict[str, Any]] | list[dict[str, Any]]) -> list[dict[str, Any]]:
        updated_dicts = []

        for d in dict_list:
            new_dict = {}
            for key, value in d.items():
                new_key = key.replace("_", "").lower()
                new_dict[new_key] = value

            updated_dicts.append(new_dict)

        return updated_dicts

    @staticmethod
    def data_pre_cleaning(violation: dict[str, Any]) -> dict[str, Any]:
        demisto.debug(
            f"CommonHelpers.data_pre_cleaning start: keys={list(violation.keys())}, "
            f"uri='{violation.get('violation_uri', '')}'"
        )
        violation_uri: str = violation.get("violation_uri", "")
        if violation_uri.startswith("//"):
            violation_uri = violation_uri[2:]

        violation["violation_uri"] = violation_uri

        tags = violation.get("tags")
        if tags:
            tags = [item for item in tags if item is not None]

        violation["tags"] = tags

        if not violation.get("dates_current_status_date"):
            violation["dates_current_status_date"] = violation.get("dates_current_date")
        violation.pop("dates_current_date", None)

        violation_type = violation.get("violation_type")
        if isinstance(violation_type, str):
            violation["violation_type"] = Mappings.VIOLATION_SUBTYPE_CODE_LABELS.get(violation_type, violation_type)

        demisto.debug(
            f"CommonHelpers.data_pre_cleaning done: uri='{violation_uri}', "
            f"tags_count={len(tags) if isinstance(tags, list) else 0}, keys={list(violation.keys())}"
        )
        return violation

    @staticmethod
    def extract_mime_type(content_type: str) -> str:
        match = re.match(r"^\s*([^;]+)", content_type)
        return match.group(1).strip() if match else "image/jpeg"

    @staticmethod
    def set_tag_downloaded_by_typoSquatting(violation: dict[str, Any], only_typosquatting: bool) -> dict[str, Any]:
        if violation.get("typosquatting_status", None) and only_typosquatting:
            violation["typosquatting_status"] = True
        else:
            violation["typosquatting_status"] = False
        return violation


""" Fetch filters """


class ViolationSubtypeFilter:
    """The normalized `Filter by Violation Type` selection.

    Holds both halves of the same selection: the canonical labels used to match
    a parsed violation, and the DRP `subtypes[]` ids used to narrow the query.

    Only a single-value selection is pushed to the API. The bundled `ciaops`
    generator serializes `subtypes[0]` alone, so sending a multi-value selection
    would silently drop every value but the first and lose those violations for
    good. With more than one type selected the query therefore stays unfiltered
    and the whole selection is enforced client-side, which costs bandwidth but
    never data.
    """

    def __init__(self, labels: set[str]) -> None:
        self.labels = labels
        self._lowered = {label.lower() for label in labels}

    @classmethod
    def from_param(cls, value: Any) -> "ViolationSubtypeFilter":
        """Build the filter from the raw parameter (None/empty, CSV or list).

        Values are matched case-insensitively against `Mappings.VIOLATION_SUBTYPE_IDS`
        and stored in their canonical spelling. An unknown value raises `ValueError`
        listing the offending tokens, so a typo in the instance config is caught at
        startup instead of silently filtering everything out.
        """
        items = argToList(value)
        if not items:
            return cls(set())

        canonical = {label.lower(): label for label in Mappings.VIOLATION_SUBTYPE_IDS}
        # The API specification calls the Scam subtype `fraud`; accept that spelling too, so a
        # value typed from the specification (or an instance saved before the rename) still works.
        canonical.setdefault("fraud", "Scam")
        labels: set[str] = set()
        unknown: list[str] = []
        for item in items:
            token = str(item).strip()
            if not token:
                continue
            label = canonical.get(token.lower())
            if label is None:
                unknown.append(token)
            else:
                labels.add(label)

        if unknown:
            raise ValueError(
                "Unknown violation type(s): " + ", ".join(sorted(unknown)) + ". "
                "Supported values: " + ", ".join(Mappings.VIOLATION_SUBTYPE_IDS)
            )
        return cls(labels)

    @property
    def is_empty(self) -> bool:
        return not self.labels

    @property
    def server_side_ids(self) -> list[int] | None:
        """The `subtypes[]` ids to send, or None when the query must stay open."""
        if len(self.labels) != 1:
            return None
        return [Mappings.VIOLATION_SUBTYPE_IDS[next(iter(self.labels))]]

    def matches(self, violation_type: Any) -> bool:
        """True when `violation_type` is selected, or when nothing is selected.

        The filter semantics of the fetch parameters: an empty selection is
        "do not filter", so every violation passes.
        """
        return True if self.is_empty else self.contains(violation_type)

    def contains(self, violation_type: Any) -> bool:
        """True only when `violation_type` is explicitly selected.

        The opt-in semantics: an empty selection selects nothing, which is what
        "create indicators for these violation types" has to mean.
        """
        if not isinstance(violation_type, str):
            return False
        return violation_type.strip().lower() in self._lowered


""" Known-violations cache """


class Deduplicator:
    """The `found_incident_ids` cache of violations this instance has emitted.

    A flat `dict[str, float]` of violation id -> unix timestamp of the last fetch that
    emitted it. `IncidentBuilder` passes a cached id through as an update and puts a
    new id through the creation filters. This class owns the parameter parsing, the
    retention pruning and the cache update; all methods are stateless and the cache
    itself lives in `lastRun`.
    """

    @staticmethod
    def convert_lookback_days_to_seconds(dedup_lookback_days: int) -> int:
        """Convert the user-facing `dedup_lookback_days` parameter into seconds.

        The integration owns its own cache cleanup (see `prune_seen_ids`)
        instead of relying on `CommonServerPython.remove_old_incidents_ids`,
        which applies a hidden `* 2` multiplier and keeps the latest ids
        forever. Owning the conversion guarantees a 1:1 contract: an id last
        emitted today is dropped exactly `dedup_lookback_days` days later.
        Non-positive inputs produce a non-positive retention, which
        `prune_seen_ids` treats as the drop-all kill-switch.
        """
        return dedup_lookback_days * Consts.SECONDS_IN_DAY

    @staticmethod
    def lookback_days_from_params(params: dict) -> int:
        """Parse the `dedup_lookback_days` parameter, falling back to the default.

        Empty, None and missing values fall back to Consts.DEFAULT_DEDUP_LOOKBACK_DAYS.
        Boolean inputs are rejected explicitly to keep the contract narrow.
        """
        dedup_lookback_days = params.get("dedup_lookback_days")
        if dedup_lookback_days in (None, ""):
            return Consts.DEFAULT_DEDUP_LOOKBACK_DAYS

        if isinstance(dedup_lookback_days, bool):
            raise ValueError("dedup_lookback_days must be an integer number of days.")

        if isinstance(dedup_lookback_days, int):
            return dedup_lookback_days

        if isinstance(dedup_lookback_days, str):
            return int(dedup_lookback_days)

        raise ValueError("dedup_lookback_days must be a string or integer value.")

    @staticmethod
    def prune_seen_ids(
        seen_ids: dict[str, float],
        retention_seconds: int,
        *,
        now: float | None = None,
    ) -> dict[str, float]:
        """Drop every cached incident id older than `retention_seconds`.

        Pure (no I/O, no demisto calls) and accepts an explicit `now` so it
        stays trivially testable. Returns a NEW dict and never mutates the input.

        Contract:
            * `retention_seconds <= 0` -> the entire cache is dropped (the
              documented kill-switch for `dedup_lookback_days = 0`; with no
              cache every violation goes through the creation filters again).
            * Entries with non-numeric / negative timestamps are treated as
              "unknown age" and dropped defensively.

        Unlike `CommonServerPython.remove_old_incidents_ids`, this does NOT pin
        the newest id forever, so a single never-re-fetched id cannot grow the
        cache unboundedly and the 1:1 contract with `dedup_lookback_days` holds.
        """
        if retention_seconds <= 0:
            return {}

        current_time = time.time() if now is None else now
        threshold = current_time - retention_seconds

        pruned: dict[str, float] = {}
        for inc_id, addition_time in seen_ids.items():
            if not isinstance(addition_time, int | float) or isinstance(addition_time, bool) or addition_time < 0:
                continue
            if addition_time >= threshold:
                pruned[inc_id] = float(addition_time)
        return pruned

    @staticmethod
    def update_seen_cache(
        last_run_state: dict,
        incidents: list[dict],
        dedup_lookback_days: int,
    ) -> None:
        """Record the ids of `incidents` as emitted now and prune old entries.

        An id already in the cache gets its timestamp refreshed, so a violation
        that keeps changing stays known for as long as it is alive. Mutates
        `last_run_state[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY]` in place.
        """
        if not incidents:
            return

        raw_cache = last_run_state.get(Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY) or {}
        if not isinstance(raw_cache, dict):
            raw_cache = {}

        cache: dict[str, float] = {}
        for inc_id, addition_time in raw_cache.items():
            if isinstance(addition_time, int | float) and not isinstance(addition_time, bool):
                cache[str(inc_id)] = float(addition_time)

        now_ts = time.time()
        for incident in incidents:
            inc_id = incident.get("id")
            if inc_id is None:
                continue
            cache[str(inc_id)] = now_ts

        retention_seconds = Deduplicator.convert_lookback_days_to_seconds(dedup_lookback_days)
        last_run_state[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY] = Deduplicator.prune_seen_ids(
            cache,
            retention_seconds=retention_seconds,
            now=now_ts,
        )


""" IncidentBuilder """


class IncidentBuilder:
    def __init__(
        self,
        client: Client,
        last_run: dict,
        first_fetch_time: str,
        max_requests: int,
        download_images: bool,
        only_typosquatting: bool,
        violation_subtypes: ViolationSubtypeFilter | None,
        violation_section: str | None,
        brands: str | None,
        dedup_lookback_days: int = Consts.DEFAULT_DEDUP_LOOKBACK_DAYS,
        max_incidents_per_fetch: int = Consts.DEFAULT_MAX_INCIDENTS_PER_FETCH,
        violation_statuses: list[str] | None = None,
        only_approval_required: bool = False,
        indicator_subtypes: ViolationSubtypeFilter | None = None,
        expire_indicator_on_close: bool = False,
        incident_severity: float | None = None,
    ) -> None:
        """Builds the incidents of one fetch.

        Filters split in two. `violation_subtypes`, `violation_section` and `brands`
        describe attributes a violation never changes and narrow the API query. The
        status and approval filters are applied only when an incident is *created*: a
        violation whose id is already in the known-violations cache is an update of an
        existing incident and is passed through unfiltered, so the pre-processing rule
        can refresh and close that incident whatever state the violation moved to.
        """
        self.client = client
        self.last_run = last_run
        self.first_fetch_time = first_fetch_time
        self.max_requests = max_requests
        self.violation_subtypes = violation_subtypes or ViolationSubtypeFilter(set())
        self.violation_section = violation_section
        self.brands = brands
        self.download_images = download_images
        self.only_typosquatting = only_typosquatting
        self.only_approval_required = only_approval_required
        # Empty selection means "no indicators", the opposite of the fetch filters,
        # where an empty selection means "everything". The indicator itself is created
        # by the postprocessing playbook, from the incident; the fetch only marks the
        # incident as wanting one.
        self.indicator_subtypes = indicator_subtypes or ViolationSubtypeFilter(set())
        self.expire_indicator_on_close = expire_indicator_on_close
        self.incident_severity = incident_severity
        if dedup_lookback_days < 0:
            raise ValueError("dedup_lookback_days must be greater than or equal to 0.")
        self.dedup_lookback_days = dedup_lookback_days
        # Hard incident-count cap; <=0 means "no cap" (caller's choice).
        self.max_incidents_per_fetch = max_incidents_per_fetch
        # Normalize the status-filter list once: lower-case, deduplicated,
        # and validated against the supported set so a typo in the YAML
        # config is caught with an actionable error instead of silently
        # filtering everything out.
        self.violation_statuses: set[str] = self._validate_violation_statuses(violation_statuses)

    @staticmethod
    def _validate_violation_statuses(value: Any) -> set[str]:
        """Normalize the `violationStatuses` parameter into a validated set.

        Accepts None/empty (no filter), a CSV string, or a list of strings.
        Each element is lower-cased, stripped, and validated against
        `Mappings.SUPPORTED_VIOLATION_STATUSES`. Unknown values raise `ValueError`
        with the offending tokens listed so the analyst can correct the
        instance config without trial-and-error.
        """
        if value in (None, ""):
            return set()

        if isinstance(value, str):
            items = [s.strip() for s in value.split(",") if s.strip()]
        elif isinstance(value, list):
            items = [str(s).strip() for s in value if str(s).strip()]
        else:
            raise ValueError("violationStatuses must be a list or a comma-separated string.")

        normalized = {s.lower() for s in items}
        unknown = normalized - Mappings.SUPPORTED_VIOLATION_STATUSES
        if unknown:
            raise ValueError(
                "Unknown violation status(es): " + ", ".join(sorted(unknown)) + ". "
                "Supported values: " + ", ".join(sorted(Mappings.SUPPORTED_VIOLATION_STATUSES))
            )
        return normalized

    @staticmethod
    def is_finished(violation: dict[str, Any]) -> bool:
        """True when DRP has finished with the violation or the customer rejected it."""
        status = violation.get("violation_status")
        if isinstance(status, str) and status.strip().lower() in Mappings.FINISHED_VIOLATION_STATUSES:
            return True
        return violation.get("approve_state") == Mappings.APPROVE_STATE_REJECTED

    @staticmethod
    def incident_name(violation: dict[str, Any]) -> str:
        """`<Type> · <Brand> · <URI>`, from whichever of the three the violation has.

        The DRP title is the same sentence for every violation of a type, so a list of
        incidents named by it cannot be told apart. The title stays in GIB DRP Title.
        """
        parts = [violation.get(key) for key in ("violation_type", "brand", "violation_uri")]
        present = [str(part).strip() for part in parts if isinstance(part, str) and part.strip()]
        if present:
            return " · ".join(present)
        return str(violation.get("title") or f"Violation {violation.get('id')}")

    @staticmethod
    def occurred_for(violation: dict[str, Any], now: datetime | None = None) -> str | None:
        """The incident's `occurred`: `detected`, unless it is missing or older than a year.

        DRP keeps `detected` from the first detection, so for a violation that resurfaced
        it can be years old; the current status date is then when the violation became
        the customer's concern. The dates are already normalized to ISO 8601 with an
        offset by `CommonHelpers.format_dates_in_dict`.
        """
        detected = violation.get("detected")
        fallback = violation.get("dates_current_status_date") or violation.get("dates_created_date")
        if not isinstance(detected, str) or not detected:
            return fallback
        try:
            detected_at = datetime.fromisoformat(detected)
        except ValueError:
            return fallback or detected
        if detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        if current - detected_at > timedelta(days=Consts.OCCURRED_MAX_AGE_DAYS) and fallback:
            return fallback
        return detected

    def transform_fields_to_grid_table(self, incident: dict):
        if Mappings.TABLES_MAPPING:
            for field in Mappings.TABLES_MAPPING:
                field_data = incident.get(field, {})
                if field_data and CommonHelpers.all_lists_empty(field_data) is False:
                    transformed_data = CommonHelpers.transform_dict(input_dict=field_data)

                    transformed_and_replaced_empty_values_data = CommonHelpers.replace_empty_values(transformed_data)
                    clean_data = CommonHelpers.remove_underscore_and_lowercase_keys(
                        transformed_and_replaced_empty_values_data  # type: ignore
                    )
                    if field == "scores":
                        clean_data = [item for item in clean_data if item["type"] != "position"]
                        for score in clean_data:
                            score_type = score.get("type")
                            if isinstance(score_type, str):
                                score["type"] = CommonHelpers.scores_tables_name_by_types.get(score_type, "Unknown")
                            else:
                                score["type"] = "Unknown"

                        demisto.debug(
                            "IncidentBuilder.transform_fields_to_grid_table: scores normalized "
                            f"(count={len(clean_data)}, types={[item.get('type') for item in clean_data]})"
                        )

                    if field == "stages":
                        # Numeric stage codes are SOC-hostile in a layout. Add a
                        # human-readable `stagename` column while preserving the
                        # original `type` integer so downstream automations that
                        # already filter on the code keep working.
                        for stage in clean_data:
                            raw_type = stage.get("type")
                            stage["stagename"] = (
                                Mappings.STAGE_TYPE_LABELS.get(raw_type, "Unknown") if isinstance(raw_type, int) else "Unknown"
                            )

                        demisto.debug(
                            "IncidentBuilder.transform_fields_to_grid_table: stages enriched "
                            f"(count={len(clean_data)}, types={[s.get('type') for s in clean_data]})"
                        )

                    incident[field] = clean_data
                else:
                    incident[field] = None

        return incident

    def _embed_images(self, image_shas: list) -> str | None:
        """Download violation images and return them as inline base64 HTML.

        Enforces the per-image and per-incident byte caps; oversize images are
        skipped (their file_sha stays retrievable via
        gibdrp-get-violation-by-id). Returns None when nothing was embedded.
        """
        embedded: list[str] = []
        total_bytes = 0
        # The payload lists the same hash once per stage/screenshot; one copy per image is enough
        # and keeps the per-incident byte budget for distinct screenshots.
        for file_sha in dict.fromkeys(image_shas):
            image_data = self.client.get_file(file_sha=file_sha)
            if not image_data:
                continue
            image_bytes, mime_type = image_data
            size = len(image_bytes)
            if size > Consts.MAX_IMAGE_BYTES or total_bytes + size > Consts.MAX_IMAGES_TOTAL_BYTES_PER_INCIDENT:
                demisto.debug(
                    "IncidentBuilder._embed_images: skipping oversize image - "
                    f"file_sha={file_sha} size={size} embedded_so_far={total_bytes}"
                )
                continue
            total_bytes += size
            image_base64_uri = f"data:{mime_type};base64,{base64.b64encode(image_bytes).decode('utf-8')}"
            embedded.append(f'<img src="{image_base64_uri}" alt="Violation Incident Image" />')
        return "<br/>".join(embedded) if embedded else None

    def build(self) -> tuple[dict[str, int | Any], list]:
        # A shallow copy of last_run is the mutable working state for the known-violations
        # cache: `Deduplicator.update_seen_cache` rewrites
        # `last_run_state[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY]` in place, and the final
        # value is persisted into `next_run`.
        last_run_state: dict = self.last_run.copy() if isinstance(self.last_run, dict) else {}
        previous_last_fetch = last_run_state.get("last_fetch")
        next_run: dict[str, int | Any] = {"last_fetch": previous_last_fetch}
        violations: list[dict[str, Any]] = []
        requests_count = 0
        max_seq_update: int | None = None

        # Entries past the retention are forgotten before the fetch, not only after it, so a
        # violation that went quiet for longer than the retention is filtered as new again.
        seen_cache_in = last_run_state.get(Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY, {})
        seen_cache_in = {str(key): value for key, value in seen_cache_in.items()} if isinstance(seen_cache_in, dict) else {}
        last_run_state[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY] = Deduplicator.prune_seen_ids(
            seen_cache_in,
            retention_seconds=Deduplicator.convert_lookback_days_to_seconds(self.dedup_lookback_days),
        )
        known_ids: set[str] = set(last_run_state[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY])
        demisto.debug(
            "IncidentBuilder.build: known-violations cache - "
            f"retention_days={self.dedup_lookback_days} cache_size_in={len(seen_cache_in)} known={len(known_ids)}"
        )

        portions = self.client.create_generator(
            violation_subtypes=self.violation_subtypes.server_side_ids,
            section=self.violation_section,
            brands=self.brands,
            first_fetch_time=self.first_fetch_time,
            last_run=self.last_run,
            only_typosquatting=self.only_typosquatting,
        )
        for portion in portions:
            portion_sequpdate = getattr(portion, "sequpdate", None)
            demisto.debug(
                "IncidentBuilder.build: processing portion - "
                f"requests_count={requests_count} max_requests={self.max_requests} "
                f"portion_sequpdate={portion_sequpdate!r}"
            )
            sequpdate = portion.sequpdate
            parse_result: list[dict[Any, Any]] = portion.parse_portion(keys=Mappings.COMMON_VIOLATION_MAPPING, as_json=False)
            demisto.debug(
                "IncidentBuilder.build: portion parsed - " f"portion_sequpdate={sequpdate!r} parsed_items={len(parse_result)}"
            )

            created_before = len(violations)
            max_seq_before = max_seq_update
            updates_in_portion = 0
            finished_skipped_in_portion = 0
            status_filtered_in_portion = 0
            type_filtered_in_portion = 0
            approval_filtered_in_portion = 0
            limit_reached = False

            # Phase 1: normalize every violation and decide whether it is an update of an
            # incident this instance created (passed through as it is) or a candidate for a
            # new incident (subject to the creation filters). Image download is deferred to
            # phase 2 so no image is fetched for a violation that is dropped here.
            kept: list[dict[str, Any]] = []
            for feed in parse_result:
                feed = CommonHelpers.data_pre_cleaning(violation=feed)
                feed = CommonHelpers.violation_source_mapping(feed=feed)
                feed = CommonHelpers.format_dates_in_dict(data=feed)
                feed = CommonHelpers.set_tag_downloaded_by_typoSquatting(
                    violation=feed, only_typosquatting=self.only_typosquatting
                )
                incident = self.transform_fields_to_grid_table(incident=feed)

                violation_id = str(incident.get("id") or "")
                if violation_id and violation_id in known_ids:
                    updates_in_portion += 1
                    kept.append(incident)
                    continue

                # A violation DRP has finished with, or the customer rejected, gets no
                # incident: it would be closed the moment it was created. This is what
                # keeps a first fetch from creating an incident per resolved violation.
                if self.is_finished(incident):
                    finished_skipped_in_portion += 1
                    continue

                # The status filter is applied here because `ciaops` does not expose the
                # `status[]` query parameter, and because it must apply to creation only.
                # The seqUpdate cursor is taken from `portion.sequpdate`, not from the kept
                # incidents, so dropping items here is safe with respect to fetch progress.
                if self.violation_statuses:
                    status = incident.get("violation_status")
                    if not isinstance(status, str) or status.lower() not in self.violation_statuses:
                        status_filtered_in_portion += 1
                        continue

                # The type filter is enforced here for the same reason, plus one of
                # its own: `subtypes[]` only reaches the API when a single type is
                # selected (see ViolationSubtypeFilter), so for a multi-type
                # selection this is the only place the filter is applied at all.
                if not self.violation_subtypes.matches(incident.get("violation_type")):
                    type_filtered_in_portion += 1
                    continue

                # Approval is a state the violation leaves once the customer decides, so it is
                # never pushed to the API: the decided violation must keep arriving as an update.
                if self.only_approval_required and incident.get("approve_state") != Mappings.APPROVE_STATE_UNDER_REVIEW:
                    approval_filtered_in_portion += 1
                    continue

                kept.append(incident)

            # Phase 2: build the incidents (image download happens here, only for
            # violations that are emitted).
            for incident in kept:
                if self.download_images:
                    images_html = self._embed_images(incident.get("images") or [])
                    if images_html:
                        incident["images"] = images_html
                    else:
                        incident.pop("images", None)
                else:
                    incident.pop("images", None)

                # `name` and `occurred` are computed here and mapped by the incoming mapper
                # from these keys, so the two never disagree. `dates_created_date` and
                # `detected` still reach the incident through their own fields.
                incident.update(
                    {
                        "name": self.incident_name(incident),
                        "occurred": self.occurred_for(incident),
                        "gibType": Endpoints.VIOLATIONS.value,
                        # Read by the postprocessing playbook, which creates the indicator
                        # from the incident so that it is linked to it and carries a source.
                        "indicator_wanted": self.indicator_subtypes.contains(incident.get("violation_type")),
                        "indicator_expire_on_close": self.expire_indicator_on_close,
                    }
                )
                # `severity` is not part of the incoming mapper, so the value set here
                # is the one the incident is created with.
                violation_incident: dict[str, Any] = {
                    "name": incident.get("name"),
                    "occurred": incident.get("occurred"),
                    "rawJSON": json_dumps(incident),
                    "dbotMirrorId": incident.get("id"),
                }
                if self.incident_severity is not None:
                    violation_incident["severity"] = self.incident_severity
                violations.append(violation_incident)

            # Every id emitted in this portion is a known violation from now on; an id that
            # already was gets its timestamp refreshed, so a violation that keeps changing
            # stays known for as long as it is alive.
            emitted_with_id = [inc for inc in kept if inc.get("id") not in (None, "")]
            if emitted_with_id:
                Deduplicator.update_seen_cache(
                    last_run_state=last_run_state,
                    incidents=emitted_with_id,
                    dedup_lookback_days=self.dedup_lookback_days,
                )
                known_ids = {str(key) for key in last_run_state.get(Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY) or {}}

            # Track the highest seqUpdate AFTER we've fully drained the
            # portion. This guarantees that we never advance the cursor
            # past items we did not process, so the per-fetch incident
            # cap (`max_incidents_per_fetch`) is always portion-aligned
            # and never produces a partial portion.
            try:
                if isinstance(sequpdate, int):
                    current_max = max_seq_update if isinstance(max_seq_update, int) else 0
                    max_seq_update = max(sequpdate, current_max)
            except Exception as e:
                demisto.debug(
                    "IncidentBuilder.build: failed to compare/track seqUpdate; skipping. "
                    f"sequpdate={sequpdate!r} max_seq_update={max_seq_update!r} "
                    f"error_type={type(e).__name__} error={e!s}\n{format_exc()}"
                )
            requests_count += 1
            created_after = len(violations)

            # Per-fetch incident cap is checked here so the current
            # portion is fully consumed before we stop. The cursor
            # advance above is consistent with the portions we drained.
            if self.max_incidents_per_fetch > 0 and len(violations) >= self.max_incidents_per_fetch:
                limit_reached = True

            demisto.debug(
                "IncidentBuilder.build: portion done - "
                f"portion_sequpdate={sequpdate!r} emitted_in_portion={created_after - created_before} "
                f"updates_in_portion={updates_in_portion} "
                f"finished_skipped_in_portion={finished_skipped_in_portion} "
                f"status_filtered_in_portion={status_filtered_in_portion} "
                f"type_filtered_in_portion={type_filtered_in_portion} "
                f"approval_filtered_in_portion={approval_filtered_in_portion} "
                f"limit_reached={limit_reached} "
                f"max_seq_update_before={max_seq_before!r} max_seq_update_after={max_seq_update!r} "
                f"requests_count={requests_count} max_requests={self.max_requests}"
            )
            if limit_reached:
                demisto.debug(
                    "IncidentBuilder.build: stopping due to max_incidents_per_fetch - "
                    f"limit={self.max_incidents_per_fetch} created={len(violations)} "
                    f"last_portion_sequpdate={sequpdate!r} max_seq_update={max_seq_update!r}"
                )
                break
            if requests_count >= self.max_requests:
                demisto.debug(
                    "IncidentBuilder.build: stopping due to max_requests limit - "
                    f"requests_count={requests_count} max_requests={self.max_requests} "
                    f"last_portion_sequpdate={sequpdate!r} max_seq_update={max_seq_update!r}"
                )
                break
            time.sleep(Consts.PORTION_PACING_SECONDS)
        # Decide effective next_run.last_fetch
        effective_last = previous_last_fetch
        if isinstance(max_seq_update, int) and max_seq_update > 0:
            if isinstance(previous_last_fetch, int) and previous_last_fetch > 0:
                effective_last = max(previous_last_fetch, max_seq_update)
            else:
                effective_last = max_seq_update
        else:
            demisto.debug(
                "IncidentBuilder.build: not updating last_fetch because no seqUpdate was observed - "
                f"previous_last_fetch={previous_last_fetch!r} max_seq_update={max_seq_update!r} "
                f"requests_count={requests_count} created_incidents={len(violations)}"
            )
        next_run["last_fetch"] = effective_last

        # Persist the known-violations cache, updated and pruned in place per portion.
        final_cache = last_run_state.get(Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY, {})
        if not isinstance(final_cache, dict):
            final_cache = {}
        next_run[Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY] = final_cache

        demisto.debug(
            "IncidentBuilder.build: "
            f"computed next_run.last_fetch={effective_last} "
            f"(prev={previous_last_fetch}, max_seq={max_seq_update}); "
            f"known_violations_cache_size={len(final_cache)}"
        )
        return next_run, violations


class BuilderCommandResponses:
    def __init__(
        self,
        requested_method: str,
        client: Client,
        args: dict,
        first_fetch: str,
        max_requests: int,
        close_incident_on_decision: bool = False,
    ) -> None:
        self.requested_method = requested_method
        self.client = client
        self.args = args
        self.first_fetch = first_fetch
        self.max_requests = max_requests
        self.close_incident_on_decision = close_incident_on_decision

    def get_brands(self) -> CommandResults:
        response_result = self.client.get_formatted_brands()
        readable_output = tableToMarkdown(
            name="Installed Brands",
            t=response_result,
            headers=["name", "id"],
            headerTransform=lambda x: x.capitalize(),
        )

        return CommandResults(
            outputs_prefix="GIBDRP.Brand",
            outputs_key_field="id",
            outputs=response_result,
            readable_output=readable_output,
            ignore_auto_extract=True,
            raw_response=response_result,
        )

    def get_subscriptions(self) -> CommandResults:
        response_result = self.client.get_formatted_subscriptions()
        readable_output = tableToMarkdown(
            name="Purchased subscriptions",
            t=response_result,
            headers="Subscriptions",
        )
        return CommandResults(
            outputs_prefix="GIBDRP.Subscription",
            outputs=response_result,
            readable_output=readable_output,
            ignore_auto_extract=True,
            raw_response=response_result,
        )

    def get_violation_by_id(self) -> list[CommandResults]:
        """
        the returned list has dict[str, Any], which is fileResult.
        And an important note, not necessarily picture files, i.e. fileResults definitely will be.
        """
        id_ = str(self.args.get("id"))
        get_images = argToBoolean(self.args.get("download_images", True))
        parse_result, updated_images = self.client.get_formatted_violation_by_id(violation_id=id_, get_images=get_images)
        parse_result = CommonHelpers.data_pre_cleaning(violation=parse_result)
        parse_result = CommonHelpers.violation_source_mapping(feed=parse_result)
        # Same date normalization as the fetch: one offset format, and the 1970 placeholder
        # DRP uses for an unknown date becomes an empty value instead of a bogus timestamp.
        parse_result = CommonHelpers.format_dates_in_dict(data=parse_result)
        # `*typosquatting_status` in the mapping is a placeholder the fetch turns into a boolean;
        # by-id has no typosquatting context, so drop it instead of outputting the literal name.
        parse_result.pop("typosquatting_status", None)
        updated_feed, additional_tables = CommonHelpers.get_table_data(feed=parse_result)
        readable_output = CommonHelpers.get_human_readable_feed(table=updated_feed, name=f"Feed {id_}")
        results = []
        results.append(
            CommandResults(
                outputs_prefix="GIBDRP.Violation",
                outputs_key_field="id",
                outputs=updated_feed,
                readable_output=readable_output,
                raw_response=updated_feed,
                ignore_auto_extract=True,
            )
        )
        results.extend(additional_tables)
        if updated_images:
            for updated_image in updated_images:
                results.append(
                    fileResult(
                        filename=f"Attached image {updated_image.get('file_sha', 'default')}",  # type: ignore
                        data=updated_image.get("image_data", ""),
                    )
                )
        return results

    def create_violation(self) -> CommandResults:
        """Create one or more DRP violations from URLs sharing a subtype and brand.

        Raises at the command boundary when the API accepts none of the
        submitted items, so a fully-failed submission surfaces as an error
        entry instead of a success-looking War Room note. A partial success
        (HTTP 207) is reported with both the succeeded and failed tables.
        """
        urls = argToList(self.args.get("url"))
        raw_subtype = str(self.args.get("violation_subtype", "")).strip()
        brand_id = str(self.args.get("brand_id", "")).strip()

        if not urls:
            raise DemistoException("At least one URL must be provided in the 'url' argument.")
        if len(urls) > Consts.MAX_CREATE_VIOLATION_ITEMS:
            raise DemistoException(
                f"Too many URLs: {len(urls)}. The DRP violation/add endpoint accepts at most "
                f"{Consts.MAX_CREATE_VIOLATION_ITEMS} items per request."
            )
        # The API enum is case-sensitive (`partnerPolicyCompliance`), so user
        # input is matched case-insensitively and mapped to the canonical value.
        violation_subtype = {s.lower(): s for s in Mappings.SUPPORTED_VIOLATION_SUBTYPES}.get(raw_subtype.lower())
        if violation_subtype is None:
            raise DemistoException(
                f"Unsupported violation_subtype '{raw_subtype}'. "
                "Supported values: " + ", ".join(sorted(Mappings.SUPPORTED_VIOLATION_SUBTYPES))
            )
        if not brand_id:
            raise DemistoException(
                "The 'brand_id' argument must not be empty. "
                "Use !gibdrp-get-brands to list the brand IDs configured for your account."
            )

        try:
            response = self.client.create_violations(urls=urls, violation_subtype=violation_subtype, brand_id=brand_id)
        except ConnectionException as e:
            # HTTP 400 (every item rejected) reaches here as a generic
            # ConnectionException; the response body with per-item reasons is
            # not available from the SDK.
            raise DemistoException(
                f"Group-IB DRP rejected the violation batch: {e!s} "
                "DRP refuses a batch when every item is invalid: a URL that is not a valid http/https URL with a host, "
                'a URL already submitted for this brand and subtype ("This URL already exists"), or an unknown brand ID. '
                "The per-item reasons are not exposed by the SDK; check the URLs and use !gibdrp-get-brands for the brand IDs."
            ) from e
        succeeded = response.get("succeeded") or []
        failed = response.get("failed") or []

        if not succeeded:
            raise DemistoException(
                f"Group-IB DRP rejected all {len(urls)} submitted violation item(s). Failed items: {json_dumps(failed)}"
            )

        readable_output = tableToMarkdown(name="Created violations", t=succeeded, removeNull=True)
        if failed:
            readable_output += "\n" + tableToMarkdown(name="Rejected violations", t=failed, removeNull=True)

        return CommandResults(
            outputs_prefix="GIBDRP.CreatedViolation",
            outputs={"succeeded": succeeded, "failed": failed},
            readable_output=readable_output,
            raw_response=response,
            ignore_auto_extract=True,
        )

    def change_violation_status(self) -> CommandResults:
        """Approve or reject a violation and tell the caller what the instance wants done with the incident.

        `closeIncident` carries the instance's **Close the incident when a violation is approved**
        setting. An integration command cannot close the investigation it runs from, so the decision
        is taken here, where the instance configuration lives, and carried out by
        `GIBDRPResolveViolation`, which runs behind the layout buttons and the playbook. A rejection
        closes the incident regardless; that rule lives in the automation, not in a setting.
        """
        id_ = str(self.args.get("id"))
        status = str(self.args.get("status"))
        self.client.change_violation_status(feed_id=id_, status=status)
        outputs = {
            "id": id_,
            "status": status,
            "approveState": Mappings.APPROVE_STATE_AFTER_DECISION.get(status),
            "closeIncident": self.close_incident_on_decision,
        }
        return CommandResults(
            outputs_prefix="GIBDRP.ViolationDecision",
            outputs_key_field="id",
            outputs=outputs,
            raw_response=outputs,
            readable_output=f"Violation '{id_}' was changed to '{status}'.",
            # The id is a 64-hex string; a plain entry would be auto-extracted as a SHA256 File indicator.
            ignore_auto_extract=True,
        )

    def build(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        if not hasattr(self, self.requested_method):
            raise AttributeError(f"Method {self.requested_method} is not implemented.")
        return getattr(self, self.requested_method)()


""" Commands """


class Commands:
    """XSOAR command dispatcher for the Group-IB DRP integration.

    `_COMMAND_TO_METHOD` is the auditable whitelist of every command name
    declared in the integration yml: an unregistered command is rejected in
    `main()` before dispatch, so a new public method never silently becomes
    a callable XSOAR command. `Commands` itself implements only the methods
    with command-specific wiring (`test_module`, `fetch_incidents`); every
    other registered name resolves on `BuilderCommandResponses` at runtime
    via `_delegate_to_builder`.
    """

    _COMMAND_TO_METHOD: dict[str, str] = {
        "test-module": "test_module",
        "fetch-incidents": "fetch_incidents",
        "gibdrp-get-brands": "get_brands",
        "gibdrp-get-subscriptions": "get_subscriptions",
        "gibdrp-get-violation-by-id": "get_violation_by_id",
        "gibdrp-change-violation-status": "change_violation_status",
        "gibdrp-create-violation": "create_violation",
    }

    def __init__(
        self,
        client: Client,
        command: str,
        args: dict,
        first_fetch: str,
        max_requests: int,
        download_images: bool,
        only_typosquatting: bool,
        violation_subtypes: ViolationSubtypeFilter | None,
        violation_section: str | None = None,
        brands: str | None = None,
        dedup_lookback_days: int = Consts.DEFAULT_DEDUP_LOOKBACK_DAYS,
        max_incidents_per_fetch: int = Consts.DEFAULT_MAX_INCIDENTS_PER_FETCH,
        violation_statuses: list[str] | None = None,
        only_approval_required: bool = False,
        indicator_subtypes: ViolationSubtypeFilter | None = None,
        expire_indicator_on_close: bool = False,
        incident_severity: float | None = None,
        close_incident_on_decision: bool = False,
    ) -> None:
        self.client = client
        self.command = command
        self.args = args
        self.first_fetch = first_fetch
        self.max_requests = max_requests
        self.last_run = demisto.getLastRun()
        self.requested_method = self._COMMAND_TO_METHOD.get(command, "")
        self.violation_subtypes = violation_subtypes
        self.violation_section = violation_section
        self.brands = brands
        self.download_images = download_images
        self.only_typosquatting = only_typosquatting
        self.dedup_lookback_days = dedup_lookback_days
        self.max_incidents_per_fetch = max_incidents_per_fetch
        self.violation_statuses = violation_statuses
        self.only_approval_required = only_approval_required
        self.indicator_subtypes = indicator_subtypes
        self.expire_indicator_on_close = expire_indicator_on_close
        self.incident_severity = incident_severity
        self.close_incident_on_decision = close_incident_on_decision

    def _delegate_to_builder(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        return BuilderCommandResponses(
            self.requested_method,
            self.client,
            self.args,
            self.first_fetch,
            self.max_requests,
            close_incident_on_decision=self.close_incident_on_decision,
        ).build()

    def test_module(self) -> str:
        """Reaching the API is the test; having brands configured is not.

        A company with valid credentials and zero configured brands is a legitimate state, so the
        check is that the brands endpoint answers, not that it answers with something. A failure
        surfaces as the underlying connection/auth error rather than as a message about brands.
        """
        self.client.get_formatted_brands()
        return "ok"

    def fetch_incidents(
        self,
    ) -> tuple[dict[str, int | Any], list]:
        return IncidentBuilder(
            client=self.client,
            last_run=self.last_run,
            first_fetch_time=self.first_fetch,
            max_requests=self.max_requests,
            violation_subtypes=self.violation_subtypes,
            violation_section=self.violation_section,
            brands=self.brands,
            download_images=self.download_images,
            only_typosquatting=self.only_typosquatting,
            dedup_lookback_days=self.dedup_lookback_days,
            max_incidents_per_fetch=self.max_incidents_per_fetch,
            violation_statuses=self.violation_statuses,
            only_approval_required=self.only_approval_required,
            indicator_subtypes=self.indicator_subtypes,
            expire_indicator_on_close=self.expire_indicator_on_close,
            incident_severity=self.incident_severity,
        ).build()

    @staticmethod
    def get_available_commands() -> list[str]:
        """Return every XSOAR command name this integration implements."""
        return list(Commands._COMMAND_TO_METHOD.keys())

    def get_results(self) -> tuple[Any, str]:
        if hasattr(self, self.requested_method):
            return getattr(self, self.requested_method)(), self.requested_method
        return self._delegate_to_builder(), self.requested_method


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()
        username, api_token = (
            params.get("credentials", {}).get("identifier", ""),
            params.get("credentials", {}).get("password", ""),
        )
        # `ciaops` joins endpoints onto this with `urllib.parse.urljoin`, which drops
        # the last path segment when the base has no trailing slash -- every request
        # would silently go to https://drp.group-ib.com/violation/list. The
        # documented URL is https://drp.group-ib.com/client_api, so normalize it here
        # instead of asking the operator to remember the slash.
        base_url = str(params.get("url", "")).strip()
        if base_url and not base_url.endswith("/"):
            base_url += "/"
        proxy = argToBoolean(params.get("proxy", False))
        verify_certificate = not argToBoolean(params.get("insecure", False))
        first_fetch = params.get("first_fetch", "3 days").strip()
        max_requests = int(params.get("max_fetch", 1))
        violation_subtypes = ViolationSubtypeFilter.from_param(params.get("violationSubtypes"))
        indicator_subtypes = ViolationSubtypeFilter.from_param(params.get("createIndicatorsForSubtypes"))
        violation_section = params.get("violationSection")
        # Single-brand filtering only (the ciaops generator sends only brands[0] as brandIds[]).
        brands = params.get("brands")
        # YAML type 8 booleans round-trip as "false"/"true" strings in XSOAR 6.x; argToBoolean normalizes them.
        download_images = argToBoolean(params.get("download_images", False))
        only_typosquatting = argToBoolean(params.get("only_typosquatting", False))
        expire_indicator_on_close = argToBoolean(params.get("expire_indicator_on_close", False))
        dedup_lookback_days = Deduplicator.lookback_days_from_params(params)
        # Hard upper bound on incidents emitted per fetch; empty/non-numeric/negative inputs fall back to the default.
        raw_max_incidents = params.get("max_incidents_per_fetch", Consts.DEFAULT_MAX_INCIDENTS_PER_FETCH)
        try:
            max_incidents_per_fetch = max(0, int(raw_max_incidents))
        except (TypeError, ValueError):
            max_incidents_per_fetch = Consts.DEFAULT_MAX_INCIDENTS_PER_FETCH
        violation_statuses = argToList(params.get("violationStatuses"))
        only_approval_required = argToBoolean(params.get("only_approval_required", False))
        incident_severity = Mappings.INCIDENT_SEVERITY_BY_NAME.get(str(params.get("incident_severity", "")).strip())
        close_incident_on_decision = argToBoolean(params.get("close_incident_on_decision", False))

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, api_token),
            proxy=proxy,
        )

        if command not in Commands.get_available_commands():
            raise Exception(f"{command} invalid")

        results, requested_method = Commands(
            client=client,
            command=command,
            args=args,
            first_fetch=first_fetch,
            max_requests=max_requests,
            violation_subtypes=violation_subtypes,
            violation_section=violation_section,
            brands=brands,
            download_images=download_images,
            only_typosquatting=only_typosquatting,
            dedup_lookback_days=dedup_lookback_days,
            max_incidents_per_fetch=max_incidents_per_fetch,
            violation_statuses=violation_statuses,
            only_approval_required=only_approval_required,
            indicator_subtypes=indicator_subtypes,
            expire_indicator_on_close=expire_indicator_on_close,
            incident_severity=incident_severity,
            close_incident_on_decision=close_incident_on_decision,
        ).get_results()
        if requested_method == "fetch_incidents":
            next_run, violations = results
            demisto.setLastRun(next_run)
            demisto.incidents(violations)
        else:
            return_results(results)

    except (DemistoException, ConnectionException) as exc:
        # An expected failure (refused request, unknown violation, bad argument): the message is the
        # error, a traceback would only bury it.
        return_error(f"Failed to execute {demisto.command()} command.\nError: {exc}")
    except Exception:
        return_error(f"Failed to execute {demisto.command()} command.\n" f"Error: {format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
