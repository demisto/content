"""
In-memory stand-in for the SOAR API endpoints that fetch-incidents calls, served through requests_mock.

List endpoints filter on the window the integration sends, page by offset, and are sorted by ID rather
than by the filtered field, which is how the real API behaves. Failures can be injected per path so
the integration's real `DemistoException` status handling is exercised.
"""

import re
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

# list endpoint -> (response list key, ID field)
LIST_ENDPOINTS = {
    "threats": ("threats", "threatId"),
    "abusecampaigns": ("campaigns", "campaignId"),
    "cases": ("cases", "caseId"),
}
# `/threats` floors both bounds to whole seconds and excludes the upper one; the others include both.
EXCLUSIVE_END_ENDPOINTS = {"threats"}
FILTER_RE = re.compile(r"(\w+) gte (\S+) and \1 lte (\S+)")
PATH_RE = re.compile(r"^/(threats|abusecampaigns|cases)(?:/([^/]+))?$")


def parse_timestamp(value: str) -> datetime:
    value = value.rstrip("Z")
    if "." in value:
        head, fraction = value.split(".", 1)
        value = f"{head}.{fraction[:6]}"
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


class FakeSoarApi:
    def __init__(self, requests_mock, base_url: str):
        self.items: dict[str, list[dict]] = {endpoint: [] for endpoint in LIST_ENDPOINTS}
        self.calls: list[tuple[str, dict]] = []
        self.ascending = False
        self.on_call: Callable[[str], None] | None = None
        self._failures: list[dict] = []
        requests_mock.get(re.compile(re.escape(base_url) + r"/(threats|abusecampaigns|cases)"), json=self._handle)

    def add_threat(self, threat_id: str, remediated: str, message_pages: list[list[dict]] | None = None) -> None:
        self.items["threats"].append({"threatId": threat_id, "latestTimeRemediated": remediated, "pages": message_pages})

    def add_campaign(self, campaign_id: str, last_reported: str) -> None:
        self.items["abusecampaigns"].append({"campaignId": campaign_id, "lastReportedTime": last_reported})

    def add_case(self, case_id: str, created: str, modified: str | None = None, **details) -> None:
        self.items["cases"].append(
            {
                "caseId": case_id,
                "createdTime": created,
                "lastModifiedTime": modified or created,
                "description": f"case {case_id}",
                "details": details,
            }
        )

    def fail(self, path_pattern: str, status: int, times: int | None = 1, body: dict | None = None) -> None:
        """Makes requests whose path matches `path_pattern` fail with `status`, `times` times (None: always)."""
        self._failures.append({"pattern": re.compile(path_pattern), "status": status, "times": times, "body": body})

    def clear_failures(self) -> None:
        self._failures.clear()

    def detail_calls(self, endpoint: str) -> list[str]:
        return [path for path, _ in self.calls if path.startswith(f"/{endpoint}/")]

    def list_calls(self, endpoint: str) -> list[dict]:
        return [query for path, query in self.calls if path == f"/{endpoint}"]

    def _handle(self, request, context):
        # requests_mock lowercases `request.path` and `request.qs`, so parse the URL directly.
        url = urlparse(request.url)
        path = url.path
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        self.calls.append((path, query))
        if self.on_call:
            self.on_call(path)
        for failure in self._failures:
            if failure["times"] != 0 and failure["pattern"].search(path):
                if failure["times"] is not None:
                    failure["times"] -= 1
                context.status_code = failure["status"]
                return failure["body"] or {"message": f"injected {failure['status']}"}
        endpoint, item_id = PATH_RE.match(path).groups()
        if item_id is None:
            return self._list(endpoint, query, context)
        return self._detail(endpoint, item_id, query, context)

    def _list(self, endpoint: str, query: dict, context) -> dict:
        list_key, id_key = LIST_ENDPOINTS[endpoint]
        field_name, gte, lte = FILTER_RE.match(query["filter"]).groups()
        start, end = parse_timestamp(gte), parse_timestamp(lte)
        if endpoint in EXCLUSIVE_END_ENDPOINTS:
            start, end = start.replace(microsecond=0), end.replace(microsecond=0)

            def in_window(t):
                return start <= t < end
        else:

            def in_window(t):
                return start <= t <= end

        matching = [item for item in self.items[endpoint] if in_window(parse_timestamp(item[field_name]))]
        matching.sort(key=lambda item: item[id_key], reverse=not self.ascending)
        page_size, page_number = int(query.get("pageSize", 100)), int(query.get("pageNumber", 1))
        page = matching[(page_number - 1) * page_size : page_number * page_size]
        response = {list_key: [self._summary(endpoint, item) for item in page], "pageNumber": page_number}
        if page_number * page_size < len(matching):
            response["nextPageNumber"] = page_number + 1
        return response

    def _summary(self, endpoint: str, item: dict) -> dict:
        if endpoint == "cases":
            return {"caseId": item["caseId"], "description": item["description"]}
        _, id_key = LIST_ENDPOINTS[endpoint]
        return {id_key: item[id_key]}

    def _detail(self, endpoint: str, item_id: str, query: dict, context) -> dict:
        _, id_key = LIST_ENDPOINTS[endpoint]
        item = next((i for i in self.items[endpoint] if i[id_key] == item_id), None)
        if item is None:
            context.status_code = 404
            return {"message": "not found"}
        if endpoint == "threats":
            pages = item["pages"] or [
                [{"threatId": item_id, "receivedTime": item["latestTimeRemediated"], "remediationTimestamp": item["latestTimeRemediated"]}]
            ]
            page_number = int(query.get("pageNumber", 1))
            response = {"threatId": item_id, "messages": pages[page_number - 1], "pageNumber": page_number}
            if page_number < len(pages):
                response["nextPageNumber"] = page_number + 1
            return response
        if endpoint == "abusecampaigns":
            return {"campaignId": item_id, "firstReported": item["lastReportedTime"]}
        details = {"caseId": item_id, "firstObserved": item["createdTime"], "genai_summary": f"summary {item_id}"}
        details.update(item["details"])
        return {key: value for key, value in details.items() if value is not None}
