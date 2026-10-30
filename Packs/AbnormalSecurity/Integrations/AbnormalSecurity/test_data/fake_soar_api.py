"""
In-memory stand-in for the SOAR API endpoints that fetch-incidents calls, served as an httpx transport.

List endpoints filter on the window the integration sends, page by offset, and are sorted by ID rather
than by the filtered field, which is how the real API behaves. Failures can be injected per path so
the integration's real `ContentClient` status handling is exercised.
"""

import re
from collections.abc import Callable
from datetime import datetime

import httpx

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


class FakeSoarApi:
    def __init__(self, base_url: str):
        self.base_path = httpx.URL(base_url).path.rstrip("/")
        self.items: dict[str, list[dict]] = {endpoint: [] for endpoint in LIST_ENDPOINTS}
        self.calls: list[tuple[str, dict]] = []
        self.ascending = False
        self.on_call: Callable[[str], None] | None = None
        self._failures: list[dict] = []

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

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix(self.base_path)
        query = dict(request.url.params)
        self.calls.append((path, query))
        if self.on_call:
            self.on_call(path)
        for failure in self._failures:
            if failure["times"] != 0 and failure["pattern"].search(path):
                if failure["times"] is not None:
                    failure["times"] -= 1
                return httpx.Response(failure["status"], json=failure["body"] or {"message": f"injected {failure['status']}"})
        match = PATH_RE.match(path)
        if match is None:
            return httpx.Response(404, json={"message": f"no fake for {path}"})
        endpoint, item_id = match.groups()
        if item_id is None:
            return self._list(endpoint, query)
        return self._detail(endpoint, item_id, query)

    def _list(self, endpoint: str, query: dict) -> httpx.Response:
        list_key, id_key = LIST_ENDPOINTS[endpoint]
        match = FILTER_RE.match(query.get("filter", ""))
        if match is None:
            return httpx.Response(400, json={"message": f"unsupported filter: {query.get('filter')}"})
        field_name, gte, lte = match.groups()
        start, end = datetime.fromisoformat(gte), datetime.fromisoformat(lte)
        if endpoint in EXCLUSIVE_END_ENDPOINTS:
            start, end = start.replace(microsecond=0), end.replace(microsecond=0)

            def in_window(t):
                return start <= t < end
        else:

            def in_window(t):
                return start <= t <= end

        page_size, page_number = query.get("pageSize", "100"), query.get("pageNumber", "1")
        if not (page_size.isdigit() and page_number.isdigit()):
            return httpx.Response(400, json={"message": "pageSize and pageNumber must be integers"})
        page_size, page_number = int(page_size), int(page_number)
        matching = [item for item in self.items[endpoint] if in_window(datetime.fromisoformat(item[field_name]))]
        matching.sort(key=lambda item: item[id_key], reverse=not self.ascending)
        page = matching[(page_number - 1) * page_size : page_number * page_size]
        response = {list_key: [self._summary(endpoint, item) for item in page], "pageNumber": page_number}
        if page_number * page_size < len(matching):
            response["nextPageNumber"] = page_number + 1
        return httpx.Response(200, json=response)

    def _summary(self, endpoint: str, item: dict) -> dict:
        if endpoint == "cases":
            return {"caseId": item["caseId"], "description": item["description"]}
        _, id_key = LIST_ENDPOINTS[endpoint]
        return {id_key: item[id_key]}

    def _detail(self, endpoint: str, item_id: str, query: dict) -> httpx.Response:
        _, id_key = LIST_ENDPOINTS[endpoint]
        item = next((i for i in self.items[endpoint] if i[id_key] == item_id), None)
        if item is None:
            return httpx.Response(404, json={"message": "not found"})
        if endpoint == "threats":
            pages = item["pages"] or [
                [{"threatId": item_id, "receivedTime": item["latestTimeRemediated"], "remediationTimestamp": item["latestTimeRemediated"]}]
            ]
            page_number = int(query.get("pageNumber", "1"))
            response = {"threatId": item_id, "messages": pages[page_number - 1], "pageNumber": page_number}
            if page_number < len(pages):
                response["nextPageNumber"] = page_number + 1
            return httpx.Response(200, json=response)
        if endpoint == "abusecampaigns":
            return httpx.Response(200, json={"campaignId": item_id, "firstReported": item["lastReportedTime"]})
        details = {"caseId": item_id, "firstObserved": item["createdTime"], "genai_summary": f"summary {item_id}"}
        details.update(item["details"])
        return httpx.Response(200, json={key: value for key, value in details.items() if value is not None})
