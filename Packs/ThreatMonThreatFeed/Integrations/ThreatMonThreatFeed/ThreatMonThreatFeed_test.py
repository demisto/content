import base64
import json
from datetime import datetime, timedelta, UTC

import pytest

import ThreatMonThreatFeed as feed
from CommonServerPython import DemistoException, FeedIndicatorType

ALL = feed.COLLECTIONS["All Threat Indicators"]
IPS = feed.COLLECTIONS["IP Address Indicators"]
NOW = datetime(2026, 11, 3, 8, 0, 0, tzinfo=UTC)
AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def stix(value_expr: str, created: datetime, labels=None, uid=None, markings=None) -> dict:
    ts = created.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": uid or f"indicator--{abs(hash((value_expr, ts)))}",
        "created": ts,
        "modified": ts,
        "name": value_expr,
        "indicator_types": ["malicious-activity"],
        "pattern": f"[{value_expr}]",
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": labels if labels is not None else ["Malware"],
        "confidence": 80,
        "object_marking_refs": markings if markings is not None else [AMBER],
    }


class FakeResponseError(DemistoException):
    def __init__(self, status):
        class Res:
            status_code = status

        super().__init__(f"HTTP {status}", res=Res())


class FakeTaxiiServer:
    """
    Mimics the ThreatMon TAXII server behaviour observed in production:
    * objects are returned newest first (date_added descending, then row id ascending),
    * ``next`` is a keyset cursor (base64 of ``{"sa": [date_ms, row_id]}``),
    * ``added_after`` is inclusive,
    * the server clock is returned in the ``Date`` header.
    """

    def __init__(self, page_size=3):
        self.rows: dict[str, list[tuple[int, dict]]] = {}
        self.row_id = 0
        self.page_size = page_size
        self.clock = NOW
        self.calls: list[dict] = []
        self.fail_on_call: int | None = None
        self.reject_cursor_once = False
        self.failing_collections: set[str] = set()

    def add(self, collection_id: str, *objects: dict) -> None:
        for obj in objects:
            self.row_id += 1
            self.rows.setdefault(collection_id, []).append((self.row_id, obj))

    @staticmethod
    def _ms(obj: dict) -> int:
        return int(feed.parse_stix_time(obj["created"]).timestamp() * 1000)

    def get_objects_page(self, collection_id, added_after, next_cursor, limit=feed.PAGE_SIZE):
        self.calls.append({"collection": collection_id, "added_after": added_after, "next": next_cursor})
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            raise DemistoException("connection reset")
        if collection_id in self.failing_collections:
            raise FakeResponseError(403)
        if next_cursor and self.reject_cursor_once:
            self.reject_cursor_once = False
            raise FakeResponseError(400)

        rows = sorted(self.rows.get(collection_id, []), key=lambda r: (-self._ms(r[1]), r[0]))
        if added_after:
            threshold = feed.from_taxii_time(added_after).timestamp() * 1000
            rows = [r for r in rows if self._ms(r[1]) >= threshold]
        if next_cursor:
            last_ms, last_id = json.loads(base64.b64decode(next_cursor))["sa"]
            rows = [r for r in rows if (-self._ms(r[1]), r[0]) > (-last_ms, last_id)]

        size = min(limit, self.page_size)
        page, more = rows[:size], len(rows) > size
        envelope = {"objects": [obj for _, obj in page], "more": more}
        if more:
            last = page[-1]
            envelope["next"] = base64.b64encode(json.dumps({"sa": [self._ms(last[1]), last[0]]}).encode()).decode()
        return envelope, self.clock

    def get_collections(self):
        return {"collections": [{"id": cid} for cid in feed.COLLECTIONS.values()]}


@pytest.fixture
def context(mocker):
    store: dict = {}
    mocker.patch.object(feed, "get_integration_context", side_effect=lambda: json.loads(json.dumps(store.get("ctx", {}))))
    mocker.patch.object(
        feed, "set_integration_context", side_effect=lambda ctx: store.__setitem__("ctx", json.loads(json.dumps(ctx)))
    )
    return store


@pytest.fixture
def created(mocker):
    sent: list[dict] = []
    mocker.patch.object(feed.demisto, "createIndicators", side_effect=lambda batch: sent.extend(batch))
    return sent


def run_fetch(server, params, mocker, now=NOW):
    return feed.fetch_indicators_command(server, params, now=now)


BASE_PARAMS = {
    "collections": "All Threat Indicators,IP Address Indicators",
    "first_fetch": "2026-11-01T00:00:00Z",
    "lookback_minutes": "60",
}


""" PARSING """


@pytest.mark.parametrize(
    "path, prop, value, expected_type, expected_value, extra",
    [
        ("ipv4-addr", "value", "1.2.3.4", FeedIndicatorType.IP, "1.2.3.4", {}),
        ("ipv4-addr", "value", "1.2.3.4:8080", FeedIndicatorType.IP, "1.2.3.4", {"port": "8080"}),
        ("ipv4-addr", "value", "10.0.0.0/8", FeedIndicatorType.CIDR, "10.0.0.0/8", {}),
        ("ipv6-addr", "value", "2001:db8::1", FeedIndicatorType.IPv6, "2001:db8::1", {}),
        ("ipv6-addr", "value", "[2001:db8::1]:443", FeedIndicatorType.IPv6, "2001:db8::1", {}),
        ("ipv6-addr", "value", "2001:db8::/32", FeedIndicatorType.IPv6CIDR, "2001:db8::/32", {}),
        ("domain-name", "value", "evil.onion", FeedIndicatorType.Domain, "evil.onion", {}),
        ("domain-name", "value", "*.evil.com", FeedIndicatorType.DomainGlob, "*.evil.com", {}),
        ("url", "value", "https://1.2.3.4:80/", FeedIndicatorType.URL, "https://1.2.3.4:80/", {}),
        ("email-addr", "value", "a@b.com", FeedIndicatorType.Email, "a@b.com", {}),
        ("file", "hashes.'SHA-256'", "ab" * 32, FeedIndicatorType.File, "ab" * 32, {"sha256": "ab" * 32}),
        ("file", "hashes.MD5", "cd" * 16, FeedIndicatorType.File, "cd" * 16, {"md5": "cd" * 16}),
        ("file", "hashes.'SHA-1'", "ef" * 20, FeedIndicatorType.File, "ef" * 20, {"sha1": "ef" * 20}),
    ],
)
def test_classify_observable(path, prop, value, expected_type, expected_value, extra):
    assert feed.classify_observable(path, prop, value) == (expected_type, expected_value, extra)


@pytest.mark.parametrize(
    "value, expected_type, expected_value, extra",
    [
        # Real values that ThreatMon publishes as domain-name observables.
        ("1.180.161.186:5000", FeedIndicatorType.IP, "1.180.161.186", {"port": "5000"}),
        ("1.180.161.186", FeedIndicatorType.IP, "1.180.161.186", {}),
        ("[2001:db8::1]:443", FeedIndicatorType.IPv6, "2001:db8::1", {}),
        ("2001:db8::1", FeedIndicatorType.IPv6, "2001:db8::1", {}),
        ("wss://cdnlivechatinc.com/ws", FeedIndicatorType.URL, "wss://cdnlivechatinc.com/ws", {}),
        ("http://zjoxyw5mkacojk5ptn2iprkivg5clow72mjk", FeedIndicatorType.URL, "http://zjoxyw5mkacojk5ptn2iprkivg5clow72mjk", {}),
        (
            "0x252a8bd2319d8a555b872990601221b3a2053bce",
            "Cryptocurrency Address",
            "0x252a8bd2319d8a555b872990601221b3a2053bce",
            {},
        ),
        (
            "xir242nunyist4d7ksfnfmhnjx4gvqbuzo7eax4o3abqjesbxjshh4qd.onion",
            FeedIndicatorType.Domain,
            "xir242nunyist4d7ksfnfmhnjx4gvqbuzo7eax4o3abqjesbxjshh4qd.onion",
            {},
        ),
        ("*.duckdns.org", FeedIndicatorType.DomainGlob, "*.duckdns.org", {}),
    ],
)
def test_classify_domain_name_reclassifies_by_shape(value, expected_type, expected_value, extra):
    assert feed.classify_observable("domain-name", "value", value) == (expected_type, expected_value, extra)


def test_classify_observable_unsupported():
    assert feed.classify_observable("mutex", "name", "x")[0] is None


def test_parse_stix_indicator_fields():
    obj = stix("domain-name:value = 'evil.com'", NOW, labels=["Malware", "Lockbit"])
    indicators, unsupported = feed.parse_stix_indicator(obj, "All Threat Indicators", ["ThreatMon", "custom"], None, 3)

    assert unsupported == []
    assert len(indicators) == 1
    ind = indicators[0]
    assert ind["value"] == "evil.com"
    assert ind["type"] == FeedIndicatorType.Domain
    assert ind["score"] == 3
    assert ind["fields"]["tags"] == ["Malware", "Lockbit", "ThreatMon", "custom"]
    assert ind["fields"]["trafficlightprotocol"] == "AMBER"
    assert ind["fields"]["stixid"] == obj["id"]
    assert ind["fields"]["firstseenbysource"] == obj["created"]
    assert "Confidence: 80" in ind["fields"]["description"]
    assert ind["rawJSON"]["threatmon_collection"] == "All Threat Indicators"


def test_parse_stix_indicator_tlp_parameter_overrides_marking():
    obj = stix("url:value = 'http://x/'", NOW)
    assert feed.parse_stix_indicator(obj, "c", ["ThreatMon"], "RED", 3)[0][0]["fields"]["trafficlightprotocol"] == "RED"


def test_parse_stix_indicator_without_marking_has_no_tlp():
    obj = stix("url:value = 'http://x/'", NOW, markings=[])
    assert "trafficlightprotocol" not in feed.parse_stix_indicator(obj, "c", ["ThreatMon"], None, 3)[0][0]["fields"]


def test_parse_stix_indicator_multiple_comparisons_and_escaped_quote():
    obj = stix("url:value = 'http://a/it\\'s' OR ipv4-addr:value = '5.6.7.8'", NOW)
    indicators, unsupported = feed.parse_stix_indicator(obj, "c", ["ThreatMon"], None, 3)
    assert [i["value"] for i in indicators] == ["http://a/it's", "5.6.7.8"]
    assert unsupported == []


def test_parse_stix_indicator_reports_unsupported():
    obj = stix("mutex:name = 'x'", NOW)
    indicators, unsupported = feed.parse_stix_indicator(obj, "c", ["ThreatMon"], None, 3)
    assert indicators == []
    assert unsupported == ["mutex:name"]
    obj["pattern"] = ""
    assert feed.parse_stix_indicator(obj, "c", [], None, 3)[1]


@pytest.mark.parametrize("reputation, expected", [("Bad", 3), ("Suspicious", 2), ("Good", 1), ("None", 0), (None, 3)])
def test_calculate_verdict(reputation, expected):
    assert feed.calculate_verdict(reputation) == expected


def test_resolve_collections_default_is_all_collections():
    assert [cid for _, cid in feed.resolve_collections({})] == list(feed.COLLECTIONS.values())


def test_resolve_collections_with_extra_ids():
    result = feed.resolve_collections({"collections": "IP Address Indicators", "collection_ids": "abc," + IPS})
    assert result == [("IP Address Indicators", IPS), ("abc", "abc")]


def test_time_helpers_round_trip_and_format():
    value = feed.to_taxii_time(NOW)
    assert value == "2026-11-03T08:00:00.000000Z"
    assert feed.from_taxii_time(value) == NOW
    assert feed.parse_http_date("Tue, 03 Nov 2026 08:41:03 GMT") == datetime(2026, 11, 3, 8, 41, 3, tzinfo=UTC)
    assert feed.parse_http_date("garbage") is None
    assert feed.parse_stix_time("2026-11-03T10:18:16.12169Z") == datetime(2026, 11, 3, 10, 18, 16, 121690, tzinfo=UTC)


""" FETCH: COMPLETENESS """


def values(sent):
    return sorted(i["value"] for i in sent)


def test_fetch_full_crawl_across_pages_and_collections(context, created, mocker):
    server = FakeTaxiiServer(page_size=3)
    server.add(ALL, *[stix(f"domain-name:value = 'd{i}.com'", NOW - timedelta(minutes=i)) for i in range(10)])
    server.add(IPS, *[stix(f"ipv4-addr:value = '1.1.1.{i}'", NOW - timedelta(minutes=i)) for i in range(7)])

    stats = run_fetch(server, BASE_PARAMS, mocker)

    assert len(created) == 17
    assert len(set(values(created))) == 17
    assert stats["completed"] == ["All Threat Indicators", "IP Address Indicators"]
    state = context["ctx"]["collections"][ALL]
    assert state["next"] is None
    # Next crawl starts from (server time at crawl start - look-back).
    assert state["added_after"] == feed.to_taxii_time(NOW - timedelta(minutes=60))
    assert server.calls[0]["added_after"] == "2026-11-01T00:00:00.000000Z"


def test_fetch_respects_page_budget_and_resumes_without_loss(context, created, mocker):
    server = FakeTaxiiServer(page_size=2)
    server.add(ALL, *[stix(f"domain-name:value = 'd{i}.com'", NOW - timedelta(minutes=i)) for i in range(9)])
    params = {**BASE_PARAMS, "collections": "All Threat Indicators", "max_pages_per_fetch": "2"}

    runs = 0
    for _ in range(5):
        runs += 1
        stats = run_fetch(server, params, mocker)
        if stats["completed"]:
            break
        assert stats["pending"] == ["All Threat Indicators"]
        assert context["ctx"]["collections"][ALL]["next"]

    assert stats["completed"] == ["All Threat Indicators"]
    assert runs == 3
    assert values(created) == sorted(f"d{i}.com" for i in range(9))


def test_fetch_resumes_after_failure_mid_crawl(context, created, mocker):
    server = FakeTaxiiServer(page_size=2)
    server.add(ALL, *[stix(f"domain-name:value = 'd{i}.com'", NOW - timedelta(minutes=i)) for i in range(7)])
    params = {**BASE_PARAMS, "collections": "All Threat Indicators"}
    server.fail_on_call = 3

    with pytest.raises(DemistoException):
        run_fetch(server, params, mocker)
    assert len(created) == 4  # two pages were committed before the failure
    assert context["ctx"]["collections"][ALL]["next"]

    server.fail_on_call = None
    run_fetch(server, params, mocker)
    assert values(created) == sorted(f"d{i}.com" for i in range(7))
    assert len(created) == 7  # nothing sent twice


def test_failing_collection_does_not_block_the_others(context, created, mocker):
    """
    Given: A collection that always fails (for example, it is not readable with the API token) and is
           ordered first because it never completed a crawl.
    When: Fetching.
    Then: The other collections are still crawled, and the failure is raised at the end of the run.
    """
    server = FakeTaxiiServer(page_size=2)
    server.add(IPS, *[stix(f"ipv4-addr:value = '1.1.1.{i}'", NOW) for i in range(3)])
    params = {**BASE_PARAMS, "collections": "All Threat Indicators,IP Address Indicators"}
    # IPS completed a crawl before, so ALL (never completed) is ordered first.
    context["ctx"] = {
        "version": feed.STATE_VERSION,
        "collections": {
            IPS: {"added_after": "2026-11-01T00:00:00.000000Z", "last_completed_at": "2026-11-02T00:00:00.000000Z"},
        },
    }
    server.failing_collections = {ALL}
    debug = mocker.patch.object(feed.demisto, "debug")

    with pytest.raises(DemistoException, match="All Threat Indicators"):
        run_fetch(server, params, mocker)

    assert any("Traceback" in str(call.args[0]) for call in debug.call_args_list)

    assert server.calls[0]["collection"] == ALL
    assert values(created) == ["1.1.1.0", "1.1.1.1", "1.1.1.2"]
    assert context["ctx"]["collections"][IPS]["last_completed_at"] == feed.to_taxii_time(NOW)


def test_fetch_does_not_commit_page_when_create_indicators_fails(context, mocker):
    server = FakeTaxiiServer(page_size=2)
    server.add(ALL, *[stix(f"domain-name:value = 'd{i}.com'", NOW - timedelta(minutes=i)) for i in range(4)])
    params = {**BASE_PARAMS, "collections": "All Threat Indicators"}
    sent: list = []
    calls = {"n": 0}

    def flaky(batch):
        calls["n"] += 1
        if calls["n"] == 2:
            raise Exception("server busy")
        sent.extend(batch)

    mocker.patch.object(feed.demisto, "createIndicators", side_effect=flaky)
    with pytest.raises(Exception, match="server busy"):
        run_fetch(server, params, mocker)
    run_fetch(server, params, mocker)

    assert values(sent) == sorted(f"d{i}.com" for i in range(4))


def test_fetch_second_run_gets_new_late_and_future_stamped_iocs(context, created, mocker):
    server = FakeTaxiiServer(page_size=3)
    server.add(ALL, *[stix(f"domain-name:value = 'old{i}.com'", NOW - timedelta(hours=i)) for i in range(5)])
    params = {**BASE_PARAMS, "collections": "All Threat Indicators"}
    run_fetch(server, params, mocker)
    assert len(created) == 5

    later = NOW + timedelta(hours=1)
    server.clock = later
    server.add(
        ALL,
        stix("domain-name:value = 'new.com'", NOW + timedelta(minutes=30)),
        # Published with a timestamp before the previous crawl started (late arrival within look-back).
        stix("domain-name:value = 'late.com'", NOW - timedelta(minutes=20)),
        # Published with a timestamp ahead of real time (as seen in production batches).
        stix("domain-name:value = 'future.com'", later + timedelta(hours=3)),
    )
    stats = run_fetch(server, params, mocker, now=later)

    assert values(created) == sorted([f"old{i}.com" for i in range(5)] + ["new.com", "late.com", "future.com"])
    assert stats["sent"] == 3
    # The previous crawl's overlap (old0 within the look-back) was re-read but not re-sent.
    assert stats["duplicates"] >= 1


def test_fetch_resends_republished_ioc(context, created, mocker):
    server = FakeTaxiiServer()
    params = {**BASE_PARAMS, "collections": "All Threat Indicators"}
    server.add(ALL, stix("domain-name:value = 'evil.com'", NOW - timedelta(days=1)))
    run_fetch(server, params, mocker)
    server.clock = NOW + timedelta(hours=2)
    server.add(ALL, stix("domain-name:value = 'evil.com'", NOW + timedelta(hours=2), labels=["Updated"]))
    run_fetch(server, params, mocker, now=NOW + timedelta(hours=2))

    assert [i["value"] for i in created] == ["evil.com", "evil.com"]
    assert created[1]["fields"]["tags"][0] == "Updated"


def test_fetch_deduplicates_across_collections_and_duplicate_rows(context, created, mocker):
    server = FakeTaxiiServer(page_size=2)
    shared = stix("domain-name:value = 'shared.com'", NOW - timedelta(minutes=5), uid="indicator--1")
    server.add(ALL, shared, stix("domain-name:value = 'only-all.com'", NOW))
    server.add(IPS, stix("ipv4-addr:value = '9.9.9.9'", NOW), stix("ipv4-addr:value = '9.9.9.9'", NOW))
    server.add(feed.COLLECTIONS["Domain Name Indicators"], shared)
    params = {**BASE_PARAMS, "collections": "All Threat Indicators,IP Address Indicators,Domain Name Indicators"}

    stats = run_fetch(server, params, mocker)

    assert values(created) == ["9.9.9.9", "only-all.com", "shared.com"]
    assert stats["duplicates"] == 2


def test_fetch_restarts_crawl_when_cursor_is_rejected(context, created, mocker):
    server = FakeTaxiiServer(page_size=2)
    server.add(ALL, *[stix(f"domain-name:value = 'd{i}.com'", NOW - timedelta(minutes=i)) for i in range(5)])
    server.reject_cursor_once = True

    run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators"}, mocker)

    assert values(created) == sorted(f"d{i}.com" for i in range(5))
    assert len(created) == 5


def test_fetch_skips_non_indicator_objects_and_reports_unsupported(context, created, mocker):
    server = FakeTaxiiServer()
    server.add(
        ALL, {"type": "marking-definition", "id": "x", "created": "2026-11-03T07:00:00.000Z"}, stix("mutex:name = 'm'", NOW)
    )
    info = mocker.patch.object(feed.demisto, "info")

    stats = run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators"}, mocker)

    assert created == []
    assert stats["unsupported"] == 1
    assert "mutex:name" in info.call_args[0][0]


def test_first_fetch_relative_time(context, created, mocker):
    server = FakeTaxiiServer()
    run_fetch(server, {"collections": "All Threat Indicators", "first_fetch": "3 days"}, mocker)
    first = feed.from_taxii_time(server.calls[0]["added_after"])
    assert timedelta(days=3) - timedelta(minutes=5) < datetime.now(UTC) - first < timedelta(days=3, minutes=5)


def test_seen_cache_is_bounded(context, created, mocker):
    server = FakeTaxiiServer(page_size=50)
    server.add(ALL, *[stix(f"domain-name:value = 'old{i}.com'", NOW - timedelta(days=10)) for i in range(20)])
    server.add(ALL, stix("domain-name:value = 'recent.com'", NOW))
    run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators", "first_fetch": "30 days"}, mocker)

    assert len(created) == 21
    assert len(feed.SeenCache(context["ctx"]["seen"])) == 1  # old objects can never be re-read, so they are not cached

    stale_bucket = str(int((NOW - timedelta(days=5)).timestamp()) // 3600 * 3600)
    context["ctx"]["seen"][stale_bucket] = "A" * 12
    run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators"}, mocker)
    assert stale_bucket not in context["ctx"]["seen"]


def test_seen_cache_round_trip_and_prune():
    cache = feed.SeenCache()
    cache.add("aaaaaaaaaaaa", 7200 + 10)
    cache.add("bbbbbbbbbbbb", 7200 + 20)
    cache.add("cccccccccccc", 10800 + 5)
    restored = feed.SeenCache(json.loads(json.dumps(cache.to_state())))
    assert len(restored) == 3
    assert "bbbbbbbbbbbb" in restored

    restored.prune(10800)  # drops the bucket [7200, 10800) only
    assert len(restored) == 1
    assert "cccccccccccc" in restored
    assert "aaaaaaaaaaaa" not in restored


def test_dedup_key_is_compact_and_distinguishes_republication():
    ind = {"type": "Domain", "value": "a.com", "fields": {"firstseenbysource": "2026-11-03T00:00:00Z"}}
    other = {**ind, "fields": {"firstseenbysource": "2026-11-04T00:00:00Z"}}
    assert len(feed.dedup_key(ind)) == feed.SeenCache.KEY_LENGTH
    assert feed.dedup_key(ind) != feed.dedup_key(other)


def test_no_collection_is_starved_by_the_page_budget(context, created, mocker):
    """
    Given: A page budget smaller than what one collection needs for every incremental crawl.
    When: Fetching repeatedly.
    Then: Every collection still completes its crawl (the budget rotates instead of always going to the
          first collection), so no collection is starved.
    """
    server = FakeTaxiiServer(page_size=2)
    collections = ["All Threat Indicators", "IP Address Indicators", "URL Indicators"]
    for i, name in enumerate(collections):
        server.add(feed.COLLECTIONS[name], *[stix(f"domain-name:value = 'c{i}-{j}.com'", NOW) for j in range(6)])
    params = {**BASE_PARAMS, "collections": ",".join(collections), "max_pages_per_fetch": "3"}

    for _ in range(9):
        run_fetch(server, params, mocker)

    assert len(set(values(created))) == 18
    for name in collections:
        assert context["ctx"]["collections"][feed.COLLECTIONS[name]].get("last_completed_at"), name


def test_crawl_order_prefers_unfinished_then_least_recently_completed():
    state = {
        "collections": {
            "a": {"last_completed_at": "2026-11-03T08:00:00.000000Z"},
            "b": {"last_completed_at": "2026-11-03T07:00:00.000000Z"},
            "c": {"next": "cursor", "last_completed_at": "2026-11-03T09:00:00.000000Z"},
        }
    }
    order = feed.crawl_order([("A", "a"), ("B", "b"), ("C", "c"), ("D", "d")], state)
    assert [cid for _, cid in order] == ["c", "d", "b", "a"]


def test_state_from_previous_integration_version_is_discarded(context, created, mocker):
    context["ctx"] = {"last_timestamp": "2026-10-30T01:23:19.753102+00:00"}
    server = FakeTaxiiServer()
    server.add(ALL, stix("domain-name:value = 'a.com'", NOW - timedelta(days=1)))
    run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators"}, mocker)
    assert values(created) == ["a.com"]
    assert context["ctx"]["version"] == feed.STATE_VERSION


""" OTHER COMMANDS """


def test_test_module_ok():
    assert feed.test_module(FakeTaxiiServer(), {}) == "ok"


def test_test_module_auth_error(mocker):
    server = FakeTaxiiServer()
    mocker.patch.object(server, "get_collections", side_effect=FakeResponseError(401))
    assert "Authorization error" in feed.test_module(server, {})


def test_test_module_missing_collection(mocker):
    server = FakeTaxiiServer()
    mocker.patch.object(server, "get_collections", return_value={"collections": [{"id": ALL}]})
    assert "IP Address Indicators" in feed.test_module(server, {"collections": "All Threat Indicators,IP Address Indicators"})


def test_test_module_invalid_first_fetch():
    assert feed.test_module(FakeTaxiiServer(), {"first_fetch": "not a date"}) == "Invalid First Fetch Time parameter."


def test_get_indicators_command(context):
    server = FakeTaxiiServer(page_size=10)
    server.add(IPS, *[stix(f"ipv4-addr:value = '1.1.1.{i}'", NOW - timedelta(minutes=i)) for i in range(5)])

    result = feed.get_indicators_command(server, {"feedTags": "x"}, {"limit": "3", "collection": "IP Address Indicators"})

    assert "1.1.1.0" in result.readable_output
    assert "1.1.1.3" not in result.readable_output
    assert len(result.raw_response) == 3
    assert "ctx" not in context  # does not touch the fetch state


def test_get_indicators_command_empty():
    assert "No indicators" in feed.get_indicators_command(FakeTaxiiServer(), {}, {}).readable_output


def test_fetch_state_and_reset_commands(context, created, mocker):
    server = FakeTaxiiServer()
    server.add(ALL, stix("domain-name:value = 'a.com'", NOW))
    run_fetch(server, {**BASE_PARAMS, "collections": "All Threat Indicators"}, mocker)

    result = feed.get_fetch_state_command({"collections": "All Threat Indicators"})
    assert result.outputs[0]["AddedAfter"] == feed.to_taxii_time(NOW - timedelta(minutes=60))
    assert result.outputs[0]["CrawlInProgress"] is False
    assert result.outputs[0]["LastCompletedCrawl"] == feed.to_taxii_time(NOW)
    assert "Added After" in result.readable_output

    feed.reset_fetch_state_command()
    assert context["ctx"] == {}


""" CLIENT """


def test_client_sends_taxii_request(requests_mock):
    requests_mock.get(
        f"https://ioc.example{feed.TAXII_API_ROOT}/collections/{ALL}/objects/",
        json={"objects": [], "more": False},
        headers={"Date": "Tue, 03 Nov 2026 08:41:03 GMT"},
    )
    client = feed.Client("https://ioc.example/", "", "token", verify=True, proxy=False)

    envelope, server_time = client.get_objects_page(ALL, "2026-11-01T00:00:00.000000Z", "abc")

    request = requests_mock.last_request
    assert request.qs == {"limit": ["500"], "added_after": ["2026-11-01t00:00:00.000000z"], "next": ["abc"]}
    assert request.headers["Accept"] == feed.TAXII_MEDIA_TYPE
    assert request.headers["Authorization"] == "Basic " + base64.b64encode(b":token").decode()
    assert envelope == {"objects": [], "more": False}
    assert server_time == datetime(2026, 11, 3, 8, 41, 3, tzinfo=UTC)


@pytest.mark.parametrize(
    "url", ["https://ioc.example", "https://ioc.example/", "https://ioc.example/taxii", "https://ioc.example/taxii/"]
)
def test_client_accepts_server_root_or_taxii_root(url):
    assert feed.Client(url, "", "token", verify=True, proxy=False)._base_url == f"https://ioc.example{feed.TAXII_API_ROOT}"


def test_main_fetch_indicators(mocker, requests_mock, context, created):
    mocker.patch.object(feed.demisto, "command", return_value="fetch-indicators")
    mocker.patch.object(
        feed.demisto,
        "params",
        return_value={"credentials": {"password": "token"}, "collections": "URL Indicators", "first_fetch": "1 day"},
    )
    requests_mock.get(
        f"{feed.DEFAULT_BASE_URL}{feed.TAXII_API_ROOT}/collections/{feed.COLLECTIONS['URL Indicators']}/objects/",
        json={"objects": [stix("url:value = 'http://evil/'", NOW)], "more": False},
    )
    feed.main()
    assert values(created) == ["http://evil/"]


def test_get_collections_command_flags_unknown_collections(mocker):
    server = FakeTaxiiServer()
    mocker.patch.object(
        server,
        "get_collections",
        return_value={
            "collections": [
                {"id": ALL, "title": "All Threat Indicators", "can_read": True},
                {"id": "new-collection", "title": "Phishing", "can_read": True},
            ]
        },
    )

    result = feed.get_collections_command(server)

    assert [(row["ID"], row["KnownByIntegration"]) for row in result.outputs] == [(ALL, True), ("new-collection", False)]
    assert "Phishing" in result.readable_output
    assert "Known By Integration" in result.readable_output
