import json
from pathlib import Path

import Intel471WatcherAlerts as feed
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


GET_REPORT_TYPE_DATA = [
    (
        "https://titan.intel471.com/report/inforep/fd1636d9f5a66098bcea8ae341b0304d",  # input
        "INFO REPORT:\n",  # expected
    ),
    (
        "https://titan.intel471.com/report/fintel/3820588e7fab5f9e24cd582fe2a9f276",  # input
        "FINTEL:\n",  # expected
    ),
    (
        "https://titan.intel471.com/report/spotrep/3ff4ef482649a94e792f8476edc84381",  # input
        "SPOT REPORT:\n",  # expected
    ),
]


@pytest.mark.parametrize("input,expected_results", GET_REPORT_TYPE_DATA)
def test_get_report_type(mocker, input, expected_results):
    """
    Given:
        - set of parameters from demisto.

    When:
        - create an instance and on every run.

    Then:
        - Returns a report type.

    """
    report_type: str = feed.get_report_type(input)
    assert report_type == expected_results


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Intel471WatcherAlerts import Client, fetch_incidents_titan

    mock_response = util_load_json("test_data/titan/search_alerts.json")
    requests_mock.get(
        "https://api.test.com/v1/alerts?showRead=true&displayWatchers=true&markAsRead=false&sort=earliest&count=1&"
        "from=1581944401",
        json=mock_response,
    )

    client = Client(base_url="https://api.test.com/v1", verify=False, headers={"Authentication": "Bearer some_api_key"})

    last_run = {
        "last_fetch": 1581944401  # Mon Feb 17 2020
    }

    latest_alert_uid, next_run, incidents = fetch_incidents_titan(
        client=client,
        max_results=1,
        last_run=last_run,
        first_fetch_time=0,
        watcher_group_uids=None,
        last_alert_uid="",
    )

    assert incidents == [
        {
            "name": "INSTANT MESSAGE:\nPart 1 sell part2",
            "occurred": "2021-10-25T11:34:47.000Z",
            "rawJSON": json.dumps(mock_response["alerts"][0]),
            "type": "Intel 471 Watcher Alert",
            "severity": 2,
            "CustomFields": {
                "intel471url": "https://titan.intel471.com/ims_thread/45678901234567890123456789012345?message_uid"
                "=34567890123456789012345678901234",
                "watchergroup": "Test Watcher Group 1",
                "watcher": 'Watcher on "sell"',
            },
            "details": "Source Object: INSTANT MESSAGE\nService: TestService\nChannel:"
            " TEST CHANNEL\nActor: \n\nPart 1 sell part2",
        }
    ]


""" VERITY471 FIXTURE-BACKED TESTS """

# Each file under test_data/verity471/ is a captured Verity471 *detail* response: one bare
# document, exactly what Client.search_alert_details_verity471 hands to an adapter in
# fetch_incidents_verity471. The documents are API schema samples, so most leaf values are the
# literal placeholder "string" — assertions therefore pin the labels and structure the adapters
# emit rather than realistic intel.

VERITY471_DIR = "test_data/verity471"

# Report fixtures carry the placeholder "string" in their "type" field, and _report_url builds the
# portal path from that field, so every report type renders the same link.
REPORT_VIEW_URL = "https://verity.intel471.com/intelligence/stringReportView/string"  # disable-secrets-detection

# (fixture stem, source_type, expected adapter, expected incident_name,
#  required incident_details substrings, expected portal url, expected alert_id)
VERITY471_CASES = [
    (
        "get_credential_sets_id",
        "creds_cred_set",
        "CredentialSetAdapter",
        "CREDENTIAL SET:\nstring",
        [
            "Source Object: CREDENTIAL SET",
            "Name: string",
            '"record_count": 0',
            '"breach_ts": "2026-01-01T00:00:00Z"',
        ],
        "https://verity.intel471.com/search?category=creds_cred_set&timeFilter=ALL_TIME&q=cred_set.name%3Dstring",
        "string",
    ),
    (
        "get_credentials_id",
        "creds_cred",
        "CredentialAdapter",
        "CREDENTIAL:\nstring",
        [
            "Source Object: CREDENTIAL",
            "Credential Login: string",
            "Detection Domain: string",
            "Password Strength: string",
            "Affiliations: string",
        ],
        "https://verity.intel471.com/credentials-dashboard/details/string",
        "string",
    ),
    (
        "get_credentials_occurrences_id",
        "creds_cred_occurrence",
        "CredentialOccurrenceAdapter",
        "CREDENTIAL OCCURRENCE:\nstring",
        [
            "Source Object: CREDENTIAL OCCURRENCE",
            "Credential Login: string",
            "Detection Domain: string",
            "Password Strength: string",
            "Credential Set: string",
        ],
        "",
        "string",
    ),
    (
        "get_events_id",
        "malware_event",
        "MalwareEventAdapter",
        "MALWARE EVENT:\nstring - string",
        [
            "Source Object: MALWARE EVENT",
            "Malware Family: string",
            "Malware Family Version: string",
            "Kill chain phases: ",
            '"phase_name": "string"',
            "Event Type: string",
            "\n\nEvent Details:\n",
            '"bot_settings"',
        ],
        "",
        "string",
    ),
    (
        "get_forums_posts_post_id",
        "forums_post",
        "ForumPostAdapter",
        "FORUM POST:\nstring",
        [
            "Source Object: FORUM POST",
            "Forum: string",
            "Thread Topic: string",
            "Actor: string",
        ],
        "https://verity.intel471.com/sources/forum/string/sub-forum/string/thread/string",
        "string",
    ),
    (
        "get_forums_private_messages_private_message_id",
        "forums_private_message",
        "ForumsPrivateMessageAdapter",
        "FORUM PRIVATE MESSAGE:\nstring",
        [
            "Source Object: FORUM PRIVATE MESSAGE",
            "Forum: string",
            "Subject: string",
            "Author: string",
        ],
        "",
        "string",
    ),
    (
        "get_indicators_id",
        "malware_indicator",
        "MalwareIndicatorAdapter",
        "MALWARE INDICATOR:\nstring - string",
        [
            "Source Object: MALWARE INDICATOR",
            "Malware Family: string",
            "Description: string",
            "Confidence Level: 0",
            "Indicator Type: domain",
            "Pattern type: string",
            "\n\nIndicator Details:\n",
            '"sha256": "string"',
        ],
        "",
        "string",
    ),
    (
        "get_malware_id",
        "malware_family",
        "EntityAdapter",
        "ENTITY:\nstring",
        [
            "Source Object: ENTITY",
            "Entity: string",
            "description - string",
            "classification.girs[0].path - string",
        ],
        "https://verity.intel471.com/malware/families/string/report",
        "string",
    ),
    (
        "get_messaging_services_messages_message_id",
        "chats_message",
        "InstantMessageAdapter",
        "INSTANT MESSAGE:\nstring",
        [
            "Source Object: INSTANT MESSAGE",
            "Service: string",
            "Channel: string",
            "Actor: string",
        ],
        "https://verity.intel471.com/sources/messaging-services/thread/string",
        "string",
    ),
    (
        "get_reports_breach_alert_id",
        "breach_alerts",
        "BreachAlertAdapter",
        "BREACH ALERT:\nstring",
        [
            "Source Object: BREACH ALERT",
            "Title: string",
            "Confidence: high (string)",
            "Actor/Group: string",
            "Victim Details:",
            '"sector": "string"',
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_fintel_id",
        "fintel",
        "FintelReportAdapter",
        "FINTEL:\nstring",
        [
            "Source Object: FINTEL",
            "Title: string",
            "Type / sub_type: string / actor_profile",
            "\n\nBody:\nstring",
            "\n\nSources:\n[0] string|type:string|source_type:string|href:string",
            "\n\nLocations:\nstring / string / string (link: string)",
            "\n\nEntities:\n[string] string",
            "\n\nDerived entities:\n[string] string",
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_geopol_id",
        "geopol_reports",
        "GeopolReportAdapter",
        "GEOPOL REPORT:\nstring",
        [
            "Source Object: GEOPOL REPORT",
            "Type / sub_type: string / spot_report",
            "\n\nIntelligence estimate:\n",
            '"threat_rating": "low"',
            "\n\nSignificant activity:\n",
            '"event_tag": "economic"',
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_info_id",
        "information_reports",
        "InformationReportAdapter",
        "INFORMATION REPORT:\nstring",
        [
            "Source Object: INFORMATION REPORT",
            "Title: string",
            "Source characterization: string",
            "\n\nBody:\nstring",
            "\n\nAssessment:\nAdmiralty code - A1",
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_malware_id",
        "malware_reports",
        "MalwareReportAdapter",
        "MALWARE REPORT:\nstring",
        [
            "Source Object: MALWARE REPORT",
            "Title: string",
            "Type: string",
            "Version: string",
            "\n\nBody:\nstring",
            "\n\nThreat:\n",
            '"family": "string"',
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_spot_id",
        "spot_reports",
        "SpotReportAdapter",
        "SPOT REPORT:\nstring",
        [
            "Source Object: SPOT REPORT",
            "\n\nstring",
            "\n\nPurported Victims:",
            '"industry": "string"',
        ],
        REPORT_VIEW_URL,
        "string",
    ),
    (
        "get_reports_vulnerability_id",
        "vulnerabilities_cve",
        "CveReportAdapter",
        "CVE REPORT:\nstring",
        [
            "Source Object: CVE REPORT",
            "CVE: string",
            "Risk Level: high",
            "Vendor: string",
            "Product: string",
            "Exploit Status: \nAvailable - True\nWeaponized - False\nProductized - False",
            "Patch Status: available",
            "Countermeasures: string",
            "Summary: string",
        ],
        "https://verity.intel471.com/vulnerabilities/new?vulnerabilityId=string",
        "string",
    ),
    (
        "get_marketplaces_marketplace_id",
        "marketplaces_website",
        "MarketplaceAdapter",
        "MARKETPLACE:\nstring",
        [
            "Source Object: MARKETPLACE",
            "Name: string",
            "Alias: string",
            "Tier: 0",
            "Active: True",
            "Link: string",
            "First seen: 2026-01-01T00:00:00Z",
            "Last seen: 2026-01-01T00:00:00Z",
            "\n\nDescription:\nstring",
        ],
        "string",  # taken from links.verity_portal.href on the document
        "string",
    ),
    (
        "get_products_product_id",
        "marketplaces_product",
        "MarketplaceProductAdapter",
        "MARKETPLACE PRODUCT:\nstring",
        [
            "Source Object: MARKETPLACE PRODUCT",
            "Title: string",
            "Kind: string",
            "Vendor: string",
            "Marketplace ID: string",
            "Price: 0.0 string",
            "Times sold: 0",
            "\n\nQuantity:\n",
            '"stock": 0',
            "\n\nShipping:\n",
            '"destinations"',
            "\n\nProduct details:\n",
            '"in_game_items"',
        ],
        "string",
        "string",
    ),
    (
        "get_resources_resource_id",
        "marketplaces_resource",
        "MarketplaceResourceAdapter",
        "MARKETPLACE RESOURCE:\nstring",
        [
            "Source Object: MARKETPLACE RESOURCE",
            "Name: string",
            "Product title: string",
            "Login available: True",
            "Password available: True",
            "Cookies available: True",
            "Infostealer browser: string",
            "Infostealer grabbed: 2026-01-01T00:00:00Z",
            "Stolen data source: string",
            "Stolen datasets: string",
        ],
        "string",
        "string",
    ),
    (
        "get_vendors_vendor_id",
        "marketplaces_seller",
        "MarketplaceVendorAdapter",
        "MARKETPLACE VENDOR:\nstring",
        [
            "Source Object: MARKETPLACE VENDOR",
            "Name: string",
            "Marketplace: string",
            "Rating: 0.0 / 0.0",
            "Valid rate (10 days): 0.0",
            "Valid rate (30 days): 0.0",
            "Valid rate (overall): 0.0",
            "Average response time: 0",
            "Forum links: string",
            "Review links: string",
        ],
        "string",
        "string",
    ),
    (
        "get_data_leak_sites_posts_id",
        "data_leak_sites_post",
        "DataLeakSitePostAdapter",
        "DATA LEAK POST:\nstring",
        [
            "Source Object: DATA LEAK POST",
            "Title: string",
            "Website: string",
            "Source URL: string",
            "Published: string",
            "Inactive: True",
            "Inactive since: string",
            "\n\nAttachments:\n[key] string|type:string|size:0|hash:string|classification:csam|url:string",
        ],
        "",  # the post document carries no links block, so there is no portal URL to use
        "string",
    ),
    (
        "get_data_leak_sites_file_listings_id_details",
        "data_leak_sites_file_listing",
        "DataLeakSiteFileListingAdapter",
        "DATA LEAK FILE LISTING:\nstring",
        [
            "Source Object: DATA LEAK FILE LISTING",
            "File name: string",
            "File ID: string",
            "Website: string",
            "Thread: string",
            "Post: string",
            "Post link: string",
            "Chunk number: 0",
            "Download link: string",
        ],
        "string",  # taken from links.verity_portal.href on the document
        "string",
    ),
]

# The captured /alerts/stream envelope. It is an API schema sample carrying a single alert whose
# source_type and detail href are the placeholder "string", so the end-to-end test below swaps
# those two fields to aim each run at a real detail fixture.
VERITY471_STREAM_FIXTURE = "get_alerts_stream"

VERITY471_CASE_IDS = [case[0] for case in VERITY471_CASES]


def util_load_verity471(stem):
    """Loads a Verity471 detail document from test_data/verity471/<stem>.json."""
    return util_load_json(f"{VERITY471_DIR}/{stem}.json")


def test_every_verity471_fixture_is_covered():
    """
    Given:
        - The fixture set under test_data/verity471/.

    When:
        - The fixtures referenced by this module are collected.

    Then:
        - Every fixture is exercised by a test, and no test points at a fixture that was renamed
          or removed.
    """
    on_disk = {path.stem for path in Path(VERITY471_DIR).glob("*.json")}
    referenced = set(VERITY471_CASE_IDS) | {VERITY471_STREAM_FIXTURE}

    assert sorted(on_disk - referenced) == [], "fixtures with no test"
    assert sorted(referenced - on_disk) == [], "tests pointing at missing fixtures"


@pytest.mark.parametrize(
    "stem,source_type,adapter_name,expected_name,expected_fragments,expected_url,expected_alert_id",
    VERITY471_CASES,
    ids=VERITY471_CASE_IDS,
)
def test_verity471_adapter(stem, source_type, adapter_name, expected_name, expected_fragments, expected_url, expected_alert_id):
    """
    Given:
        - A Verity471 detail document captured in test_data/verity471/<stem>.json.

    When:
        - fetch_incidents_verity471 picks an adapter for the alert's source_type and renders the
          incident name, details and portal URL.

    Then:
        - The documented adapter is selected, and the rendered incident fields carry the
          document's values under the expected labels.
    """
    document = util_load_verity471(stem)

    adapter_cls = feed.VERITY471_DOCUMENT_TYPES.get(source_type, feed.UnknownAlertAdapter)
    assert adapter_cls.__name__ == adapter_name

    adapted = adapter_cls(document)

    assert adapted.incident_name == expected_name
    assert adapted.alert_id == expected_alert_id

    details = adapted.incident_details
    for fragment in expected_fragments:
        assert fragment in details, f"{stem}: missing {fragment!r} in incident_details"

    assert feed.compose_verity471_url(document, adapted.alert_id, source_type) == expected_url


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "Source Object: X"),  # missing -> skipped
        ("", "Source Object: X"),  # empty -> skipped
        ("   ", "Source Object: X"),  # whitespace only -> skipped
        ([], "Source Object: X"),  # empty collection -> skipped
        (0, "Source Object: X\nField: 0"),  # falsy number -> kept
        (0.0, "Source Object: X\nField: 0.0"),
        (False, "Source Object: X\nField: False"),  # falsy bool -> kept
        ("value", "Source Object: X\nField: value"),
    ],
)
def test_verity_append_field(value, expected):
    """
    Given:
        - A field value that may be missing, blank, or falsy-but-meaningful.

    When:
        - _verity_append_field renders it.

    Then:
        - Missing and blank values are dropped, while 0 and False are kept — marketplace documents
          carry meaningful zeroes (tier, times_sold, rating, response time).
    """
    assert feed._verity_append_field("Source Object: X", "Field", value) == expected


@pytest.mark.parametrize(
    "price,expected",
    [
        ([{"value": 0.0, "currency": "string"}], "0.0 string"),
        ([{"value": 12.5, "currency": "USD"}, {"value": 10, "currency": "EUR"}], "12.5 USD, 10 EUR"),
        ([{"value": 7}], "7"),
        ([], ""),
        (None, ""),
        ("not-a-list", ""),
    ],
)
def test_verity_format_price(price, expected):
    """
    Given:
        - The price list on a marketplace product document.

    When:
        - _verity_format_price renders it.

    Then:
        - Each entry becomes "<value> <currency>", and non-list input yields an empty string.
    """
    assert feed._verity_format_price(price) == expected


@pytest.mark.parametrize("stem,source_type", [(c[0], c[1]) for c in VERITY471_CASES], ids=VERITY471_CASE_IDS)
def test_verity471_incident_details_never_leak_blank_labels(stem, source_type):
    """
    Given:
        - A Verity471 detail document.

    When:
        - incident_details is rendered.

    Then:
        - No label is emitted with an empty value (the _verity_is_blank guards hold), and the
          details always open with the source-object header.
    """
    document = util_load_verity471(stem)
    adapter_cls = feed.VERITY471_DOCUMENT_TYPES.get(source_type, feed.UnknownAlertAdapter)
    details = adapter_cls(document).incident_details

    assert details.startswith("Source Object: ")
    for line in details.splitlines():
        if line.endswith(": ") and not line.startswith("Exploit Status"):
            raise AssertionError(f"{stem}: emitted an empty label: {line!r}")


@pytest.mark.parametrize(
    "stem,nested_path",
    [
        ("get_messaging_services_messages_message_id", ("message", "id")),
        ("get_forums_posts_post_id", ("post", "id")),
        ("get_forums_private_messages_private_message_id", ("private_message", "id")),
    ],
)
def test_verity471_alert_id_resolves_nested_ids(stem, nested_path):
    """
    Given:
        - A Verity471 document whose identifier is nested (e.g. message.id) with no top-level "id".

    When:
        - BaseAdapter.alert_id is read.

    Then:
        - The nested identifier is returned.
    """
    document = util_load_verity471(stem)
    assert "id" not in document
    expected = document[nested_path[0]][nested_path[1]]

    assert feed.BaseAdapter(document).alert_id == expected


""" VERITY471 ALERT STREAM TESTS """

STREAM_URL = "https://api.intel471.cloud/integrations/watchers/v1/alerts/stream"
WATCHER_GROUPS_URL = "https://api.intel471.cloud/integrations/watchers/v1/watcher-groups"
WATCHERS_URL = "https://api.intel471.cloud/integrations/watchers/v1/watchers"
DETAIL_URL = "https://api.verity.intel471.com/detail"


def build_verity471_stream(source_type, href):
    """Returns the captured stream envelope with its single alert aimed at a given detail fixture."""
    envelope = util_load_verity471(VERITY471_STREAM_FIXTURE)
    alert = envelope["alerts"][0]
    alert["source_type"] = source_type
    alert["links"]["verity_api"]["href"] = href
    return envelope


def register_verity471_stream(requests_mock, envelope, detail_json):
    """Wires up the four endpoints a Verity471 fetch touches."""
    requests_mock.get(STREAM_URL, json=envelope)
    requests_mock.get(DETAIL_URL, json=detail_json)
    requests_mock.get(WATCHER_GROUPS_URL, json={"watchers_groups": [{"description": "Leaked credentials"}]})
    requests_mock.get(WATCHERS_URL, json={"watchers": [{"description": 'Watcher on "acme.com"'}]})

    # Both watcher lookups are lru_cached on the Client method, so drop entries left by other tests.
    feed.Client.search_watcher_group_details_verity471.cache_clear()
    feed.Client.search_watcher_details_verity471.cache_clear()


def make_verity471_client():
    return feed.Client(
        base_url="https://api.intel471.cloud",
        verify=False,
        headers={"Authentication": "Bearer some_api_key"},
    )


def test_verity471_stream_fixture_matches_the_fields_the_fetch_reads():
    """
    Given:
        - The captured /alerts/stream response.

    When:
        - Its envelope and alert records are inspected.

    Then:
        - Every field fetch_incidents_verity471 reads off the stream is present, so a schema change
          on the Verity side surfaces here rather than as a KeyError mid-fetch.
    """
    envelope = util_load_verity471(VERITY471_STREAM_FIXTURE)

    assert set(envelope) == {"alerts", "count", "cursor_next"}
    assert envelope["cursor_next"] == "string"

    alert = envelope["alerts"][0]
    for field in ("id", "watcher_group_id", "watcher_id", "source_type", "creation_ts", "highlights", "links"):
        assert field in alert, field
    assert feed.deep_get(alert, "links.verity_api.href", None) is not None
    assert set(alert["highlights"][0]) == {"field_name", "snippets"}


@pytest.mark.parametrize(
    "stem,source_type,expected_name",
    [(c[0], c[1], c[3]) for c in VERITY471_CASES],
    ids=VERITY471_CASE_IDS,
)
def test_fetch_incidents_verity471(requests_mock, stem, source_type, expected_name):
    """
    Given:
        - The captured /alerts/stream response, pointed at one source type's detail fixture.

    When:
        - fetch_incidents_verity471 runs.

    Then:
        - One incident is produced with that adapter's name, the watcher metadata and highlights
          resolved, and next_run carrying the alert's creation_ts plus the stream cursor.
    """
    envelope = build_verity471_stream(source_type, DETAIL_URL)
    register_verity471_stream(requests_mock, envelope, util_load_verity471(stem))

    last_cursor, next_run, incidents = feed.fetch_incidents_verity471(
        client=make_verity471_client(),
        max_results=100,
        last_run={},
        first_fetch_time=0,
        watcher_group_uids=None,
    )

    assert last_cursor == "string"
    assert next_run == {"last_fetch": 1767225600000, "last_cursor": "string"}  # 2026-01-01T00:00:00Z
    assert len(incidents) == 1

    incident = incidents[0]
    assert incident["name"] == expected_name
    assert incident["type"] == feed.INCIDENT_TYPE
    assert incident["severity"] == 2  # no severity on the alert -> defaults to Medium
    assert incident["occurred"] == "2026-01-01T00:00:00.000Z"
    assert incident["rawJSON"] == json.dumps(envelope["alerts"][0])
    assert incident["details"].startswith("Source Object: ")
    assert incident["CustomFields"]["watchergroup"] == "[Watcher Group ID 0] Leaked credentials"
    assert incident["CustomFields"]["watcher"] == '[Watcher ID 0] Watcher on "acme.com"'
    assert incident["CustomFields"]["highlights"] == "string - string"


def test_fetch_incidents_verity471_unmapped_source_type(requests_mock):
    """
    Given:
        - A stream alert whose source_type has no adapter (the fixture's own "string" placeholder).

    When:
        - fetch_incidents_verity471 runs.

    Then:
        - The incident is still created, rendered by UnknownAlertAdapter.
    """
    envelope = build_verity471_stream("string", DETAIL_URL)
    register_verity471_stream(requests_mock, envelope, util_load_verity471("get_marketplaces_marketplace_id"))

    _, _, incidents = feed.fetch_incidents_verity471(
        client=make_verity471_client(),
        max_results=100,
        last_run={},
        first_fetch_time=0,
        watcher_group_uids=None,
    )

    assert len(incidents) == 1
    assert incidents[0]["name"] == "UNKNOWN ALERT TYPE:\nUID: string"
    assert incidents[0]["CustomFields"]["intel471url"] == ""


def test_fetch_incidents_verity471_skips_alerts_without_details(requests_mock):
    """
    Given:
        - A stream alert whose detail endpoint returns an empty body.

    When:
        - fetch_incidents_verity471 runs.

    Then:
        - The alert is skipped rather than producing an empty incident, and the cursor still advances.
    """
    envelope = build_verity471_stream("creds_cred", DETAIL_URL)
    register_verity471_stream(requests_mock, envelope, {})

    last_cursor, next_run, incidents = feed.fetch_incidents_verity471(
        client=make_verity471_client(),
        max_results=100,
        last_run={},
        first_fetch_time=0,
        watcher_group_uids=None,
    )

    assert incidents == []
    assert last_cursor == "string"
    assert next_run["last_cursor"] == "string"


def test_fetch_incidents_verity471_resumes_from_last_run(requests_mock):
    """
    Given:
        - A stored last_run holding a cursor and a last_fetch newer than the streamed alert.

    When:
        - fetch_incidents_verity471 runs.

    Then:
        - The stored cursor and last_fetch are sent to the stream endpoint, and the older alert
          does not drag last_fetch backwards.
    """
    envelope = build_verity471_stream("creds_cred", DETAIL_URL)
    register_verity471_stream(requests_mock, envelope, util_load_verity471("get_credentials_id"))

    _, next_run, incidents = feed.fetch_incidents_verity471(
        client=make_verity471_client(),
        max_results=25,
        last_run={"last_fetch": 1800000000000, "last_cursor": "previous-cursor"},
        first_fetch_time=0,
        watcher_group_uids=None,
    )

    stream_request = next(r for r in requests_mock.request_history if r.path.endswith("/alerts/stream"))
    assert stream_request.qs["cursor"] == ["previous-cursor"]
    assert stream_request.qs["from"] == ["1800000000001"]
    assert stream_request.qs["size"] == ["25"]

    assert len(incidents) == 1
    assert next_run["last_fetch"] == 1800000000001


""" NON-DICT DETAIL RESPONSE TESTS """


@pytest.mark.parametrize(
    "document,expected_details",
    [
        ("<binary>", "Source Object: UNKNOWN ALERT TYPE\n\n<binary>"),
        ("  <b>spaced</b>  ", "Source Object: UNKNOWN ALERT TYPE\n\nspaced"),
        ("", "Source Object: UNKNOWN ALERT TYPE"),
        (0, "Source Object: UNKNOWN ALERT TYPE\n\n0"),
        ([], "Source Object: UNKNOWN ALERT TYPE"),
        ([{"a": 1}], 'Source Object: UNKNOWN ALERT TYPE\n\n[\n  {\n    "a": 1\n  }\n]'),
    ],
)
def test_unknown_alert_adapter_accepts_non_dict_documents(document, expected_details):
    """
    Given:
        - A detail response that is a bare scalar or a list rather than an object (the raw file
          download endpoint returns the string "<binary>").

    When:
        - UnknownAlertAdapter renders it.

    Then:
        - A usable incident is produced instead of AttributeError. Before this was guarded,
          incident_name raised first, making the list and scalar arms of incident_details dead.
    """
    adapted = feed.UnknownAlertAdapter(document)

    assert adapted.alert_id is None
    assert adapted.incident_name == "UNKNOWN ALERT TYPE:\nUID: "
    assert adapted.incident_details == expected_details


def test_fetch_incidents_verity471_handles_non_dict_detail_response(requests_mock):
    """
    Given:
        - A stream alert whose detail endpoint returns a bare JSON string.

    When:
        - fetch_incidents_verity471 runs.

    Then:
        - The alert still becomes an incident rather than raising and losing the whole batch.
    """
    envelope = build_verity471_stream("string", DETAIL_URL)
    register_verity471_stream(requests_mock, envelope, "<binary>")

    _, _, incidents = feed.fetch_incidents_verity471(
        client=make_verity471_client(),
        max_results=100,
        last_run={},
        first_fetch_time=0,
        watcher_group_uids=None,
    )

    assert len(incidents) == 1
    assert incidents[0]["name"] == "UNKNOWN ALERT TYPE:\nUID: "
    assert incidents[0]["details"] == "Source Object: UNKNOWN ALERT TYPE\n\n<binary>"
    assert incidents[0]["CustomFields"]["intel471url"] == ""


""" TITAN WATCHER LOOKUP TESTS """


def test_compose_incident_watcher_details_resolves_group_and_watcher():
    """
    Given:
        - An alert whose watcher group and watcher are both present in the batch.

    When:
        - compose_incident_watcher_details runs.

    Then:
        - Both descriptions are returned.
    """
    alert = {"watcherGroupUid": "wg-1", "watcherUid": "w-1"}
    watcher_groups = [{"uid": "wg-1", "name": "My group", "watchers": [{"uid": "w-1", "description": "My watcher"}]}]

    assert feed.compose_incident_watcher_details(alert, watcher_groups) == ("My group", "My watcher")


@pytest.mark.parametrize(
    "alert",
    [
        {"watcherGroupUid": "missing", "watcherUid": "w-1"},  # group not in the batch
        {"watcherGroupUid": "wg-1", "watcherUid": "missing"},  # watcher not in the group
    ],
    ids=["unknown-group", "unknown-watcher"],
)
def test_compose_incident_watcher_details_tolerates_missing_entries(alert):
    """
    Given:
        - An alert referencing a watcher group or watcher that is absent from the batch.

    When:
        - compose_incident_watcher_details runs.

    Then:
        - Empty descriptions come back instead of IndexError, which previously failed the entire
          Titan fetch and made the "if watcher_group" / "if watcher" guards unreachable.
    """
    watcher_groups = [{"uid": "wg-1", "name": "My group", "watchers": [{"uid": "w-1", "description": "My watcher"}]}]

    group_description, watcher_description = feed.compose_incident_watcher_details(alert, watcher_groups)

    assert group_description in ("", "My group")
    assert watcher_description == ""
