from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from collections.abc import Generator

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type:ignore


MOCK_IP_INDICATOR = {
    "id": "ipv4--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "ipv4",
    "value": "1.2.3.4",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 87
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_DOMAIN_INDICATOR = {
    "id": "fqdn--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "fqdn",
    "value": "domain.test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 100
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_URL_INDICATOR = {
    "id": "url--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "url",
    "value": "https://domain.test/test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 99
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_FILE_INDICATOR = {
    "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "md5",
    "value": "ae1747c930e9e4f45fbc970a83b52284",
    "is_exclusive": True,
    "is_publishable": True,
    "associated_hashes": [
        {
            "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "md5",
            "value": "ae1747c930e9e4f45fbc970a83b52284"
        },
        {
            "id": "sha1--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha1",
            "value": "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
        },
        {
            "id": "sha256--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha256",
            "value": "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"
        }
    ],
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 88
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_INDICATORS_LIST = {"indicators": [
    MOCK_IP_INDICATOR,
    MOCK_DOMAIN_INDICATOR,
    MOCK_URL_INDICATOR,
    MOCK_FILE_INDICATOR
]}


class MandiantClient(BaseClient):
    def __init__(self, config):
        base_url = "https://api.intelligence.mandiant.com"
        verify = not config.get("insecure", False)
        proxy = config.get("proxy", False)
        super().__init__(base_url, verify, proxy, ok_codes=(200,))

        self.api_key = config.get("api_key", "")
        self.secret_key = config.get("secret_key", "")
        self.timeout = int(config.get("timeout", 60))
        page_size = int(config.get("page_size", 1000))
        self.page_size = 1000 if page_size > 1000 else page_size
        self.tlp_color = config.get("tlp_color", "RED")
        self.feed_tags = argToList(config.get("feedTags", ""))
        self.reliability = config.get("feedReliability", "A - Completely reliable")
        self.minimum_threat_score = int(config.get("feedMinimumThreatScore", 80))
        self.exclude_osint = config.get("feedExcludeOSIntel", True)
        self.first_fetch = 90 if int(config.get("first_fetch", 30)) > 90 else int(config.get("first_fetch", 30))
        self.headers = {
            "X-App-Name": "content.xsoar.cortex.mandiant.feed.v1.1",
            "Accept": "application/json"
        }

    def _get(self, path: str, params: Dict = {}) -> Dict[str, Any]:
        try:
            response = self._http_request(method="GET", url_suffix=path, auth=(self.api_key, self.secret_key),
                                          headers=self.headers, params=params, timeout=self.timeout)
            return response
        except DemistoException as e:
            raise DemistoException(e)

    def get_entitlements(self) -> Dict:
        return self._get("/v4/entitlements")

    def yield_indicators(self, start_time: int, end_time: int, limit: int) -> Generator:
        for i in MOCK_INDICATORS_LIST.get("indicators", []):  # noqa: UP028
            yield i
        # params = {
        #     "start_epoch": start_time,
        #     "end_epoch": end_time,
        #     "limit": limit,
        #     "include_campaigns": True,
        #     "include_reports": True,
        #     "include_threat_rating": True,
        #     "include_misp": False,
        #     "include_category": True
        # }

        # while True:
        #     api_response = self._get("/v4/indicator", params=params)

        #     if not api_response:
        #         break

        #     indicators_from_api = api_response.get("indicators", [])
        #     for indicator in indicators_from_api:
        #         yield indicator

        #     if not api_response.get("next") or len(indicators_from_api) <= limit:
        #         break

        #     params = {
        #         "next": api_response.get("next", ""),
        #         "include_campaigns": True,
        #         "include_reports": True,
        #         "include_threat_rating": True,
        #         "include_misp": False,
        #         "include_category": True
        #     }


def calculate_start_time(end_time: int, first_fetch: int) -> int:
    last_run = demisto.getLastRun()

    if not last_run:
        return end_time - (86400 * first_fetch)

    return last_run.get("last_run")


def is_osint(indicator: Dict) -> bool:
    sources = [s.get("source_name").lower() for s in indicator.get("sources", [])]

    return "mandiant" not in sources


def get_threat_score(indicator: Dict) -> int:
    threat_score = indicator.get("threat_rating", {}).get("threat_score", 0)
    if not isinstance(threat_score, int):
        return 0
    return threat_score


def include_in_feed(indicator: Dict, exclude_osint: bool, min_threat_score: int) -> bool:
    if exclude_osint and is_osint(indicator):
        return False

    if get_threat_score(indicator) < min_threat_score:
        return False

    return True


def get_hash_value(indicator: dict, hash_type: str) -> str:
    hash_value = ""
    for a in indicator.get("associated_hashes", []):
        hash_value = a.get("value", "") if a.get("type") == hash_type else ""
        if hash_value:
            break
    return hash_value


def get_categories(sources: List) -> List:
    categories = set()
    for source in sources:
        for c in source.get("category", []):
            categories.add(c.lower())

    return list(categories)


def build_indicator_relationships(value_: str, indicator: Dict) -> List:
    relationships: List = []
    entity_a = value_
    entity_a_type = indicator.get("type", "")

    for association in indicator.get("attributed_associations", []):
        association_type = association.get("type", "")
        entity_b = association.get("name", "")

        if association_type == "threat-actor":
            relationships.append(EntityRelationship(name="uses", reverse_name="used-by", entity_a=entity_a,
                                                    entity_a_type=entity_a_type, entity_b=entity_b,
                                                    entity_b_type="Threat Actor").to_indicator())
        elif association_type == "malware":
            relationships.append(EntityRelationship(name="indicates", reverse_name="indicated-by", entity_a=entity_a,
                                                    entity_a_type=entity_a_type, entity_b=entity_b,
                                                    entity_b_type="Malware").to_indicator())

    for campaign in indicator.get("campaigns", []):
        title = campaign.get("title")
        campaign_id = campaign.get("name")
        entity_b = f"{title} ({campaign_id})"
        relationships.append(EntityRelationship(name="indicates", reverse_name="indicated-by", entity_a=entity_a,
                                                entity_a_type=entity_a_type, entity_b=entity_b,
                                                entity_b_type="Campaign").to_indicator())

    return relationships


def translate_indicator(indicator: Dict, tlp_color: str, tags: List) -> Dict:
    feed_type_map = {
        "ipv4": FeedIndicatorType.IP,
        "fqdn": FeedIndicatorType.Domain,
        "url": FeedIndicatorType.URL,
        "md5": FeedIndicatorType.File,
    }

    indicator["type"] = feed_type_map.get(indicator.get("type", ""))
    if not indicator["type"]:
        raise KeyError("Invalid indicator type returned by Mandiant API")

    xsoar_indicator = {}
    xsoar_indicator["value"] = indicator.get("value")
    xsoar_indicator["type"] = indicator.get("type")
    xsoar_indicator["rawJSON"] = indicator

    fields: Dict[str, Any] = {}

    fields["STIX ID"] = indicator.get("id", "")
    fields["Traffic Light Protocol"] = "GREEN" if is_osint(indicator) else tlp_color
    fields["Mandiant First Seen"] = indicator.get("first_seen", "")
    fields["Mandiant Last Seen"] = indicator.get("last_seen", "")
    fields["Mandiant Threat Score"] = indicator.get("threat_rating", {}).get("threat_score", 0)
    fields["Mandiant Severity Level"] = indicator.get("threat_rating", {}).get("severity_level", "unknown")

    if indicator.get("type") == FeedIndicatorType.File:
        fields["md5"] = get_hash_value(indicator, "md5")
        fields["sha1"] = get_hash_value(indicator, "sha1")
        fields["sha256"] = get_hash_value(indicator, "sha256")

    fields["Tags"] = []
    for t in tags:
        fields["Tags"].append(t)
    for category in get_categories(indicator.get("sources", [])):
        fields["Tags"].append(category)

    xsoar_indicator["fields"] = fields
    xsoar_indicator["relationships"] = build_indicator_relationships(indicator.get("value", ""), indicator)

    return xsoar_indicator


def get_utc_now_timestamp() -> int:
    return int(datetime.now(timezone.utc).replace(tzinfo=timezone.utc).timestamp())


def fetch_indicators_command(client: MandiantClient) -> List:
    indicators_list = []
    end_time = get_utc_now_timestamp()
    start_time = calculate_start_time(end_time, client.first_fetch)

    for i in client.yield_indicators(start_time, end_time, client.page_size):
        if not include_in_feed(i, client.exclude_osint, client.minimum_threat_score):
            continue
        indicators_list.append(translate_indicator(i, client.tlp_color, client.feed_tags))

    demisto.setLastRun({"last_run": end_time})

    return indicators_list


def get_indicators_command(client: MandiantClient, args: Dict) -> List:
    limit = int(args.get("limit", 10))
    indicators_list: List[Dict] = []
    current_time = get_utc_now_timestamp()
    start_time = current_time - 86400

    for i in client.yield_indicators(start_time, current_time, client.page_size):
        if len(indicators_list) == limit:
            break
        if not include_in_feed(i, client.exclude_osint, client.minimum_threat_score):
            continue

        indicators_list.append(translate_indicator(i, client.tlp_color, client.feed_tags))

    return indicators_list


def test_module(client: MandiantClient) -> str:
    try:
        result = client.get_entitlements()
        if not result.get("entitlements"):
            raise Exception
        return "ok"
    except DemistoException as ex:
        raise DemistoException(str(ex))


def main() -> None:
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = MandiantClient(demisto.params())

        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client)

            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == "test-module":
            return_results(test_module(client))

        elif command == "mandiant-get-indicators":
            return_results(get_indicators_command(client, demisto.args()))

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
