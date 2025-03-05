from collections.abc import Callable

import dateutil.parser
import pytz

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type:ignore

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

MAP_TYPE_TO_URL = {
    "Malware": "malware",
    "Actors": "actor",
    "Indicators": "indicator",
    "Vulnerability": "vulnerability",
    "Campaign": "campaign",
}
MAP_TYPE_TO_RESPONSE = {
    "Malware": "malware",
    "Actors": "threat-actors",
    "Indicators": "indicators",
}

MAP_INDICATORS = {
    "fqdn": {"name": FeedIndicatorType.Domain, "dbotscore": DBotScoreType.DOMAIN},
    "ipv4": {"name": FeedIndicatorType.IP, "dbotscore": DBotScoreType.IP},
    "md5": {"name": FeedIndicatorType.File, "dbotscore": DBotScoreType.FILE},
    "sha1": {"name": FeedIndicatorType.File, "dbotscore": DBotScoreType.FILE},
    "sha256": {"name": FeedIndicatorType.File, "dbotscore": DBotScoreType.FILE},
    "url": {"name": FeedIndicatorType.URL, "dbotscore": DBotScoreType.URL},
    "vulnerability": {"name": FeedIndicatorType.CVE, "dbotscore": DBotScoreType.CVE},
    "Malware": {
        "name": ThreatIntel.ObjectsNames.MALWARE,
        "dbotscore": DBotScoreType.CUSTOM,
    },
    "Actors": {
        "name": ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "dbotscore": DBotScoreType.CUSTOM,
    },
    "Campaign": {"name": ThreatIntel.ObjectsNames.CAMPAIGN},
}

MAP_TYPE_TO_ATTACKPATTERN_KEY = {"Actors": "threat-actors", "Malware": "malware"}

DEFAULT_TIMEOUT = 60
ENRICHMENT_TIMEOUT = 10

""" CLIENT CLASS """


class MandiantClient(BaseClient):
    """Client class to interact with the service API"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        secret_key: str,
        verify: bool,
        proxy: bool,
        timeout: int,
        first_fetch: str,
        limit: int,
        types: List,
        metadata: bool = False,
        enrichment: bool = False,
        tags: List = None,
        tlp_color: str = "RED",
    ):
        if not tags:
            tags = []

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200,))
        self._api_credentials = (api_key, secret_key)

        self._headers = {
            "X-App-Name": "content.xsoar.cortex.mandiantadvantage.v1.0",
            "Accept": "application/json",
            "Authorization": f"Bearer {self._get_token()}",
        }
        self.timeout = timeout
        if is_time_sensitive():
            # For reputation commands which run during an enrichment we limit the timeout
            self.timeout = ENRICHMENT_TIMEOUT
        self.first_fetch = first_fetch
        self.limit = limit
        self.types = types
        self.metadata = metadata
        self.tlp_color = tlp_color
        self.tags = tags
        self.enrichment = enrichment

        add_sensitive_log_strs(self._get_token())

    def _get_token(self) -> str:
        """
        Returns the token from the integration context if available and has not expired
        Otherwise, a new token is retrieved from the Mandiant API and stored in the integration context
        Returns:
            str: the bearer token that is currently in the integration context
        """
        integration_context = get_integration_context()
        token = integration_context.get("token", "")
        valid_until = integration_context.get("valid_until")

        now_timestamp = arg_to_datetime("now").timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until and now_timestamp < valid_until:
            return token

        # else generate a token and update the integration context accordingly
        token = self._retrieve_token()

        return token

    def _retrieve_token(self) -> str:
        """
        Retrieve a new token from the Mandiant API
        """
        headers = {"accept": "application/json"}
        data = {"grant_type": "client_credentials"}

        resp = self._http_request(
            method="POST",
            auth=self._api_credentials,
            headers=headers,
            url_suffix="token",
            resp_type="json",
            data=data,
        )
        self._token = resp.get("access_token")

        integration_context = get_integration_context()
        integration_context.update({"token": self._token})

        token_expiration = resp.get(
            "expires_in", datetime.timestamp(datetime.now(timezone.utc))
        )

        # Subtract 10 minutes from the expiration time as a buffer
        integration_context.update({"valid_until": token_expiration - 600})
        set_integration_context(integration_context)

        return self._token

    def get_indicator_info_endpoint(
        self, identifier: str, indicator_type: str, info_type: str
    ) -> List:
        """
        Retrieve detailed information for a given indicator.
        Args:
          identifier (Dict): Indicator's identifier.
          indicator_type (str): The indicator type.
          info_type (str): Type of additional info
        Returns:
          List: A list containing the response values
        """
        url = f"v4/{MAP_TYPE_TO_URL[indicator_type]}"
        url = urljoin(url, identifier)
        url = urljoin(url, info_type)
        if url[-1] == "/":
            url = url[:-1]

        call_result = {}
        try:
            call_result = self._http_request(
                method="GET", url_suffix=url, timeout=self.timeout
            )
        except DemistoException as e:
            # If there is an internal issue inside the server, don't fail the entire fetch session
            if e.res.status_code != 500:
                raise e

        if info_type == "attack-pattern":
            res = call_result.get(MAP_TYPE_TO_ATTACKPATTERN_KEY[indicator_type], [])
            if len(res) >= 1:
                res = res[0].get("attack-patterns", [])
            else:
                return []
            if isinstance(res, str) and res == "redacted":
                return []
            elif res and isinstance(res, dict):
                return list(res.keys())
            else:
                return []
        else:
            return call_result.get(info_type, [])

    def get_indicator_info(self, identifier: str, indicator_type: str) -> dict:
        """
        Retrieve detailed information for a given indicator.
        Args:
            identifier (Dict): Indicator's identifier.
            indicator_type (str): The indicator type
        Returns:
            Dict: Additional data of the indicator.
        """
        url = f"v4/{MAP_TYPE_TO_URL[indicator_type]}"
        url = urljoin(url, identifier)

        if url[-1] == "/":
            url = url[:-1]

        call_result = {}
        try:
            call_result = self._http_request(
                method="GET", url_suffix=url, timeout=self.timeout
            )
        except DemistoException as e:
            # If there is an internal issue inside the server, don't fail the entire fetch session
            if e.res.status_code != 500:
                raise e

        return call_result

    def get_indicators(
        self, indicator_type: str = "Indicators", params: dict = None
    ) -> List:
        """
        Retrieve a list of indicators from Mandiant Threat Intelligence
        Args:
            indicator_type (str): The indicator type.  Defaults to `indicators` (all indicators).
            params (Dict): HTTP call params
        Returns:
            List: A list of indicators
        """
        params = params or {}
        try:
            url = f"/v4/{MAP_TYPE_TO_URL[indicator_type]}"
            response = self._http_request(
                method="GET", url_suffix=url, timeout=self.timeout, params=params
            )
            response = response.get(MAP_TYPE_TO_RESPONSE[indicator_type], [])

        except DemistoException as e:
            demisto.error(f"Error retrieving objects from Mandiant Threat Intel: {e}")
            response = []

        return response

    def get_indicators_by_value(self, indicator_value: str, params: dict = None):
        params = params or {}
        request_body = {
            "requests": [{"values": [indicator_value]}],
            "include_campaigns": True,
        }
        try:
            url = "/v4/indicator"
            response = self._http_request(
                method="POST",
                url_suffix=url,
                timeout=self.timeout,
                params=params,
                json_data=request_body,
            )
            response = response.get("indicators", [])
            if self.enrichment:
                for indicator in response:
                    reports = self.get_indicator_info_endpoint(
                        indicator_type="Indicators",
                        identifier=indicator["id"],
                        info_type="reports",
                    )
                    indicator["publications"] = reports

        except DemistoException as e:
            demisto.error(f"Error retrieving objects from Mandiant Threat Intel: {e}")
            response = []

        return response


""" HELPER FUNCTIONS """


def get_last_updated(indicator: dict) -> datetime:
    last_updated = arg_to_datetime(indicator.get("last_updated"))
    if not last_updated:
        raise RuntimeError("Unable to retrieve `last_updated` date")
    else:
        return last_updated


def filter_last_updated(indicator: dict, start_time: datetime) -> bool:
    indicator_last_updated = get_last_updated(indicator)
    return indicator_last_updated.timestamp() > start_time.timestamp()


def last_updated_filter(start_time: datetime):
    return (
        lambda indicator: get_last_updated(indicator).timestamp()
        > start_time.timestamp()
    )


def get_verdict(mscore: Optional[int]) -> int:
    """
    Convert mscore to dbot score
    Args:
        mscore (str): mscore, value from 0 to 100
    Returns:
        int: DBotScore
    """
    if mscore is None:
        return Common.DBotScore.NONE
    mscore_int: int = int(mscore)
    if 0 <= mscore_int <= 20:
        return Common.DBotScore.GOOD
    elif 21 <= mscore_int <= 50:
        return Common.DBotScore.NONE
    elif 51 <= mscore_int <= 80:
        return Common.DBotScore.SUSPICIOUS
    elif 81 <= mscore_int <= 100:
        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.NONE


def get_dbot_score(indicator: dict, indicator_type: str = None) -> dict:
    if indicator_type is None:
        indicator_type = MAP_INDICATORS[indicator["type"]]["dbotscore"]
    return {
        "Indicator": indicator.get("value"),
        "Type": indicator_type,
        "Vendor": "Mandiant Advantage Threat Intelligence",
        "Score": get_verdict(indicator.get("mscore", 0)),
        "Reliability": demisto.params().get(
            "feedReliability", DBotScoreReliability.A_PLUS
        ),
    }


def get_dbot_score_obj(dbot_score: dict) -> Common.DBotScore:
    return Common.DBotScore(
        indicator=dbot_score["Indicator"],
        indicator_type=dbot_score["Type"],
        score=dbot_score["Score"],
        reliability=dbot_score["Reliability"]
    )


def get_indicator_relationships(
    raw_indicator: dict,
    indicator_field: str,
    entity_a_field: str,
    entity_a_type: str,
    entity_b_field: str,
    entity_b_type: str,
    name: str,
    reverse_name: str,
) -> List[dict]:
    """
    Creates relationships for the given indicator
    Args:
        raw_indicator (Dict): indicator
        indicator_field (str): indicator field that contains the entities list
        entity_a_field (str): indicator field that contains the entity name
        entity_a_type (str): indicator field that contains the entity type
        entity_b_field (str): entity field that contains the entity name
        entity_b_type (str): entity field that contains the entity type
        name (str): the relationship name
        reverse_name (str): the relationship reverse name
    Returns:
    """
    entities_list = raw_indicator.get(indicator_field, [])
    relationships = []

    if entities_list != "redacted":
        relationships = [
            EntityRelationship(
                entity_a=raw_indicator.get(entity_a_field, ""),
                entity_a_type=entity_a_type,
                name=name,
                entity_b=entity.get(entity_b_field, ""),
                entity_b_type=entity_b_type,
                reverse_name=reverse_name,
                brand="Mandiant Advantage Threat Intelligence",
                source_reliability="A - Completely reliable",
            ).to_indicator()
            for entity in entities_list
        ]
    return relationships


def create_malware_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[None, dict]:
    """
    Creates a malware indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): indicator
    Returns:
        Dict: malware indicator
    """
    raw_indicator = {
        k: v for k, v in raw_indicator.items() if v and v != "redacted"
    }  # filter none and redacted values

    fields = {
        "operatingsystemrefs": raw_indicator.get("operating_systems"),
        "aliases": [i["name"] for i in raw_indicator.get("aliases", [])],
        "capabilities": raw_indicator.get("capabilities"),
        "tags": [
            i.get("name", "")
            for i in argToList(  # type:ignore
                raw_indicator.get("industries")
            )
        ]
        + client.tags,  # type:ignore
        "mandiantdetections": raw_indicator.get("detections"),
        "yara": [
            (yara.get("name"), yara.get("id"))
            for yara in raw_indicator.get("yara", [])  # type: ignore
        ]
        if raw_indicator.get("yara", []) != "redacted"
        else [],
        "roles": raw_indicator.get("roles"),
        "stixid": raw_indicator.get("id"),
        "name": raw_indicator.get("name"),
        "description": raw_indicator.get("description"),
        "updateddate": raw_indicator.get("last_updated"),
        "lastseenbysource": raw_indicator.get("last_activity_time"),
        "trafficlightprotocol": client.tlp_color,
        "Is Malware Family": raw_indicator.get("inherently_malicious", 0) == 1,
        "DBot Score": get_dbot_score(raw_indicator, indicator_type="Malware"),
    }

    fields = {
        k: v for k, v in fields.items() if v and v != "redacted"
    }  # filter none and redacted values

    relationships = get_indicator_relationships(
        raw_indicator,
        "actors",
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "cve",
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        "name",
        FeedIndicatorType.CVE,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "malware",
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    indicator_obj = {
        "value": raw_indicator.get("name"),
        "type": ThreatIntel.ObjectsNames.MALWARE,
        "rawJSON": raw_indicator,
        "fields": fields,
        "relationships": relationships,
        "score": get_verdict(raw_indicator.get("mscore")),
    }

    return None, indicator_obj


def create_campaign_indicator(client: MandiantClient, raw_indicator: dict) -> dict:
    """
    Creates a campaign indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): indicator
    Returns:
        Dict: campaign indicator
    """
    raw_indicator = {
        k: v for k, v in raw_indicator.items() if v and v != "redacted"
    }  # filter none and redacted values

    fields = {
        "actors": [a["name"] for a in raw_indicator.get("actors", [])],
        "description": raw_indicator.get("description"),
        "tags": [
            i.get("name", "") for i in argToList(raw_indicator.get("industries", []))
        ]
        + client.tags,
        "DBot Score": get_dbot_score(raw_indicator, indicator_type="Campaign"),
        "publications": generate_publications(raw_indicator.get("reports", [])),
    }

    relationships = get_indicator_relationships(
        raw_indicator,
        "actors",
        "short_name",
        ThreatIntel.ObjectsNames.CAMPAIGN,
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "malware",
        "short_name",
        ThreatIntel.ObjectsNames.CAMPAIGN,
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "vulnerabilities",
        "short_name",
        ThreatIntel.ObjectsNames.CAMPAIGN,
        "name",
        FeedIndicatorType.CVE,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    indicator_obj = {
        "value": raw_indicator.get("short_name"),
        "type": ThreatIntel.ObjectsNames.CAMPAIGN,
        "rawJSON": raw_indicator,
        "fields": fields,
        "relationships": relationships,
    }

    return indicator_obj


def create_actor_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[None, dict]:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator
    Returns:
        Dict: Parsed indicator
    """
    raw_indicator = {
        k: v for k, v in raw_indicator.items() if v and v != "redacted"
    }  # filter none and redacted values

    primary_motivation = None
    if len(raw_indicator.get("motivations", [])) >= 1:
        primary_motivation = raw_indicator["motivations"][0].get("name")

    fields = {
        "primarymotivation": primary_motivation,
        "tags": [
            industry.get("name")
            for industry in raw_indicator.get("industries", [])
            # type: ignore
        ]
        + client.tags,
        "aliases": [
            alias.get("name") for alias in raw_indicator.get("aliases", [])
        ],  # type:ignore
        "firstseenbysource": [
            item.get("earliest") for item in raw_indicator.get("observed", [])
        ],  # type:ignore
        "lastseenbysource": [
            item.get("recent") for item in raw_indicator.get("observed", [])
        ],  # type:ignore
        "targets": [
            target.get("name")
            for target in raw_indicator.get(  # type:ignore
                "locations", {}
            ).get(
                "target", []
            )
        ],  # type:ignore
        "stixid": raw_indicator.get("id"),
        "name": raw_indicator.get("name"),
        "description": raw_indicator.get("description"),
        "updateddate": raw_indicator.get("last_updated"),
        "trafficlightprotocol": client.tlp_color,
        "DBot Score": get_dbot_score(raw_indicator, indicator_type="Actor"),
    }

    fields = {
        k: v for k, v in fields.items() if v and v != "redacted"
    }  # filter none and redacted values

    relationships = get_indicator_relationships(
        raw_indicator,
        "malware",
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "name",
        ThreatIntel.ObjectsNames.MALWARE,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "cve",
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "cve_id",
        FeedIndicatorType.CVE,
        EntityRelationship.Relationships.TARGETS,
        EntityRelationship.Relationships.TARGETED_BY,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "tools",
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "name",
        ThreatIntel.ObjectsNames.TOOL,
        EntityRelationship.Relationships.USES,
        EntityRelationship.Relationships.USED_BY,
    )

    relationships += get_indicator_relationships(
        raw_indicator,
        "associated_uncs",
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "name",
        ThreatIntel.ObjectsNames.THREAT_ACTOR,
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )

    indicator_obj = {
        "value": raw_indicator.get("name"),
        "type": ThreatIntel.ObjectsNames.THREAT_ACTOR,
        "rawJSON": raw_indicator,
        "score": get_verdict(raw_indicator.get("mscore")),
        "fields": fields,
        "relationships": relationships,
    }

    return None, indicator_obj


def parse_cvss(cve: dict) -> dict:
    """
    Parse CVSS information into XSOAR format
    Args:
        cve: A raw CVE indicator dict
    Returns:
        dict: The parsed CVE fields for use in a CVE indicator
    """
    cvss = {}

    if "v3.1" in cve.get("common_vulnerability_scores", {}):
        cve_details = cve["common_vulnerability_scores"]["v3.1"]
        cvss = {
            "cvss": "v3.1",
            "cvssvector": cve_details.get("vector_string"),
            "cvssscore": cve_details.get("base_score", 0),
            "cvss3": [
                {
                    "metric": camel_case_to_underscore(k).replace("_", " ").title(),
                    "values": v,
                }
                for k, v in cve_details.items()
            ],
        }
    elif "v2.0" in cve.get("common_vulnerability_scores", {}):
        cve_details = cve["common_vulnerability_scores"]["v2.0"]
        cvss = {
            "cvss": "v2.0",
            "cvssvector": cve_details.get("vector_string"),
            "cvssscore": cve_details.get("base_score", 0),
            "cvss2": [
                {
                    "metric": camel_case_to_underscore(k).replace("_", " ").title(),
                    "values": v,
                }
                for k, v in cve_details.items()
            ],
        }

    return cvss


def create_cve_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.CVE, dict]:
    """
    Create CVE indicator
    Args:
        client: MandiantClient
        raw_indicator (Dict): raw indicator
    Returns:
        Dict: Parsed indicator
    """
    cvss_data = parse_cvss(raw_indicator)
    indicator_obj = create_base_indicator(client, raw_indicator, FeedIndicatorType.CVE)
    additional_fields = {"id": raw_indicator.get("value")}
    additional_fields = additional_fields | cvss_data

    indicator_obj["fields"] = indicator_obj["fields"] | additional_fields

    indicator = Common.CVE(
        id=additional_fields["id"],
        cvss=str(cvss_data["cvssscore"]),
        published=indicator_obj["rawJSON"]["publish_date"],
        modified=indicator_obj["rawJSON"]["last_modified_date"],
        description=indicator_obj["rawJSON"]["title"]
    )

    return indicator, indicator_obj


def create_file_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.File, dict]:
    """
    Args:
        client: MandiantClient
        raw_indicator (Dict): raw indicator
    Returns:
        Dict: Parsed indicator
    """

    indicator_obj = create_base_indicator(client, raw_indicator, FeedIndicatorType.File)

    sha1_hashes = [
        associated_hash["value"]
        for associated_hash in raw_indicator.get("associated_hashes", [])
        if associated_hash["type"] == "sha1"
    ]
    sha256_hashes = [
        associated_hash["value"]
        for associated_hash in raw_indicator.get("associated_hashes", [])
        if associated_hash["type"] == "sha256"
    ]

    if len(sha1_hashes) != 1:
        sha1_hashes = [None]
    if len(sha256_hashes) != 1:
        sha256_hashes = [None]

    additional_fields = {
        "md5": raw_indicator.get("value"),
        "sha256": sha256_hashes[0] or None,
        "sha1": sha1_hashes[0] or None,
    }
    additional_fields = {
        k: v for k, v in additional_fields.items() if v and v != "redacted"
    }  # filter none and redacted values

    indicator_obj["fields"] = indicator_obj["fields"] | additional_fields

    indicator = Common.File(
        dbot_score=get_dbot_score_obj(indicator_obj["fields"]["dbotscore"]),
        md5=additional_fields.get("md5"),
        sha1=additional_fields.get("sha1"),
        sha256=additional_fields.get("sha256"),
    )

    return indicator, indicator_obj


def create_ip_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.IP, dict]:
    """
    Args:
        client: MandiantClient
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = create_base_indicator(client, raw_indicator, FeedIndicatorType.IP)
    additional_fields = {
        "ip": raw_indicator.get("value"),
    }

    indicator_obj["fields"] = indicator_obj["fields"] | additional_fields
    indicator = Common.IP(
        dbot_score=get_dbot_score_obj(indicator_obj["fields"]["dbotscore"]),
        ip=additional_fields["ip"]
    )

    return indicator, indicator_obj


def create_fqdn_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.Domain, dict]:
    """
    Args:
        client: MandiantClient
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = create_base_indicator(client, raw_indicator, FeedIndicatorType.FQDN)
    additional_fields = {
        "dns": raw_indicator.get("value"),
        "domain": raw_indicator.get("value"),
    }

    indicator_obj["fields"] = indicator_obj["fields"] | additional_fields

    indicator = Common.Domain(
        domain=raw_indicator.get("value"),
        dns=raw_indicator.get("value"),
        dbot_score=get_dbot_score_obj(indicator_obj["fields"]["dbotscore"])
    )

    return indicator, indicator_obj


def create_url_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.URL, dict]:
    """
    Args:
        client: MandiantClient
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """

    indicator_obj = create_base_indicator(client, raw_indicator, FeedIndicatorType.URL)
    additional_fields = {
        "url": raw_indicator.get("value"),
    }

    indicator_obj["fields"] = indicator_obj["fields"] | additional_fields

    indicator = Common.URL(
        url=additional_fields["url"],
        dbot_score=get_dbot_score_obj(indicator_obj["fields"]["dbotscore"])
    )

    return indicator, indicator_obj


def create_indicator(client: MandiantClient, raw_indicator: dict) -> tuple[Common.Indicator, dict]:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    return MAP_INDICATORS_FUNCTIONS[raw_indicator.get("type", "")](client, raw_indicator)
    # return create_base_indicator(client, raw_indicator, indicator_type)


def create_base_indicator(
    client: MandiantClient, raw_indicator: dict, indicator_type: str
) -> dict:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator
        indicator_type (str): Type of indicator
    Returns: Parsed indicator Additional keys under "fields" must be added after creation
    """

    # If the indicator is only Open-Source intelligence, mark the TLP Color as
    # GREEN.  Otherwise, use the configured value

    information_is_osint = True
    for source in raw_indicator.get("sources", []):
        if not source.get("osint", False):
            information_is_osint = False

    tlp_color = "GREEN" if information_is_osint else client.tlp_color

    campaign_relationships = [
        EntityRelationship(
            entity_a=raw_indicator["value"],
            entity_a_type=indicator_type,
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_b=campaign.get("name"),
            entity_b_type=ThreatIntel.ObjectsNames.CAMPAIGN,
            reverse_name=EntityRelationship.Relationships.RELATED_TO,
        ).to_indicator()
        for campaign in raw_indicator.get("campaigns", [])
        if campaign
    ]

    fields = {
        "primarymotivation": raw_indicator.get("motivations"),
        "firstseenbysource": raw_indicator.get("first_seen"),
        "lastseenbysource": raw_indicator.get("last_seen"),
        "stixid": raw_indicator.get("id"),
        "trafficlightprotocol": tlp_color,
        "publications": generate_publications(raw_indicator.get("publications", [])),
        "dbotscore": get_dbot_score(raw_indicator),
        "tags": client.tags
    }

    fields = {
        k: v for k, v in fields.items() if v and v != "redacted"
    }  # filter none and redacted values
    indicator_obj = {
        "value": raw_indicator.get("value"),
        "score": get_verdict(raw_indicator.get("mscore")),
        # "DBotScore": get_dbot_score(raw_indicator),
        "rawJSON": raw_indicator,
        "type": indicator_type,
        "fields": fields,
        "relationships": campaign_relationships,
    }
    return indicator_obj


MAP_INDICATORS_FUNCTIONS: dict[str, Callable] = {
    "Malware": create_malware_indicator,
    "Actors": create_actor_indicator,
    "Indicators": create_indicator,
    "file": create_file_indicator,
    "md5": create_file_indicator,
    "ip": create_ip_indicator,
    "ipv4": create_ip_indicator,
    "domain": create_fqdn_indicator,
    "url": create_url_indicator,
    "fqdn": create_fqdn_indicator,
    "cve": create_cve_indicator,
}


def generate_publications(reports_list: list[dict]):
    if not reports_list:
        return []

    return [
        {
            "source": "Mandiant",
            "title": report.get("title", ""),
            "link": f"https://advantage.mandiant.com/reports/{report.get('report_id')}",
            "timestamp": dateutil.parser.parse(
                report.get("published_date", str(datetime.utcnow()))
            ).timestamp(),
        }
        for report in reports_list
    ]


def enrich_indicators(
    client: MandiantClient, indicators_list: List, indicator_type: str
) -> None:
    """
    For each indicator in indicators_list create relationships and adding the relevant indicators
    Args:
        client (MandiantClient): client
        indicators_list (List): list of raw indicators
        indicator_type (str): the current indicator type
    Returns:
        List of relevant indicators
    """
    for indicator in indicators_list:
        indicator_id = indicator.get("fields", {}).get("stixid", "")
        indicator_name = indicator.get("fields", {}).get("name", "")

        reports_list = client.get_indicator_info_endpoint(
            indicator_type=indicator_type, identifier=indicator_id, info_type="reports"
        )

        reports_relationships = [
            EntityRelationship(
                entity_a=indicator_name,
                entity_a_type=MAP_INDICATORS[indicator_type]["name"],
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_b=report.get("title"),
                entity_b_type=ThreatIntel.ObjectsNames.REPORT,
                reverse_name=EntityRelationship.Relationships.RELATED_TO,
                fields=report,
            ).to_indicator()
            for report in reports_list
            if report
        ]

        general_list = client.get_indicator_info_endpoint(
            indicator_type=indicator_type,
            identifier=indicator_id,
            info_type="indicators",
        )

        general_relationships = [
            EntityRelationship(
                entity_a=indicator_name,
                entity_a_type=MAP_INDICATORS[indicator_type]["name"],
                name=EntityRelationship.Relationships.INDICATED_BY,
                entity_b=general_indicator.get("value"),
                entity_b_type=MAP_INDICATORS[general_indicator.get("type", "")]["name"],
                reverse_name=EntityRelationship.Relationships.INDICATOR_OF,
            ).to_indicator()
            for general_indicator in general_list
            if general_indicator
        ]

        attack_pattern_list = client.get_indicator_info_endpoint(
            indicator_type=indicator_type,
            identifier=indicator_id,
            info_type="attack-pattern",
        )

        attack_pattern_relationships = [
            EntityRelationship(
                entity_a=indicator_name,
                entity_a_type=MAP_INDICATORS[indicator_type]["name"],
                name=EntityRelationship.Relationships.USES,
                entity_b=attack_pattern,
                entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                reverse_name=EntityRelationship.Relationships.USED_BY,
            ).to_indicator()
            for attack_pattern in attack_pattern_list
            if attack_pattern
        ]

        campaigns_list = client.get_indicator_info_endpoint(
            indicator_type=indicator_type,
            identifier=indicator_id,
            info_type="campaigns",
        )

        campaign_relationships = [
            EntityRelationship(
                entity_a=indicator_name,
                entity_a_type=MAP_INDICATORS[indicator_type]["name"],
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_b=campaign.get("short_name"),
                entity_b_type=ThreatIntel.ObjectsNames.CAMPAIGN,
                reverse_name=EntityRelationship.Relationships.RELATED_TO,
            ).to_indicator()
            for campaign in campaigns_list
            if campaign
        ]

        relationships = (
            reports_relationships
            + general_relationships
            + attack_pattern_relationships
            + campaign_relationships
        )

        indicator["relationships"] = indicator.get("relationships", []) + relationships

        indicator["fields"]["publications"] = indicator["fields"].get(
            "publications", []
        ) + generate_publications(reports_list=reports_list)


def get_new_indicators(
    client: MandiantClient, last_run: str, indicator_type: str, limit: int
) -> tuple[List, str]:
    """
    Get a list of new indicators
    Args:
        client (MandiantClient): client
        last_run (str): last run as free text or date format
        indicator_type (str): the desired type to fetch
        limit (int): number of indicator to fetch
    Returns:
        tuple[List, str]: A list of new indicators, and the new "last updated" checkpoint
    """
    start_date = arg_to_datetime(last_run)
    minimum_mscore = int(demisto.params().get("feedMinimumConfidence", 80))
    exclude_osint = demisto.params().get("feedExcludeOSIntel", True)

    params = {}
    if indicator_type == "Indicators":
        # for indicator type the earliest time to fetch is 90 days ago
        earliest_fetch = arg_to_datetime("89 days ago")
        assert earliest_fetch is not None

        param_start_date: datetime = datetime.fromtimestamp(0)
        if start_date is not None:
            param_start_date = max(
                earliest_fetch.replace(tzinfo=pytz.UTC), start_date.replace(tzinfo=pytz.UTC)
            )  # type:ignore
        else:
            param_start_date = earliest_fetch
        params = {
            "start_epoch": int(param_start_date.timestamp()),
            "limit": limit,
            "exclude_osint": exclude_osint,
            "sort_by": "last_updated:asc"
        }  # type:ignore

    new_indicators_list = client.get_indicators(indicator_type, params=params)

    if indicator_type != "Indicators":  # new to old
        new_indicators_list.sort(key=get_last_updated, reverse=True)  # type:ignore
        new_indicators_list = list(
            filter(last_updated_filter(start_date), new_indicators_list)  # type: ignore
        )
        if new_indicators_list:
            return new_indicators_list, new_indicators_list[-1]["last_updated"]
        else:
            return [], last_run
    else:
        updated_indicators = []
        # For Indicators of Compromise only
        for indicator in new_indicators_list:
            # Check if indicator should be added no matter what
            # E.g. it meets the `param` requirements
            if indicator["mscore"] >= minimum_mscore:
                updated_indicators.append(indicator)
            else:
                existing_indicators = list(IndicatorsSearcher(value=indicator["value"]))
                if len(existing_indicators) > 0 and int(existing_indicators[0].get("total", 0)) > 0:
                    updated_indicators.append(indicator)
        return updated_indicators, new_indicators_list[-1]["last_updated"]


def get_indicator_list(
    client: MandiantClient, limit: int, first_fetch: str, indicator_type: str
) -> tuple[List[dict], str]:
    """
    Get a list of indicators of the given type
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to return.
        first_fetch (str): Get indicators newer than first_fetch.
        indicator_type (str): indicator type
    Returns:
        tuple[List[dict], str]: A list of indicators, and the new "last updated" checkpoint
    """
    last_run_dict = demisto.getLastRun()
    indicators_list = last_run_dict.get(f"{indicator_type}List", [])
    new_last_updated = last_run = last_run_dict.get(f"{indicator_type}LastFetch", first_fetch)
    if len(indicators_list) < limit:
        new_indicators_list, new_last_updated = get_new_indicators(
            client, last_run, indicator_type, limit
        )
        indicators_list += new_indicators_list

    if indicators_list:
        new_indicators_list = indicators_list[:limit]

        indicators_list = new_indicators_list

    return indicators_list, new_last_updated


def fetch_indicators(client: MandiantClient, args: dict = None) -> tuple[List, dict]:
    """
    For each type the fetch indicator command will:
        1. Fetch a list of indicators from the Mandiant Threat Intelligence API
        2. Fetch additional information about each indicator from the Mandiant Threat Intelligence API and add it to the
           original indicator
        3. Enrich indicators by retrieving relationship information from the Mandiant Threat Intelligence API and adding
           it to the original indicator
        NOTE: This requires an additional 3 API calls per indicator
    Args:
        client (MandiantClient): client
        args (Dict): If provided, these arguments override those in the `client`
    Returns:
        List of all indicators
    """
    if not args:
        args = {}

    limit = int(args.get("limit", client.limit))

    # Cap maximum number of indicators to 1000
    if limit > 1000:
        limit = 1000

    metadata = argToBoolean(args.get("indicatorMetadata", client.metadata))
    enrichment = argToBoolean(args.get("indicatorRelationships", client.enrichment))
    types = argToList(args.get("type", client.types))

    first_fetch = client.first_fetch

    result = []
    last_run_dict = demisto.getLastRun()

    demisto.debug("fetching indicators")

    for indicator_type in types:
        indicators_list, new_last_updated = get_indicator_list(client, limit, first_fetch, indicator_type)

        if metadata:
            indicators_list = [
                client.get_indicator_info(
                    identifier=indicator.get("id"),  # type:ignore
                    indicator_type=indicator_type,
                )
                for indicator in indicators_list
            ]
        demisto.debug("getting indicators")
        indicators = [
            MAP_INDICATORS_FUNCTIONS[indicator_type](client, indicator)[1]
            for indicator in indicators_list
        ]
        if enrichment and indicator_type != "Indicators":
            enrich_indicators(client, indicators, indicator_type)

        result += indicators

        last_run_dict[f"{indicator_type}List"] = indicators[limit:]
        if indicators_list:
            last_run_dict[f"{indicator_type}LastFetch"] = new_last_updated

    return (result, last_run_dict)


def debug_fetch_indicators(client: MandiantClient, args: dict = None):
    indicators, _ = fetch_indicators(client, args)
    return [CommandResults(outputs=indicator,
                           outputs_prefix="MANDIANTTI.Feed",
                           ignore_auto_extract=True) for indicator in indicators]


def batch_fetch_indicators(client: MandiantClient):
    """
    For each type the fetch indicator command will:
        1. Fetch a list of indicators from the Mandiant Threat Intelligence API
        2. Fetch additional information about each indicator from the Mandiant Threat Intelligence API and add it to the
           original indicator
        3. Enrich indicators by retrieving relationship information from the Mandiant Threat Intelligence API and adding
           it to the original indicator
        NOTE: This requires an additional 3 API calls per indicator
    Args:
        client (MandiantClient): client
    Returns:
        List of all indicators
    """

    result, last_run_dict = fetch_indicators(client=client)

    for b in batch(result, batch_size=2000):
        demisto.createIndicators(b)

    demisto.setLastRun(last_run_dict)


def fetch_indicator_by_value(client: MandiantClient, args: dict = None):
    args = args if args else {}
    indicator_value: str = args["indicator_value"]

    INDICATOR_TYPE_MAP: dict[str, str] = {"ipv4": "ip", "fqdn": "domain", "url": "url", "md5": "file"}

    indicators_list = client.get_indicators_by_value(indicator_value=indicator_value)

    indicators = [
        MAP_INDICATORS_FUNCTIONS[INDICATOR_TYPE_MAP[indicator["type"]]](
            client, indicator
        )
        for indicator in indicators_list
    ]

    for indicator in indicators:
        indicator[1]["value"] = indicators_value_to_clickable([indicator[1]["value"]])

    if indicators:
        table = {
            'Value': indicators[0][1]["rawJSON"]['value'],
            'MScore': indicators[0][1]["rawJSON"]['mscore'],
            'Last Seen': indicators[0][1]["rawJSON"]["last_seen"]
        }
        indicator_type = indicators[0][1]["rawJSON"]["type"].lower()

        markdown = tableToMarkdown(f'Mandiant Advantage Threat Intelligence information for {table["Value"]}\n'
                                   f'[View on Mandiant Advantage](https://advantage.mandiant.com/indicator/'
                                   f'{indicator_type}/{table["Value"]})',
                                   table)

        return CommandResults(
            readable_output=markdown,
            content_format=formats["json"],
            outputs_prefix=f"MANDIANTTI.{INDICATOR_TYPE_MAP[indicators_list[0]['type']].upper()}",
            outputs=[i[1] for i in indicators],
            outputs_key_field="name",
            ignore_auto_extract=True,
        )
    else:
        return f"No indicators found matching value {indicator_value}"


def fetch_threat_actor(client: MandiantClient, args: dict = None):
    args = args if args else {}
    actor_name: str = args["actor_name"]

    indicator_obj: dict = client.get_indicator_info(
        identifier=actor_name, indicator_type="Actors"
    )
    indicator = [create_actor_indicator(client, indicator_obj)[1]]

    if client.enrichment:
        enrich_indicators(client, indicator, "Actors")

    demisto.createIndicators(indicator)

    # indicator[0]['fields']['name'] = indicators_value_to_clickable([indicator[0]['fields']['name']])

    return CommandResults(
        content_format=formats["json"],
        outputs=indicator,
        outputs_prefix="MANDIANTTI.ThreatActor",
        outputs_key_field="name",
        ignore_auto_extract=True,
    )


def fetch_malware_family(client: MandiantClient, args: dict = None):
    args = args if args else {}
    malware_name: str = str(args.get("malware_name"))

    indicator = client.get_indicator_info(
        identifier=malware_name, indicator_type="Malware"
    )
    indicator_list = [create_malware_indicator(client, indicator)[1]]
    if client.enrichment:
        enrich_indicators(client, indicator_list, "Malware")

    demisto.createIndicators(indicator_list)

    indicator_list[0]["fields"]["name"] = indicators_value_to_clickable(
        [indicator_list[0]["fields"]["name"]]
    )

    return CommandResults(
        content_format=formats["json"],
        outputs=indicator_list,
        outputs_prefix="MANDIANTTI.Malware",
        outputs_key_field="name",
        ignore_auto_extract=True,
    )


def fetch_campaign(client: MandiantClient, args: dict = None):
    args = args if args else {}
    campaign: str = str(args.get("campaign_id"))

    indicator = client.get_indicator_info(
        identifier=campaign, indicator_type="Campaign"
    )

    indicator_list = [create_campaign_indicator(client, indicator)]

    demisto.createIndicators(indicator_list)

    return CommandResults(
        content_format=formats["json"],
        outputs=indicator_list,
        outputs_prefix="MANDIANTTI.Campaign",
        outputs_key_field="name",
        ignore_auto_extract=True,
    )


def fetch_reputation(client: MandiantClient, args: dict = None):
    args = args if args else {}
    input_type: str = demisto.command()
    indicator_values: list[str] = argToList(str(args.get(input_type)))

    if input_type == "cve":
        indicators_list = [client.get_indicator_info(i, "Vulnerability") for i in indicator_values]
    else:
        indicators_list = []
        for i in indicator_values:
            indicators_list.extend(client.get_indicators_by_value(i))

    indicators = [
        MAP_INDICATORS_FUNCTIONS[input_type](client, indicator)
        for indicator in indicators_list
    ]

    demisto.createIndicators([i[1] for i in indicators])

    if indicators:
        output = []
        for indicator_obj, indicator in indicators:
            demisto.debug(json.dumps(indicator))
            table = {
                'Value': indicator['value'],
                'MScore': indicator["rawJSON"].get("mscore", ''),
                'Last Seen': indicator["rawJSON"].get("last_seen", '')
            }
            indicator_type = indicator["rawJSON"]["type"].lower()

            markdown = tableToMarkdown(f'Mandiant Advantage Threat Intelligence information for {indicator["value"]}\n'
                                       f'[View on Mandiant Advantage](https://advantage.mandiant.com/indicator/'
                                       f'{indicator_type}/{indicator["value"]})',
                                       table)

            output.append(CommandResults(
                readable_output=markdown,
                outputs_prefix=f"MANDIANTTI.{input_type.upper()}",
                outputs=indicator,
                indicator=indicator_obj,
                ignore_auto_extract=True))
        return output
    else:
        return f"No indicators found matching value {indicator_values}"


""" COMMAND FUNCTIONS """


def test_module(client: MandiantClient) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``MandiantClient``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # Note: As part of client initialization, a token is retrieved, which requires successful authentication
    # Therefor, if a user has reached this point with a valid MandiantClient, everything is working

    indicators = client.get_indicators(params={"limit": 1})

    if indicators is not None:
        return "ok"

    else:
        return "failed to retrieve indicator"


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get("insecure", False)

    proxy = params.get("proxy", False)
    api_key = params.get("api_key", "")
    secret_key = params.get("secret_key", "")
    base_url = params.get("api_base_url", "")
    timeout = int(params.get("timeout", DEFAULT_TIMEOUT))
    tlp_color = params.get("tlp_color")
    feedTags = argToList(params.get("feedTags"))
    first_fetch = params.get("first_fetch", "3 days ago")
    limit = int(params.get("max_fetch", 50))
    metadata = argToBoolean(params.get("indicatorMetadata", False))
    enrichment = argToBoolean(params.get("indicatorRelationships", False))
    types = argToList(params.get("type"))

    demisto.debug(f"Command being called is {command}")
    try:
        client = MandiantClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            secret_key=secret_key,
            timeout=timeout,
            tags=feedTags,
            tlp_color=tlp_color,
            first_fetch=first_fetch,
            limit=limit,
            metadata=metadata,
            enrichment=enrichment,
            types=types,
        )

        command_map: dict[str, Callable] = {
            "mati-get-indicator": fetch_indicator_by_value,
            "mati-get-actor": fetch_threat_actor,
            "mati-get-malware": fetch_malware_family,
            "mati-get-campaign": fetch_campaign,
            "file": fetch_reputation,
            "ip": fetch_reputation,
            "url": fetch_reputation,
            "domain": fetch_reputation,
            "cve": fetch_reputation,
            "mati-feed-get-indicators": debug_fetch_indicators
        }
        params_only_cmds: dict[str, Callable] = {
            "test-module": test_module,
            "fetch-indicators": batch_fetch_indicators,
        }

        if command in command_map:
            return_results(command_map[command](client, args))
        elif command in params_only_cmds:
            return_results(params_only_cmds[command](client))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
