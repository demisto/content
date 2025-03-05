from taxii2client.common import TokenAuth
from taxii2client.v20 import Server, as_pages

from CommonServerPython import *
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = "Unit42v2 Feed"
UNIT42_TYPES_TO_DEMISTO_TYPES = {
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
}

THREAT_INTEL_TYPE_TO_DEMISTO_TYPES = {
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
}

""" CONSTANTS """
RELATIONSHIP_TYPES = EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()
DEFAULT_INDICATOR_SCORE = 3  # default verdict of fetched indicators is malicious

from TAXII2ApiModule import *  # noqa: E402


class Client(STIX2XSOARParser):
    def __init__(self, api_key, verify):
        """Implements class for Unit 42 feed.

        Args:
            api_key: unit42 API Key.
            verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        """
        super().__init__(
            id_to_object={},
            base_url="https://stix2.unit42.org/taxii",
            verify=verify,
            proxy=argToBoolean(demisto.params().get("proxy") or "false"),
        )
        self._api_key = api_key
        self._proxies = handle_proxy()
        self.objects_data = {}
        self.server = Server(url=self._base_url, auth=TokenAuth(key=self._api_key), verify=self._verify, proxies=self._proxies)

    def get_stix_objects(self, test: bool = False, items_types: Optional[list] = None):
        if not items_types:
            items_types = []
        for type_ in items_types:
            self.fetch_stix_objects_from_api(test, type=type_)

    def fetch_stix_objects_from_api(self, test: bool = False, limit: int = -1, **kwargs):
        """Retrieves all entries from the feed.

        Args:
            test: Whether it was called during clicking the test button or not - designed to save time.
            limit: number of indicators for get command
        """
        data: list = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                for _ in range(2):
                    try:
                        objects: list = []
                        for bundle in as_pages(collection.get_objects, per_request=100, **kwargs):
                            objects.extend(bundle.get("objects") or [])
                            if test and limit < len(objects):
                                return objects

                        data.extend(objects)
                        break
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 502:
                            demisto.debug("Received 502 error, retrying...")
                            time.sleep(25)
                        else:
                            raise

        if test:
            return data

        self.objects_data[kwargs.get("type")] = data
        return None

    def get_report_object(self, obj_id: str):
        """Get specific report object by id.

        Args:
        obj_id: The object ID.
        id_to_object: a dict in the form of - id: stix_object.

        Returns:
            A sub report object.
        """
        sub_report_obj = self.id_to_object.get(obj_id, {})
        if not sub_report_obj:
            if report_from_api := self.fetch_stix_objects_from_api(type="report", id=obj_id):
                sub_report_obj = report_from_api[0] if len(report_from_api) == 1 else None
                if not sub_report_obj:
                    demisto.debug(f"{INTEGRATION_NAME}: Found more then one object for report object {obj_id} skipping")
            else:
                demisto.debug(f"{INTEGRATION_NAME}: Could not find report object {obj_id}")
        return sub_report_obj


def extract_ioc_value(value: str):
    """
    Extract SHA-256 from string:
    ([file:name = 'blabla' OR file:name = 'blabla'] AND [file:hashes.'SHA-256' = '1111'])" -> 1111
    """
    try:
        return re.search("(?<='SHA-256' = ').*?(?=')", value).group(0)  # type:ignore # guardrails-disable-line
    except AttributeError:
        return None


def parse_indicators(indicator_objects: list, feed_tags: Optional[list] = None, tlp_color: Optional[str] = None) -> list:
    """Parse the IOC objects retrieved from the feed.
    Args:
      indicator_objects: a list of objects containing the indicators.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
    Returns:
        A list of processed indicators.
    """
    if not feed_tags:
        feed_tags = []

    indicators = []
    if indicator_objects:
        for indicator_object in indicator_objects:
            pattern = indicator_object.get("pattern") or ""
            pattern_value = Client.get_single_pattern_value(pattern)
            if not pattern_value:
                continue
            raw_name = indicator_object.get("name", "")

            for key in UNIT42_TYPES_TO_DEMISTO_TYPES:
                if pattern.startswith(f"[{key}"):  # retrieve only Demisto indicator types
                    indicator_obj = {
                        "value": pattern_value,
                        "type": UNIT42_TYPES_TO_DEMISTO_TYPES.get(key),
                        "score": DEFAULT_INDICATOR_SCORE,  # default verdict of fetched indicators is malicious
                        "rawJSON": indicator_object,
                        "fields": {
                            "firstseenbysource": indicator_object.get("created"),
                            "indicatoridentification": indicator_object.get("id"),
                            "tags": list(set(indicator_object.get("labels") or []).union(feed_tags)),
                            "modified": indicator_object.get("modified"),
                            "reportedby": "Unit42",
                        },
                    }
                    if "file:hashes" in pattern and raw_name != pattern_value:
                        indicator_obj["fields"]["associatedfilenames"] = raw_name

                    if tlp_color:
                        indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

                    indicators.append(indicator_obj)

    return indicators


def parse_malware(client, malware_objects: list = [], feed_tags: list = [], tlp_color: Optional[str] = None) -> list:
    """Parse the IOC objects retrieved from the feed.
    Args:
      malware_objects: a list of objects containing the instances of malware.
    Returns:
        A list of processed malware.
    """

    malware_list = []
    for malware_object in malware_objects:
        malware_object = STIX2XSOARParser.parse_malware(client, malware_object)[0]
        malware_object["fields"]["tags"] = list(feed_tags)
        if tlp_color:
            malware_object["fields"]["trafficlightprotocol"] = tlp_color
        malware_list.append(malware_object)
    return malware_list


def is_atom42_main_report(report_obj):
    """Our definition for main report is a report with 'object_refs'
    list that contains only objects of the type not a report and a report with
    description.

    Args:
      report_obj: The report object.
    Returns:
        A boolean.
    """
    obj_refs = report_obj.get("object_refs", [])
    contain_report = False
    contain_intrusion_set = False
    if report_obj.get("name") == "ATOM Campaign Report":
        return False
    for obj_ref in obj_refs:
        if not obj_ref.startswith(("report--", "intrusion-set--")):
            return False
        if obj_ref.startswith("intrusion-set--"):
            contain_intrusion_set = True
        if obj_ref.startswith("report--"):
            contain_report = True
    return contain_intrusion_set and contain_report


def is_atom42_sub_report(report_obj):
    """Our definition for sub report is a report with 'object_refs'
    list that contains only objects not for type intrusion-set or report.

    Args:
      report_obj: The report object.
    Returns:
        A boolean.
    """
    obj_refs = report_obj.get("object_refs", [])
    is_report_description = report_obj.get("description") is not None
    only_reports_and_intrusion_set = True
    if report_obj.get("name") == "ATOM Campaign Report":
        return True
    for obj_ref in obj_refs:
        if not obj_ref.startswith(("report--", "intrusion-set--")):
            only_reports_and_intrusion_set = False
    return not (is_report_description or only_reports_and_intrusion_set)


def create_relationship_entity(entity_a: Optional[str], entity_b: str, entity_b_type: str):
    """Creates relationship entity object.

    Args:
      entity_a: the indictor name of entity_a - report name is required.
      entity_b: the indictor name of entity_b.
      entity_b_type: the the indictor type of entity_b.

    Returns:
        A EntityRelationship object.
    """
    entity_relation = EntityRelationship(
        name="related-to",
        entity_a=f"[Unit42 ATOM] {entity_a}",
        entity_a_type=ThreatIntel.ObjectsNames.REPORT,
        entity_b=entity_b,
        entity_b_type=entity_b_type,
    )
    return entity_relation.to_indicator()


def create_relationship_list(id_to_object, report_object: dict, sub_report_obj: dict, campaign_only: bool) -> tuple:
    """Creates relationship list and obj refs list.

    Args:
      id_to_object: a dict in the form of - id: stix_object.
      report_object: A report objects.
      sub_report_obj: A sub-report objects.
      campaign_only: bool indicates whether to add only campaign indicators.

    Returns:
        tuple of two lists the first list is a relationships list and the second list is an object ref list.
    """
    obj_refs_excluding_relationships_prefix = []
    relationships = []
    sub_report_obj_object_refs = sub_report_obj.get("object_refs", [])
    for related_obj in sub_report_obj_object_refs:
        # relationship-- objects ref handled in parse_relationships
        if not related_obj.startswith("relationship--"):
            obj_refs_excluding_relationships_prefix.append(related_obj)
            if id_to_object.get(related_obj):
                entity_b_obj_type, entity_b_value = STIX2XSOARParser.get_entity_b_type_and_value(related_obj, id_to_object, True)
                if not entity_b_obj_type:
                    demisto.debug(f"{INTEGRATION_NAME}: Could not find the type/name of {related_obj} skipping.")
                    continue
                if campaign_only:
                    if related_obj.startswith("campaign--"):
                        relationship_entity = create_relationship_entity(
                            report_object.get("name"),
                            entity_b_value,
                            entity_b_obj_type,
                        )
                        relationships.append(relationship_entity)
                else:
                    relationship_entity = create_relationship_entity(
                        report_object.get("name"),
                        entity_b_value,
                        entity_b_obj_type,
                    )
                    relationships.append(relationship_entity)
    return relationships, obj_refs_excluding_relationships_prefix


def get_relationships_from_sub_reports(client, report_object, id_to_object, campaign_only):
    """Parse the Reports objects retrieved from the feed.

    Args:
      report_objects: a list of report objects containing the reports.
      id_to_object: a dict in the form of - id: stix_object.
      campaign_only: bool indicates whether to add only campaign indicators.

    Returns:
        A list of relationships and a list of obj_refs_excluding_relationships_prefix.
    """
    object_ref_to_return = []
    object_refs = report_object.get("object_refs", [])
    relationships: list[dict[str, Any]] = []
    obj_refs_excluding_relationships_prefix = []
    for obj in object_refs:
        if obj.startswith("report--"):
            # if the report id in the object ref we will not create relationships
            if obj == report_object.get("id"):
                continue
            sub_report_obj = client.get_report_object(obj)
            if sub_report_obj:
                relationships_list, sub_report_obj_object_refs = create_relationship_list(
                    id_to_object, report_object, sub_report_obj, campaign_only
                )
                relationships.extend(relationships_list)
                obj_refs_excluding_relationships_prefix.extend(sub_report_obj_object_refs)
    if obj_refs_excluding_relationships_prefix:
        object_ref_to_return = client.create_obj_refs_list(obj_refs_excluding_relationships_prefix)
    return relationships, object_ref_to_return


def parse_reports_and_report_relationships(
    client: Client,
    report_objects: list,
    feed_tags: Optional[list] = None,
    tlp_color: Optional[str] = None,
    id_to_object: Optional[dict] = None,
):
    """Parse the Reports objects retrieved from the feed.

    Args:
      report_objects: a list of report objects containing the reports.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
      id_to_object: a dict in the form of - id: stix_object.

    Returns:
        A list of processed reports.
    """
    if not feed_tags:
        feed_tags = []

    if not id_to_object:
        id_to_object = {}

    reports = []

    for report_object in report_objects:
        if is_atom42_sub_report(report_object):
            demisto.debug(f"{INTEGRATION_NAME}: skipping {report_object.get('id')} is a sub report")
            continue
        is_main_report = is_atom42_main_report(report_object)
        report_list = client.parse_report(
            report_object, "[Unit42 ATOM] ", ignore_reports_relationships=is_main_report, is_unit42_report=True
        )
        report = report_list[0]
        report["value"] = f"[Unit42 ATOM] {report_object.get('name')}"
        report["fields"]["tags"] = list((set(report_object.get("labels") or [])).union(set(feed_tags)))
        report["fields"]["reportedby"] = "Unit42"

        if tlp_color:
            report["fields"]["trafficlightprotocol"] = tlp_color

        report["rawJSON"] = {
            "unit42_id": report_object.get("id"),
            "unit42_labels": report_object.get("labels"),
            "unit42_published": report_object.get("published"),
            "unit42_created_date": report_object.get("created"),
            "unit42_modified_date": report_object.get("modified"),
            "unit42_description": report_object.get("description"),
            "unit42_object_refs": report_object.get("object_refs"),
        }
        report_relationships, obj_refs_output = get_relationships_from_sub_reports(
            client, report_object, id_to_object, (not is_main_report)
        )
        if obj_refs_output:
            report["fields"].setdefault("Report Object References", []).extend(obj_refs_output)
        report["relationships"].extend(report_relationships)

        reports.append(report)

    return reports


def parse_campaigns(client: Client, campaigns_objs, feed_tags, tlp_color):
    """Parse the Campaign objects retrieved from the feed.

    Args:
      campaigns_obj: a list of campaign objects containing the campaign.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.

    Returns:
        A list of processed campaign.
    """
    campaigns_indicators = []
    for campaigns_obj in campaigns_objs:
        campaigns_indicator_list = client.parse_campaign(campaigns_obj)
        campaigns_indicator = campaigns_indicator_list[0]
        campaigns_indicator["fields"]["reportedby"] = "Unit42"
        campaigns_indicator["fields"]["tags"] = list(feed_tags)
        for field_name in ["aliases", "objective"]:
            if campaigns_indicator["fields"].get(field_name) is not None:
                campaigns_indicator["fields"].pop(field_name)
        if tlp_color:
            campaigns_indicator["fields"]["trafficlightprotocol"] = tlp_color

        campaigns_indicators.append(campaigns_indicator)

    return campaigns_indicators


def handle_multiple_dates_in_one_field(field_name: str, field_value: str):
    """Parses datetime fields to handle one value or more

    Args:
        field_name (str): The field name that holds the data (created/modified).
        field_value (str): Raw value returned from feed.

    Returns:
        str. One datetime value (min/max) according to the field name.
    """
    dates_as_string = field_value.splitlines()
    dates_as_datetime = [datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ") for date in dates_as_string]

    if field_name == "created":
        return f"{min(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
    else:
        return f"{max(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"


def create_attack_pattern_indicator(client: Client, attack_indicator_objects, feed_tags, tlp_color) -> List:
    """Parse the Attack Pattern objects retrieved from the feed.

    Args:
      attack_indicator_objects: a list of Attack Pattern objects containing the Attack Pattern.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
      is_up_to_6_2: is the server version is up to 6.2

    Returns:
        A list of processed Attack Pattern.
    """

    attack_pattern_indicators = []

    for attack_indicator_object in attack_indicator_objects:
        attack_indicator_list = client.parse_attack_pattern(attack_indicator_object, ignore_external_id=True)
        attack_indicator = attack_indicator_list[0]
        mitre_id, value = client.get_mitre_attack_id_and_value_from_name(attack_indicator_object)

        attack_indicator["value"] = value
        attack_indicator["fields"].update(
            {
                "reportedby": "Unit42",
                "firstseenbysource": handle_multiple_dates_in_one_field("created", attack_indicator_object.get("created")),
                "modified": handle_multiple_dates_in_one_field("modified", attack_indicator_object.get("modified")),
                "tags": list(feed_tags),
                "mitreid": mitre_id,
            }
        )
        attack_indicator["fields"]["tags"].extend([mitre_id])

        if tlp_color:
            attack_indicator["fields"]["trafficlightprotocol"] = tlp_color

        attack_pattern_indicators.append(attack_indicator)
    return attack_pattern_indicators


def create_course_of_action_indicators(client: Client, course_of_action_objects, feed_tags, tlp_color):
    """Parse the Course of Action objects retrieved from the feed.

    Args:
      course_of_action_objects: a list of Course of Action objects containing the Course of Action.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.

    Returns:
      A list of processed campaign.
    """
    course_of_action_indicators = []

    for coa_indicator_object in course_of_action_objects:
        coa_indicator_list = client.parse_course_of_action(coa_indicator_object)
        coa_indicator = coa_indicator_list[0]
        coa_indicator["fields"].update(
            {
                "reportedby": "Unit42",
                "firstseenbysource": handle_multiple_dates_in_one_field("created", coa_indicator_object.get("created")),
                "modified": handle_multiple_dates_in_one_field("modified", coa_indicator_object.get("modified")),
                "tags": list(feed_tags),
            }
        )
        if "action_type" in coa_indicator["fields"]:
            coa_indicator["fields"].pop("action_type")
        if tlp_color:
            coa_indicator["fields"]["trafficlightprotocol"] = tlp_color

        course_of_action_indicators.append(coa_indicator)

    return course_of_action_indicators


def create_intrusion_sets(client: Client, intrusion_sets_objects, feed_tags, tlp_color):
    course_of_action_indicators = []

    for intrusion_set_object in intrusion_sets_objects:
        intrusion_set_list = client.parse_intrusion_set(intrusion_set_object, ignore_external_id=True)
        intrusion_set = intrusion_set_list[0]
        intrusion_set["fields"].update(
            {
                "reportedby": "Unit42",
                "firstseenbysource": handle_multiple_dates_in_one_field("created", intrusion_set_object.get("created")),
                "modified": handle_multiple_dates_in_one_field("modified", intrusion_set_object.get("modified")),
                "tags": list(feed_tags),
            }
        )
        for field_name in ["secondary_motivations", "aliases", "primary_motivation", "resource_level", "goals"]:
            if intrusion_set["fields"].get(field_name) is not None:
                intrusion_set["fields"].pop(field_name)
        if tlp_color:
            intrusion_set["fields"]["trafficlightprotocol"] = tlp_color

        course_of_action_indicators.append(intrusion_set)

    return course_of_action_indicators


def get_ioc_type(indicator, id_to_object):
    """
    Get IOC type by extracting it from the pattern field.

    Args:
        indicator: the indicator to get information on.
        id_to_object: a dict in the form of - id: stix_object.

    Returns:
        str. the IOC type.
    """
    ioc_type = ""
    indicator_obj = id_to_object.get(indicator, {})
    pattern = indicator_obj.get("pattern", "")
    for unit42_type in UNIT42_TYPES_TO_DEMISTO_TYPES:
        if pattern.startswith(f"[{unit42_type}"):
            ioc_type = UNIT42_TYPES_TO_DEMISTO_TYPES.get(unit42_type)  # type: ignore
            break
    return ioc_type


def get_ioc_value(ioc, id_to_obj):
    """
    Get IOC value from either the indicator `name` or `pattern` fields.

    Args:
        ioc: the indicator to get information on.
        id_to_obj: a dict in the form of - id: stix_object.

    Returns:
        str. the IOC value. if its reports we add to it [Unit42 ATOM] prefix,
        if its attack pattern remove the id from the name.
    """
    ioc_obj = id_to_obj.get(ioc)
    if not ioc_obj:
        return None

    if ioc_obj.get("type") == "report":
        return f"[Unit42 ATOM] {ioc_obj.get('name')}"

    elif ioc_obj.get("type") == "attack-pattern":
        return STIX2XSOARParser.get_mitre_attack_id_and_value_from_name(ioc_obj)[1]

    for key in ("name", "pattern"):
        if ioc_value := extract_ioc_value(ioc_obj.get(key, "")):
            return ioc_value

    return ioc_obj.get("name")


def create_list_relationships(relationships_objects, id_to_object):
    """Parse the Relationships objects retrieved from the feed.

    Args:
      relationships_objects: a list of relationships objects containing the relationships.
      id_to_object: a dict in the form of - id: stix_object.

    Returns:
        A list of processed relationships.
    """
    relationships_list = []

    for relationships_object in relationships_objects:
        relationship_type = relationships_object.get("relationship_type")
        if relationship_type not in RELATIONSHIP_TYPES:
            if relationship_type == "indicates":
                relationship_type = "indicated-by"
            else:
                demisto.debug(f"Invalid relation type: {relationship_type}")
                continue

        a_threat_intel_type = relationships_object.get("source_ref").split("--")[0]
        a_type = ""
        if a_threat_intel_type in THREAT_INTEL_TYPE_TO_DEMISTO_TYPES:
            a_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(a_threat_intel_type)  # type: ignore
        elif a_threat_intel_type == "indicator":
            a_type = get_ioc_type(relationships_object.get("source_ref"), id_to_object)

        b_threat_intel_type = relationships_object.get("target_ref").split("--")[0]
        b_type = ""
        if b_threat_intel_type in THREAT_INTEL_TYPE_TO_DEMISTO_TYPES:
            b_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(b_threat_intel_type)  # type: ignore
        if b_threat_intel_type == "indicator":
            b_type = get_ioc_type(relationships_object.get("target_ref"), id_to_object)

        if not a_type or not b_type:
            continue

        mapping_fields = {
            "lastseenbysource": relationships_object.get("modified"),
            "firstseenbysource": relationships_object.get("created"),
        }

        entity_a = get_ioc_value(relationships_object.get("source_ref"), id_to_object)
        entity_b = get_ioc_value(relationships_object.get("target_ref"), id_to_object)

        entity_relation = EntityRelationship(
            name=relationship_type,
            entity_a=entity_a,
            entity_a_type=a_type,
            entity_b=entity_b,
            entity_b_type=b_type,
            fields=mapping_fields,
        )
        relationships_list.append(entity_relation.to_indicator())
    return relationships_list


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.get_stix_objects(test=True, items_types=["indicator", "report"])
    return "ok"


def fetch_indicators(
    client: Client, feed_tags: Optional[list] = None, tlp_color: Optional[str] = None, create_relationships=False
) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
        create_relationships: Create indicators relationships
    Returns:
        List. Processed indicators from feed.
    """
    if not feed_tags:
        feed_tags = []

    item_types_to_fetch_from_api = [
        "report",
        "indicator",
        "malware",
        "campaign",
        "attack-pattern",
        "relationship",
        "course-of-action",
        "intrusion-set",
    ]
    client.get_stix_objects(items_types=item_types_to_fetch_from_api)

    for type_, objects in client.objects_data.items():
        demisto.info(f"Fetched {len(objects)} Unit42 {type_} objects.")
    id_to_object = {
        obj.get("id"): obj
        for obj in client.objects_data["report"]
        + client.objects_data["indicator"]
        + client.objects_data["malware"]
        + client.objects_data["campaign"]
        + client.objects_data["attack-pattern"]
        + client.objects_data["course-of-action"]
        + client.objects_data["intrusion-set"]
    }
    client.id_to_object = id_to_object
    ioc_indicators = parse_indicators(client.objects_data["indicator"], feed_tags, tlp_color)
    reports = parse_reports_and_report_relationships(client, client.objects_data["report"], feed_tags, tlp_color, id_to_object)
    campaigns = parse_campaigns(client, client.objects_data["campaign"], feed_tags, tlp_color)
    malware = parse_malware(client, client.objects_data["malware"], feed_tags, tlp_color)
    attack_patterns = create_attack_pattern_indicator(client, client.objects_data["attack-pattern"], feed_tags, tlp_color)
    intrusion_sets = create_intrusion_sets(client, client.objects_data["intrusion-set"], feed_tags, tlp_color)
    course_of_actions = create_course_of_action_indicators(client, client.objects_data["course-of-action"], feed_tags, tlp_color)

    dummy_indicator = {}
    if create_relationships:
        list_relationships = create_list_relationships(client.objects_data["relationship"], id_to_object)

        dummy_indicator = {"value": "$$DummyIndicator$$", "relationships": list_relationships}

    if dummy_indicator:
        ioc_indicators.append(dummy_indicator)

    if ioc_indicators:
        demisto.debug(f"Feed Unit42 v2: {len(ioc_indicators)} XSOAR Indicators were created.")
    if reports:
        demisto.debug(f"Feed Unit42 v2: {len(reports)} XSOAR Reports Indicators were created.")
    if campaigns:
        demisto.debug(f"Feed Unit42 v2: {len(campaigns)} XSOAR campaigns Indicators were created.")
    if attack_patterns:
        demisto.debug(f"Feed Unit42 v2: {len(attack_patterns)} Attack Patterns Indicators were created.")
    if course_of_actions:
        demisto.debug(f"Feed Unit42 v2: {len(course_of_actions)} Course of Actions Indicators were created.")
    if intrusion_sets:
        demisto.debug(f"Feed Unit42 v2: {len(intrusion_sets)} Intrusion Sets Indicators were created.")
    if malware:
        demisto.debug(f"Feed Unit42 v2: {len(malware)} Malware Indicators were created.")
    return ioc_indicators + reports + campaigns + attack_patterns + course_of_actions + intrusion_sets + malware


def get_indicators_command(
    client: Client, args: Dict[str, str], feed_tags: Optional[list] = None, tlp_color: Optional[str] = None
) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Demisto Outputs.
    """
    limit = arg_to_number(args.get("limit")) or 10
    if not feed_tags:
        feed_tags = []

    ind_type = args.get("indicators_type")

    indicators = client.fetch_stix_objects_from_api(test=True, type=ind_type, limit=limit)

    if ind_type == "indicator":
        indicators = parse_indicators(indicators, feed_tags, tlp_color)
    else:
        indicators = create_attack_pattern_indicator(client, indicators, feed_tags, tlp_color)
    limited_indicators = indicators[:limit]

    readable_output = tableToMarkdown("Unit42 Indicators:", t=limited_indicators, headers=["type", "value", "fields"])

    command_results = CommandResults(
        outputs_prefix="", outputs_key_field="", outputs={}, readable_output=readable_output, raw_response=limited_indicators
    )

    return command_results


def main():  # pragma: no cover
    """
    PARSE AND VALIDATE FEED PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    api_key = params.get("credentials", {}).get("password") or str(params.get("api_key", ""))
    verify = not params.get("insecure", False)
    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    create_relationships = argToBoolean(params.get("create_relationships"))

    command = demisto.command()
    demisto.debug(f"Command being called in Unit42 v2 feed is: {command}")

    try:
        client = Client(api_key, verify)

        if command == "test-module":
            result = test_module(client)
            demisto.results(result)

        elif command == "fetch-indicators":
            indicators = fetch_indicators(client, feed_tags, tlp_color, create_relationships)
            for iter_ in batch(indicators, batch_size=2000):
                try:
                    demisto.createIndicators(iter_)
                except Exception:
                    # find problematic indicator
                    for indicator in iter_:
                        try:
                            demisto.createIndicators([indicator])
                        except Exception as err:
                            demisto.debug(
                                f"createIndicators Error: failed to create the following indicator:" f" {indicator}\n {err}"
                            )
                    raise

        elif command == "unit42-get-indicators":
            return_results(get_indicators_command(client, args, feed_tags, tlp_color))

    except Exception as err:
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
