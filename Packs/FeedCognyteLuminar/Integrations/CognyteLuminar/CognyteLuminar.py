from functools import partial
from urllib import parse
from CommonServerPython import *

stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")
API_URL = "/externalApi"
LEAKED_RECORD = "LEAKED CREDENTIAL"
LEAKED_CREDENTIALS_TABLE_HEADER = "Leaked Credentials from Luminar"
IOC_TABLE_HEADER = "Indicators from Luminar"
LUMINAR_TO_XSOAR_TYPES = {
    'file': FeedIndicatorType.File,
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IP,
    'mac-addr': FeedIndicatorType.IP,
    'domain-name': FeedIndicatorType.Domain,
    'email-addr': FeedIndicatorType.Email,
    'url': FeedIndicatorType.URL,
    'windows-registry-key': FeedIndicatorType.Registry,
    'user-account': FeedIndicatorType.Account
}


def enrich_incident_items(parent, childrens, feed_tags, tlp_color):
    """
    This will get Account, Incident objects
    Args:
        parent: Incident
        childrens: Accounts
        feed_tags: feed_tags
        tlp_color: tlp_color

    Returns: Incident, Account objects

    """
    modified_childrens = []

    for children in childrens:
        tags = [LEAKED_RECORD, f'Incident: {parent.get("name")}', f'Credentials:{children.get("credential")}']
        if feed_tags:
            tags.extend(list(feed_tags))

        additional_field = {
            'tags': tags,
            "category": LEAKED_RECORD,
            'accounttype': LEAKED_RECORD,
            'displayname': children.get('display_name'),
            'emailaddress': children.get('display_name'),
            'creationdate': parent.get('created'),
            'firstseenbysource': parent.get('created'),
            'updateddate': parent.get('modified'),
            'lastseenbysource': parent.get('created'),
            "shortdescription": parent.get('description') or "",
            "trafficlightprotocol": tlp_color
        }

        indicator = {
            'value': children.get("account_login"),
            'occurred': datetime.strptime(parent.get("created"),
                                          '%Y-%m-%dT%H:%M:%S.%f%z').strftime(
                "%m/%d/%Y, %H:%M:%S"),
            'type': FeedIndicatorType.Account,
            'rawJSON': dict(children),
            'fields': additional_field,
        }
        modified_childrens.append(indicator)
    return parent, modified_childrens


def enrich_malware_items(parent, childrens, feed_tags, tlp_color):
    """
    This will get Malware, Indicator objects
    Args:
        parent: Malware
        childrens: Indicator
        feed_tags: feed_tags
        tlp_color: tlp_color

    Returns: Malware, Indicator Objects

    """
    modified_childrens = []
    modified_parent = None
    all_tags = set()
    for children in childrens:
        indicator_type = None
        pattern = children.get("pattern")
        for match in stix_regex_parser.findall(pattern):
            stix_type, stix_property, value = match
            if stix_type in LUMINAR_TO_XSOAR_TYPES:
                indicator_type = LUMINAR_TO_XSOAR_TYPES[stix_type]
                if indicator_type == FeedIndicatorType.File and not str(stix_property).__contains__("hashes"):
                    indicator_type = None
            else:
                indicator_type = stix_type

        if indicator_type:
            malware_types = parent.get("malwareTypes")
            children.update(indicator_type=indicator_type)
            parent["name"] = children["name"]
            children["value"] = value
            relationship_obj = EntityRelationship(
                name=EntityRelationship.Relationships.INDICATED_BY,
                entity_a=value,
                entity_a_type=indicator_type,
                entity_b=parent["name"],
                entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
            )
            tags = list(children["indicator_types"])
            all_tags.update(tags)

            tags.append("Malware Family: " + parent["name"])
            malware_types_str = ",".join(malware_types)
            indicator_type_str = ",".join(children["indicator_types"])
            tags.append(f"Malware Type: {malware_types_str}")
            if feed_tags:
                tags.extend(list(feed_tags))

            indicator = {
                'value': value,
                'occurred': datetime.strptime(children["created"],
                                              '%Y-%m-%dT%H:%M:%S.%f%z').strftime(
                    "%m/%d/%Y, %H:%M:%S"),
                'type': indicator_type,
                'rawJSON': dict(children),
                'fields': {
                    "category": "Malware",
                    "malwarefamily": children["name"],
                    "shortdescription": f"This {indicator_type} was involved in {indicator_type_str}",
                    "creationdate": children["created"],
                    'firstseenbysource': children["created"],
                    "updateddate": children["modified"],
                    'lastseenbysource': children["modified"],
                    "tags": tags,
                    "trafficlightprotocol": tlp_color
                },
                'relationships': [relationship_obj.to_indicator()]
            }
            modified_childrens.append(indicator)

    if parent:
        additional_fields = {
            "STIX Is Malware Family": parent["is_family"],
            "tags": list(all_tags),
            "stixid": parent["id"],
            'STIX Malware Types': parent["malwareTypes"],
            'malware_types': parent["malwareTypes"]
        }
        modified_parent = {
            'value': parent["name"],
            'occurred': datetime.strptime(parent["created"],
                                          '%Y-%m-%dT%H:%M:%S.%f%z').strftime(
                "%m/%d/%Y, %H:%M:%S"),
            'type': ThreatIntel.ObjectsNames.MALWARE,
            'rawJSON': dict(parent),
            'fields': additional_fields,
        }

    return modified_parent, modified_childrens


def generic_item_finder(all_objects, item_id):
    return filter(lambda x: x.get("id") == item_id, all_objects)


class Client(BaseClient):
    """
    This class handles logic for Luminar API
    """

    def __init__(self, base_url: str, account_id: str, client_id: str, client_secret: str, verify: bool = False,
                 proxy: bool = False, tags: list = [], tlp_color: Optional[str] = None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200,),
        )
        self.luminar_account_id = account_id
        self.luminar_client_id = client_id
        self.luminar_client_secret = client_secret
        self.offset = 0
        self.limit = 100
        self.feed_tags = tags
        self.tlp_color = tlp_color

    def fetch_access_token(self):
        """
            function to fetch the access token
        """
        req_url = f"{self._base_url}/realm/{self.luminar_account_id}/token"
        req_headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
        }
        req_data = parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.luminar_client_id,
            "client_secret": self.luminar_client_secret
        })
        r = requests.post(req_url, headers=req_headers, data=req_data)
        return r.json()['access_token']

    def fetch_luminar_api_feeds(self, is_fetch_command=True):
        """
        This will fetch the luminar feed for FEED Command
        Returns:
        """
        is_feed = True
        while is_feed:
            access_token = self.fetch_access_token()
            params: Dict[str, Union[int, int]] = {}
            if is_fetch_command:
                last_run = self.get_last_run()
                if last_run:
                    params = {"timestamp": int(last_run), "limit": self.limit}
                else:
                    params = {"limit": self.limit, "offset": self.offset}
                    self.offset += self.limit
            else:
                params = {"limit": self.limit, "offset": self.offset}
                self.offset += self.limit
            req_url = f"{self._base_url}/stix"
            req_headers = {"Authorization": "Bearer %s" % access_token}
            luminar_feed = requests.get(req_url, params=params, headers=req_headers).json()
            luminar_objects = luminar_feed.get("objects")
            if not luminar_objects or len(luminar_objects) == 1:
                if is_fetch_command:
                    self.set_last_run()
                is_feed = False
            yield luminar_objects

    def fetch_luminar_indicators(self):
        """
            This method will create indicators into XSOAR
        """
        for luminar_feed in self.fetch_luminar_api_feeds(is_fetch_command=True):
            if not luminar_feed:
                continue
            get_item_by_id = partial(generic_item_finder, luminar_feed)
            relationships: Dict[Any, Any] = {}
            for relationship in filter(lambda x: x.get("type") == "relationship", luminar_feed):
                relationship_items = relationships.get(relationship.get("target_ref"), [])
                relationship_items.append(relationship.get("source_ref"))
                relationships[relationship["target_ref"]] = relationship_items

            for key, group in relationships.items():
                parent = next(get_item_by_id(key), None)
                children: List[Any] = list(filter(None, [next(get_item_by_id(item_id), None) for item_id in group]))

                if parent and parent.get("type") == "malware":
                    indicators_list = []
                    modified_parent, modified_childrens = enrich_malware_items(parent, children,
                                                                               self.feed_tags, self.tlp_color)
                    indicators_list.extend(modified_childrens)
                    indicators_list.append(modified_parent)
                    for b in batch(indicators_list, batch_size=2000):
                        demisto.createIndicators(b)
                elif parent and parent.get("type") == "incident":
                    incidents_list = []
                    modified_parent, modified_childrens = enrich_incident_items(parent, children,
                                                                                self.feed_tags, self.tlp_color)
                    incidents_list.extend(modified_childrens)
                    incidents_list.append(modified_parent)
                    for b in batch(incidents_list, batch_size=2000):
                        demisto.createIndicators(b)
                else:
                    parent_type = parent.get("type") if parent else ""
                    demisto.info(f"Type not handled : {parent_type}")
                    continue

    def get_luminar_indicators_list(self):
        """
        This will get the indicators from Luminar for get-indicators method.
        Returns: list
        """
        luminar_indicators_list = []
        for luminar_feed in self.fetch_luminar_api_feeds(is_fetch_command=False):
            luminar_indicators = []
            if not luminar_feed:
                continue
            if luminar_feed:
                ioc_list = [ele for ele in list(luminar_feed) if ele["type"] == "indicator"]
                if ioc_list:
                    luminar_indicators.append(ioc_list)
            if luminar_indicators:
                for lum_indicator in luminar_indicators[0]:
                    indicator_type = None
                    pattern = lum_indicator["pattern"]
                    for match in stix_regex_parser.findall(pattern):
                        stix_type, stix_property, value = match
                        if stix_type in LUMINAR_TO_XSOAR_TYPES:
                            indicator_type = LUMINAR_TO_XSOAR_TYPES[stix_type]
                            if indicator_type == FeedIndicatorType.File and \
                                    not str(stix_property).__contains__("hashes"):
                                indicator_type = None
                    if indicator_type:
                        indicator = {
                            'Indicator Type': indicator_type,
                            'Indicator Value': value,
                            'Malware Family': lum_indicator["name"],
                            'rawJSON': dict(lum_indicator)
                        }
                    else:
                        indicator = {}
                        demisto.debug(f"{indicator_type=} -> {indicator=}")
                    luminar_indicators_list.append(indicator)
        return luminar_indicators_list

    def get_luminar_leaked_credentials_list(self):
        """
        This will get the leaked records from Luminar for get-leaked-records method.
        Returns: list
        """
        luminar_leaked_credentials_list = []
        for luminar_feed in self.fetch_luminar_api_feeds(is_fetch_command=False):
            luminar_leaked_records = []
            if not luminar_feed:
                continue
            if luminar_feed:
                user_account_list = [ele for ele in list(luminar_feed) if ele["type"] == "user-account"]
                if user_account_list:
                    luminar_leaked_records.append(user_account_list)

            if luminar_leaked_records:
                for luminar_leaked_record in luminar_leaked_records[0]:
                    credentials = luminar_leaked_record.get("credential", "")
                    indicator = {
                        'Indicator Type': FeedIndicatorType.Account,
                        'Indicator Value': luminar_leaked_record["account_login"],
                        'Credentials': credentials,
                        'rawJSON': dict(luminar_leaked_record)
                    }
                    luminar_leaked_credentials_list.append(indicator)
        return luminar_leaked_credentials_list

    @staticmethod
    def set_last_run():
        """
        sets the last run
        """
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        demisto.setIntegrationContext({'last_modified_time': timestamp})
        demisto.info(f'set last_run: {timestamp}')

    @staticmethod
    def get_last_run() -> str:
        """ Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """
        return demisto.getIntegrationContext().get('last_modified_time')


def cognyte_luminar_get_leaked_records(client: Client, args: dict):
    """
    This function is used to fetch the luminar indicators and show in the war room
    Args:
        client: client object
        args: limit

    Returns:

    """
    limit = arg_to_number(args.get('limit', 50), arg_name='limit')
    leaked_records = client.get_luminar_leaked_credentials_list()
    leaked_records = leaked_records[:limit]
    if leaked_records:
        readable_output = tableToMarkdown(name=LEAKED_CREDENTIALS_TABLE_HEADER, t=leaked_records,
                                          headers=["Indicator Type", "Indicator Value", "Credentials"],
                                          headerTransform=pascalToSpace)

        return CommandResults(
            outputs=leaked_records,
            outputs_prefix='Luminar.Leaked_Credentials',
            outputs_key_field='',
            readable_output=readable_output,
            raw_response=leaked_records
        )
    else:
        return CommandResults(
            readable_output='No Leaked Records Found.'
        )


def cognyte_luminar_get_indicators(client: Client, args: dict):
    """
    This function is used to fetch the luminar indicators and show in the war room
    Args:
        client: client object
        args: limit

    Returns:

    """
    limit = arg_to_number(args.get('limit', 50), arg_name='limit')
    indicators_list = client.get_luminar_indicators_list()
    indicators_list = indicators_list[:limit]
    if indicators_list:
        readable_output = tableToMarkdown(name=IOC_TABLE_HEADER, t=indicators_list,
                                          headers=["Indicator Type", "Indicator Value", "Malware Family"],
                                          headerTransform=pascalToSpace)
        return CommandResults(
            outputs=indicators_list,
            outputs_prefix='Luminar.Indicators',
            outputs_key_field='',
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(
            readable_output='No Indicators Found.'
        )


def module_test(client: Client) -> str:
    try:
        client.fetch_access_token()
    except Exception:
        raise Exception("Could not connect to Luminar API\n"
                        "\nCheck your credentials and try again.")
    return 'ok'


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def fetch_indicators_command(client: Client):
    """ fetch indicators from the Luminar API
    Args:
        client: Client object
    Returns:
        list of indicators(list)
    """
    client.fetch_luminar_indicators()
    return True


def main() -> None:
    params = demisto.params()
    base_url = urljoin(params.get('luminar_base_url'), API_URL)
    account_id = params.get('luminar_account_id')
    client_id = params.get('luminar_client_id')
    client_secret = params.get('luminar_client_secret')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    client = Client(
        base_url=base_url,
        account_id=account_id,
        client_id=client_id,
        client_secret=client_secret,
        verify=verify_certificate,
        proxy=proxy,
        tags=tags,
        tlp_color=tlp_color
    )
    command = demisto.command()
    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if command == 'fetch-indicators':
            fetch_indicators_command(client=client)
        elif command == 'luminar-get-indicators':
            return_results(cognyte_luminar_get_indicators(client=client, args=demisto.args()))
        elif command == 'luminar-get-leaked-records':
            return_results(cognyte_luminar_get_leaked_records(client=client, args=demisto.args()))
        elif command == "luminar-reset-fetch-indicators":
            return_results(reset_last_run())
        elif command == 'test-module':
            result = module_test(client=client)
            return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
