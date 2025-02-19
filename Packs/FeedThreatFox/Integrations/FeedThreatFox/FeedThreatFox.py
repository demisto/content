import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

LOG_LINE = "THREAT FOX -"
LIMIT_SUPPORTED_QUERIES = ['tag', 'malware']


class Client(BaseClient):
    def get_indicators_request(self, query: dict) -> dict:
        url_suffix = '/api/v1'
        body = query
        return self._http_request('POST', url_suffix=url_suffix, json_data=body)

    def test_module(self) -> str:
        """Tests API connectivity and authentication'

        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param Client: client to use

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        """
        self.get_indicators_request({'days': 1, 'limit': 5})
        return 'ok'


def check_args_for_query(args: dict) -> tuple[bool, str | None]:
    """Validates that exactly one of these fields is provided:
        'search_term', 'id', 'hash', 'tag', or 'malware'.
    Args:
        args: dict
    Returns:
        Boolean: True if params are valid and False otherwise.
        Str: The query type (one of these: 'search_term', 'id', 'hash', 'tag', 'malware').
            If args are not valid than it will be None.
    """
    args_lst = list(args.keys())
    if 'limit' in args_lst:
        args_lst.remove('limit')
    if len(args_lst) != 1:
        raise DemistoException("Arguments given are invalid. Please specify exactly one argument to search by.")
    else:
        return args_lst[0]


def create_query(query_arg, id: str | None = None, search_term: str | None = None,
                 hash: str | None = None, tag: str | None = None, malware: str | None = None,
                 days: str | None = None, limit: str | None = None) -> dict:
    """Creates a valid query to send to the API.

    Args:
        query_arg (str): the query type (should be one of those:
        'search_term', 'id', 'hash', 'tag', 'malware', 'days').

    Returns:
        Str: The query to send to the API.
    """

    query_dict = {'search_term': 'search_ioc', 'id': 'ioc', 'hash': 'search_hash',
                  'tag': 'taginfo', 'malware': 'malwareinfo'}

    q_id = arg_to_number(id)

    query = assign_params(
        query=query_dict[query_arg],
        id=q_id,
        search_term=search_term,
        hash=hash,
        tag=tag,
        malware=malware,
    )

    # Only queries searching by tag or malware can specify a limit.
    if query_arg in LIMIT_SUPPORTED_QUERIES:
        q_limit = arg_to_number(limit) or 50
        if q_limit > 1000:
            demisto.debug("Limit higher than 1000. Getting first 1000 indicators.")
            q_limit = 1000
        query['limit'] = q_limit

    return query


def parse_indicators_for_get_command(indicators) -> List[dict[str, Any]]:
    """Parses the list of indicators returned from the api to indicators that can be returned to the war room.

    Args:
        indicators (list): list of indicators from api raw response.

    Returns:
        List[dict[str, Any]]: List of indicators that can be returned to the war room.
    """
    res = []
    indicators = [indicators] if type(indicators) is not list else indicators
    for indicator in indicators:
        res.append(assign_params(
            ID=indicator.get('id'),
            Value=get_value(indicator),
            Description=indicator.get('threat_type_desc'),
            MalwareFamilyTags=indicator.get('malware_printable') if indicator.get(
                'malware_printable') != 'Unknown malware' else None,
            AliasesTags=indicator.get('malware_alias'),
            FirstSeenBySource=indicator.get('first_seen'),
            LastSeenBySource=indicator.get('last_seen'),
            ReportedBy=indicator.get('reporter'),
            Tags=tags(indicator, with_ports=True),
            Confidence=str(indicator.get('confidence_level')),
            Publications=publications(indicator)
        ))
    return res


def indicator_type(indicator: dict) -> str:
    """Returns the Demisto ioc type according to 'ioc_type' field in the indicator
    """
    type = indicator.get('ioc_type')
    if type == 'domain':
        return FeedIndicatorType.FQDN
    elif type == 'url':
        return FeedIndicatorType.URL
    elif type == 'ip:port':
        return FeedIndicatorType.IP
    elif type == 'envelope_from' or type == 'body_from':
        return FeedIndicatorType.Email
    else:  # 'sha1_hash' 'sha256_hash' 'md5_hash'
        return FeedIndicatorType.File


def parse_indicator_for_fetch(indicator: dict, with_ports: bool, create_relationship: bool, tlp_color: str) -> dict[str, Any]:
    """Parses the indicator given from the api to an indicator that can be sent to Threat Intel min XSOAR.

    Args:
        indicator (dict): The raw data of the indicator.
        with_ports (bool): whether to return the indicator with a tag representing it's port (relevant for ip indicators only).
        create_relationship (bool): Whether to create the indicator with relationships.
        tlp_color (str): The tlp color of the indicator

    Returns:
        dict[str, Any]: An indicator that can be sent to Threat Intel in XSOAR.
    """

    demisto_ioc_type = indicator_type(indicator)
    ioc_value = get_value(indicator)
    relationships = create_relationships(ioc_value, indicator['ioc_type'], indicator.get("malware_printable"),
                                         demisto_ioc_type) if create_relationship else None

    fields = assign_params(
        indicatoridentification=indicator.get('id'),
        description=indicator.get('threat_type_desc'),
        malwarefamily=indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
        aliases=indicator.get('malware_alias'),
        firstseenbysource=to_date(indicator.get('first_seen')),
        lastseenbysource=to_date(indicator.get('last_seen')),
        reportedby=indicator.get('reporter'),
        Tags=tags(indicator, with_ports),
        publications=publications(indicator),
        confidence=indicator.get('confidence_level'),
        trafficlightprotocol=tlp_color
    )

    return assign_params(
        value=ioc_value,
        type=demisto_ioc_type,
        fields=fields,
        relationships=relationships,
        rawJSON=indicator
    )


def publications(indicator: dict) -> Optional[List[dict[str, Any]]]:
    """creates the publications field for the indicator.

    Args:
        indicator (dict): The indicator.

    Returns:
        Optional[List[dict[str, Any]]]: The list of relevant publications for this indicator
        or None if the indicator has no publications.
    """
    if not indicator.get('reference'):
        return None
    malware_printable = indicator.get('malware_printable')

    return [{'link': indicator.get('reference'),
             'title': malware_printable if malware_printable and malware_printable != 'Unknown malware' else 'Malware',
             'source': 'ThreatFox'}]


def to_date(date) -> Optional[str]:
    """parses the date returned from raw response to a date in the right format for indicator fields in XSOAR.
    """
    if date:
        parsed_date = arg_to_datetime(date, required=False)
        if parsed_date:
            return parsed_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    return None


def tags(indicator: dict, with_ports: bool) -> List[str]:
    """Returns a list of tags to add to the indicator given

    Args:
        indicator (dict): The raw response of the indicator.
        with_ports (bool): whether to return the indicator with a tag representing it's port (relevant for ip indicators only).

    Returns:
        List[str]: List of tags to add to the indicator.
    """
    res = [indicator.get('malware_printable') if indicator.get('malware_printable')
           != 'Unknown malware' else None, indicator.get('threat_type')]
    if indicator.get('tags'):
        res.extend(indicator['tags'])
    if indicator.get('malware_alias'):
        res.extend(indicator['malware_alias'].split(','))
    if with_ports and indicator.get('ioc_type') == "ip:port":
        res.append('port: ' + indicator['ioc'].split(':')[1])

    res = [tag.lower() for tag in res if tag]

    # remove duplicate tags
    res = list(set(res))

    return res


def get_value(indicator) -> str:
    """Returns the value of the indicator.
    For example, when indicator is: {'id': '123', 'ioc': '1.1.1.1:80', 'ioc_type': 'ip:port'}
    then returned value will be '1.1.1.1'.
    When indicator is: {'id': '456', 'ioc': 'habbkj', 'ioc_type': 'sha1_hash'}
    then returned value will be 'habbkj'.
    """
    if indicator.get('ioc_type') == 'ip:port':
        return indicator.get('ioc').split(':')[0]
    return indicator.get('ioc')


def create_relationships(value: str, type: str, related_malware: Optional[str], demisto_ioc_type: str) -> list:
    """Returns a list of relationships of the indicator.

    Args:
        value (str): The indicator value.
        type (str): The indicator type as given in the raw response.
        related_malware (Optional[str]): The malware related to the indicator to create a relationship to.
        demisto_ioc_type (str): The indicator type as a Demisto type.

    Returns:
        list: List of relationships.
    """

    if related_malware and related_malware != 'Unknown malware':
        name = EntityRelationship.Relationships.COMMUNICATED_BY \
            if type == 'domain' or type == "ip:port" or type == 'url' else EntityRelationship.Relationships.RELATED_TO
        reverse_name = EntityRelationship.Relationships.COMMUNICATED_WITH \
            if type == 'domain' or type == "ip:port" or type == 'url' else EntityRelationship.Relationships.RELATED_TO
        return [EntityRelationship(entity_a=value, entity_a_type=demisto_ioc_type,
                                   name=name,
                                   entity_b=related_malware, entity_b_type=FeedIndicatorType.Malware,
                                   brand='ThreatFox Feed', reverse_name=reverse_name).to_indicator()]
    return []


def validate_interval(interval: int) -> int:
    """Validates that the given interval is in days between 1 to 7,
    due to using the standard interval input type which supports minutes as well.

    Raises:
        DemistoException: If the interval is invalid.

    Returns:
        int: The interval, if it is valid.
    """
    if interval % 1440 != 0:  # 1440 is the number of minutes in a day
        raise DemistoException("The fetch interval must be in whole days, between 1-7.")
    elif interval > 10080:
        raise DemistoException("The fetch interval must not be more than 7 days.")
    return interval


def threatfox_get_indicators_command(client: Client, args: dict[str, Any]) -> CommandResults:

    search_term = args.get('search_term')
    id = args.get('id')
    hash = args.get('hash')
    tag = args.get('tag')
    malware = args.get('malware')
    limit = args.get('limit')

    query_type = check_args_for_query(args)

    query = create_query(query_type, id, search_term, hash, tag, malware, limit=limit)

    demisto.debug(f'{LOG_LINE} calling api with {query=}')
    try:
        result = client.get_indicators_request(query)
    except DemistoException as e:
        if 'malware' in query and '502' in str(e):  # if illegal malware is provided an 502 error response returns
            raise DemistoException('Error in API call [502] - Bad Gateway. Make sure the malware you entered in valid')

    query_status = result.get('query_status')
    query_data = result.get('data')

    if query_status != 'ok' and query_status:
        raise DemistoException(f'failed to run command, {query_status=}, {query_data=}')

    parsed_indicators = parse_indicators_for_get_command(result.get('data') or result)

    demisto.debug(f'{LOG_LINE} got {len(parsed_indicators)} indicators')

    human_readable = tableToMarkdown(name='Indicators', t=parsed_indicators,
                                     headers=['ID', 'Value', 'Description', 'MalwareFamilyTags',
                                              'AliasesTags', 'FirstSeenBySource', 'LastSeenBySource', 'ReportedBy',
                                              'Tags', 'Confidence', 'Publications'], removeNull=True, is_auto_json_transform=True)

    return CommandResults(readable_output=human_readable)


def fetch_indicators_command(client: Client, with_ports: bool, confidence_threshold: int,
                             create_relationship: bool, interval: int, tlp_color: str, last_run: dict):

    now = datetime.now(timezone.utc)
    days_for_query = int(interval / 1440)  # The interval is validated already in the main

    if last_run:
        last_successful_run = dateparser.parse(last_run["last_successful_run"], settings={
                                               'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
        if last_successful_run:
            time_delta = now - last_successful_run
            days_for_query = time_delta.days + 1
        else:
            raise DemistoException('failed to fetch indicators')  # not supposed to happen

    # handling case of more than 7 days history, as the API fail longer-fetching queries.
    if days_for_query > 7:  # api can get up to 7 days
        days_for_query = 7

    response = client.get_indicators_request({"query": "get_iocs", "days": days_for_query})

    if response.get('query_status') != 'ok':
        raise DemistoException(f"couldn't fetch, {response.get('query_status')}")

    indicators = response['data']
    demisto.debug(f'{LOG_LINE} got {len(indicators)}')

    results = []

    for indicator in indicators:

        if indicator.get('ioc_type') == 'sha3_384_hash':
            demisto.debug(f'{LOG_LINE} got indicator of indicator type "sha3" skipping it')
            continue
        if (arg_to_number(indicator.get('confidence_level')) or 75) < confidence_threshold:
            demisto.debug(f'{LOG_LINE} got indicator with low confidence level, skipping it')
            continue

        results.append(parse_indicator_for_fetch(indicator, with_ports, create_relationship, tlp_color))

    return now.strftime('%Y-%m-%dT%H:%M:%SZ'), results


''' MAIN FUNCTION '''


def main() -> None:

    command = demisto.command()

    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    with_ports = argToBoolean(params.get('with_ports'))
    confidence_threshold = arg_to_number(params.get('confidence_threshold')) or 75
    create_relationship = argToBoolean(params.get('create_relationship'))
    tlp_color = params.get('tlp_color') or 'CLEAR'
    interval = validate_interval(arg_to_number(params.get('feedFetchInterval')) or 1440)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(base_url=base_url)

        if command == 'test-module':
            result = client.test_module()
            return_results(result)

        elif command == 'threatfox-get-indicators':
            return_results(threatfox_get_indicators_command(client, demisto.args()))

        elif command == 'fetch-indicators':
            next_run, res = fetch_indicators_command(client=client, with_ports=with_ports,
                                                     confidence_threshold=confidence_threshold,
                                                     create_relationship=create_relationship, interval=interval,
                                                     tlp_color=tlp_color, last_run=demisto.getLastRun())
            for iter_ in batch(res, batch_size=2000):
                demisto.debug(f"{LOG_LINE} {iter_=}")
                demisto.createIndicators(iter_)
            demisto.setLastRun({"last_successful_run": next_run})

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
