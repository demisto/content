import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from datetime import datetime, UTC
from typing import Any
from dateparser import parse

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''

MALICIOUS_DICTIONARY: dict[Any, int] = {
    'low': Common.DBotScore.GOOD,
    'medium': Common.DBotScore.SUSPICIOUS,
    'high': Common.DBotScore.BAD
}

MALICIOUS_THRESHOLD = MALICIOUS_DICTIONARY.get(demisto.params().get('threshold', 'high'))

''' CLIENT '''


class Client:
    """
    The integration's client
    """

    def __init__(self, params: dict[str, str], reliability: Optional[DBotScoreReliability] = None):
        self.cs_client: CrowdStrikeClient = CrowdStrikeClient(params=params)
        self.reliability = reliability
        self.query_params: dict[str, str] = {'offset': 'offset', 'limit': 'limit', 'sort': 'sort', 'free_search': 'q'}
        self.date_params: dict[str, dict[str, str]] = {
            'created_date': {'operator': '', 'api_key': 'created_date'},
            'last_updated_date': {'operator': '', 'api_key': 'last_updated'},
            'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
            'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
            'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'},
        }

    def build_request_params(self, args: dict[str, Any]) -> dict[str, Any]:
        """
        Build the params dict for the request
        :param args: Cortex XSOAR args
        :return: The params dict
        """
        params: dict[str, Any] = {key: args.get(arg) for arg, key in self.query_params.items()}
        query = args.get('query')
        params['filter'] = query if query else self.build_filter_query(args)
        return assign_params(**params)

    def build_filter_query(self, args: dict[str, str]) -> str:
        """
        Builds the filter query in Falcon Query Language (FQL)
        :param args: Cortex XSOAR args
        :return: The query
        """
        filter_query: str = ''

        for key in args:
            if key not in self.query_params:
                if key not in self.date_params:
                    values: List[str] = argToList(args[key], ',')
                    for value in values:
                        filter_query += f"{key}:'{value}'+"
                else:
                    operator: Optional[str] = self.date_params.get(key, {}).get('operator')
                    api_key: Optional[str] = self.date_params.get(key, {}).get('api_key')
                    # Parsing date argument of ISO format or free language into datetime object,
                    # replacing TZ with UTC, taking its timestamp format and rounding it up.
                    parsed_date = parse(args[key])
                    assert parsed_date is not None
                    filter_query += f"{api_key}:" \
                                    f"{operator}{int(parsed_date.replace(tzinfo=UTC).timestamp())}+"

        if filter_query.endswith('+'):
            filter_query = filter_query[:-1]

        return filter_query

    def get_indicator(self, indicator_value: str) -> dict[str, Any]:
        # crowdstrike do not allow passing single quotes - so we encode them
        # we are not encoding the entire indicator value, as the other reserved chars (such as + and &) are allowed
        indicator_value = indicator_value.replace("'", "%27")
        args: dict[str, Any] = {
            'indicator': indicator_value,
            'limit': 1
        }
        params: dict[str, Any] = self.build_request_params(args)
        return self.cs_client.http_request(method='GET', url_suffix='intel/combined/indicators/v1', params=params)

    def cs_actors(self, args: dict[str, str]) -> dict[str, Any]:
        url_suffix = 'intel/combined/actors/v1'
        if argToBoolean(args.pop('display_full_fields', False)):
            url_suffix += '?fields=__full__'
        params: dict[str, Any] = self.build_request_params(args)
        return self.cs_client.http_request(method='GET', url_suffix=url_suffix, params=params)

    def cs_indicators(self, args: dict[str, str]) -> dict[str, Any]:
        params: dict[str, Any] = self.build_request_params(args)
        return self.cs_client.http_request(method='GET', url_suffix='intel/combined/indicators/v1', params=params)

    def cs_reports(self, args: dict[str, str]) -> dict[str, Any]:
        url_suffix = 'intel/combined/reports/v1'
        if argToBoolean(args.pop('display_full_fields', False)):
            url_suffix += '?fields=__full__'
        params: dict[str, Any] = self.build_request_params(args)
        return self.cs_client.http_request(method='GET', url_suffix=url_suffix, params=params)


''' HELPER FUNCTIONS '''


def get_dbot_score_type(indicator_type: str) -> Exception | DBotScoreType | str:
    """
    Returns the dbot score type
    :param indicator_type: The indicator type
    :return: The dbot score type
    """
    if indicator_type == 'ip':
        return DBotScoreType.IP
    elif indicator_type == 'domain':
        return DBotScoreType.DOMAIN
    elif indicator_type == 'file' or indicator_type == 'hash':
        return DBotScoreType.FILE
    elif indicator_type == 'url':
        return DBotScoreType.URL
    else:
        raise DemistoException('Indicator type is not supported.')


def get_score_from_resource(r: dict[str, Any]) -> int:
    """
    Calculates the DBotScore for the resource
    :param r: The resource
    :return: The DBotScore
    """
    malicious_confidence: int = MALICIOUS_DICTIONARY.get(r.get('malicious_confidence'), 0)
    if malicious_confidence == 3 or MALICIOUS_THRESHOLD == 1:
        score = 3
    elif malicious_confidence == 2 or MALICIOUS_THRESHOLD == 2:
        score = 2
    else:
        score = 1
    return score


def get_indicator_hash_type(indicator_value: str) -> str | Exception:
    """
    Calculates the type of the hash
    :param indicator_value: The hash value
    :return: The hash type
    """
    length: int = len(indicator_value)
    if length == 32:
        return 'hash_md5'
    elif length == 40:
        return 'hash_sha1'
    elif length == 64:
        return 'hash_sha256'
    else:
        raise DemistoException(f'Invalid hash. Hash length is: {length}. Please provide either MD5 (32 length)'
                               f', SHA1 (40 length) or SHA256 (64 length) hash.')


def get_indicator_object(indicator_value: Any, indicator_type: str, dbot_score: Common.DBotScore) \
        -> Common.IP | Common.URL | Common.File | Common.Domain | None:
    """
    Returns the corresponding indicator common object
    :param indicator_value: The indicator value
    :param indicator_type: The indicator value
    :param dbot_score: The indicator DBotScore
    :return: The indicator common object
    """
    if indicator_type == 'ip':
        return Common.IP(
            ip=indicator_value,
            dbot_score=dbot_score
        )
    elif indicator_type == 'url':
        return Common.URL(
            url=indicator_value,
            dbot_score=dbot_score
        )
    elif indicator_type == 'hash':
        hash_type: str | Exception = get_indicator_hash_type(indicator_value)
        if hash_type == 'hash_md5':
            return Common.File(
                md5=indicator_value,
                dbot_score=dbot_score
            )
        elif hash_type == 'hash_sha1':
            return Common.File(
                sha1=indicator_value,
                dbot_score=dbot_score
            )
        else:
            return Common.File(
                sha256=indicator_value,
                dbot_score=dbot_score
            )
    elif indicator_type == 'domain':
        return Common.Domain(
            domain=indicator_value,
            dbot_score=dbot_score
        )
    else:
        return None


def should_filter_resource_by_type(resource, indicator_type, indicator_value):
    """
    checks if a resource should be filtered by his type.
    :param resource: The resource object
    :param indicator_type: The indicator type
    :param indicator_value: The indicator value
    :return: True if the resource should be filtered (don't match the indicator type) or False otherwise.
    """
    # indicator type was not filtered using the query due to a bug in the CrowdStrike API.
    if indicator_type == 'hash':
        filter_type = get_indicator_hash_type(indicator_value)
    elif indicator_type == 'ip':
        filter_type = 'ip_address'
    else:
        filter_type = indicator_type

    return resource.get('type') != filter_type


def build_indicator(indicator_value: str, indicator_type: str, title: str, client: Client) -> List[CommandResults]:
    """
    Builds an indicator entry
    :param indicator_value: The indicator value
    :param indicator_type: The indicator type
    :param title: The title to show to the user
    :param client: The integration's client
    :return: The indicator entry
    """
    res: dict[str, Any] = client.get_indicator(indicator_value)
    resources: List[Any] = res.get('resources', [])
    results: List[CommandResults] = []

    if resources:
        for r in resources:
            if should_filter_resource_by_type(r, indicator_type, indicator_value):
                continue
            output = get_indicator_outputs(r)
            score = get_score_from_resource(r)
            dbot_score = Common.DBotScore(
                indicator=indicator_value,
                indicator_type=get_dbot_score_type(indicator_type),
                integration_name='CrowdStrike Falcon Intel v2',
                malicious_description='High confidence',
                score=score,
                reliability=client.reliability
            )
            indicator = get_indicator_object(indicator_value, indicator_type, dbot_score)
            results.append(CommandResults(
                outputs=output,
                outputs_prefix='FalconIntel.Indicator',
                outputs_key_field='ID',
                indicator=indicator,
                readable_output=tableToMarkdown(name=title, t=output, headerTransform=pascalToSpace),
                raw_response=res
            ))

    else:
        results.append(create_indicator_result_with_dbotscore_unknown(indicator=indicator_value,
                                                                      indicator_type=DBotScoreType.FILE
                                                                      if indicator_type == 'hash' else indicator_type))

    return results


def get_values(items_list: List[Any], return_type: str = 'str', keys: str | List[Any] = 'value') \
        -> str | List[str | dict]:
    """
    Returns the values of list's items
    :param items_list: The items list
    :param return_type: Whether to return string or list
    :param keys: The key to get the data
    :return: The values list
    """
    new_list: List[Any] = []
    if not items_list:
        return new_list
    if isinstance(keys, str):
        new_list = [item.get(keys) for item in items_list]
    elif isinstance(keys, list):
        new_list = [{underscoreToCamelCase(f): item.get(f) for f in item if f in keys} for item in items_list]
    if return_type == 'list':
        return new_list
    return ', '.join(str(item) for item in new_list)


def get_indicator_outputs(resource: dict[str, Any]) -> dict[str, Any]:
    """
    Build the output and extra context of an indicator
    :param resource: The indicator's object
    :return: The indicator's human readable
    """
    output: dict[str, Any] = {}

    if resource:
        indicator_id = resource.get('id')
        indicator_value = resource.get('indicator')
        indicator_type = resource.get('type')
        last_update = resource.get('last_update')
        publish_date = resource.get('publish_date')
        malicious_confidence = resource.get('malicious_confidence')
        reports = resource.get('reports')
        actors = resource.get('actors')
        malware_families = resource.get('malware_families')
        kill_chains = resource.get('kill_chains')
        domain_types = resource.get('domain_types')
        ip_address_types = resource.get('ip_address_types')
        relations: List[Any] = resource.get('relations', [])[:10]
        labels: List[Any] = resource.get('labels', [])[:10]

        output = assign_params(**{
            'ID': indicator_id,
            'Type': indicator_type,
            'Value': indicator_value,
            'LastUpdate': datetime.fromtimestamp(last_update, UTC).isoformat() if last_update
            else None,
            'PublishDate': datetime.fromtimestamp(publish_date, UTC).isoformat() if publish_date
            else None,
            'MaliciousConfidence': malicious_confidence,
            'Reports': reports,
            'Actors': actors,
            'MalwareFamilies': malware_families,
            'KillChains': kill_chains,
            'DomainTypes': domain_types,
            'IPAddressTypes': ip_address_types,
            'Relations': [f'{item.get("Type")}: {item.get("Indicator")}' for item in  # type: ignore
                          get_values(relations, return_type='list', keys=['indicator', 'type'])],
            'Labels': get_values(labels, return_type='list', keys='name')
        })

    return output


''' COMMANDS '''


def run_test_module(client: Client) -> str | Exception:
    """
    If a client is successfully constructed then an access token was successfully created,
    therefore the username and password are valid and a connection was made.
    On top of the above, this function validates the http request to indicators endpoint.
    :param client: the client object with an access token
    :return: ok if got a valid access token and not all the quota is used at the moment
    """
    client.cs_client.http_request('GET', 'intel/combined/indicators/v1', params={'limit': 1})
    return 'ok'


def file_command(files: List, client: Client) -> List[CommandResults]:
    results: List[CommandResults] = []
    for file in files:
        results += build_indicator(file, 'hash', 'Falcon Intel file reputation:\n', client)
    return results


def ip_command(ips: List, client: Client) -> List[CommandResults]:
    results: List[CommandResults] = []
    for ip in ips:
        results += build_indicator(ip, 'ip', 'Falcon Intel IP reputation:\n', client)
    return results


def url_command(urls: List, client: Client) -> List[CommandResults]:
    results: List[CommandResults] = []
    for url in urls:
        results += build_indicator(url, 'url', 'Falcon Intel URL reputation:\n', client)
    return results


def domain_command(domains: List, client: Client) -> List[CommandResults]:
    results: List[CommandResults] = []
    for domain in domains:
        results += build_indicator(domain, 'domain', 'Falcon Intel domain reputation:\n', client)
    return results


def cs_actors_command(client: Client, args: dict[str, str]) -> CommandResults:
    res: dict[str, Any] = client.cs_actors(args)
    resources: List[Any] = res.get('resources', [])
    outputs: List[dict[str, Any]] = []
    md_outputs: List[dict[str, Any]] = []
    md: str = ''
    title: str = 'Falcon Intel Actor search:'

    if resources:
        for r in resources:
            image_url = r.get('image', {}).get('url')
            name = r.get('name')
            actor_id = r.get('id')
            url = r.get('url')
            slug = r.get('slug')
            short_description = r.get('short_description')
            description = r.get('description')
            first_activity_date = r.get('first_activity_date')
            last_activity_date = r.get('last_activity_date')
            active = r.get('active')
            known_as = r.get('known_as')
            target_industries = r.get('target_industries') or []
            target_countries = r.get('target_countries') or []
            origins = r.get('origins') or []
            motivations = r.get('motivations') or []
            capability = r.get('capability', {}).get('value')
            group = r.get('group')
            region = r.get('region', {}).get('value')
            kill_chain = r.get('kill_chain')

            output: dict[str, Any] = assign_params(**{
                'ImageURL': image_url,
                'Name': name,
                'ID': actor_id,
                'URL': url,
                'Slug': slug,
                'ShortDescription': short_description,
                'Description': description,
                'FirstActivityDate': datetime.fromtimestamp(first_activity_date, UTC).isoformat()
                if first_activity_date else None,
                'LastActivityDate': datetime.fromtimestamp(last_activity_date, UTC).isoformat()
                if last_activity_date else None,
                'Active': active,
                'KnownAs': known_as,
                'TargetIndustries': get_values(target_industries, return_type='list'),
                'TargetCountries': get_values(target_countries, return_type='list'),
                'Origins': get_values(origins, return_type='list'),
                'Motivations': get_values(motivations, return_type='list'),
                'Capability': capability,
                'Group': group,
                'Region': region,
                'KillChains': kill_chain
            })
            outputs.append(output)

            md_output: dict[str, Any] = output
            for key in ('URL', 'ImageURL'):
                if key in md_output:
                    value = md_output[key]
                    md_output[key] = f'[{value}]({value})'

            md_outputs.append(md_output)
    else:
        md = 'No actors found.'

    results: CommandResults = CommandResults(
        outputs=outputs,
        outputs_key_field='ID',
        outputs_prefix='FalconIntel.Actor',
        readable_output=md if md else tableToMarkdown(name=title, t=md_outputs, headerTransform=pascalToSpace, removeNull=True),
        raw_response=res
    )

    return results


def cs_indicators_command(client: Client, args: dict[str, str]) -> List[CommandResults]:
    res: dict[str, Any] = client.cs_indicators(args)
    resources: List[Any] = res.get('resources', [])
    results: List[CommandResults] = []
    title: str = 'Falcon Intel Indicator search:'

    if resources:
        for r in resources:
            output = get_indicator_outputs(r)
            indicator_value = output.get('Value')
            indicator_type = output.get('Type')
            indicator: Optional[Common.Indicator] = None

            if indicator_type in ('hash_md5', 'hash_sha256', 'hash_sha1', 'ip_address', 'url', 'domain'):
                if indicator_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
                    indicator_type = 'hash'
                elif indicator_type == 'ip_address':
                    indicator_type = 'ip'
                score = get_score_from_resource(r)
                dbot_score = Common.DBotScore(
                    indicator=indicator_value,
                    indicator_type=get_dbot_score_type(indicator_type),
                    integration_name='CrowdStrike Falcon Intel v2',
                    malicious_description='High confidence',
                    score=score,
                    reliability=client.reliability
                )
                indicator = get_indicator_object(indicator_value, indicator_type, dbot_score)
            results.append(CommandResults(
                outputs=output,
                outputs_prefix='FalconIntel.Indicator',
                outputs_key_field='ID',
                readable_output=tableToMarkdown(name=title, t=output, headerTransform=pascalToSpace),
                raw_response=res,
                indicator=indicator
            ))
    else:
        results.append(CommandResults(
            readable_output='No indicators found.'
        ))

    return results


def cs_reports_command(client: Client, args: dict[str, str]) -> CommandResults:
    res: dict[str, Any] = client.cs_reports(args)
    resources: List[Any] = res.get('resources', [])
    outputs: List[dict[str, Any]] = []
    md_outputs: List[dict[str, Any]] = []
    md: str = ''
    title: str = 'Falcon Intel Report search:'

    if resources:
        for r in resources:
            report_id: int = r.get('id')
            url: str = r.get('url')
            name: str = r.get('name')
            report_type: str = r.get('type', {}).get('name')
            sub_type: str = r.get('sub_type', {}).get('name')
            slug: str = r.get('slug')
            created_date: int = r.get('created_date')
            last_modified_date: int = r.get('last_modified_date')
            short_description: str = r.get('short_description')
            description: str = r.get('description')
            target_industries: List[Any] = r.get('target_industries') or []
            target_countries: List[Any] = r.get('target_countries') or []
            motivations: List[Any] = r.get('motivations') or []
            tags: List[Any] = r.get('tags') or []
            actors: List[Any] = r.get('actors') or []

            output: dict[str, Any] = assign_params(**{
                'ID': report_id,
                'URL': url,
                'Name': name,
                'Type': report_type,
                'SubType': sub_type,
                'Slug': slug,
                'CreatedDate': datetime.fromtimestamp(created_date, UTC).isoformat()
                if created_date else None,
                'LastModifiedSate': datetime.fromtimestamp(last_modified_date, UTC).isoformat()
                if last_modified_date else None,
                'ShortDescription': short_description,
                'Description': description,
                'TargetIndustries': get_values(target_industries, return_type='list'),
                'TargetCountries': get_values(target_countries, return_type='list'),
                'Motivations': get_values(motivations, return_type='list'),
                'Tags': get_values(tags, return_type='list'),
                'Actors': get_values(actors, return_type='list', keys='name')
            })
            outputs.append(output)

            md_output: dict[str, Any] = output
            if 'URL' in md_output:
                value = md_output['URL']
                md_output['URL'] = f'[{value}]({value})'

            md_outputs.append(md_output)

    else:
        md = 'No reports found.'

    results: CommandResults = CommandResults(
        outputs_prefix='FalconIntel.Report',
        outputs=outputs,
        outputs_key_field='ID',
        readable_output=md if md else tableToMarkdown(name=title, t=outputs, headerTransform=pascalToSpace, removeNull=True),
        raw_response=res
    )

    return results


def main():
    params: dict[str, str] = demisto.params()

    reliability = params.get('integrationReliability', 'C - Fairly reliable')
    reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability) if \
        DBotScoreReliability.is_valid_type(reliability) else None

    args: dict[str, str] = demisto.args()
    results: CommandResults | List[CommandResults]
    try:
        command: str = demisto.command()
        LOG(f'Command being called in CrowdStrike Falcon Intel v2 is: {command}')
        client: Client = Client(params=params, reliability=reliability)
        if command == 'test-module':
            result: str | Exception = run_test_module(client)
            return_results(result)
        elif command == 'file':
            results = file_command(argToList(args['file']), client)
            return_results(results)
        elif command == 'ip':
            results = ip_command(argToList(args['ip']), client)
            return_results(results)
        elif command == 'url':
            results = url_command(argToList(args['url']), client)
            return_results(results)
        elif command == 'domain':
            results = domain_command(argToList(args['domain']), client)
            return_results(results)
        elif command == 'cs-actors':
            results = cs_actors_command(client, args)
            return_results(results)
        elif command == 'cs-indicators':
            results = cs_indicators_command(client, args)
            return_results(results)
        elif command == 'cs-reports':
            results = cs_reports_command(client, args)
            return_results(results)
        else:
            raise NotImplementedError(f'{command} command is not an existing CrowdStrike Falcon Intel v2 integration')
    except Exception as err:
        return_error(f'Unexpected error:\n{str(err)}', error=traceback.format_exc())


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
