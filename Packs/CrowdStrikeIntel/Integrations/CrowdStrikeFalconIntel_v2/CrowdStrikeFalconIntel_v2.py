import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from datetime import datetime, timezone
from typing import Union, Any, Tuple, Dict
from dateparser import parse

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''

MALICIOUS_DICTIONARY: Dict[Any, int] = {
    'low': Common.DBotScore.GOOD,
    'medium': Common.DBotScore.SUSPICIOUS,
    'high': Common.DBotScore.BAD
}

MALICIOUS_THRESHOLD = MALICIOUS_DICTIONARY.get(demisto.params().get('threshold', 'high'))

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'

''' CLIENT '''


class Client:
    """
    The integration's client
    """

    def __init__(self, params: Dict[str, str]):
        self._cs_client: CrowdStrikeClient = CrowdStrikeClient(params=params)
        self.query_params: List[str] = ['offset', 'limit', 'sort', 'q']
        self.date_params: Dict[str, Dict[str, str]] = {
            'created_date': {'operator': '', 'api_key': 'created_date'},
            'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
            'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
            'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'}
        }

    def build_request_params(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the params dict for the request
        :param args: Cortex XSOAR args
        :return: The params dict
        """
        params: Dict[str, Any] = {key: args.get(key) for key in self.query_params}
        query = args.get('query')
        params['filter'] = query if query else self.build_filter_query(args)
        return assign_params(**params)

    def build_filter_query(self, args: Dict[str, str]) -> str:
        """
        Builds the filter query in Falcon Query Language (FQL)
        :param args: Cortex XSOAR args
        :return: The query
        """
        filter_query: str = str()

        for key in args:
            if key not in self.query_params:
                if key not in self.date_params:
                    values: List[str] = argToList(args[key], ',')
                    for value in values:
                        filter_query += f"{key}:'{value}'+"
                else:
                    operator: Optional[str] = self.date_params.get(key, {}).get('operator')
                    api_key: Optional[str] = self.date_params.get(key, {}).get('api_key')
                    filter_query += f"{api_key}:{operator}{int(parse(args[key]).timestamp())}+"

        if filter_query.endswith('+'):
            filter_query = filter_query[:-1]

        return filter_query

    def check_quota_status(self) -> Dict[str, Any]:
        return self._cs_client.check_quota_status()

    def get_indicator(self, indicator_value: str, indicator_type: str) -> Dict[str, Any]:
        args: Dict[str, Any] = {
            'indicator': indicator_value,
            'limit': 1
        }
        if indicator_type == 'hash':
            args['type'] = get_indicator_hash_type(indicator_value)
        elif indicator_type == 'ip':
            args['type'] = 'ip_address'
        else:
            args['type'] = indicator_type

        params: Dict[str, Any] = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/indicators/v1', params=params)

    def cs_actors(self, args: Dict[str, str]) -> Dict[str, Any]:
        params: Dict[str, Any] = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/actors/v1', params=params)

    def cs_indicators(self, args: Dict[str, str]) -> Dict[str, Any]:
        params: Dict[str, Any] = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/indicators/v1', params=params)

    def cs_reports(self, args: Dict[str, str]) -> Dict[str, Any]:
        params: Dict[str, Any] = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/reports/v1', params=params)


''' HELPER FUNCTIONS '''


def get_score_from_resource(r: Dict[str, Any]) -> int:
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


def get_indicator_hash_type(indicator_value: str) -> Union[str, Exception]:
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


def get_indicator_object(indicator_value: Any, indicator_type: str, dbot_score: Common.DBotScore,
                         extra_context: Dict[str, Any] = None) -> Union[Common.IP, Common.URL, Common.File,
                                                                        Common.Domain, None]:
    """
    Returns the corresponding indicator common object
    :param indicator_value: The indicator value
    :param indicator_type: The indicator value
    :param dbot_score: The indicator DBotScore
    :param extra_context: Extra fields of the indicator to add to context
    :return: The indicator common object
    """
    if indicator_type == 'ip':
        return Common.IP(
            ip=indicator_value,
            dbot_score=dbot_score,
            extra_context_fields=extra_context
        )
    elif indicator_type == 'url':
        return Common.URL(
            url=indicator_value,
            dbot_score=dbot_score,
            extra_context_fields=extra_context
        )
    elif indicator_type == 'hash':
        hash_type: Union[str, Exception] = get_indicator_hash_type(indicator_value)
        if hash_type == 'hash_md5':
            return Common.File(
                md5=indicator_value,
                dbot_score=dbot_score,
                extra_context_fields=extra_context
            )
        elif hash_type == 'hash_sha1':
            return Common.File(
                sha1=indicator_value,
                dbot_score=dbot_score,
                extra_context_fields=extra_context
            )
        else:
            return Common.File(
                sha256=indicator_value,
                dbot_score=dbot_score,
                extra_context_fields=extra_context
            )
    elif indicator_type == 'domain':
        return Common.Domain(
            domain=indicator_value,
            dbot_score=dbot_score,
            extra_context_fields=extra_context
        )
    else:
        return None


def build_indicator(indicator_value: str, indicator_type: str, title: str, client: Client) -> CommandResults:
    """
    Builds an indicator entry
    :param indicator_value: The indicator value
    :param indicator_type: The indicator type
    :param title: The title to show to the user
    :param client: The integration's client
    :return: The indicator entry
    """
    res: Dict[str, Any] = client.get_indicator(indicator_value, indicator_type)
    resources: List[Any] = res.get('resources', [])
    indicators: List[Union[Common.IP, Common.URL, Common.File, Common.Domain, None]] = list()
    outputs: List[Dict[str, Any]] = list()
    md: str = str()

    if resources:
        for r in resources:
            output, indicator_extra_context = get_indicator_data(r)
            outputs.append(output)
            score = get_score_from_resource(r)
            dbot_score = Common.DBotScore(
                indicator=indicator_value,
                indicator_type=DBotScoreType.get_dbot_score_type(indicator_type),
                integration_name='FalconIntel',
                malicious_description='High confidence',
                score=score
            )
            indicator = get_indicator_object(indicator_value, indicator_type, dbot_score, indicator_extra_context)
            indicators.append(indicator)
    else:
        md = 'No indicator found.'

    results: CommandResults = CommandResults(
        outputs=outputs,
        outputs_prefix='FalconIntel.Indicator',
        outputs_key_field='ID',
        indicators=indicators,
        readable_output=md if md else f"{tableToMarkdown(name=title, t=outputs, headerTransform=pascalToSpace)}",
        raw_response=res
    )

    return results


def get_values(items_list: List[Any], return_type: str = 'str', keys: Union[str, List[Any]] = 'value') \
        -> Union[str, List[Union[str, Dict]]]:
    """
    Returns the values of list's items
    :param items_list: The items list
    :param return_type: Whether to return string or list
    :param keys: The key to get the data
    :return: The values list
    """
    new_list: List[Any] = list()
    if isinstance(keys, str):
        new_list = [item.get(keys) for item in items_list]
    elif isinstance(keys, list):
        new_list = [{underscoreToCamelCase(f): item.get(f) for f in item if f in keys} for item in items_list]
    if return_type == 'list':
        return new_list
    return ', '.join(str(item) for item in new_list)


def get_indicator_data(o: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Build the output and extra context of an indicator
    :param o: The indicator's object
    :return: The indicator's human readable
    """
    output: Dict[str, Any] = dict()
    indicator_context_fields: Dict[str, Any] = dict()

    if o:
        indicator_id = o.get('id')
        indicator_value = o.get('indicator')
        indicator_type = o.get('type')
        last_update = o.get('last_update')
        publish_date = o.get('publish_date')
        malicious_confidence = o.get('malicious_confidence')
        reports = o.get('reports')
        actors = o.get('actors')
        malware_families = o.get('malware_families')
        kill_chains = o.get('kill_chains')
        domain_types = o.get('domain_types')
        ip_address_types = o.get('ip_address_types')
        relations: List[Any] = o.get('relations', [])[:10]
        labels: List[Any] = o.get('labels', [])[:10]

        output = assign_params(**{
            'ID': indicator_id,
            'Type': indicator_type,
            'Value': indicator_value,
            'LastUpdate': datetime.fromtimestamp(last_update, timezone.utc).strftime(DATE_FORMAT) if last_update
            else None,
            'PublishDate': datetime.fromtimestamp(publish_date, timezone.utc).strftime(DATE_FORMAT) if publish_date
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

        indicator_context_fields = assign_params(**{
            'Reports': reports,
            'Actors': actors,
            'MalwareFamilies': malware_families,
            'KillChains': kill_chains
        })

    return output, indicator_context_fields


''' COMMANDS '''


def test_module(client: Client) -> Union[str, Exception]:
    """
    If a client is successfully constructed then an accesses token was successfully reached,
    therefore the username and password are valid and a connection was made.
    Additionally, checks if not using all the optional quota and check that an http request to actors & indicators
    endpoints in successful.
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    output: Dict[str, Any] = client.check_quota_status()

    error = output.get('errors')
    if error and isinstance(error, list):
        return error[0]

    meta = output.get('meta')
    if meta is not None and isinstance(meta, dict):
        quota = meta.get('quota')
        if quota is not None:
            total = quota.get('total')
            used = quota.get('used')
            if total <= used:
                raise Exception(f'Quota limitation has been reached: {used}')
            else:
                client._cs_client.http_request('GET', 'intel/combined/indicators/v1', params={'limit': 1})
                client._cs_client.http_request('GET', 'intel/combined/actors/v1', params={'limit': 1})
                return 'ok'
    raise Exception('Quota limitation is unreachable')


def file_command(file: str, client: Client) -> CommandResults:
    return build_indicator(file, 'hash', 'Falcon Intel file reputation:\n', client)


def ip_command(ip: str, client: Client) -> CommandResults:
    return build_indicator(ip, 'ip', 'Falcon Intel IP reputation:\n', client)


def url_command(url: str, client: Client) -> CommandResults:
    return build_indicator(url, 'url', 'Falcon Intel URL reputation:\n', client)


def domain_command(domain: str, client: Client) -> CommandResults:
    return build_indicator(domain, 'domain', 'Falcon Intel domain reputation:\n', client)


def cs_actors_command(client: Client, args: Dict[str, str]) -> CommandResults:
    res: Dict[str, Any] = client.cs_actors(args)
    resources: List[Any] = res.get('resources', [])
    outputs: List[Dict[str, Any]] = list()
    md: str = str()
    title: str = 'Falcon Intel Actor search:'

    if resources:
        for r in resources:
            image_url = r.get('image', {}).get('url')
            name = r.get('name')
            actor_id = r.get('id')
            url = r.get('url')
            slug = r.get('slug')
            short_description = r.get('short_description')
            first_activity_date = r.get('first_activity_date')
            last_activity_date = r.get('last_activity_date')
            active = r.get('active')
            known_as = r.get('known_as')
            target_industries = r.get('target_industries', [])
            target_countries = r.get('target_countries', [])
            origins = r.get('origins', [])
            motivations = r.get('motivations', [])
            capability = r.get('capability', {}).get('value')
            group = r.get('group')
            region = r.get('region', {}).get('value')
            kill_chain = r.get('kill_chain')

            output: Dict[str, Any] = assign_params(**{
                'ImageURL': image_url,
                'Name': name,
                'ID': actor_id,
                'URL': url,
                'Slug': slug,
                'ShortDescription': short_description,
                'FirstActivityDate': datetime.fromtimestamp(first_activity_date, timezone.utc).strftime(DATE_FORMAT)
                if first_activity_date else None,
                'LastActivityDate': datetime.fromtimestamp(last_activity_date, timezone.utc).strftime(DATE_FORMAT)
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
    else:
        md = 'No actors found.'

    results: CommandResults = CommandResults(
        outputs=outputs,
        outputs_key_field='ID',
        outputs_prefix='FalconIntel.Actor',
        readable_output=md if md else tableToMarkdown(name=title, t=outputs, headerTransform=pascalToSpace),
        raw_response=res
    )

    return results


def cs_indicators_command(client: Client, args: Dict[str, str]) -> CommandResults:
    res: Dict[str, Any] = client.cs_indicators(args)
    resources: List[Any] = res.get('resources', [])
    indicators: List[Union[Common.IP, Common.URL, Common.File, Common.Domain, None]] = list()
    outputs: List[Dict[str, Any]] = list()
    md: str = str()
    title: str = 'Falcon Intel Indicator search:'

    if resources:
        for r in resources:
            output, indicator_extra_context = get_indicator_data(r)
            indicator_value = output.get('Value')
            outputs.append(output)
            indicator_type = output.get('Type')

            if indicator_type in ('hash_md5', 'hash_sha256', 'hash_sha1', 'ip_address', 'url', 'domain'):
                if indicator_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
                    indicator_type = 'hash'
                elif indicator_type == 'ip_address':
                    indicator_type = 'ip'
                score = get_score_from_resource(r)
                dbot_score = Common.DBotScore(
                    indicator=indicator_value,
                    indicator_type=DBotScoreType.get_dbot_score_type(indicator_type),
                    integration_name='FalconIntel',
                    malicious_description='High confidence',
                    score=score
                )
                indicator = get_indicator_object(indicator_value, indicator_type, dbot_score, indicator_extra_context)
                indicators.append(indicator)
    else:
        md = 'No indicators found.'

    results: CommandResults = CommandResults(
        outputs=outputs,
        outputs_prefix='FalconIntel.Indicator',
        outputs_key_field='ID',
        readable_output=md if md else f"{tableToMarkdown(name=title, t=outputs, headerTransform=pascalToSpace)}",
        raw_response=res,
        indicators=indicators
    )

    return results


def cs_reports_command(client: Client, args: Dict[str, str]) -> CommandResults:
    res: Dict[str, Any] = client.cs_reports(args)
    resources: List[Any] = res.get('resources', [])
    outputs: List[Dict[str, Any]] = list()
    md: str = str()
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
            target_industries: List[Any] = r.get('target_industries', [])
            target_countries: List[Any] = r.get('target_countries', [])
            motivations: List[Any] = r.get('motivations', [])
            tags: List[Any] = r.get('tags', [])

            output: Dict[str, Any] = assign_params(**{
                'ID': report_id,
                'URL': url,
                'Name': name,
                'Type': report_type,
                'SubType': sub_type,
                'Slug': slug,
                'CreatedDate': datetime.fromtimestamp(created_date, timezone.utc).strftime(DATE_FORMAT)
                if created_date else None,
                'LastModifiedSate': datetime.fromtimestamp(last_modified_date, timezone.utc).strftime(DATE_FORMAT)
                if last_modified_date else None,
                'ShortDescription': short_description,
                'TargetIndustries': get_values(target_industries, return_type='list'),
                'TargetCountries': get_values(target_countries, return_type='list'),
                'Motivations': get_values(motivations, return_type='list'),
                'Tags': get_values(tags, return_type='list')
            })
            outputs.append(output)
    else:
        md = 'No reports found.'

    results: CommandResults = CommandResults(
        outputs_prefix='FalconIntel.Report',
        outputs=outputs,
        outputs_key_field='ID',
        readable_output=md if md else tableToMarkdown(name=title, t=outputs, headerTransform=pascalToSpace),
        raw_response=res
    )

    return results


def main():
    params: Dict[str, str] = demisto.params()
    args: Dict[str, str] = demisto.args()
    try:
        command: str = demisto.command()
        LOG(f'Command being called in CrowdStrike Falcon Intel v2 is: {command}')
        client: Client = Client(params=params)
        if command == 'test-module':
            result: Union[str, Exception] = test_module(client)
            return_results(result)
        elif command == 'file':
            results: CommandResults = file_command(args['file'], client)
            return_results(results)
        elif command == 'ip':
            results = ip_command(args['ip'], client)
            return_results(results)
        elif command == 'url':
            results = url_command(args['url'], client)
            return_results(results)
        elif command == 'domain':
            results = domain_command(args['domain'], client)
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

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
