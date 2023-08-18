import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

POPULATE_INDICATOR_FIELDS = ['indicator_type', 'value', 'id']
INDICATOR_TYPES = ['Domain', 'Email', 'File MD', 'IP', 'IPv6', 'IPv6CIDR', 'URL']

''' STANDALONE FUNCTION '''


def execute_get_indicators_by_query(query: str, indicators_types: dict) -> list:
    """
    Executes GetIndicatorsByQuery and returns a list of indicators.
    Args:
        query: a query from the user.
        indicators_types: A dict of in indicators types.
    Returns:
        A list of indicators.
    """
    indicator_list = []
    res = demisto.executeCommand('GetIndicatorsByQuery', args={'populateFields': POPULATE_INDICATOR_FIELDS, 'query': query})
    indicators = res[0]['Contents']
    for indicator in indicators:
        indicator_type = indicator.get('indicator_type')
        indicator_value = indicator.get('value')
        if indicator_type in INDICATOR_TYPES:
            indicator_list.append({'value': indicator_value,
                                   'itype': indicators_types.get('ip') if indicator_type.lower() in {'ip', 'ipv6', 'ipv6cidr'}
                                   else indicators_types.get(indicator_type.lower())})
    return indicator_list


def validate_indicators(email_list: list, md5_list: list, ip_list: list, url_list: list, domain_list: list) -> None:
    """
    Validates users indicators input.
    Args:
        email_list: A list of emails.
        md5_list: A list of md5s.
        ip_list: A list of IPs.
        url_list: A list of URLs.
        domain_list: A list of domains.
    """
    invalid_indicators = []
    for email in email_list:
        if not re.match(emailRegex, email):
            invalid_indicators.append(email)
    for md5 in md5_list:
        if not re.match(md5Regex, md5):
            invalid_indicators.append(md5)
    for ip in ip_list:
        if FeedIndicatorType.ip_to_indicator_type(ip) is None:
            invalid_indicators.append(ip)
    for url in url_list:
        if not re.match(urlRegex, url):
            invalid_indicators.append(url)
    for domain in domain_list:
        if not re.match(domainRegex, domain):
            invalid_indicators.append(domain)
    if len(invalid_indicators) > 0:
        raise DemistoException(f'Invalid indicators values: {", ".join(map(str,invalid_indicators))}')


def get_indicators_from_user(args: dict, indicators_types: dict) -> list:
    """
    Validate and returns a list of indicators from user args.
    Args:
        args: Arguments provided by user.
        indicators_types: A dict of in indicators types.
    Returns:
        A list of indicators.
    """
    indicator_list: list[dict] = []
    indicators = {'email_list': argToList(args.get('email_values', [])),
                  'md5_list': argToList(args.get('md5_values', [])),
                  'ip_list': argToList(args.get('ip_values', [])), 'url_list': argToList(args.get('url_values', [])),
                  'domain_list': argToList(args.get('domain_values', []))}
    validate_indicators(**indicators)
    for indicator_list_name, indicators_list in indicators.items():
        indicator_type = indicator_list_name.split("_")[0]
        indicator_list.extend(
            {
                'value': indicator_value,
                'itype': indicators_types.get(indicator_type),
            }
            for indicator_value in indicators_list
        )
    return indicator_list


def get_indicators_and_build_json(args: dict) -> CommandResults:
    """
    Gets a list of indicators and builds JSON.
    Args:
        args: Arguments provided by user.
    Returns:
        A CommandResults object with the relevant JSON.
    """
    list_indicators = []
    indicators_types = {'email': args.get('email_indicator_type', 'mal_email'),
                        'md5': args.get('md5_indicator_type', 'mal_md5'),
                        'ip': args.get('ip_indicator_type', 'mal_ip'),
                        'url': args.get('url_indicator_type', 'mal_url'),
                        'domain': args.get('domain_indicator_type', 'mal_domain')}
    if indicator_query := args.get('indicator_query'):
        list_indicators = execute_get_indicators_by_query(indicator_query, indicators_types)
    else:
        list_indicators = get_indicators_from_user(args, indicators_types)
    outputs = str({'objects': list_indicators})
    return CommandResults(outputs_key_field='ThreatstreamBuildIocImportJson',
                          outputs={'ThreatstreamBuildIocImportJson': outputs},
                          readable_output=outputs)


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        return_results(get_indicators_and_build_json(args))
    except Exception as ex:
        return_error(f'Failed to execute ThreatstreamBuildIocImportJson. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
