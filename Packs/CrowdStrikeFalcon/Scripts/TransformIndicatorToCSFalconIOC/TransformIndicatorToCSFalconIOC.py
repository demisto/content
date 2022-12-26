from CommonServerPython import *

# Feel free to change it hard-coded
IOC_SOURCE = 'Cortex XSOAR'
IOC_DESCRIPTION = ''

POPULATE_INDICATOR_FIELDS = ['value', 'expiration', 'score', 'description', 'tags', 'indicator_type']

INDICATOR_FIELDS_TO_CS_FALCON_IOC = {
    'value': 'value',
    'expiration': 'expiration',
    'score': 'severity',
    'description': 'description',
    'tags': 'tags',
    'indicator_type': 'type',
}

# Feel free to change it hard-coded.
# Possible values in CS Falcon are: Informational, Low, Medium, High and Critical

DBOT_SCORE_TO_CS_FALCON_SEVERITY = {
    Common.DBotScore.BAD: 'High',
    Common.DBotScore.SUSPICIOUS: 'Medium',
    Common.DBotScore.GOOD: 'Informational',
    Common.DBotScore.NONE: 'Informational',
}


def convert_unique_fields(ioc: dict, action: str, host_groups: list, platforms: list, applied_globally: bool):
    # XSOAR indicators always have score
    ioc['severity'] = DBOT_SCORE_TO_CS_FALCON_SEVERITY[
        ioc.get('severity')]    # type: ignore

    if ioc.get('type'):
        indicator_type = ioc.get('type')
        indicator_value = ioc.get('value', '')
        if indicator_type == 'File':
            hash_type = get_hash_type(indicator_value)
            if hash_type == 'md5':
                ioc['type'] = 'md5'
            elif hash_type == 'sha256':
                ioc['type'] = 'sha256'
        elif indicator_type == 'IP':
            ip_type = FeedIndicatorType.ip_to_indicator_type(indicator_value)
            if ip_type == 'IP':
                ioc['type'] = 'ipv4'
            elif ip_type == 'IPv6':
                ioc['type'] = 'ipv6'
        elif indicator_type == 'Domain':
            ioc['type'] = 'domain'
        else:
            raise DemistoException(f'The indicator type: {indicator_type} does not exist in CS Falcon')
    # If you want to map the action field, you can do it here.
    # Note: The action arg is mandatory with CS Falcon api
    # Possible values are: 'no_action', 'allow', 'detect', 'prevent_no_ui', and 'prevent'.
    ioc['action'] = action
    # Note: The platforms arg is mandatory with CS Falcon api
    if not platforms:
        raise ValueError('Platform is required.')
    ioc['platforms'] = platforms

    ioc['source'] = IOC_SOURCE

    if host_groups:
        ioc['host_groups'] = host_groups
    if applied_globally:
        ioc['applied_globally'] = applied_globally
    if not ioc.get('description', '') and IOC_DESCRIPTION:
        ioc['description'] = IOC_DESCRIPTION

    return ioc


def get_indicators_by_query():
    action = demisto.args().pop('action')
    platforms = argToList(demisto.args().pop('platforms'))
    host_groups = argToList(demisto.args().pop('host_groups')) if demisto.args().get('host_groups') else []
    applied_globally = argToBoolean(demisto.args().pop('applied_globally'))
    demisto.args().update({'populateFields': POPULATE_INDICATOR_FIELDS})
    indicators = execute_command('GetIndicatorsByQuery', args=demisto.args())
    cs_falcon_iocs = []
    if indicators:
        for indicator in indicators:
            # convert XSOAR indicator to CS Falcon IOC
            cs_falcon_ioc = {INDICATOR_FIELDS_TO_CS_FALCON_IOC[indicator_field]: indicator_value for
                             (indicator_field, indicator_value) in indicator.items()}
            cs_falcon_ioc = convert_unique_fields(cs_falcon_ioc, action, host_groups, platforms, applied_globally)
            cs_falcon_iocs.append(cs_falcon_ioc)
    return cs_falcon_iocs


def main():
    try:
        cs_falcon_iocs = get_indicators_by_query()
        human_readable = tableToMarkdown('TransformIndicatorToCSFalconIOC is done:',
                                         cs_falcon_iocs, removeNull=True,
                                         headers=list(INDICATOR_FIELDS_TO_CS_FALCON_IOC.values()))
        context = {
            'TransformIndicatorToCSFalconIOC.JsonOutput': json.dumps(cs_falcon_iocs),
            'TransformIndicatorToCSFalconIOC.Indicators': cs_falcon_iocs,
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': cs_falcon_iocs,
            'EntryContext': context,
            'HumanReadable': human_readable,
        })

    except Exception as ex:
        return_error(f'Failed to execute TransformIndicatorToCSFalconIOC. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
