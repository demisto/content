from CommonServerPython import *
import traceback

POPULATE_INDICATOR_FIELDS = ["value", "indicator_type", "applications", "user", "firstSeen",
                             "expiration", "lastSeen", "score", "title", "description"]

INDICATOR_FIELDS_TO_MS_DEFENDER_IOC = {
    "value": "indicatorValue",
    "indicator_type": "indicatorType",
    "applications": "application",
    "user": "createdBy",
    "firstSeen": "creationTimeDateTimeUtc",
    "expiration": "expirationTime",
    "lastSeen": "lastUpdateTime",
    "score": "Severity",
    "title": "title",
    "description": "description",
    # enter (hard-coded) your wanted indicator arguments per MS docs (make sure to remove the '#'):
    # {https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator?view=o365-worldwide} ##
    # "" : "externalID",
    # "" : "sourceType",
    # "" : "lastUpdatedBy",
    # "" : "recommendedActions",
    # "" : "rbacGroupNames",
    # "" : "rbacGroupIds",
    # "" : "generateAlert",
    # "" : "createdBySource",
}

# feel free to change it hard-coded.
# Possible values in MS Defender are: Informational, Low, Medium and High
DBOT_SCORE_TO_MS_DEFENDER_SEVERITY = {
    Common.DBotScore.BAD: "High",
    Common.DBotScore.SUSPICIOUS: "Medium",
    Common.DBotScore.GOOD: "Informational",
    Common.DBotScore.NONE: "Informational",
}


def convert_unique_fields(ioc, action):
    ioc['Severity'] = DBOT_SCORE_TO_MS_DEFENDER_SEVERITY[ioc.get('Severity')]  # XSOAR indicators always have score
    if ioc.get('indicatorType'):
        indicator_type = ioc.get('indicatorType')
        indicator_value = ioc.get('indicatorValue', "")
        if indicator_type == 'File':
            hash_type = get_hash_type(indicator_value)
            if hash_type == 'md5':
                ioc["indicatorType"] = "FileMd5"
            elif hash_type == 'sha1':
                ioc["indicatorType"] = "FileSha1"
            if hash_type == 'sha256':
                ioc["indicatorType"] = "FileSha256"
        elif indicator_type == "IP":
            ioc["indicatorType"] = "IpAddress"
        elif indicator_type == "DOMAIN":
            ioc["indicatorType"] = "DomainName"
        elif indicator_type == "URL":
            ioc["indicatorType"] = "Url"
        else:
            raise DemistoException(f"The indicator type: {indicator_type} does not exist in MS Defender")
    # if you want to map the action field, you can do it here.
    # Note: the action arg is mandatory with MS Defender api
    # Possible values are: "Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate" and "Allowed".
    ioc['action'] = action
    # Note: the title arg is mandatory with MS Defender api, please change it
    if not ioc.get('title'):
        ioc['title'] = "XSOAR Indicator title"
    # Note: the description arg is mandatory with MS Defender api, please change it
    if not ioc.get('description'):
        ioc['description'] = "XSOAR Indicator description"
    return ioc


def get_indicators_by_query():
    action = demisto.args().pop('action')
    demisto.args().update({'populateFields': POPULATE_INDICATOR_FIELDS})
    indicators = execute_command('GetIndicatorsByQuery', args=demisto.args())
    ms_defender_iocs = []
    if indicators:
        for indicator in indicators:
            # convert XSOAR indicator to MS Defender IOC
            ms_defender_ioc = {INDICATOR_FIELDS_TO_MS_DEFENDER_IOC[indicator_field]: indicator_value for
                               (indicator_field, indicator_value) in indicator.items()}
            ms_defender_ioc = convert_unique_fields(ms_defender_ioc, action)
            ms_defender_iocs.append(ms_defender_ioc)
    return ms_defender_iocs


def main():
    try:
        ms_defender_iocs = get_indicators_by_query()
        human_readable = tableToMarkdown('TransformIndicatorToMSDefenderIOC id done:',
                                         ms_defender_iocs, removeNull=True,
                                         headers=list(INDICATOR_FIELDS_TO_MS_DEFENDER_IOC.values()))
        context = {
            'TransformIndicatorToMSDefenderIOC.JsonOutput': json.dumps(ms_defender_iocs),
            'TransformIndicatorToMSDefenderIOC.Indicators': ms_defender_iocs,
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': ms_defender_iocs,
            'EntryContext': context,
            'HumanReadable': human_readable,
        })

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute TransformIndicatorToMSDefenderIOC. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
