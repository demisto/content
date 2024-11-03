import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
''' IMPORTS '''


import requests  # noqa
import traceback  # noqa
from typing import Dict, Any  # noqa
from datetime import datetime, timedelta  # noqa
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member
DEMISO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


SNX_TYPES_TO_DEMISTO_TYPES = {
    'url:value': FeedIndicatorType.URL,
    'md5:value': FeedIndicatorType.File,
    'sha-1:value': FeedIndicatorType.File,
    'sha-256:value': FeedIndicatorType.File,
    'ipv4-addr:value': FeedIndicatorType.IP,
    'domain:value': FeedIndicatorType.Domain,
    'ipv6-addr:value': FeedIndicatorType.IPv6,
    'email-addr:value': FeedIndicatorType.Email,
    'domain-name:value': FeedIndicatorType.Domain,
    'file:hashes.MD5': FeedIndicatorType.File,
    'file:hashes.SHA256': FeedIndicatorType.File,
    'file:hashes.SHA1': FeedIndicatorType.File
}

STIX_INTEL_TYPE_TO_DEMISTO_TYPES = {
    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'report': ThreatIntel.ObjectsNames.REPORT,
    'malware': ThreatIntel.ObjectsNames.MALWARE,
    'course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'tool': ThreatIntel.ObjectsNames.TOOL,
    'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'infrastructure': ThreatIntel.ObjectsNames.INFRASTRUCTURE,
}

XSOAR_RELATIONSHIP_TYPES = EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()


class DemistoScore():
    UNKNOWN = 0
    BENIGN = 1
    SUSPICIOUS = 2
    MALICIOUS = 3


class SNXIocParse():
    SNX_ID_KEY = "id"
    SNX_URL_KEY = "URL"
    SNX_TYPE_KEY = "type"
    SNX_NAME_KEY = "name"
    SNX_VALUE_KEY = "value"
    SNX_BENIGN_TYPE = "benign"
    SNX_PATTERN_KEY = "pattern"
    SNX_OBJECTS_KEY = "objects"
    SNX_CREATED_KEY = "created"
    SNX_MALWARE_KEY = "malware"
    SNX_UNKNOWN_TYPE = "unknown"
    SNX_MODIFIED_KEY = "modified"
    SNX_INDICATOR_KEY = "indicator"
    SNX_INDICATES_KEY = "indicates"
    SNX_SOURCE_REF_KEY = "source_ref"
    SNX_TARGET_REF_KEY = "target_ref"
    SNX_CONFIDENCE_KEY = "confidence"
    SNX_EXTERNAL_ID_KEY = "external_id"
    SNX_VALID_UNTIL_KEY = "valid_until"
    SNX_FILE_MD5_KEY = "file:hashes.MD5"
    SNX_ONION_ADDR_KEY = "Onion address"
    SNX_DESCRIPTIONS_KEY = "description"
    SNX_RELATIONSHIP_KEY = "relationship"
    SNX_MALWARE_TYPE_KEY = "malware_types"
    SNX_FEED_KEY = "SecneurX Threat Feeds"
    SNX_RELATIONSHIPS_KEY = "relationships"
    SNX_ATTACK_PATTERN_KEY = "attack-pattern"
    SNX_INDICATORS_TYPE_KEY = "indicator_types"
    SNX_EXTERNAL_REF_KEY = "external_references"
    DEMISTO_ONION_ADDRESS_TYPE = "Onion Address"
    SNX_RELATIONSHIP_TYPE_KEY = "relationship_type"
    SNX_MALICIOUS_LIST = ["malicious-activity", "compromised"]
    SNX_SUSPICIOUS_LIST = ["anomalous-activity", "anonymization"]


class Client(BaseClient):
    """Implements class for SecneurX Threat Feeds."""

    def get_feeds(self, feed_date: Optional[str] = None):
        try:
            params = {}
            if feed_date:
                params = {'date': feed_date}
            return self._http_request(
                method='GET',
                url_suffix="/getfeeds",
                params=params,
                timeout=90,
            ), None

        except Exception as e:
            return None, e


def test_module(client: Client) -> Any:
    getIndicatorsCommand(client, {'limit': 2})
    return 'ok'


def parseIndicators(feedJson: dict) -> Any:
    try:
        indicatorList = []
        if feedJson:
            jsonContent = feedJson[SNXIocParse.SNX_OBJECTS_KEY]
            relationship_iocs = []
            ioc_contents = {}
            for ioc_data in jsonContent:
                try:
                    tagList = []
                    mitreIdValue = None
                    createdValue = None
                    modifiedValue = None
                    indicatorType = None
                    indicatorValue = None
                    confidenceValue = None
                    expirationValue = None
                    indicatorIdValue = None
                    descriptionValue = None
                    reportByValue = SNXIocParse.SNX_FEED_KEY
                    verdictScore = DemistoScore.MALICIOUS
                    if ioc_data[SNXIocParse.SNX_TYPE_KEY] == SNXIocParse.SNX_INDICATOR_KEY:
                        if SNXIocParse.SNX_ID_KEY in ioc_data.keys():
                            indicatorIdValue = ioc_data[SNXIocParse.SNX_ID_KEY]
                        if SNXIocParse.SNX_PATTERN_KEY in ioc_data.keys():
                            patternKey, patternValue = parse_ioc_values(ioc_data)
                            if patternKey and patternValue:
                                indicatorType = patternKey
                                indicatorValue = patternValue
                            else:
                                continue
                        if SNXIocParse.SNX_CREATED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_CREATED_KEY]
                            createdValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_MODIFIED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_MODIFIED_KEY]
                            modifiedValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_DESCRIPTIONS_KEY in ioc_data.keys():
                            tagsInfo = ioc_data[SNXIocParse.SNX_DESCRIPTIONS_KEY]
                            tagList = tagsInfo.split(",")
                        if SNXIocParse.SNX_CONFIDENCE_KEY in ioc_data.keys():
                            confidenceValue = ioc_data[SNXIocParse.SNX_CONFIDENCE_KEY]
                        if SNXIocParse.SNX_VALID_UNTIL_KEY in ioc_data.keys():
                            expirationValue = ioc_data[SNXIocParse.SNX_VALID_UNTIL_KEY]
                        if SNXIocParse.SNX_INDICATORS_TYPE_KEY in ioc_data.keys():
                            verdictInfo = ioc_data[SNXIocParse.SNX_INDICATORS_TYPE_KEY]
                            if len(verdictInfo) >= 1:
                                verdictInfo = verdictInfo[0]
                                if verdictInfo.lower() in SNXIocParse.SNX_MALICIOUS_LIST:
                                    verdictScore = DemistoScore.MALICIOUS
                                elif verdictInfo.lower() in SNXIocParse.SNX_SUSPICIOUS_LIST:
                                    verdictScore = DemistoScore.SUSPICIOUS
                                elif verdictInfo.lower() == SNXIocParse.SNX_BENIGN_TYPE:
                                    verdictScore = DemistoScore.BENIGN
                                elif verdictInfo.lower() == SNXIocParse.SNX_UNKNOWN_TYPE:
                                    verdictScore = DemistoScore.UNKNOWN
                                else:
                                    verdictScore = DemistoScore.MALICIOUS
                        if indicatorType == SNXIocParse.SNX_URL_KEY:
                            if SNXIocParse.SNX_ONION_ADDR_KEY in tagList:
                                indicatorType = SNXIocParse.DEMISTO_ONION_ADDRESS_TYPE
                        ioc_contents[indicatorIdValue] = {
                            "type": indicatorType,
                            "value": indicatorValue
                        }

                    elif ioc_data[SNXIocParse.SNX_TYPE_KEY] == SNXIocParse.SNX_MALWARE_KEY:
                        indicatorType = STIX_INTEL_TYPE_TO_DEMISTO_TYPES[SNXIocParse.SNX_MALWARE_KEY]
                        if SNXIocParse.SNX_ID_KEY in ioc_data.keys():
                            indicatorIdValue = ioc_data[SNXIocParse.SNX_ID_KEY]
                        if SNXIocParse.SNX_NAME_KEY in ioc_data.keys():
                            indicatorValue = ioc_data[SNXIocParse.SNX_NAME_KEY]
                        if SNXIocParse.SNX_CREATED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_CREATED_KEY]
                            createdValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_MODIFIED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_MODIFIED_KEY]
                            modifiedValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_MALWARE_TYPE_KEY in ioc_data.keys():
                            tagList = ioc_data[SNXIocParse.SNX_MALWARE_TYPE_KEY]
                            if SNXIocParse.SNX_UNKNOWN_TYPE in tagList:
                                tagList.clear()
                                tagList.append(indicatorValue)
                        if SNXIocParse.SNX_DESCRIPTIONS_KEY in ioc_data.keys():
                            descriptionValue = ioc_data[SNXIocParse.SNX_DESCRIPTIONS_KEY]
                        verdictScore = ThreatIntel.ObjectsScore.MALWARE
                        ioc_contents[indicatorIdValue] = {
                            "type": indicatorType,
                            "value": indicatorValue
                        }

                    elif ioc_data[SNXIocParse.SNX_TYPE_KEY] == SNXIocParse.SNX_RELATIONSHIP_KEY:
                        relationship_iocs.append(ioc_data)

                    elif ioc_data[SNXIocParse.SNX_TYPE_KEY] == SNXIocParse.SNX_ATTACK_PATTERN_KEY:
                        indicatorType = STIX_INTEL_TYPE_TO_DEMISTO_TYPES[SNXIocParse.SNX_ATTACK_PATTERN_KEY]
                        if SNXIocParse.SNX_ID_KEY in ioc_data.keys():
                            indicatorIdValue = ioc_data[SNXIocParse.SNX_ID_KEY]
                        if SNXIocParse.SNX_NAME_KEY in ioc_data.keys():
                            indicatorValue = ioc_data[SNXIocParse.SNX_NAME_KEY]
                        if SNXIocParse.SNX_CREATED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_CREATED_KEY]
                            createdValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_MODIFIED_KEY in ioc_data.keys():
                            timeData = ioc_data[SNXIocParse.SNX_MODIFIED_KEY]
                            modifiedValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNXIocParse.SNX_DESCRIPTIONS_KEY in ioc_data.keys():
                            descriptionValue = ioc_data[SNXIocParse.SNX_DESCRIPTIONS_KEY]
                        if SNXIocParse.SNX_EXTERNAL_REF_KEY in ioc_data.keys():
                            externalRefList = ioc_data[SNXIocParse.SNX_EXTERNAL_REF_KEY]
                            for externalRef in externalRefList:
                                if SNXIocParse.SNX_EXTERNAL_ID_KEY in externalRef.keys():
                                    mitreIdValue = externalRef[SNXIocParse.SNX_EXTERNAL_ID_KEY]
                                    tagList = mitreIdValue
                        verdictScore = ThreatIntel.ObjectsScore.ATTACK_PATTERN
                        ioc_contents[indicatorIdValue] = {
                            "type": indicatorType,
                            "value": indicatorValue
                        }

                    else:
                        continue

                    indicatorObj = {}
                    if indicatorValue is not None:
                        indicatorObj["value"] = indicatorValue
                    else:
                        continue
                    if indicatorType is not None:
                        indicatorObj["type"] = indicatorType
                    else:
                        continue
                    indicatorObj["score"] = verdictScore
                    indicatorObj["rawJson"] = ioc_data
                    indicatorObj["fields"] = {}
                    if len(tagList) >= 1:
                        indicatorObj["fields"]["tags"] = tagList
                    if indicatorIdValue is not None:
                        indicatorObj["fields"]["stixid"] = indicatorIdValue
                        indicatorObj["fields"]["indicatoridentification"] = indicatorIdValue
                    if createdValue is not None:
                        indicatorObj["fields"]["firstseenbysource"] = createdValue
                    if modifiedValue is not None:
                        indicatorObj["fields"]["modified"] = modifiedValue
                    if expirationValue is not None:
                        indicatorObj["fields"]["expiration_date"] = expirationValue
                    if confidenceValue is not None:
                        indicatorObj["fields"]["confidence"] = confidenceValue
                    if descriptionValue is not None:
                        indicatorObj["fields"]["description"] = descriptionValue
                    if mitreIdValue is not None:
                        indicatorObj["fields"]["mitreid"] = mitreIdValue
                    indicatorObj["fields"]["reportedby"] = reportByValue
                    indicatorList.append(indicatorObj)

                except Exception as e:
                    raise DemistoException(e)
            if relationship_iocs:
                indicatorList.append(parse_ioc_relationships(relationship_iocs, ioc_contents))

    except Exception as e:
        raise DemistoException(e)
    return indicatorList


def parse_ioc_values(ioc_data):
    try:
        patternInfo = ioc_data[SNXIocParse.SNX_PATTERN_KEY]
        patternInfo = patternInfo.replace('[', '')
        patternData = patternInfo.replace(']', '')
        patternKey = patternData.split("=")[0].strip()
        patternValue = patternData.split("=")[1].replace("'", '').strip()
        ioc_type = None
        if patternKey == SNXIocParse.SNX_FILE_MD5_KEY:
            ioc_type = patternKey
        else:
            ioc_type = patternKey.lower()
        if ioc_type in SNX_TYPES_TO_DEMISTO_TYPES:
            patternKey = SNX_TYPES_TO_DEMISTO_TYPES[ioc_type]
            return patternKey, patternValue
        else:
            return None, None

    except Exception as e:
        raise DemistoException(e)


def parse_ioc_relationships(relationshipIocs, ioc_contents):
    dummy_indicator: dict[str, Any] = {}
    relationships_list = []
    try:
        for relation_obj in relationshipIocs:
            try:
                sourceRefIoc = None
                targetRefIoc = None
                sourceRefIocType = None
                targetRefIocType = None
                relationshipType = None
                reverseRelationshipType = None
                if SNXIocParse.SNX_RELATIONSHIP_TYPE_KEY in relation_obj.keys():
                    iocRelationType = relation_obj[SNXIocParse.SNX_RELATIONSHIP_TYPE_KEY]
                    if iocRelationType.lower() == SNXIocParse.SNX_INDICATES_KEY:
                        relationshipType = EntityRelationship.Relationships.INDICATOR_OF
                        reverseRelationshipType = "indicated-by"
                    else:
                        demisto.debug(f"Invalid relation type: {relationshipType}")
                        continue

                if SNXIocParse.SNX_SOURCE_REF_KEY in relation_obj.keys():
                    try:
                        sourceRefId = relation_obj[SNXIocParse.SNX_SOURCE_REF_KEY]
                        sourceRefIocType = ioc_contents[sourceRefId]["type"]
                        sourceRefIoc = ioc_contents[sourceRefId]["value"]
                    except Exception:
                        continue

                if SNXIocParse.SNX_TARGET_REF_KEY in relation_obj.keys():
                    try:
                        targetRefId = relation_obj[SNXIocParse.SNX_TARGET_REF_KEY]
                        targetRefIocType = ioc_contents[targetRefId]["type"]
                        targetRefIoc = ioc_contents[targetRefId]["value"]
                    except Exception:
                        continue

                if not sourceRefIocType or not targetRefIocType:
                    continue
                attackPatternType = STIX_INTEL_TYPE_TO_DEMISTO_TYPES[SNXIocParse.SNX_ATTACK_PATTERN_KEY]
                if sourceRefIocType == attackPatternType or targetRefIocType == attackPatternType:
                    relationshipType = EntityRelationship.Relationships.USES
                    reverseRelationshipType = "used-by"
                timelineFields = {
                    'lastseenbysource': relation_obj[SNXIocParse.SNX_MODIFIED_KEY],
                    'firstseenbysource': relation_obj[SNXIocParse.SNX_CREATED_KEY]
                }
                entityRelation = EntityRelationship(
                    name=relationshipType,
                    entity_a=sourceRefIoc,
                    entity_a_type=sourceRefIocType,
                    entity_b=targetRefIoc,
                    entity_b_type=targetRefIocType,
                    fields=timelineFields,
                    reverse_name=reverseRelationshipType
                )
                relationships_list.append(entityRelation.to_indicator())

            except Exception as e:
                raise DemistoException(e)

        if relationships_list:
            dummy_indicator[SNXIocParse.SNX_VALUE_KEY] = "$$DummyIndicator$$"
            dummy_indicator[SNXIocParse.SNX_RELATIONSHIPS_KEY] = relationships_list

    except Exception as e:
        raise DemistoException(e)
    return dummy_indicator


def getIndicatorsCommand(client: Client, args: dict[str, int]) -> CommandResults:
    count = arg_to_number(args.get('limit')) or 2
    feedJson, err_msg = client.get_feeds(None)
    if feedJson:
        indicatorList = parseIndicators(feedJson)
        finalIndicatorList = indicatorList[:count]
        readableOutput = tableToMarkdown('SecneurX Threat Feeds Indicators: ',
                                         t=finalIndicatorList, headers=['type', 'value', 'fields'])
        command_result = CommandResults(
            outputs_prefix='',
            outputs_key_field='',
            outputs={},
            readable_output=readableOutput,
            raw_response=finalIndicatorList
        )
        return command_result
    else:
        msg = None
        try:
            if err_msg.res.status_code == 403:
                msg = 'Authorization Error: make sure API Key (or) Feed URL is correctly set'
            elif err_msg.res.status_code == 401:
                msg = 'Authorization Error: API Key is expired'
            else:
                msg = 'Configuration Error'
        except Exception:
            msg = 'Endpoint Error: Invalid Feed URL'
        raise DemistoException(msg)


def fetchThreatFeeds(client: Client, feed_date: Optional[str] = None) -> Any:
    feedJson, err_msg = client.get_feeds(feed_date)
    if feedJson:
        indicators = parseIndicators(feedJson)
        return indicators
    else:
        return None


def getListOfDays(startDate, endDate) -> List:
    daysList = []
    try:
        daysData = endDate - startDate
        daysCount = daysData.days
        if daysCount == 0:
            daysList.append(endDate.strftime('%Y%m%d'))
            return daysList
        else:
            for i in range(daysCount):
                day = startDate + timedelta(days=1)
                daysList.append(day.strftime('%Y%m%d'))
                startDate = day

    except Exception as e:
        demisto.error(e)
    return daysList


def fetchFeedDates(firstFetchDate, firstFetchValue):
    startDate = None
    endDate = None
    if not firstFetchDate:
        startDateValue, endDateValue = parse_date_range(firstFetchValue)
        startDate = startDateValue.date()
        endDate = endDateValue.date()
    else:
        startDate = datetime.strptime(firstFetchDate, '%Y-%m-%d')
        startDate = startDate.date()
        endDate = datetime.now().date()
    return startDate, endDate


def createIndicatorsInDemisto(client: Client, dateList, test_case):
    for i in dateList:
        indicatorList = fetchThreatFeeds(client, i)
        if indicatorList and len(indicatorList) > 0:
            if not test_case:
                demisto.createIndicators(indicatorList)
        else:
            return False
    return True


def main():
    api_key = demisto.params().get("apikey")
    base_url = urljoin(demisto.params().get("url"), "/API/v1")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {"x-api-key": f'{api_key}'}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        firstFetchDate = None
        firstFetchValue = demisto.params().get('first_fetch')
        integrationCache = demisto.getIntegrationContext()
        if 'first_fetch_date' in integrationCache.keys():
            firstFetchDate = integrationCache.get('first_fetch_date')

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'snxfeeds-get-indicators':
            return_results(getIndicatorsCommand(client, demisto.args()))

        elif demisto.command() == 'fetch-indicators':
            startDate, endDate = fetchFeedDates(firstFetchDate, firstFetchValue)
            dateList = getListOfDays(startDate, endDate)
            bRet = createIndicatorsInDemisto(client, dateList, False)
            if bRet is True:
                demisto.info("Successfully created the indicators")
                endDateFormat = endDate.strftime('%Y-%m-%d')
                demisto.setIntegrationContext({'first_fetch_date': str(endDateFormat)})
            else:
                raise DemistoException("Cannot create the indicators in demisto")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
