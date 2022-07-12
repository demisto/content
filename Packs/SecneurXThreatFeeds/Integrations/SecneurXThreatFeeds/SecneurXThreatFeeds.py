import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
''' IMPORTS '''


import requests # noqa
import traceback # noqa
from typing import Dict, Any # noqa
from datetime import datetime, timedelta # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
SNX_ID_KEY = "id"
SNX_PATTERN_KEY = "pattern"
SNX_OBJECTS_KEY = "objects"
SNX_CREATED_KEY = "created"
SNX_MODIFIED_KEY = "modified"
SNX_DESCRIPTIONS_KEY = "description"
SNX_FEED_KEY = "SecneurX Threat Feeds"
DEMISO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


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
    result = getIndicatorsCommand(client, {'limit': 2})
    if type(result.raw_response) == list and len(result.raw_response) == 2:
        return 'ok'
    else:
        return result.raw_response


def parseIndicators(feedJson: Dict) -> Any:
    try:
        indicatorList = []
        if feedJson:
            if SNX_OBJECTS_KEY in feedJson.keys():
                jsonContent = feedJson[SNX_OBJECTS_KEY]
                for i in jsonContent:
                    try:
                        tagList = []
                        indicatorType = None
                        indicatorValue = None
                        indicatorIdValue = None
                        createdValue = None
                        modifiedValue = None
                        reportByValue = SNX_FEED_KEY
                        if SNX_ID_KEY in i.keys():
                            indicatorIdValue = i[SNX_ID_KEY]
                        if SNX_DESCRIPTIONS_KEY in i.keys():
                            tagsData = i[SNX_DESCRIPTIONS_KEY]
                            tagList = tagsData.split(',')
                        if SNX_PATTERN_KEY in i.keys():
                            indicatorType = i[SNX_PATTERN_KEY].split(':', 1)[0].replace('[', '')
                            if indicatorType == "domain-name":
                                indicatorType = "Domain"
                            elif indicatorType == 'url':
                                indicatorType = "URL"
                            elif indicatorType == "ip":
                                indicatorType = "IP"
                            else:
                                indicatorType = None
                            indicatorValue = i[SNX_PATTERN_KEY].split(':', 1)[1].split("=", 1)[1]
                            indicatorValue = indicatorValue.replace(" ", "").replace("'", "").replace(']', '')
                        if SNX_CREATED_KEY in i.keys():
                            timeData = i[SNX_CREATED_KEY]
                            createdValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        if SNX_MODIFIED_KEY in i.keys():
                            timeData = i[SNX_MODIFIED_KEY]
                            modifiedValue = datetime.strptime(timeData, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(DEMISO_DATE_FORMAT)
                        indicatorObj = {}
                        if indicatorValue is not None:
                            indicatorObj["value"] = indicatorValue
                        else:
                            continue
                        if indicatorType is not None:
                            indicatorObj["type"] = indicatorType
                        else:
                            continue
                        indicatorObj["rawJson"] = i
                        indicatorObj["fields"] = {
                            "firstseenbysource": createdValue,
                            "indicatoridentification": indicatorIdValue,
                            "verdict": "Malicious",
                            "tags": tagList,
                            "modified": modifiedValue,
                            "reportedby": reportByValue
                        }
                        indicatorList.append(indicatorObj)

                    except Exception as e:
                        demisto.error(e)

    except Exception as e:
        demisto.error(e)
    return indicatorList


def getIndicatorsCommand(client: Client, args: Dict[str, int]) -> CommandResults:
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
        result = None
        try:
            if err_msg.res.status_code == 403:
                result = 'Authorization Error: make sure API Key (or) Feed URL is correctly set'
            elif err_msg.res.status_code == 401:
                result = 'Authorization Error: API Key is expired'
            else:
                result = 'Configuration Error'
        except Exception:
            result = 'Endpoint Error: Invalid Feed URL'
        return CommandResults(outputs_prefix='', raw_response=result)


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
            for j in batch(indicatorList, batch_size=2000):
                if not test_case:
                    demisto.createIndicators(j)
        else:
            return False
    return True


def checkAllFieldsInList(indicatorList):
    indicatorKeyList = []
    indicatorValueList = []
    for i in indicatorList:
        try:
            if 'fields' in i.keys():
                fieldData = i['fields']
                if len(fieldData) > 0:
                    indicatorValueList.append(fieldData)
                indicatorKeyList.append('fields')
            if 'value' in i.keys():
                valueData = i['value']
                if len(valueData) > 0:
                    indicatorValueList.append(valueData)
                indicatorKeyList.append('value')
            if 'rawJson' in i.keys():
                rawData = i['rawJson']
                if len(rawData) > 0:
                    indicatorValueList.append(rawData)
                indicatorKeyList.append('rawJson')
            if 'type' in i.keys():
                typeData = i['type']
                if len(typeData) > 0:
                    indicatorValueList.append(typeData)
                indicatorKeyList.append('type')
        except Exception as e:
            demisto.error(e)
    return indicatorKeyList, indicatorValueList


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
