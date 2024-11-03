import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from collections import OrderedDict  # noqa

import json  # noqa
import traceback  # noqa
from typing import Dict, Any  # noqa


# Disable insecure warnings
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

SNX_IOC_TYPES_TO_DEMISTO_TYPES = {
    'url': FeedIndicatorType.URL,
    'md5': FeedIndicatorType.File,
    'sha-1': FeedIndicatorType.File,
    'sha-256': FeedIndicatorType.File,
    'ipv4-addr': FeedIndicatorType.IP,
    'domain': FeedIndicatorType.Domain,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'email-addr': FeedIndicatorType.Email,
    'domain-name': FeedIndicatorType.Domain,
    'file:hashes.MD5': FeedIndicatorType.File
}

SNX_VERDICT_TO_DBOTSCORE = {
    'No Threats': Common.DBotScore.GOOD,
    'Suspicious': Common.DBotScore.SUSPICIOUS,
    'Malware': Common.DBotScore.BAD,
    'Ransomware': Common.DBotScore.BAD
}


class Client(BaseClient):
    """Implement class for SecneurX Analysis sandbox"""

    def get_response(self, urlSuffix: str, paramsDict: dict[str, str]):
        try:
            if urlSuffix == '/get_report':
                respType = 'text'
            else:
                respType = 'json'
            return self._http_request(
                method="GET",
                url_suffix=urlSuffix,
                params=paramsDict,
                resp_type=respType,
                timeout=90
            ), None

        except Exception as e:
            return None, e

    def submit_file(self, urlSuffix: str, fileData: dict[str, Any], paramsDict: dict[str, str]):
        try:
            return self._http_request(
                method="POST",
                url_suffix=urlSuffix,
                files=fileData,
                params=paramsDict,
                timeout=90
            ), None

        except Exception as e:
            return None, e

    def submit_url(self, urlSuffix: str, paramsDict: dict[str, str], urlParams: dict[str, str]):
        try:
            return self._http_request(
                method="POST",
                url_suffix=urlSuffix,
                data=urlParams,
                params=paramsDict,
                timeout=90
            ), None

        except Exception as e:
            return None, e


class SNXReportParser():
    JSON_URL = "url"
    JSON_IOC = "IOC"
    JSON_KEY = "key"
    JSON_DATA = "data"
    JSON_TYPE = "type"
    JSON_VALUE = "value"
    JSON_OBJECTS = "objects"
    JSON_PATTERN = "pattern"
    JSON_PLATFORM = "platform"
    JSON_HOSTNAME = "hostname"
    JSON_DNS_REQ = "dnsLookups"
    JSON_TAGS = "ArtifactsTags"
    JSON_FILE_SHA256 = "sha256"
    JSON_JA3_LIST = "ja3Digests"
    JSON_METHOD = "requestMethod"
    JSON_RESOLVEDIPS = "resolvedIps"
    JSON_VERDICTS = "ArtifactsVerdict"
    JSON_FILE_WRITTEN = "filesWritten"
    JSON_FILE_DROPPED = "filesDropped"
    JSON_FILE_DELETED = "filesDeleted"
    JSON_FILE_MODIFIED = "fileModified"
    JSON_HTTP_REQ = "httpConversations"
    JSON_ANALYSIS_TIME = "completedTime"
    JSON_REGISTRY_SET = "registryKeysSet"
    JSON_SHA256 = "analysisSubjectSha256"
    JSON_STATUS_CODE = "responseStatusCode"
    JSON_PROCESS_CREATED = "processesCreated"
    JSON_REGISTRY_DELETED = "registryKeysDeleted"
    SNX_SUBMISSION_NAME_KEY = "analysisSubjectName"
    SNX_SUBMISSION_TYPE_KEY = "analysisSubjectType"


class JsonTableParser():
    SNX_URL = "URL"
    SNX_TAGS = "Tags"
    SNX_SHA256 = "SHA256"
    SNX_METHOD = "Method"
    SNX_VERDICT = "Verdict"
    SNX_DNS_REQ = "DNSRequests"
    SNX_JA3_LIST = "JA3Digests"
    SNX_PLATFORM_KEY = "Platform"
    SNX_HTTP_REQ = "HTTPRequests"
    SNX_STATUS_CODE = "StatusCode"
    SNX_REGISTRY_SET = "RegistrySet"
    SNX_FILE_WRITTEN = "FileCreated"
    SNX_FILE_DROPPED = "FileDropped"
    SNX_FILE_DELETED = "FileDeleted"
    SNX_FILE_MODIFIED = "FileModified"
    SNX_ANALYSIS_TIME = "SubmissionTime"
    SNX_PROCESS_CREATED = "ProcessCreated"
    SNX_REGISTRY_DELETED = "RegistryDeleted"


class SNXResponse():
    FAILED = 0
    SUCCESS = 1
    SNX_URL_KEY = "url"
    SNX_MSG_KEY = "msg"
    SNX_IOC_KEY = "IOC"
    SNX_FILE_KEY = "file"
    SNX_NULL_KEY = "NULL"
    SAMPLE_KEY = "Sample"
    POLLING_KEY = "polling"
    TIMEOUT_KEY = "timeout"
    SNX_RESULT_KEY = "data"
    INTERVAL_KEY = "interval"
    SNX_SHA256_KEY = "sha256"
    SNX_FAILED_KEY = "Failed"
    SNX_STATUS_KEY = "status"
    SNX_MALWARE_KEY = "Malware"
    SNX_VERDICT_KEY = "verdict"
    SNX_SUCCESS_KEY = "success"
    SNX_REBOOT_KEY = "reboot_on"
    SNX_WINDOWS_KEY = "Windows7"
    SNX_PLATFORM_KEY = "platform"
    SNX_PRIORITY_KEY = "priority"
    SNX_DURATION_KEY = "duration"
    SNX_FILENAME_KEY = "file_name"
    SNX_ERROR_MSG_KEY = "error_msg"
    SNX_TASK_UUID_KEY = "task_uuid"
    SNX_COMPLETED_KEY = "Completed"
    SNX_EXTENSTION_KEY = "extension"
    SNX_LAST_HOURS_KEY = "last_hours"
    SNX_LAST_COUNT_KEY = "last_count"
    SNX_PROVIDER = "SecneurX Analysis"
    SNX_REPORT_KEY = "report_available"
    SNX_REPORT_FORMAT_KEY = "report_format"
    SNX_FILE_PWD_KEY = "compressed_password"


class SNXErrorMsg():
    SUCCESS_MSG = "ok"
    CONFIG_ERR = "Configuration Error"
    INVALID_ERR = "Endpoint Error: Invalid Server URL"
    FAILED_ERR = "Submit Error: Sample submittion failed"
    AUTH_ERR = "Authorization Error: make sure API Key is correctly set"
    SERVER_ERR = "Endpoint Error: Invalid Server URL (or) Invalid input parameters values"
    NOT_FOUND_ERR = "Report could not be generated"


def test_module(client: Client) -> Any:
    get_status_cmd(client, {SNXResponse.SNX_LAST_COUNT_KEY: '2'})
    return SNXErrorMsg.SUCCESS_MSG


def create_request_json(argsDict: dict[str, str]) -> dict:
    params = {}
    try:
        if SNXResponse.SNX_TASK_UUID_KEY in argsDict:
            params[SNXResponse.SNX_TASK_UUID_KEY] = argsDict.get(SNXResponse.SNX_TASK_UUID_KEY)
        if SNXResponse.SNX_LAST_COUNT_KEY in argsDict:
            params[SNXResponse.SNX_LAST_COUNT_KEY] = argsDict.get(SNXResponse.SNX_LAST_COUNT_KEY)
        if SNXResponse.SNX_LAST_HOURS_KEY in argsDict:
            params[SNXResponse.SNX_LAST_HOURS_KEY] = argsDict.get(SNXResponse.SNX_LAST_HOURS_KEY)
        if "Platform" in argsDict:
            platformValue = argsDict.get("Platform")
            params[SNXResponse.SNX_PLATFORM_KEY] = str(platformValue)
        if "Priority" in argsDict:
            priorityValue = argsDict.get("Priority")
            params[SNXResponse.SNX_PRIORITY_KEY] = str(priorityValue)
        if "Extension" in argsDict:
            extnValue = argsDict.get("Extension")
            if extnValue is not None and len(extnValue) != 0:
                params[SNXResponse.SNX_EXTENSTION_KEY] = argsDict.get("Extension")
        if "Duration" in argsDict:
            durationValue = argsDict.get("Duration")
            if durationValue is not None and len(durationValue) != 0:
                params[SNXResponse.SNX_DURATION_KEY] = argsDict.get("Duration")
        if "File Password" in argsDict:
            pwdValue = argsDict.get("File Password")
            if pwdValue is not None and len(pwdValue) != 0:
                params[SNXResponse.SNX_FILE_PWD_KEY] = pwdValue
        if "Reboot" in argsDict:
            params[SNXResponse.SNX_REBOOT_KEY] = argsDict.get("Reboot")
        if SNXResponse.SNX_REPORT_FORMAT_KEY in argsDict:
            params[SNXResponse.SNX_REPORT_FORMAT_KEY] = argsDict.get(SNXResponse.SNX_REPORT_FORMAT_KEY)

    except Exception as e:
        demisto.error(e)
    return params


def error_response(err_msg) -> str:
    msg = None
    try:
        if err_msg.res.status_code == 401:
            msg = SNXErrorMsg.AUTH_ERR
        elif err_msg.res.status_code == 400:
            msg = SNXErrorMsg.SERVER_ERR
        elif err_msg.res.status_code == 404:
            msg = SNXErrorMsg.NOT_FOUND_ERR
        elif err_msg.res.status_code == 500:
            msg = SNXErrorMsg.FAILED_ERR
        else:
            msg = SNXErrorMsg.CONFIG_ERR
    except Exception:
        msg = SNXErrorMsg.INVALID_ERR
    return msg


def parse_response(response):
    try:
        jsonContent = OrderedDict()
        if SNXReportParser.JSON_SHA256 in response.keys():
            jsonContent[JsonTableParser.SNX_SHA256] = response[SNXReportParser.JSON_SHA256]
        if SNXReportParser.JSON_PLATFORM in response.keys():
            jsonContent[JsonTableParser.SNX_PLATFORM_KEY] = response[SNXReportParser.JSON_PLATFORM]
        if SNXReportParser.JSON_ANALYSIS_TIME in response.keys():
            jsonContent[JsonTableParser.SNX_ANALYSIS_TIME] = response[SNXReportParser.JSON_ANALYSIS_TIME]
        if SNXReportParser.JSON_VERDICTS in response.keys():
            verdictResult = None
            verdictValue = response[SNXReportParser.JSON_VERDICTS]
            verdictResult = verdictValue.lower().capitalize()
            jsonContent[JsonTableParser.SNX_VERDICT] = verdictResult
        if SNXReportParser.JSON_TAGS in response.keys():
            jsonContent[JsonTableParser.SNX_TAGS] = response[SNXReportParser.JSON_TAGS]
        if SNXReportParser.JSON_DNS_REQ in response.keys():
            dnsList = []
            for dnsData in response[SNXReportParser.JSON_DNS_REQ]:
                dnsReq = []
                if SNXReportParser.JSON_HOSTNAME in dnsData.keys():
                    dnsReq.append(dnsData[SNXReportParser.JSON_HOSTNAME])
                if SNXReportParser.JSON_RESOLVEDIPS in dnsData.keys():
                    dnsReq.append(dnsData[SNXReportParser.JSON_RESOLVEDIPS])
                data = formatCell(dnsReq)
                dnsList.append(data)
            if dnsList:
                jsonContent[JsonTableParser.SNX_DNS_REQ] = dnsList
        if SNXReportParser.JSON_HTTP_REQ in response.keys():
            httpList = []
            split_line = ""
            for httpData in response[SNXReportParser.JSON_HTTP_REQ]:
                methodValue = None
                requestValue = None
                statusCodeValue = None
                if SNXReportParser.JSON_METHOD in httpData.keys():
                    methodValue = httpData[SNXReportParser.JSON_METHOD]
                if SNXReportParser.JSON_URL in httpData.keys():
                    requestValue = httpData[SNXReportParser.JSON_URL]
                if SNXReportParser.JSON_STATUS_CODE in httpData.keys():
                    statusCodeValue = httpData[SNXReportParser.JSON_STATUS_CODE]
                if methodValue and requestValue and statusCodeValue:
                    httpList.append(f"{split_line}[" + methodValue + "] "
                                    + requestValue + " [Status : " + str(statusCodeValue) + "]")
                    split_line = '\n'
            if httpList:
                jsonContent[JsonTableParser.SNX_HTTP_REQ] = httpList
        if SNXReportParser.JSON_JA3_LIST in response.keys():
            jsonContent[JsonTableParser.SNX_JA3_LIST] = response[SNXReportParser.JSON_JA3_LIST]
        if SNXReportParser.JSON_PROCESS_CREATED in response.keys():
            creationList = convert_json_to_str(response[SNXReportParser.JSON_PROCESS_CREATED])
            jsonContent[JsonTableParser.SNX_PROCESS_CREATED] = creationList
        if SNXReportParser.JSON_REGISTRY_SET in response.keys():
            registrySetList = []
            split_line = ""
            for registry_data in response[SNXReportParser.JSON_REGISTRY_SET]:
                keyData = registry_data[SNXReportParser.JSON_KEY]
                registrySetList.append(f"{split_line}" + keyData)
                split_line = "\n"
            if registrySetList:
                jsonContent[JsonTableParser.SNX_REGISTRY_SET] = registrySetList
        if SNXReportParser.JSON_REGISTRY_DELETED in response.keys():
            jsonContent[JsonTableParser.SNX_REGISTRY_DELETED] = response[SNXReportParser.JSON_REGISTRY_DELETED]
        if SNXReportParser.JSON_FILE_WRITTEN in response.keys():
            fileCreatedList = convert_json_to_str(response[SNXReportParser.JSON_FILE_WRITTEN])
            jsonContent[JsonTableParser.SNX_FILE_WRITTEN] = fileCreatedList
        if SNXReportParser.JSON_FILE_DROPPED in response.keys():
            file_drop_list = []
            for file_drop in response[SNXReportParser.JSON_FILE_DROPPED]:
                sha256Value = file_drop[SNXReportParser.JSON_FILE_SHA256]
                typeValue = file_drop[SNXReportParser.JSON_TYPE]
                file_drop_list.append(typeValue + " : " + sha256Value)
            if file_drop_list:
                jsonContent[JsonTableParser.SNX_FILE_DROPPED] = file_drop_list
        if SNXReportParser.JSON_FILE_DELETED in response.keys():
            fileDeletedList = convert_json_to_str(response[SNXReportParser.JSON_FILE_DELETED])
            jsonContent[JsonTableParser.SNX_FILE_DELETED] = fileDeletedList
        if SNXReportParser.JSON_FILE_MODIFIED in response.keys():
            fileModifiedList = convert_json_to_str(response[SNXReportParser.JSON_FILE_MODIFIED])
            jsonContent[JsonTableParser.SNX_FILE_MODIFIED] = fileModifiedList
        if SNXReportParser.JSON_IOC in response.keys() and SNXReportParser.JSON_DATA in response[SNXReportParser.JSON_IOC].keys():
            iocList = parse_report_iocs(response[SNXReportParser.JSON_IOC][SNXReportParser.JSON_DATA])
            jsonContent[SNXResponse.SNX_IOC_KEY] = iocList
        return jsonContent

    except Exception as e:
        raise DemistoException(e)


def convert_json_to_str(data_list):
    formated_list = []
    try:
        split_line = ''
        for data in data_list:
            formatValue = json.dumps(data)
            formatValue = formatValue.rstrip('"').lstrip('"')
            formated_list.append(f"{split_line}" + formatValue)
            split_line = "\n"
    except Exception as e:
        raise DemistoException(e)
    return formated_list


def parse_report_iocs(ioc_json):
    parsed_ioc_list = []
    try:
        if SNXReportParser.JSON_OBJECTS in ioc_json.keys():
            ioc_list = ioc_json[SNXReportParser.JSON_OBJECTS]
            for ioc_data in ioc_list:
                if SNXReportParser.JSON_PATTERN in ioc_data.keys():
                    patternData = ioc_data[SNXReportParser.JSON_PATTERN]
                    patternData = patternData.replace('[', '').replace(']', '')
                    patternKey = patternData.split(":")[0]
                    patternValue = patternData.split(" = ")[1].replace("'", '')
                    if patternKey.lower() in SNX_IOC_TYPES_TO_DEMISTO_TYPES:
                        patternKey = SNX_IOC_TYPES_TO_DEMISTO_TYPES[patternKey]
                    parsed_ioc_list.append(patternKey + " : " + str(patternValue))

    except Exception as e:
        raise DemistoException(e)
    return parsed_ioc_list


def format_report_contents(contents):
    try:
        def dict_to_string(nested_dict):
            return json.dumps(nested_dict).lstrip('{').rstrip('}').replace('\'', '').replace('\"', '')

        table_contents = OrderedDict()
        for key, val in contents.items():
            if isinstance(val, dict):
                table_contents[key] = dict_to_string(val)
            elif isinstance(val, list):
                table_values = []
                for item in val:
                    if isinstance(item, dict):
                        table_values.append(dict_to_string(item))
                    else:
                        table_values.append(item)
                table_contents[key] = table_values
            else:
                table_contents[key] = val
        return table_contents
    except Exception as e:
        raise DemistoException(e)


def parse_dbot_score(reportJson):
    dbotScore = None
    try:
        if reportJson:
            submissionType = reportJson.get(SNXReportParser.SNX_SUBMISSION_TYPE_KEY, None)
            verdictValue = reportJson.get(SNXReportParser.JSON_VERDICTS, None)
            verdictScore = 0
            if verdictValue is not None and verdictValue in SNX_VERDICT_TO_DBOTSCORE:
                verdictScore = SNX_VERDICT_TO_DBOTSCORE[verdictValue]
            if submissionType == SNXResponse.SNX_FILE_KEY:
                indicatorValue = reportJson.get(SNXReportParser.JSON_SHA256, None)
                if indicatorValue:
                    dbotScore = Common.DBotScore(
                        indicator=indicatorValue,
                        indicator_type=DBotScoreType.FILE,
                        score=verdictScore,
                        integration_name=SNXResponse.SNX_PROVIDER
                    )
            else:
                indicatorValue = reportJson.get(SNXReportParser.SNX_SUBMISSION_NAME_KEY, None)
                if indicatorValue:
                    dbotScore = Common.DBotScore(
                        indicator=indicatorValue,
                        indicator_type=DBotScoreType.URL,
                        score=verdictScore,
                        integration_name=SNXResponse.SNX_PROVIDER
                    )

    except Exception as e:
        raise DemistoException(e)
    return dbotScore


def parse_report_entity(reportJson):
    dbot_score = parse_dbot_score(reportJson)
    indicator = None
    try:
        if reportJson and dbot_score:
            submissionType = reportJson.get(SNXReportParser.SNX_SUBMISSION_TYPE_KEY, None)
            verdictValue = reportJson.get(SNXReportParser.JSON_VERDICTS, None)
            tagList = reportJson.get(SNXReportParser.JSON_TAGS, verdictValue)
            sha256Value = reportJson.get(SNXReportParser.JSON_SHA256, None)
            subjectName = reportJson.get(SNXReportParser.SNX_SUBMISSION_NAME_KEY, None)
            if subjectName:
                if submissionType == SNXResponse.SNX_FILE_KEY:
                    indicator = Common.File(
                        name=subjectName,
                        dbot_score=dbot_score,
                        sha256=sha256Value,
                        tags=tagList,
                        description=verdictValue
                    )
                elif submissionType == SNXResponse.SNX_URL_KEY:
                    indicator = Common.URL(
                        url=subjectName,
                        dbot_score=dbot_score,
                        tags=tagList,
                        description=verdictValue
                    )  # type: ignore

    except Exception as e:
        raise DemistoException(e)
    return indicator


def post_submit_file(client: Client, args: dict[str, str]) -> CommandResults:
    urlSuffix = "/submit_file"
    entryId = args.get('EntryID') or None
    if entryId is None:
        raise DemistoException("Entry ID Not Found")
    platformValue = args.get('platform') or SNXResponse.SNX_WINDOWS_KEY
    params = create_request_json(args)
    if 'platform' not in params.keys():
        params['platform'] = platformValue
    fileEntry = demisto.getFilePath(entryId)
    fileName = fileEntry['name']
    filePath = fileEntry['path']
    fileData = {'file': (fileName, open(filePath, 'rb'))}
    response, err_msg = client.submit_file(urlSuffix, fileData, params)
    if response:
        if SNXResponse.SNX_SUCCESS_KEY in response.keys() and SNXResponse.SNX_RESULT_KEY in response.keys():
            finalJson = response[SNXResponse.SNX_RESULT_KEY]
            readableOutput = tableToMarkdown(f"File Submitted Successfully: {fileName}", finalJson)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.SubmitFile",
                outputs=finalJson
            )
        else:
            readableOutput = tableToMarkdown(f"File Submission Failed: {fileName}", response)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.SubmitFile",
                outputs=response
            )
    else:
        msg = error_response(err_msg)
        outputJson = {SNXResponse.SNX_ERROR_MSG_KEY: msg}
        readableOutput = tableToMarkdown(f"File Submission Failed: {fileName}", t=outputJson)
        return CommandResults(readable_output=readableOutput, outputs_prefix="SecneurXAnalysis.SubmitFile", outputs=outputJson)


def post_submit_url(client: Client, args: dict[str, str]) -> CommandResults:
    urlSuffix = "/analyze_url"
    urlValue = args.get("URL") or None
    if urlValue is None or len(urlValue) == 0:
        raise DemistoException("Input url value is empty")
    params = create_request_json(args)
    urlParams = {SNXReportParser.JSON_URL: urlValue}
    response, err_msg = client.submit_url(urlSuffix, params, urlParams)
    if response:
        if SNXResponse.SNX_SUCCESS_KEY in response.keys() and SNXResponse.SNX_RESULT_KEY in response.keys():
            finalJson = response[SNXResponse.SNX_RESULT_KEY]
            readableOutput = tableToMarkdown("URL Submitted Successfuly", finalJson)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.SubmitURL",
                outputs=finalJson
            )
        else:
            readableOutput = tableToMarkdown("URL Submission Failed", response)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.SubmitURL",
                outputs=response
            )
    else:
        msg = error_response(err_msg)
        outputJson = {SNXResponse.SNX_ERROR_MSG_KEY: msg}
        readableOutput = tableToMarkdown("URL Submission Failed", t=outputJson)
        return CommandResults(readable_output=readableOutput, outputs_prefix="SecneurXAnalysis.SubmitURL", outputs=outputJson)


def get_verdict_cmd(client: Client, args: dict[str, str]) -> CommandResults:
    taskUuid = args.get(SNXResponse.SNX_TASK_UUID_KEY) or None
    if taskUuid is None:
        raise DemistoException("Task UUID Parameter value is not found")
    else:
        urlSuffix = "/get_verdict"
        params = {SNXResponse.SNX_TASK_UUID_KEY: taskUuid}
        response, err_msg = client.get_response(urlSuffix, params)
        if response:
            if SNXResponse.SNX_SUCCESS_KEY in response.keys() and response[SNXResponse.SNX_SUCCESS_KEY] == SNXResponse.SUCCESS:
                dataResult = response[SNXResponse.SNX_RESULT_KEY]
                readableOutput = tableToMarkdown(f"SecneurX Analysis - Verdict Result: {taskUuid}", t=dataResult)
                return CommandResults(
                    readable_output=readableOutput,
                    outputs=dataResult,
                    outputs_key_field="task_uuid",
                    outputs_prefix="SecneurXAnalysis.Verdict",
                    raw_response=dataResult
                )
            else:
                readableOutput = tableToMarkdown(f"SecneurX Analysis - Verdict Result: {taskUuid}", t=response)
                return CommandResults(
                    readable_output=readableOutput,
                    outputs={"Status": SNXResponse.SNX_FAILED_KEY},
                    outputs_key_field="task_uuid",
                    outputs_prefix="SecneurXAnalysis.Verdict",
                    raw_response=response
                )
        else:
            msg = error_response(err_msg)
            outputJson = {SNXResponse.SNX_ERROR_MSG_KEY: msg, "Status": SNXResponse.SNX_FAILED_KEY}
            readableOutput = tableToMarkdown("SecneurX Analysis - Error", t=outputJson)
            return CommandResults(
                readable_output=readableOutput,
                outputs=outputJson,
                outputs_prefix="SecneurXAnalysis.Verdict",
                outputs_key_field="task_uuid"
            )


def get_completed_cmd(client: Client, args: dict[str, str]) -> CommandResults:
    urlSuffix = "/get_completed"
    params = create_request_json(args)
    response, err_msg = client.get_response(urlSuffix, params)
    if response:
        if SNXResponse.SNX_SUCCESS_KEY in response.keys() and response[SNXResponse.SNX_SUCCESS_KEY] == SNXResponse.SUCCESS:
            reportList = response.get(SNXResponse.SNX_RESULT_KEY, SNXResponse.SNX_NULL_KEY)
            if reportList != SNXResponse.SNX_NULL_KEY and len(reportList) > 0:
                readableOutput = tableToMarkdown("SecneurX Analysis - List of Completed Samples:", t=reportList,
                                                 headers=[
                                                     SNXResponse.SNX_TASK_UUID_KEY, SNXResponse.SNX_VERDICT_KEY,
                                                     SNXResponse.SNX_STATUS_KEY, SNXResponse.SNX_REPORT_KEY])
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Completed",
                    raw_response=reportList
                )
            else:
                msgJson = {"msg": "No samples to display"}
                readableOutput = tableToMarkdown("SecneurX Analysis - List of Completed Samples: ", msgJson)
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Completed",
                    outputs=msgJson
                )
        else:
            readableOutput = tableToMarkdown("", response)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.Completed",
                outputs=response
            )
    else:
        msg = error_response(err_msg)
        raise DemistoException(msg)


def get_pending_cmd(client: Client, args: dict[str, str]) -> CommandResults:
    urlSuffix = "/get_processing"
    params = create_request_json(args)
    response, err_msg = client.get_response(urlSuffix, params)
    if response:
        if SNXResponse.SNX_SUCCESS_KEY in response.keys() and response[SNXResponse.SNX_SUCCESS_KEY] == SNXResponse.SUCCESS:
            reportList = response.get(SNXResponse.SNX_RESULT_KEY, SNXResponse.SNX_NULL_KEY)
            if reportList != SNXResponse.SNX_NULL_KEY and len(reportList) > 0:
                for report in reportList:
                    if SNXResponse.SNX_FILENAME_KEY in report.keys():
                        report[SNXResponse.SAMPLE_KEY] = report[SNXResponse.SNX_FILENAME_KEY]
                    elif SNXReportParser.JSON_URL in report.keys():
                        report[SNXResponse.SAMPLE_KEY] = report[SNXReportParser.JSON_URL]
                    else:
                        continue
                readableOutput = tableToMarkdown("SecneurX Analysis - List of Samples in Pending State: ", t=reportList,
                                                 headers=[SNXResponse.SNX_TASK_UUID_KEY, SNXResponse.SAMPLE_KEY,
                                                          SNXResponse.SNX_STATUS_KEY, SNXResponse.SNX_SHA256_KEY])
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Pending",
                    raw_response=reportList
                )
            else:
                msgJson = {'msg': "No samples to display"}
                readableOutput = tableToMarkdown("SecneurX Analysis - List of Samples in Pending State:", msgJson)
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Pending",
                    outputs=msgJson
                )
        else:
            readableOutput = tableToMarkdown("", response)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.Pending",
                outputs=response
            )
    else:
        msg = error_response(err_msg)
        raise DemistoException(msg)


def get_status_cmd(client: Client, args: dict[str, str]) -> CommandResults:
    urlSuffix = "/get_status"
    params = create_request_json(args)
    response, err_msg = client.get_response(urlSuffix, params)
    if response:
        if SNXResponse.SNX_SUCCESS_KEY in response.keys() and response[SNXResponse.SNX_SUCCESS_KEY] == SNXResponse.SUCCESS:
            reportList = response.get(SNXResponse.SNX_RESULT_KEY, SNXResponse.SNX_NULL_KEY)
            if reportList != SNXResponse.SNX_NULL_KEY and len(reportList) > 0:
                for report in reportList:
                    if SNXResponse.SNX_FILENAME_KEY in report.keys():
                        report[SNXResponse.SAMPLE_KEY] = report[SNXResponse.SNX_FILENAME_KEY]
                    elif SNXReportParser.JSON_URL in report.keys():
                        report[SNXResponse.SAMPLE_KEY] = report[SNXReportParser.JSON_URL]
                    else:
                        continue
                readableOutput = tableToMarkdown("SecneurX Analysis - Status of Submitted Samples:", t=reportList,
                                                 headers=[SNXResponse.SNX_TASK_UUID_KEY, SNXResponse.SAMPLE_KEY,
                                                          SNXResponse.SNX_STATUS_KEY, SNXResponse.SNX_SHA256_KEY])
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Status",
                    raw_response=reportList
                )
            else:
                msgJson = {"msg": "No samples to display"}
                readableOutput = tableToMarkdown("SecneurX Analysis - Status of Submitted Samples: ", msgJson)
                return CommandResults(
                    readable_output=readableOutput,
                    outputs_prefix="SecneurXAnalysis.Status",
                    outputs=msgJson
                )
        else:
            readableOutput = tableToMarkdown("", response)
            return CommandResults(
                readable_output=readableOutput,
                outputs_prefix="SecneurXAnalysis.Status",
                outputs=response
            )

    else:
        msg = error_response(err_msg)
        raise DemistoException(msg)


def get_report_cmd(client: Client, args: dict[str, str]):
    urlSuffix = "/get_report"
    taskUuid = args.get(SNXResponse.SNX_TASK_UUID_KEY) or None
    reportFormat = args.get(SNXResponse.SNX_REPORT_FORMAT_KEY) or "json"
    if reportFormat is None or reportFormat != "html" and reportFormat != "json":
        raise DemistoException("Invalid value of report file format paramater")
    if taskUuid is None:
        raise DemistoException("Task Uuid Parameter value is not found")
    elif len(taskUuid) <= 10:
        raise DemistoException("Invalid Task Uuid value")
    else:
        reportExtn = "." + reportFormat
        params = create_request_json(args)
        response, err_msg = client.get_response(urlSuffix, params)
        if response:
            if reportFormat == "json":
                resJson = json.loads(response)
                contents = parse_response(resJson)
                indicator = parse_report_entity(resJson)
                title = None
                headerList = []
                readableContents = None
                for header in contents.keys():
                    headerList.append(header)
                title = (f"SecneurX Analysis - Detailed Report of the Analyzed Sample: {taskUuid}")
                readableContents = format_report_contents(contents)
                readableOutputs = tableToMarkdown(title, readableContents, headers=headerList, headerTransform=pascalToSpace)
                reportFileName = taskUuid + reportExtn
                fileContent = fileResult(reportFileName, response)
                return_results(fileContent)
                return CommandResults(
                    readable_output=readableOutputs,
                    indicator=indicator,
                    outputs=contents,
                    outputs_prefix="SecneurXAnalysis.Report",
                    raw_response=resJson
                )
            else:
                reportFileName = taskUuid + reportExtn
                fileContent = fileResult(reportFileName, response)
                demisto.results(fileContent)
        else:
            msg = error_response(err_msg)
            result = {SNXResponse.SNX_ERROR_MSG_KEY: msg, "Status": SNXResponse.SNX_FAILED_KEY}
            readableOutputs = tableToMarkdown(f"SecneurX Analysis - Failed: {taskUuid}", result)
            return CommandResults(
                readable_output=readableOutputs,
                outputs_prefix="SecneurXAnalysis.Report",
                outputs=result
            )


def get_quota_cmd(client: Client) -> CommandResults:
    urlSuffix = "/get_quota"
    response, err_msg = client.get_response(urlSuffix, {})
    if response:
        if response.get(SNXResponse.SNX_SUCCESS_KEY) == SNXResponse.SUCCESS:
            quotaData = response[SNXResponse.SNX_RESULT_KEY]
            readableOutput = tableToMarkdown("SecneurX Analysis - API Key Quota Usage:", t=quotaData)
            return CommandResults(
                readable_output=readableOutput,
                outputs=quotaData,
                outputs_prefix="SecneurXAnalysis.Quota",
                raw_response=response
            )
        else:
            readableOutput = tableToMarkdown("SecneurX Analysis - API Key Quota Usage:", t=response)
            return CommandResults(
                readable_output=readableOutput,
                outputs=response,
                outputs_prefix="SecneurXAnalysis.Quota",
                raw_response=response
            )
    else:
        msg = error_response(err_msg)
        raise DemistoException(msg)


def main():
    apiKey = demisto.params().get("apiKey")
    baseUrl = urljoin(demisto.params().get("url"), "/api/v1")
    verifyCertificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    headers = {"api-key": apiKey}
    client = Client(
        base_url=baseUrl,
        verify=verifyCertificate,
        headers=headers,
        proxy=proxy
    )
    cmdAction = demisto.command()
    demisto.debug(f"Command being called is {cmdAction}")
    try:
        if cmdAction == "test-module":
            result = test_module(client)
            return_results(result)

        elif cmdAction == "snx-analysis-get-verdict":
            return_results(get_verdict_cmd(client, demisto.args()))

        elif cmdAction == "snx-analysis-get-completed":
            return_results(get_completed_cmd(client, demisto.args()))

        elif cmdAction == "snx-analysis-get-pending":
            return_results(get_pending_cmd(client, demisto.args()))

        elif cmdAction == "snx-analysis-get-status":
            return_results(get_status_cmd(client, demisto.args()))

        elif cmdAction == "snx-analysis-submit-file":
            return_results(post_submit_file(client, demisto.args()))

        elif cmdAction == "snx-analysis-submit-url":
            return_results(post_submit_url(client, demisto.args()))

        elif cmdAction == "snx-analysis-get-report":
            return_results(get_report_cmd(client, demisto.args()))

        elif cmdAction == "snx-analysis-get-quota":
            return_results(get_quota_cmd(client))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {cmdAction} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
