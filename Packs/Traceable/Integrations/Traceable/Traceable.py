import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import urllib3
from urllib import parse
from string import Template
from datetime import datetime, timedelta, UTC
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter, Retry
import ipaddress
import time


# Disable insecure warnings
urllib3.disable_warnings()


s = requests.Session()
retries = Retry(
    total=30,
    other=10,
    connect=10,
    read=10,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
s.mount("https://", HTTPAdapter(max_retries=retries))


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

XSOAR_SEVERITY_BY_TRACEABLE_SEVERITY = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}


get_threat_events_query = """{
  explore(
    scope: "DOMAIN_EVENT"
    limit: $limit
    between: {
      startTime: "$starttime"
      endTime: "$endtime"
    }
    offset: 0
    $filter_by_clause
    orderBy: [
      { keyExpression: { key: "timestamp" } }
    ]
  ) {
    results {
        $field_list
    }
  }
}
"""

get_spans_for_trace_id = """{
  spans(
    between: {
      startTime: "$starttime"
      endTime: "$endtime"
    }
    offset: 0
    orderBy: [{ direction: DESC, keyExpression: { key: "startTime" } }]
    $filter_by_clause
  ) {
    results {
      id
      protocolName: attribute(expression: { key: "protocolName" })
      serviceName: attribute(expression: { key: "serviceName" })
      displaySpanName: attribute(expression: { key: "displaySpanName" })
      userIdentifier: attribute(expression: { key: "userIdentifier" })
      sessionId: attribute(expression: { key: "sessionId" })
      ipAddress: attribute(expression: { key: "ipAddress" })
      statusCode: attribute(expression: { key: "statusCode" })
      errorCount: attribute(expression: { key: "errorCount" })
      duration: attribute(expression: { key: "duration" })
      startTime: attribute(expression: { key: "startTime" })
      endTime: attribute(expression: { key: "endTime" })
      traceId: attribute(expression: { key: "traceId" })
      spanTags: attribute(expression: { key: "spanTags" })
      spanResponseBody: attribute(expression: { key: "spanResponseBody" })
      spanResponseHeaders: attribute(expression: { key: "spanResponseHeaders" })
      spanResponseCookies: attribute(expression: { key: "spanResponseCookies" })
      spanRequestBody: attribute(expression: { key: "spanRequestBody" })
      spanRequestHeaders: attribute(expression: { key: "spanRequestHeaders" })
      spanRequestCookies: attribute(expression: { key: "spanRequestCookies" })
    }
  }
}
"""

api_entities_query = """query entities
{
  entities(
    scope: "API"
    between: {
      startTime: "$starttime"
      endTime: "$endtime"
    }
    offset: 0
    $filter_by_clause
  ) {
    results {
      id
      $fields_list
    }
  }
}"""


class Helper:
    @staticmethod
    def construct_filterby_expression(*clauses):
        non_null_list = [i for i in clauses if i is not None]
        return "filterBy: [" + ",".join(non_null_list) + "]"

    @staticmethod
    def fix_start_timestamp(string_timestamp: str):
        return f"{string_timestamp[:-1]}.000Z"

    @staticmethod
    def fix_end_timestamp(string_timestamp: str):
        return f"{string_timestamp[:-1]}.999Z"

    @staticmethod
    def construct_field_selection_expression(field_list):
        non_null_field_list = [i for i in field_list if i is not None and i != ""]
        expression_list = ""
        for field in non_null_field_list:
            expression = f"{field}: selection(expression: {{key: \"{field}\"}}) {{ value }}"
            expression_list = expression_list + expression + "\n"
        return expression_list

    @staticmethod
    def construct_field_attribute_expression(field_list):
        non_null_field_list = [i for i in field_list if i is not None and i != ""]
        expression_list = ""
        for field in non_null_field_list:
            expression = f"{field}: attribute(expression: {{ key: \"{field}\" }})"
            expression_list = expression_list + expression + "\n"
        return expression_list

    @staticmethod
    def datetime_to_string(d):
        return d.strftime(DATE_FORMAT)

    @staticmethod
    def now_time_to_string():
        return Helper.datetime_to_string(datetime.utcnow())

    @staticmethod
    def start_datetime_to_string(d):
        return Helper.fix_start_timestamp(Helper.datetime_to_string(d))

    @staticmethod
    def end_datetime_to_string(d):
        return Helper.fix_end_timestamp(Helper.datetime_to_string(d))

    @staticmethod
    def string_to_datetime(s):
        return datetime.strptime(s, DATE_FORMAT)

    @staticmethod
    def construct_key_expression(key, value, _type="ATTRIBUTE", operator="IN"):
        if type(value) is bool and operator == "IN":
            msg = f"Value of type {type(value).__name__} doesn't allow operator {operator}"
            demisto.error(msg)
            raise Exception(msg)
        if key is None:
            demisto.info("Key was None. Couldn't create Key Expression.")
            return ""
        if operator == "IN":
            _value = value
            if value is not None:
                if type(value) is str:
                    _value = f'"{value}"'
                elif isinstance(value, int | float):
                    _value = value
                elif type(value) is list and len(value) > 0:
                    if type(value[0]) is str:
                        _value = ",".join([f'"{v}"' for v in value])
                    elif type(value[0]) is int or type(value[0]) is float:
                        _value = ",".join([f"{v}" for v in value])

            else:
                demisto.info(
                    "Value was found None. Returning without creating Key Expression. Key: "
                    + key
                )
                return ""
            return (
                '{keyExpression: {key: "'
                + key
                + '"}, operator: '
                + operator
                + ", value: ["
                + str(_value)
                + "], type: "
                + _type
                + "}"
            )
        elif operator == "EQUALS":
            _value = ""
            if type(value) is str:
                _value = f'"{value}"'
            elif type(value) is bool:
                _value = f"{str(value).lower()}"
            else:
                _value = value
            return (
                '{keyExpression: {key: "'
                + key
                + '"}, operator: '
                + operator
                + ", value: "
                + str(_value)
                + ", type: "
                + _type
                + "}"
            )
        else:
            raise Exception("Unknown Operator: " + operator)

    @staticmethod
    def is_error(obj, *hierarchy):
        if obj is None:
            return True
        _obj = obj
        for el in hierarchy:
            if (el not in _obj) or (_obj[el] is None):
                return True
            _obj = _obj[el]
        return False


""" CLIENT CLASS """


class Client(BaseClient):
    REQUESTS_TIMEOUT = 60
    pack_version = "1.1.1"

    def __init__(
        self,
        base_url,
        verify=True,
        proxy=False,
        ok_codes=(),
        headers=None,
        auth=None,
        timeout=REQUESTS_TIMEOUT,
    ):
        if headers is None:
            headers = {}

        headers["Content-Type"] = "application/json"
        headers["x-traceable-xsoar"] = f"traceable-xsoar-integration; version={self.pack_version}"
        self.headers = headers
        self.url = base_url + "/graphql"
        self.securityScoreCategoryList = None
        self.threatCategoryList = None
        self.ipReputationLevelList = None
        self.ipAbuseVelocityList = None
        self.ipCategoriesList = None
        self.limit = 100
        self.proxy = proxy
        self.span_fetch_threadpool = 10
        self.app_url = ""
        self.ignore_status_code_tuples = []
        self.environments = None
        self.integration_context: dict = {}
        self.fetch_unique_incidents: bool = True
        self.span_query_batch_size = 50
        self.timegap_between_repeat_incidents = 'in 7 days'
        self.__mandatory_domain_event_field_list = ["actorCountry", "actorIpAddress", "apiId", "environment", "eventDescription",
                                                    "id", "ipCategories", "name", "securityScoreCategory", "spanId",
                                                    "statusCode", "timestamp", "traceId", "serviceName", "anomalousAttribute"]
        self.__allowed_optional_domain_event_field_list = ["actorDevice", "actorEntityId", "actorId", "actorScoreCategory",
                                                           "actorSession", "apiName", "apiUri",
                                                           "category", "ipAbuseVelocity", "ipReputationLevel",
                                                           "securityEventType", "securityScore", "serviceId",
                                                           "actorScore", "threatCategory", "type"]
        self.__allowed_optional_api_atrributes = [
            "isExternal", "isAuthenticated", "riskScore", "riskScoreCategory", "isLearnt"
        ]
        self.optional_api_attributes = []
        self.domain_event_field_list = []
        self.__query_api_attributes = False
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth, timeout)

    def __init_integration_context__(self):
        self.integration_context = get_integration_context()

    def set_integration_context_key_value(self, key, value):
        self.__init_integration_context__()
        self.integration_context[key] = value
        self.__commit_integration_context__()

    def set_span_query_batch_size(self, span_query_batch_size=50):
        self.span_query_batch_size = span_query_batch_size

    def set_timegap_between_repeat_incidents(self, d):
        self.timegap_between_repeat_incidents = d

    def get_integration_context_key_value(self, key):
        self.__init_integration_context__()
        return self.integration_context.get(key)

    def delete_integration_context_key_value(self, key):
        self.__init_integration_context__()
        self.integration_context.pop(key)
        self.__commit_integration_context__()

    def __commit_integration_context__(self):
        set_integration_context(self.integration_context)

    def set_security_score_category_list(self, securityScoreCategoryList):
        self.securityScoreCategoryList = securityScoreCategoryList

    def set_app_url(self, app_url):
        if app_url:
            demisto.info(f"Setting Traceable Platform UI Base Url to: {app_url}")
            self.app_url = app_url
        else:
            demisto.info("No Traceable Platform UI Base Url provided.")

    def set_threat_category_list(self, threatCategoryList):
        self.threatCategoryList = threatCategoryList

    def set_ip_reputation_level_list(self, ipReputationLevelList):
        self.ipReputationLevelList = ipReputationLevelList

    def set_ip_categories_list(self, ipCategoriesList):
        _ipCategoriesList = []
        for ipCategory in ipCategoriesList:
            if ipCategory == "Unknown":
                _ipCategoriesList.append("IP_LOCATION_TYPE_UNSPECIFIED")
            elif ipCategory == "Anonymous VPN":
                _ipCategoriesList.append("IP_LOCATION_TYPE_ANONYMOUS_VPN")
            elif ipCategory == "Hosting Provider":
                _ipCategoriesList.append("IP_LOCATION_TYPE_HOSTING_PROVIDER")
            elif ipCategory == "Public Proxy":
                _ipCategoriesList.append("IP_LOCATION_TYPE_PUBLIC_PROXY")
            elif ipCategory == "TOR Exit Node":
                _ipCategoriesList.append("IP_LOCATION_TYPE_TOR_EXIT_NODE")
            elif ipCategory == "BOT":
                _ipCategoriesList.append("IP_LOCATION_TYPE_BOT")
            else:
                error = f"Unknown ipCategory {ipCategory} specified."
                raise Exception(error)
        self.ipCategoriesList = _ipCategoriesList

    def set_ip_abuse_velocity_list(self, ipAbuseVelocityList):
        _ipAbuseVelocityList = []
        for ipAbuseVelocity in ipAbuseVelocityList:
            if ipAbuseVelocity == "UNKNOWN":
                _ipAbuseVelocityList.append("IP_ABUSE_VELOCITY_UNSPECIFIED")
            else:
                _ipAbuseVelocityList.append(ipAbuseVelocity)
        self.ipAbuseVelocityList = _ipAbuseVelocityList

    def set_span_fetch_threadpool(self, span_fetch_threadpool):
        self.span_fetch_threadpool = span_fetch_threadpool

    def set_limit(self, limit):
        self.limit = limit

    def set_environments(self, environments):
        self.environments = environments

    def __parse_status_code_strings(self, status_code_list_string: str):
        if status_code_list_string is None:
            return []
        _status_code_list_string = status_code_list_string.rstrip().lstrip()
        if _status_code_list_string == "":
            return []
        range_tuple_list = []
        ranges = status_code_list_string.split(",")
        for range in ranges:
            bounds = range.split("-")
            lower = -1
            upper = -1
            bounds_len = len(bounds)
            if bounds_len > 2:
                demisto.info(f"Invalid status code range {range}. Ignoring.")
                continue
            if bounds_len > 0:
                try:
                    lower = int(bounds[0].lstrip().rstrip())
                    upper = lower
                except ValueError as e:
                    demisto.info(f"Couldn't parse bounds for status code range {range}. Exception {e}. Ignoring Range.")
                    continue
            if bounds_len > 1:
                try:
                    upper = int(bounds[1].lstrip().rstrip())
                except ValueError as e:
                    demisto.info(f"Couldn't parse bounds for status code range {range}. Exception {e}. Ignoring Range.")
                    continue
            if lower < 100 or lower > 599 or upper < 100 or upper > 599 or lower > upper:
                demisto.info(f"Invalid status code range {range}. Ignoring.")
                continue
            range_tuple_list.append((lower, upper))
        return range_tuple_list

    def is_ignored_status_code(self, status_code: int):
        return any(status_code in range(lower, upper + 1) for lower, upper in self.ignore_status_code_tuples)

    def set_ignore_status_codes(self, status_code_list_string):
        self.ignore_status_code_tuples = self.__parse_status_code_strings(status_code_list_string)

    def __process_domain_event_field_list(self, field_list: list):
        demisto.debug(f"List of allowed optional fields: {self.__allowed_optional_domain_event_field_list}")
        demisto.debug(f"Processing Option Field list: {field_list}")
        final_list = []
        final_list.extend(self.__mandatory_domain_event_field_list)

        if field_list is not None and len(field_list) > 0:
            for field in field_list:
                if field in self.__allowed_optional_domain_event_field_list and field not in final_list:
                    final_list.append(field)
                    demisto.debug(f"Adding {field} to list of Incident fields to query.")
                else:
                    demisto.info(f"Ignoring {field} as it is not allowed.")
        return final_list

    def get_domain_event_query_fields(self):
        if len(self.domain_event_field_list) == 0:
            demisto.debug(
                "Optional incident field list was not provided. Initializing with minimum required fields:"
                + f" {self.__mandatory_domain_event_field_list}")
            self.set_domain_event_field_list(None)
        return Helper.construct_field_selection_expression(self.domain_event_field_list)

    def set_domain_event_field_list(self, field_list):
        self.domain_event_field_list = self.__process_domain_event_field_list(field_list)

    def set_fetch_unique_incidents(self, fetch_unique_incidents: bool):
        self.fetch_unique_incidents = fetch_unique_incidents

    def set_optional_api_attributes(self, field_list):
        if len(field_list) == 0:
            field_list = []
        final_attributes_list = []
        for attribute in field_list:
            if attribute in self.__allowed_optional_api_atrributes and attribute not in final_attributes_list:
                final_attributes_list.append(attribute)
        self.optional_api_attributes = final_attributes_list
        if len(self.optional_api_attributes) > 0:
            self.__query_api_attributes = True

    def graphql_query(self, query, params={}, verify=False, additional_logging=""):
        demisto.debug(f"graphql_query: Entered into graphql_query {additional_logging}")
        demisto.debug(f"graphql_query: Running request...{additional_logging}")
        start = time.time()
        response = requests.post(
            self.url,
            json={"query": query, "variables": params},
            headers=self.headers,
            verify=verify,
        )
        end = time.time()
        demisto.info(f"graphql_query: Completed request in {(end-start)} seconds...{additional_logging}")

        if (
            response is not None
            and response.status_code != 200
            and response.text is not None
        ):
            msg = (f"Error occurred: {response.text} | Status Code: {(response.status_code)} | "
                   + f"additional_logging: {additional_logging}")
            demisto.error(msg)
            raise Exception(msg)

        demisto.debug(f"graphql_query: Completed checking request for non 200 errors...{additional_logging}")

        is_error, error = self.errors_in_response(response)
        demisto.debug(f"graphql_query: Completed errors_in_response...{additional_logging}")
        if is_error:
            demisto.debug(f"graphql_query: printing error...{additional_logging}")
            demisto.error(error)
            raise Exception(error)

        demisto.debug(f"graphql_query: Completed checking request for error objects...{additional_logging}")

        if response is not None and response.text is not None:
            response_obj = json.loads(response.text)
            demisto.info(f"Returning from graphql_query {additional_logging}")
            return response_obj

        demisto.info(f"graphql_query: Did not return the results so now throw exception...{additional_logging}")

        raise Exception(f"Something went wrong: {json.dumps(response, indent=2)} {additional_logging}")

    def errors_in_response(self, response):
        if response is not None and response.status_code == 200:
            response_obj: dict = json.loads(response.text)
            return (
                "error" in response_obj,
                response_obj["error"] if "error" in response_obj else None,
            )
        return True, json.dumps(response, indent=2)

    def get_span_for_trace_id(self, starttime, endtime, traceid=None, spanid=None):
        demisto.info(f"get_span_for_trace_id: Starting span query for traceid {traceid} and spanid {spanid}")
        if not spanid:
            msg = f"spanid cannot be None. Will not query span for the span list: {spanid}"
            demisto.info(msg)
            return None
        trace_id_clause = None
        if traceid is not None:
            trace_id_clause = Helper.construct_key_expression("traceId", traceid)
        span_id_clause = None
        if spanid is not None:
            span_id_clause = Helper.construct_key_expression("id", spanid)
        is_anomalous_clause = Helper.construct_key_expression("isAnomalous", True, operator="EQUALS")
        filter_by_clause = Helper.construct_filterby_expression(
            trace_id_clause, span_id_clause, is_anomalous_clause
        )
        query = Template(get_spans_for_trace_id).substitute(
            starttime=Helper.start_datetime_to_string(starttime),
            endtime=Helper.end_datetime_to_string(endtime),
            limit=self.limit,
            filter_by_clause=filter_by_clause,
        )
        demisto.debug(f"get_span_for_trace_id: Span query: {query}")
        demisto.info(f"get_span_for_trace_id: starting graphql_query for traceid {traceid} and spanid {spanid}")
        ret = self.graphql_query(query, additional_logging=f"traceid = {traceid}")
        demisto.debug(f"get_span_for_trace_id: completed graphql_query for traceid {traceid} and spanid {spanid}")
        return ret

    def get_threat_events_query(
        self,
        starttime,
        endtime=datetime.utcnow(),
    ):
        environment_clause = None
        securityScoreCategory_clause = None
        threatCategory_clause = None
        ipReputationLevel_clause = None
        ipAbuseVelocity_clause = None
        ipCategories_clause = None

        if self.environments is not None:
            environment_clause = Helper.construct_key_expression(
                "environment", self.environments
            )

        if (
            self.securityScoreCategoryList is not None
            and len(self.securityScoreCategoryList) > 0
        ):
            securityScoreCategory_clause = Helper.construct_key_expression(
                "securityScoreCategory", self.securityScoreCategoryList
            )

        if self.threatCategoryList is not None and len(self.threatCategoryList) > 0:
            threatCategory_clause = Helper.construct_key_expression(
                "threatCategory", self.threatCategoryList
            )

        if (
            self.ipReputationLevelList is not None
            and len(self.ipReputationLevelList) > 0
        ):
            ipReputationLevel_clause = Helper.construct_key_expression(
                "ipReputationLevel", self.ipReputationLevelList
            )

        if self.ipCategoriesList is not None and len(self.ipCategoriesList) > 0:
            ipCategories_clause = Helper.construct_key_expression(
                "ipCategories", self.ipCategoriesList
            )

        if self.ipAbuseVelocityList is not None and len(self.ipAbuseVelocityList) > 0:
            ipAbuseVelocity_clause = Helper.construct_key_expression(
                "ipAbuseVelocity", self.ipAbuseVelocityList
            )

        filter_by_clause = Helper.construct_filterby_expression(
            environment_clause,
            securityScoreCategory_clause,
            threatCategory_clause,
            ipReputationLevel_clause,
            ipCategories_clause,
            ipAbuseVelocity_clause,
        )

        demisto.info("Limit set to: " + str(self.limit))
        query = Template(get_threat_events_query).substitute(
            limit=self.limit,
            starttime=Helper.start_datetime_to_string(starttime),
            endtime=Helper.end_datetime_to_string(endtime),
            filter_by_clause=filter_by_clause,
            field_list=self.get_domain_event_query_fields()
        )
        return query

    def get_api_endpoint_details_query(self, api_id_list, starttime, endtime):
        filter_by_clause = Helper.construct_filterby_expression(
            Helper.construct_key_expression("id", api_id_list)
        )
        fields_list = Helper.construct_field_attribute_expression(self.optional_api_attributes)
        return Template(api_entities_query).substitute(
            filter_by_clause=filter_by_clause,
            fields_list=fields_list,
            limit=self.limit,
            starttime=Helper.start_datetime_to_string(starttime),
            endtime=Helper.end_datetime_to_string(endtime),
        )

    def get_api_endpoint_details(self, api_id_list, starttime, endtime):
        demisto.debug(f"API ID list length is: {len(api_id_list)}")
        demisto.info("Starting get_api_endpoint_details.")
        if len(api_id_list) == 0:
            return []
        query = self.get_api_endpoint_details_query(api_id_list, starttime, endtime)
        result = self.graphql_query(query)

        if Helper.is_error(result, "data", "entities", "results"):
            msg = "Error Object: " + json.dumps(result)
            demisto.error(msg)
            raise Exception(msg)

        demisto.debug("Ending get_api_endpoint_details.")

        return result["data"]["entities"]["results"]

    def get_threat_events(
        self,
        starttime,
        endtime=datetime.utcnow(),
    ):

        query = self.get_threat_events_query(starttime, endtime)
        demisto.debug(f"Query is: {query}")
        result = self.graphql_query(query)
        if Helper.is_error(result, "data", "explore", "results"):
            msg = f"Error Object: {json.dumps(result)}"
            demisto.error(msg)
            raise Exception(msg)

        results = result["data"]["explore"]["results"]

        demisto.info(f"Retrieved: {len(results)} Domain Events")
        demisto.debug(f"Result is:{json.dumps(results, indent=2)}")

        events = []
        first = True
        future_list = []
        api_id_map = {}
        with ThreadPoolExecutor(max_workers=self.span_fetch_threadpool) as executor:
            span_id_list = []
            for domain_event in results:
                if Helper.is_error(domain_event, "traceId", "value"):
                    demisto.info(
                        f"Couldn't find traceId in Domain Event: {json.dumps(domain_event, indent=2)}"
                    )
                    continue

                if Helper.is_error(domain_event, "spanId", "value"):
                    demisto.info(
                        f"Couldn't find spanId in Domain Event: {json.dumps(domain_event, indent=2)}"
                    )
                    continue

                if ("statusCode" in domain_event and "value" in domain_event["statusCode"]):
                    status_code = domain_event["statusCode"]["value"]
                    if (self.is_ignored_status_code(status_code)):
                        continue

                trace_id = domain_event["traceId"]["value"]
                span_id = domain_event["spanId"]["value"]
                if (
                    "apiId" in domain_event
                    and domain_event.get("apiId")
                    and domain_event.get("apiId") != "null"
                    and domain_event.get("apiId") != ""
                    and "value" in domain_event.get("apiId")
                    and domain_event.get("apiId", {}).get("value")
                    and domain_event.get("apiId", {}).get("value") != "null"
                    and domain_event.get("apiId", {}).get("value") != ""
                ):
                    api_id_map[domain_event["apiId"]["value"]] = True

                demisto.debug(f"Forking thread for span retrieval traceid {trace_id} spanid {span_id}")

                span_id_list.append(span_id)
                if len(span_id_list) >= self.span_query_batch_size:
                    future = executor.submit(
                        self.get_span_for_trace_id,
                        starttime=starttime,
                        endtime=endtime,
                        spanid=span_id_list,
                    )
                    demisto.debug(f"Submitted job successfully for spanids {span_id_list}")
                    future_list.append(future)
                    demisto.info("Completed thread for span retrieval")
                    span_id_list = []
            if len(span_id_list) > 0:
                future = executor.submit(
                    self.get_span_for_trace_id,
                    starttime=starttime,
                    endtime=endtime,
                    spanid=span_id_list,
                )
                demisto.debug(f"Submitted job successfully for spanids {span_id_list}")
                future_list.append(future)
                demisto.info("Completed thread for span retrieval")
                span_id_list = []
        span_id_map = {}
        demisto.info("Extracting spans from threads.")
        for future in future_list:
            trace_results = future.result()
            if Helper.is_error(trace_results, "data", "spans", "results"):
                msg = f"Error Object: {json.dumps(trace_results)}. Couldn't get the Span."
                demisto.info(msg)
            else:
                if len(trace_results["data"]["spans"]["results"]) > 0:
                    traces = trace_results["data"]["spans"]["results"]
                    for trace in traces:
                        if (
                            "id" in trace
                            and trace.get("id") != ""
                            and trace.get("id") not in span_id_map
                        ):
                            span_id_map[trace["id"]] = trace
                else:
                    demisto.info("Didn't find any spans. Span array length:"
                                 + f" {len(trace_results['data']['spans']['results'])}."
                                 + f" Span Object: {json.dumps(trace_results['data']['spans']['results'])}")

        api_endpoint_details = []
        api_endpoint_details_map: dict = {}

        if self.__query_api_attributes:
            api_endpoint_details = self.get_api_endpoint_details(
                list(api_id_map.keys()), starttime, endtime
            )
            api_endpoint_details_map = {
                api_endpoint_detail["id"]: api_endpoint_detail
                for api_endpoint_detail in api_endpoint_details
            }
        api_endpoint_details = None

        for domain_event in results:
            if (
                "spanId" in domain_event
                and "value" in domain_event.get("spanId")
                and domain_event.get("spanId", {}).get("value") != ""
                and domain_event.get("spanId", {}).get("value") in span_id_map
            ):
                domain_event["spans"] = span_id_map.get(domain_event.get("spanId").get("value"))
            demisto.info("Done waiting for the future object...")
            domain_event["type"] = "Exploit"
            if (
                domain_event["environment"] is not None
                and domain_event["environment"]["value"] is not None
            ):
                domain_event["environment"] = domain_event["environment"]["value"]
            if (
                domain_event["serviceName"] is not None
                and domain_event["serviceName"]["value"] is not None
            ):
                domain_event["serviceName"] = domain_event["serviceName"]["value"]
            if (
                domain_event["apiId"] is not None
                and domain_event["apiId"]["value"] is not None
            ):
                domain_event["apiId"] = domain_event["apiId"]["value"]
            else:
                domain_event["apiId"] = None
            if (
                domain_event["anomalousAttribute"] is not None
                and domain_event["anomalousAttribute"]["value"] is not None
            ):
                domain_event["anomalousAttribute"] = domain_event["anomalousAttribute"]["value"]
            else:
                domain_event["anomalousAttribute"] = None
            if (
                domain_event["name"] is not None
                and domain_event["name"]["value"] is not None
            ):
                domain_event["displayname"] = domain_event["name"]["value"]
                domain_event["name"] = domain_event["name"]["value"]
            if (
                domain_event["actorCountry"] is not None
                and domain_event["actorCountry"]["value"] is not None
            ):
                domain_event["country"] = domain_event["actorCountry"]["value"]
            if (
                domain_event["actorIpAddress"] is not None
                and domain_event["actorIpAddress"]["value"] is not None
            ):
                domain_event["sourceip"] = domain_event["actorIpAddress"]["value"]
            if (
                domain_event["securityScoreCategory"] is not None
                and domain_event["securityScoreCategory"]["value"] is not None
            ):
                domain_event["riskscore"] = domain_event["securityScoreCategory"][
                    "value"
                ]
                domain_event["severity"] = domain_event["securityScoreCategory"][
                    "value"
                ]
            if (
                "ipCategories" in domain_event
                and "value" in domain_event["ipCategories"]
                and len(domain_event["ipCategories"]["value"]) > 0
                and "actorIpAddress" in domain_event
                and "value" in domain_event["actorIpAddress"]
            ):
                is_private = False
                for ipCategory in domain_event["ipCategories"]["value"]:
                    if (
                        ipCategory == "IP_LOCATION_TYPE_UNSPECIFIED"
                        and ipaddress.ip_address(
                            domain_event["actorIpAddress"]["value"]
                        ).is_private
                    ):
                        domain_event["ipAddressType"] = "Internal"
                        is_private = True
                if not is_private:
                    domain_event["ipAddressType"] = "External"

            if (
                self.__query_api_attributes
                and "isExternal" in self.optional_api_attributes
                and "apiId" in domain_event
                and domain_event["apiId"] is not None
                and domain_event["apiId"] != "null"
                and domain_event["apiId"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]] is not None
                and "isExternal" in api_endpoint_details_map[domain_event["apiId"]]
                and api_endpoint_details_map[domain_event["apiId"]][
                    "isExternal"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]][
                    "isExternal"
                ] != "null"
            ):
                if api_endpoint_details_map[domain_event["apiId"]][
                    "isExternal"
                ]:
                    domain_event["apiType"] = "External"
                else:
                    domain_event["apiType"] = "Internal"
            if (
                self.__query_api_attributes
                and "isAuthenticated" in self.optional_api_attributes
                and "apiId" in domain_event
                and domain_event["apiId"] is not None
                and domain_event["apiId"] != "null"
                and domain_event["apiId"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]] is not None
                and "isAuthenticated" in api_endpoint_details_map[domain_event["apiId"]]
                and api_endpoint_details_map[domain_event["apiId"]][
                    "isAuthenticated"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]][
                    "isAuthenticated"
                ]
                != "null"
            ):
                domain_event["apiIsAuthenticated"] = api_endpoint_details_map[domain_event["apiId"]]["isAuthenticated"]
            if (
                self.__query_api_attributes
                and "riskScore" in self.optional_api_attributes
                and "apiId" in domain_event
                and domain_event.get("apiId", '') != ''
                and domain_event.get("apiId", '') != "null"
                and domain_event.get("apiId", '') in api_endpoint_details_map
                and "riskScore" in api_endpoint_details_map.get(domain_event.get("apiId"), {})
                and api_endpoint_details_map.get(domain_event.get("apiId"), {}).get("riskScore") is not None
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("riskScore", '') != ''
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("riskScore", '') != "null"
            ):
                domain_event["apiRiskScore"] = api_endpoint_details_map.get(domain_event["apiId"], {}).get("riskScore")
            if (
                self.__query_api_attributes
                and "riskScoreCategory" in self.optional_api_attributes
                and "apiId" in domain_event
                and domain_event.get("apiId", '') != ''
                and domain_event.get("apiId", '') != "null"
                and domain_event.get("apiId", '') in api_endpoint_details_map
                and "riskScoreCategory" in api_endpoint_details_map.get(domain_event.get("apiId", ''), {})
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("riskScoreCategory", '') != ''
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("riskScoreCategory", '') != 'null'
            ):
                domain_event["apiRiskScoreCategory"] = api_endpoint_details_map.get(
                    domain_event.get("apiId"), {}
                ).get("riskScoreCategory")

            if (
                self.__query_api_attributes
                and "isLearnt" in self.optional_api_attributes
                and domain_event.get("apiId", '') != ''
                and domain_event.get("apiId", '') != "null"
                and domain_event.get("apiId", '') in api_endpoint_details_map
                and api_endpoint_details_map.get(domain_event.get("apiId", '')) is not None
                and "isLearnt" in api_endpoint_details_map.get(domain_event.get("apiId", ''), {})
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("isLearnt", '') != ''
                and api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("isLearnt", '') != 'null'
            ):
                domain_event["apiIsLearnt"] = api_endpoint_details_map.get(domain_event.get("apiId", ''), {}).get("isLearnt")

            if "ipAddressType" not in domain_event:
                domain_event["ipAddressType"] = "Internal"

            if "apiType" not in domain_event and self.__query_api_attributes and "isExternal" in self.optional_api_attributes:
                domain_event["apiType"] = "Unknown"

            if (
                "id" in domain_event
                and "value" in domain_event.get("id", {})
                and self.app_url != ""
                and "environment" in domain_event
                and domain_event.get("environment", '') != ''
            ):
                domain_event["eventUrl"] = (
                    f"{self.app_url}/security-event/"
                    + domain_event.get("id", {}).get("value")
                    + "?time=90d&env="
                    + parse.quote(domain_event.get("environment"))
                )

            events.append(domain_event)
            if first:
                first = False
                demisto.debug(f"Domain Event: {json.dumps(domain_event, indent=3)}")
            demisto.debug(
                f"Complete Domain Event is: {json.dumps(domain_event, indent=2)}"
            )

        return events


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    message: str = ""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)
        query = client.get_threat_events_query(start_time, end_time)
        demisto.debug("Query is: " + query)
        result = client.graphql_query(query)
        if Helper.is_error(result, "data", "explore", "results"):
            msg = "Error Object: " + json.dumps(result)
            demisto.error(msg)
            raise Exception(msg)

        results = result["data"]["explore"]["results"]
        demisto.info(f"Query successfully completed. Returned {len(results)} records")
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def list_incident_cache_command(client: Client):
    client.__init_integration_context__()
    return [{"id": key, "expiry": value} for key, value in client.integration_context.items()]


def purge_incident_cache_command(client: Client):
    client.__init_integration_context__()
    result = []
    for key, value in client.integration_context.items():

        result.append({
            "id": key,
            "expiry": value,
            "deletion_status": "deleted"
        })
    client.integration_context = {}
    client.__commit_integration_context__()
    return result


def fetch_incidents(client: Client, last_run, first_fetch_time):
    last_fetch = last_run.get("last_fetch")

    # Handle first time fetch
    _last_fetch: datetime = (
        dateparser.parse(first_fetch_time)  # type: ignore
        if last_fetch is None
        else dateparser.parse(last_fetch)
    )

    latest_created_time: datetime = _last_fetch
    incidents = []
    items = client.get_threat_events(_last_fetch, datetime.utcnow())
    demisto.info(f"Retrieved {len(items)} records.")

    if client.fetch_unique_incidents:
        for key, _context_entry_date in client.integration_context.items():
            if _context_entry_date is not None:
                context_entry_date = Helper.string_to_datetime(_context_entry_date)
                if context_entry_date < datetime.utcnow():
                    client.delete_integration_context_key_value(key)

    if len(items) > 0:
        demisto.debug(f"First Incident: {json.dumps(items[0], indent=3)}")
    for item in items:
        context_value = None
        context_key = ""
        if client.fetch_unique_incidents:
            context_key = (f"{item['environment']}_{item['serviceName']}_{item['name']}_{item['apiId']}_"
                           + f"{item['anomalousAttribute']}")
            context_value = client.get_integration_context_key_value(context_key)
            if context_value is not None:
                context_entry_date = Helper.string_to_datetime(context_value)
                if context_entry_date < datetime.utcnow():
                    context_value = None
        incident_created_time: datetime = datetime.fromtimestamp(
            item["timestamp"]["value"] / 1000
        )
        if context_value is None:
            demisto.info(f"Context key {context_key} not found in instance cache. Creating a new incident.")
            incident = {
                "name": item["name"],
                "displayname": item["displayname"],
                "country": item["country"],
                "sourceip": item["sourceip"],
                "riskscore": item["riskscore"],
                "ipAddressType": item["ipAddressType"],
                "severity": XSOAR_SEVERITY_BY_TRACEABLE_SEVERITY.get(
                    item["severity"], IncidentSeverity.UNKNOWN
                ),
                "rawJSON": json.dumps(item),
            }
            if ("eventUrl" in item
                    and item.get("eventUrl", '') != ''):
                incident["eventUrl"] = item.get("eventUrl")

            incidents.append(incident)
            if context_key != "":
                demisto.info(f"Adding Context key {context_key} to the instance cache.")
                client.set_integration_context_key_value(context_key, Helper.datetime_to_string(
                    dateparser.parse(client.timegap_between_repeat_incidents)))
        else:
            demisto.info(
                f"Found existing context record with key {context_key} and value {context_value}. Will not create new incident.")

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time.replace(
            tzinfo=UTC
        ) > latest_created_time.replace(tzinfo=UTC):
            latest_created_time = incident_created_time

    next_run = {"last_fetch": latest_created_time.strftime(DATE_FORMAT)}
    demisto.info("Done processing all incidents.")
    return next_run, incidents


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    base_url = demisto.params()["url"]
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        first_fetch_time = demisto.params().get("first_fetch", "3 days").strip()
        securityScoreCategoryList = demisto.params().get("securityScoreCategory")
        threatCategoryList = demisto.params().get("threatCategory")
        ipReputationLevelList = demisto.params().get("ipReputationLevel")
        ipAbuseVelocityList = demisto.params().get("ipAbuseVelocity")
        limit = int(demisto.params().get("max_fetch", 100))
        span_fetch_threadpool = int(demisto.params().get("span_fetch_threadpool", 10))
        app_url = demisto.params().get("app_url")
        ipCategoriesList = demisto.params().get("ipCategories")
        ignoreStatusCodes = demisto.params().get("ignoreStatusCodes", "")
        optionalDomainEventFieldList = demisto.params().get("optionalDomainEventFieldList")
        optionalAPIAttributes = demisto.params().get("optionalAPIAttributes")
        fetch_unique_incidents = demisto.params().get("isFetchUniqueIncidents")
        span_query_batch_size = int(demisto.params().get("span_query_batch_size", 50))
        timegap_between_repeat_incidents = demisto.params().get("timegap_between_repeat_incidents", 'in 7 days')

        if span_query_batch_size > 1000:
            msg = "Set a value for span_query_batch_size between 1 and 1000."
            demisto.error(msg)
            raise Exception(msg)

        _env = demisto.params().get("environment")

        environments = None
        if _env is not None and len(_env) > 0:
            environments = argToList(_env)

        apikey = demisto.params().get("credentials", {}).get("password")
        headers: dict = {"Authorization": apikey, "Content-Type": "application/json"}
        client = Client(
            base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        demisto.info(f"Pack version - {client.pack_version}")

        client.set_security_score_category_list(securityScoreCategoryList)
        client.set_threat_category_list(threatCategoryList)
        client.set_ip_reputation_level_list(ipReputationLevelList)
        client.set_ip_abuse_velocity_list(ipAbuseVelocityList)
        client.set_environments(environments)
        client.set_span_fetch_threadpool(span_fetch_threadpool)
        client.set_ip_categories_list(ipCategoriesList)
        client.set_app_url(app_url)
        client.set_ignore_status_codes(ignoreStatusCodes)
        client.set_domain_event_field_list(optionalDomainEventFieldList)
        client.set_optional_api_attributes(optionalAPIAttributes)
        client.set_fetch_unique_incidents(fetch_unique_incidents)
        client.set_span_query_batch_size(span_query_batch_size)
        client.set_timegap_between_repeat_incidents(timegap_between_repeat_incidents)
        client.set_limit(limit)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'list_incident_cache':
            result = list_incident_cache_command(client)
            return_results(
                CommandResults(
                    outputs_prefix='Traceable.Instancecache',
                    outputs_key_field='id',
                    outputs=result
                )
            )
        elif demisto.command() == 'purge_incident_cache':
            result = purge_incident_cache_command(client)
            return_results(
                CommandResults(
                    outputs_prefix='Traceable.Instancecache',
                    outputs_key_field='id',
                    outputs=result
                )
            )
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
