import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import urllib3
from urllib import parse
from string import Template
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter, Retry
import ipaddress


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
    limit: $limit
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
      userCountry: attribute(expression: { key: "userCountry" })
      userCity: attribute(expression: { key: "userCity" })
      userRoles: attribute(expression: { key: "userRoles" })
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
    limit: $limit
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
    def datetime_to_string(d: datetime):
        return d.strftime(DATE_FORMAT)

    @staticmethod
    def start_datetime_to_string(d: datetime):
        return Helper.fix_start_timestamp(Helper.datetime_to_string(d))

    @staticmethod
    def end_datetime_to_string(d: datetime):
        return Helper.fix_end_timestamp(Helper.datetime_to_string(d))

    @staticmethod
    def string_to_datetime(s):
        return datetime.strptime(s, DATE_FORMAT)

    @staticmethod
    def construct_key_expression(key, value, _type="ATTRIBUTE", operator="IN"):
        if key is None:
            demisto.info("Key was None. Couldn't create Key Expression.")
            return ""
        if operator == "IN":
            _value = value
            if value is not None:
                if type(value) == str:
                    _value = f'"{value}"'
                elif isinstance(value, int | float):
                    _value = value
                elif type(value) == list and len(value) > 0:
                    if type(value[0]) == str:
                        _value = ",".join([f'"{v}"' for v in value])
                    elif type(value[0]) == int or type(value[0]) == float:
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
            _value = f'"{value}"' if type(value) == str else value
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
        self.__mandatory_domain_event_field_list = ["actorCountry", "actorIpAddress", "apiId", "environment", "eventDescription",
                                                    "id", "ipCategories", "name", "securityScoreCategory", "spanId",
                                                    "statusCode", "timestamp", "traceId"]
        self.__allowed_optional_domain_event_field_list = ["actorDevice", "actorEntityId", "actorId", "actorScoreCategory",
                                                           "actorSession", "anomalousAttribute", "apiName", "apiUri",
                                                           "category", "ipAbuseVelocity", "ipReputationLevel",
                                                           "securityEventType", "securityScore", "serviceId", "serviceName",
                                                           "actorScore", "threatCategory", "type"]
        self.__allowed_optional_api_atrributes = [
            "isExternal", "isAuthenticated", "riskScore", "riskScoreCategory", "isLearnt"
        ]
        self.optional_api_attributes = []
        self.domain_event_field_list = []
        self.__query_api_attributes = False
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth, timeout)

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

    def graphql_query(self, query, params={}, verify=False):
        demisto.debug("Entered from graphql_query")
        demisto.debug("Running request...")
        response = requests.post(
            self.url,
            json={"query": query, "variables": params},
            headers=self.headers,
            verify=verify,
        )
        demisto.debug("Completed request...")

        if (
            response is not None
            and response.status_code != 200
            and response.text is not None
        ):
            msg = f"Error occurred: {response.text} | Status Code: {(response.status_code)}"
            demisto.error(msg)
            raise Exception(msg)

        is_error, error = self.errors_in_response(response)
        if is_error:
            demisto.error(error)
            raise Exception(error)

        if response is not None and response.text is not None:
            response_obj = json.loads(response.text)
            demisto.debug("Returning from graphql_query")
            return response_obj

        raise Exception(f"Something went wrong: {json.dumps(response, indent=2)}")

    def errors_in_response(self, response):
        if response is not None and response.status_code == 200:
            response_obj: dict = json.loads(response.text)
            return (
                "error" in response_obj,
                response_obj["error"] if "error" in response_obj else None,
            )
        return True, json.dumps(response, indent=2)

    def get_span_for_trace_id(self, starttime, endtime, traceid=None, spanid=None):
        if traceid is None or len(traceid) < 1:
            msg = "traceid cannot be None."
            demisto.error(msg)
            raise Exception(msg)
        trace_id_clause = None
        if traceid is not None:
            trace_id_clause = Helper.construct_key_expression("traceId", traceid)
        span_id_clause = None
        if spanid is not None:
            span_id_clause = Helper.construct_key_expression("id", spanid)
        filter_by_clause = Helper.construct_filterby_expression(
            trace_id_clause, span_id_clause
        )
        query = Template(get_spans_for_trace_id).substitute(
            starttime=Helper.start_datetime_to_string(starttime),
            endtime=Helper.end_datetime_to_string(endtime),
            limit=self.limit,
            filter_by_clause=filter_by_clause,
        )
        demisto.debug(f"Span query: {query}")
        return self.graphql_query(query)

    def get_threat_events_query(
        self,
        starttime,
        endtime=datetime.now(),
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
        if len(api_id_list) == 0:
            return []
        query = self.get_api_endpoint_details_query(api_id_list, starttime, endtime)
        result = self.graphql_query(query)

        if Helper.is_error(result, "data", "entities", "results"):
            msg = "Error Object: " + json.dumps(result)
            demisto.error(msg)
            raise Exception(msg)

        return result["data"]["entities"]["results"]

    def get_threat_events(
        self,
        starttime,
        endtime=datetime.now(),
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
        api_id_list = []
        with ThreadPoolExecutor(max_workers=self.span_fetch_threadpool) as executor:
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
                    domain_event["apiId"] is not None
                    and domain_event["apiId"]["value"] is not None
                    and domain_event["apiId"]["value"] != "null"
                ):
                    api_id_list.append(domain_event["apiId"]["value"])

                demisto.info("Forking thread for span retrieval")

                future = executor.submit(
                    self.get_span_for_trace_id,
                    starttime=starttime,
                    endtime=endtime,
                    traceid=trace_id,
                    spanid=span_id,
                )
                demisto.info("Submitted job successfully.")
                future_list.append((domain_event, future))
                demisto.info("Completed thread for span retrieval")

        api_endpoint_details = []
        api_endpoint_details_map = {}

        if self.__query_api_attributes:
            api_endpoint_details = self.get_api_endpoint_details(
                api_id_list, starttime, endtime
            )
            api_endpoint_details_map = {
                api_endpoint_detail["id"]: api_endpoint_detail
                for api_endpoint_detail in api_endpoint_details
            }
        api_endpoint_details = None

        for domain_event, future in future_list:
            trace_results = future.result()
            domain_event["type"] = "Exploit"
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
                and "value" in domain_event["apiId"]
                and domain_event["apiId"]["value"] is not None
                and domain_event["apiId"]["value"] != "null"
                and domain_event["apiId"]["value"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]["value"]] is not None
                and "isExternal" in api_endpoint_details_map[domain_event["apiId"]["value"]]
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isExternal"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isExternal"
                ] != "null"
            ):
                if api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isExternal"
                ]:
                    domain_event["apiType"] = "External"
                else:
                    domain_event["apiType"] = "Internal"
            if (
                self.__query_api_attributes
                and "isAuthenticated" in self.optional_api_attributes
                and "apiId" in domain_event
                and "value" in domain_event["apiId"]
                and domain_event["apiId"]["value"] is not None
                and domain_event["apiId"]["value"] != "null"
                and domain_event["apiId"]["value"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]["value"]] is not None
                and "isAuthenticated" in api_endpoint_details_map[domain_event["apiId"]["value"]]
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isAuthenticated"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isAuthenticated"
                ]
                != "null"
            ):
                domain_event["apiIsAuthenticated"] = api_endpoint_details_map[domain_event["apiId"]["value"]]["isAuthenticated"]
            if (
                self.__query_api_attributes
                and "riskScore" in self.optional_api_attributes
                and "apiId" in domain_event
                and "value" in domain_event["apiId"]
                and domain_event["apiId"]["value"] is not None
                and domain_event["apiId"]["value"] != "null"
                and domain_event["apiId"]["value"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]["value"]] is not None
                and "riskScore" in api_endpoint_details_map[domain_event["apiId"]["value"]]
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "riskScore"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "riskScore"
                ]
                != "null"
            ):
                domain_event["apiRiskScore"] = api_endpoint_details_map[domain_event["apiId"]["value"]]["riskScore"]
            if (
                self.__query_api_attributes
                and "riskScoreCategory" in self.optional_api_attributes
                and "apiId" in domain_event
                and "value" in domain_event["apiId"]
                and domain_event["apiId"]["value"] is not None
                and domain_event["apiId"]["value"] != "null"
                and domain_event["apiId"]["value"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]["value"]] is not None
                and "riskScoreCategory" in api_endpoint_details_map[domain_event["apiId"]["value"]]
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "riskScoreCategory"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "riskScoreCategory"
                ]
                != "null"
            ):
                domain_event["apiRiskScoreCategory"] = api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "riskScoreCategory"
                ]

            if (
                self.__query_api_attributes
                and "isLearnt" in self.optional_api_attributes
                and "apiId" in domain_event
                and "value" in domain_event["apiId"]
                and domain_event["apiId"]["value"] is not None
                and domain_event["apiId"]["value"] != "null"
                and domain_event["apiId"]["value"] in api_endpoint_details_map
                and api_endpoint_details_map[domain_event["apiId"]["value"]] is not None
                and "isLearnt" in api_endpoint_details_map[domain_event["apiId"]["value"]]
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isLearnt"
                ] is not None
                and api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isLearnt"
                ]
                != "null"
            ):
                domain_event["apiIsLearnt"] = api_endpoint_details_map[domain_event["apiId"]["value"]][
                    "isLearnt"
                ]

            if "ipAddressType" not in domain_event:
                domain_event["ipAddressType"] = "Internal"

            if "apiType" not in domain_event and self.__query_api_attributes and "isExternal" in self.optional_api_attributes:
                domain_event["apiType"] = "Unknown"

            if ("id" in domain_event and "value" in domain_event["id"] and self.app_url != ""
                    and "environment" in domain_event and "value" in domain_event["environment"]):
                domain_event["eventUrl"] = (
                    f"{self.app_url}/security-event/"
                    + domain_event["id"]["value"]
                    + "?time=90d&env="
                    + parse.quote(domain_event["environment"]["value"])
                )

            if Helper.is_error(trace_results, "data", "spans", "results"):
                msg = f"Error Object: {json.dumps(result)}. Couldn't get the Span."
                demisto.info(msg)
            else:
                demisto.info(f"Found Span with id: {span_id}. Adding to Event with id {domain_event['id']['value']}.")
                if len(trace_results["data"]["spans"]["results"]) > 0:
                    domain_event["spans"] = trace_results["data"]["spans"]["results"][0]
                else:
                    demisto.info("Didn't find any spans. Span array length:"
                                 + f" {len(trace_results['data']['spans']['results'])}."
                                 + f" Span Object: {json.dumps(trace_results['data']['spans']['results'])}")

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
        end_time = datetime.now()
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
    items = client.get_threat_events(_last_fetch, datetime.now())
    demisto.info(f"Retrieved {len(items)} records.")
    if len(items) > 0:
        demisto.debug(f"First Incident: {json.dumps(items[0], indent=3)}")
    for item in items:
        incident_created_time: datetime = datetime.fromtimestamp(
            item["timestamp"]["value"] / 1000
        )
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
                and item["eventUrl"] is not None
                and item["eventUrl"] != ""):
            incident["eventUrl"] = item["eventUrl"]

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time.replace(
            tzinfo=timezone.utc
        ) > latest_created_time.replace(tzinfo=timezone.utc):
            latest_created_time = incident_created_time

    next_run = {"last_fetch": latest_created_time.strftime(DATE_FORMAT)}
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
        demisto.params().get("optionalAPIAttributes")

        _env = demisto.params().get("environment")

        environments = None
        if _env is not None and len(_env) > 0:
            environments = argToList(_env)

        apikey = demisto.params().get("credentials", {}).get("password")
        headers: dict = {"Authorization": apikey, "Content-Type": "application/json"}
        client = Client(
            base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

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

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
