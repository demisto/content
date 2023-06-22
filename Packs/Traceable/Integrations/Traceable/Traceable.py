import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import urllib3
from typing import Dict, Any
from string import Template
from datetime import datetime, timezone
import logging
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter, Retry


# Disable insecure warnings
urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="[%(filename)s:%(lineno)s - %(funcName)15s() ] %(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s",
    handlers=[logging.StreamHandler()],
)

s = requests.Session()
retries = Retry(
    total=30,
    connect=10,
    read=10,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
s.mount("http://", HTTPAdapter(max_retries=retries))
s.mount("https://", HTTPAdapter(max_retries=retries))


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

get_traces_query = """
query GetTraces($limit: Int!, $starttime: DateTime!, $endtime: DateTime!)
{
  traces(
    type: API_TRACE
    limit: $limit
    between: {startTime: $starttime, endTime: $endtime}
    offset: 0
    filterBy: [{keyExpression: {key: "environment"}, operator: IN, value: ["production"], type: ATTRIBUTE}]
  ) {
    results {
      id
      environment: attribute(expression: {key: "environment"})
      apiName: attribute(expression: {key: "apiName"})
      apiId: attribute(expression: {key: "apiId"})
      isExternal: attribute(expression: {key: "isExternal"})
      ipAddress: attribute(expression: {key: "ipAddress"})
      requestUrl: attribute(expression: {key: "requestUrl"})
      status: attribute(expression: {key: "status"})
      statusCode: attribute(expression: {key: "statusCode"})
      statusMessage: attribute(expression: {key: "statusMessage"})
      startTime: attribute(expression: {key: "startTime"})
    }
    total
  }
}
"""

get_traces_query_template = """
{
  traces(
    type: API_TRACE
    limit: $limit
    between: {startTime: "$starttime", endTime: "$endtime"}
    offset: 0
    $filter_by_clause
  ) {
    results {
      id
      environment: attribute(expression: {key: "environment"})
      apiName: attribute(expression: {key: "apiName"})
      apiId: attribute(expression: {key: "apiId"})
      isExternal: attribute(expression: {key: "isExternal"})
      ipAddress: attribute(expression: {key: "ipAddress"})
      requestUrl: attribute(expression: {key: "requestUrl"})
      status: attribute(expression: {key: "status"})
      statusCode: attribute(expression: {key: "statusCode"})
      statusMessage: attribute(expression: {key: "statusMessage"})
      startTime: attribute(expression: {key: "startTime"})
    }
    total
  }
}
"""

get_endpoints_query = """
query GetEndPoints($limit: Int!, $starttime: DateTime!, $endtime: DateTime!)
{
  entities5: entities(
    scope: "API"
    limit: $limit
    between: {startTime: "$starttime", endTime: "$endtime"}
    offset: 0
    orderBy: [{direction: DESC, keyExpression: {key: "apiRiskScore"}}]
    filterBy: [{keyExpression: {
        key: "apiDiscoveryState"
        }, 
        operator: IN, value: ["DISCOVERED", "UNDER_DISCOVERY"], type: ATTRIBUTE}, 
        {keyExpression: {key: "environment"}, operator: EQUALS, value: "production", type: ATTRIBUTE}]
    includeInactive: false
  ) {
    results {
      id
      name: attribute(expression: {key: "name"})
      isAuthenticated: attribute(expression: {key: "isAuthenticated"})
      changeLabel: attribute(expression: {key: "changeLabel"})
      changeLabelTimestamp: attribute(expression: {key: "changeLabelTimestamp"})
      isExternal: attribute(expression: {key: "isExternal"})
      labels {
        count
        total
        results {
          id
          key
          description
          color
        }
      }
      isLearnt: attribute(expression: {key: "isLearnt"})
      serviceId: attribute(expression: {key: "serviceId"})
      piiTypes: attribute(expression: {key: "piiTypes"})
      dataTypeIds: attribute(expression: {key: "dataTypeIds"})
      serviceName: attribute(expression: {key: "serviceName"})
      apiRiskScore: attribute(expression: {key: "apiRiskScore"})
      apiRiskScoreCategory: attribute(expression: {key: "apiRiskScoreCategory"})
      riskLikelihoodFactors: attribute(expression: {key: "riskLikelihoodFactors"})
      riskImpactFactors: attribute(expression: {key: "riskImpactFactors"})
      numCalls: metric(expression: {key: "numCalls"}) {
        sum {
          value
        }
      }
      errorCount: metric(expression: {key: "errorCount"}) {
        sum {
          value
        }
      }
      lastCalledTimestamp: attribute(expression: {key: "lastCalledTimestamp"})
    }
    total
  }
}
"""

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
      threatCategory: selection(expression: {key: "threatCategory"}) {
        value
      }
      id: selection(expression: { key: "id" }) {
        value
      }
      name: selection(expression: { key: "name" }) {
        value
      }
      type: selection(expression: { key: "type" }) {
        value
      }
      environment: selection(expression: { key: "environment" }) {
        value
      }
      serviceName: selection(expression: { key: "serviceName" }) {
        value
      }
      apiName: selection(expression: { key: "apiName" }) {
        value
      }
      apiId: selection(expression: { key: "apiId"}) {
        value
      }
      serviceId: selection(expression: { key: "serviceId" }) {
        value
      }
      threatActorScore: selection(expression: { key: "actorScore" }) {
        value
      }
      anomalousAttribute: selection(expression: { key: "anomalousAttribute" }) {
        value
      }
      eventDescription: selection(expression: { key: "eventDescription" }) {
        value
      }
      actorId: selection(expression: { key: "actorId" }) {
        value
      }
      actorCountry: selection(expression: { key: "actorCountry" }) {
        value
      }
      actorIpAddress: selection(expression: { key: "actorIpAddress" }) {
        value
      }
      actorDevice: selection(expression: { key: "actorDevice" }) {
        value
      }
      apiUri: selection(expression: { key: "apiUri" }) {
        value
      }
      traceId: selection(expression: { key: "traceId" }) {
        value
      }
      statusCode: selection(expression: { key: "statusCode" }) {
        value
      }
      actorEntityId: selection(expression: { key: "actorEntityId" }) {
        value
      }
      actorScoreCategory: selection(expression: { key: "actorScoreCategory" }) {
        value
      }
      securityScoreCategory: selection(
        expression: { key: "securityScoreCategory" }
      ) {
        value
      }
      securityScore: selection(expression: { key: "securityScore" }) {
        value
      }
      category: selection(expression: { key: "category" }) {
        value
      }
      securityEventType: selection(expression: { key: "securityEventType" }) {
        value
      }
      ipCategories: selection(expression: { key: "ipCategories" }) {
        value
      }
      ipReputationLevel: selection(expression: { key: "ipReputationLevel" }) {
        value
      }
      ipAbuseVelocity: selection(expression: { key: "ipAbuseVelocity" }) {
        value
      }
      spanId: selection(expression: { key: "spanId" }) {
        value
      }
      actorSession: selection(expression: { key: "actorSession" }) {
        value
      }
      timestamp: selection(expression: { key: "timestamp" }) {
        value
      }
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
    # total
  }
}
"""


""" CLIENT CLASS """


class Helper:
    @staticmethod
    def apiname_to_filename_prefix(apiname: str):
        return (
            apiname.lower()
            .replace(" ", "_")
            .replace("/", "_")
            .replace("{", "")
            .replace("}", "")
            .replace("-", "_")
            .replace("%", "")
        )

    @staticmethod
    def get_specific_yaml_config(config: dict):
        config_name = config["use_config"]
        for config_item in config["config_list"]:
            if config_item["name"] == config_name:
                return config_item
        return None

    @staticmethod
    def construct_filterby_expression(*clauses):
        non_null_list = [i for i in clauses if i is not None]
        return "filterBy: [" + ",".join(non_null_list) + "]"

    @staticmethod
    def datetime_to_string(d: datetime):
        return d.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def needs_quoting(s):
        _type = type(s)
        if _type == float or _type == int or _type == bool:
            return False
        else:
            return True

    @staticmethod
    def list_to_string(items):
        s = ""
        start = True
        for item in items:
            if Helper.needs_quoting(item):
                _s = '"' + str(item) + '"'
            else:
                _s = str(item)
            if start:
                s = _s
                start = False
            else:
                s = "," + s
        return s

    @staticmethod
    def construct_key_expression(key, value, _type="ATTRIBUTE", operator="IN"):
        # "filterBy: [{keyExpression: {key: \"environment\"}, operator: IN, value: [\"" + environment + "\"], type: ATTRIBUTE}]"
        if key is None:
            logging.warning("Key was None. Couldn't create Key Expression.")
            return ""
        if operator == "IN":
            _value = value
            if value is not None:
                if type(value) == str:
                    _value = '"' + value + '"'
                elif type(value) == int or type(value) == float:
                    _value = value
                elif type(value) == list and len(value) > 0:
                    if type(value[0]) == str:
                        _value = '"' + '","'.join(value) + '"'
                    elif type(value[0]) == int or type(value[0]) == float:
                        _value = ",".join(value)
            else:
                logging.warning(
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
                + _value
                + "], type: "
                + _type
                + "}"
            )
        elif operator == "EQUALS":
            return (
                '{keyExpression: {key: "'
                + key
                + '"}, operator: '
                + operator
                + ", value: "
                + value
                + ", type: "
                + type
                + "}"
            )
        else:
            raise Exception("Unknown Operator: " + operator)

    @staticmethod
    def get_now_time():
        return datetime.now()

    @staticmethod
    def date_arithmetic(time: datetime, op: str, unit: str, _delta: int):
        d = None
        _unit = unit.lower()
        if _unit == "hours":
            d = timedelta(hours=_delta)
        elif _unit == "minutes":
            d = timedelta(minutes=_delta)
        elif _unit == "seconds":
            d = timedelta(seconds=_delta)
        elif _unit == "days":
            d = timedelta(days=_delta)
        elif _unit == "weeks":
            d = timedelta(weeks=_delta)
        elif _unit == "microseconds":
            d = timedelta(microseconds=_delta)
        elif _unit == "milliseconds":
            d = timedelta(milliseconds=_delta)
        else:
            raise Exception("Unit: " + _unit + " unknown.")

        _op = op.lower()
        if _op == "minus":
            return time - d
        elif _op == "plus":
            return time + d
        else:
            raise Exception("Unknown operation: " + _op)

    @staticmethod
    def is_error(obj, *hierarchy):
        if obj is None:
            return True
        _obj = obj
        for el in hierarchy:
            if _obj[el] is None:
                return True
            _obj = _obj[el]
        return False

    @staticmethod
    def convert_results_to_csv(results: dict, filename: str):
        with open(filename, "w") as f:
            f.write("Session ID, Token Type, Auth Type, Call Count\n")
            for item in results["explore"]["results"]:
                session_id = item["sessionId"]["value"]
                tags_session_token_type = item["tags_session_token_type"]["value"]
                tags_traceableai_auth_types = (
                    '"'
                    + item["tags_traceableai_auth_types"]["value"][1:-1].replace(
                        '"', ""
                    )
                    + '"'
                )
                count_calls = item["count_calls"]["value"]
                op = (
                    session_id
                    + ","
                    + tags_session_token_type
                    + ","
                    + tags_traceableai_auth_types
                    + ","
                    + str(count_calls)
                )

                # print(op)
                f.write(op + "\n")


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    REQUESTS_TIMEOUT = 60

    def __init__(
        self,
        base_url,
        verify=True,
        proxy=False,
        ok_codes=tuple(),
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
        self.limit = None
        self.environments = None
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth, timeout)

    def set_security_score_category_list(self, securityScoreCategoryList):
        self.securityScoreCategoryList = securityScoreCategoryList

    def set_threat_category_list(self, threatCategoryList):
        self.threatCategoryList = threatCategoryList

    def set_ip_reputation_level_list(self, ipReputationLevelList):
        self.ipReputationLevelList = ipReputationLevelList

    def set_ip_abuse_velocity_list(self, ipAbuseVelocityList):
        self.ipAbuseVelocityList = ipAbuseVelocityList

    def set_limit(self, limit):
        self.limit = limit

    def set_environments(self, environments):
        self.environments = environments

    def graphql_query(self, query, params={}, verify=False):
        response = requests.post(
            self.url,
            json={"query": query, "variables": {}},
            headers=self.headers,
            verify=verify,
        )

        if response is not None and response.status_code != 200:
            if response.text is not None:
                msg = (
                    "Error occurred: "
                    + response.text
                    + " | Status Code: "
                    + str(response.status_code)
                )
                logging.error(msg)
                raise Exception(msg)

        is_error, error = self.errors_in_response(response)
        if is_error:
            logging.error(error)
            raise Exception(error)

        if response is not None and response.text is not None:
            response_obj = json.loads(response.text)
            return response_obj

        raise Exception("Something went wrong: " + json.dumps(response, indent=2))

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
            logging.error(msg)
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
            starttime=Helper.datetime_to_string(starttime),
            endtime=Helper.datetime_to_string(endtime),
            limit=self.limit,
            filter_by_clause=filter_by_clause,
        )
        logging.debug("Query is: " + query)
        return self.graphql_query(query)

    def get_threat_events(
        self, starttime: datetime, endtime: datetime = datetime.now()
    ):
        environment_clause = None
        securityScoreCategory_clause = None
        threatCategory_clause = None
        ipReputationLevel_clause = None
        ipAbuseVelocity_clause = None

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

        if self.ipAbuseVelocityList is not None and len(self.ipAbuseVelocityList) > 0:
            ipAbuseVelocity_clause = Helper.construct_key_expression(
                "ipAbuseVelocity", self.ipAbuseVelocityList
            )

        filter_by_clause = Helper.construct_filterby_expression(
            environment_clause,
            securityScoreCategory_clause,
            threatCategory_clause,
            ipReputationLevel_clause,
            ipAbuseVelocity_clause,
        )
        logging.info("Limit set to: " + str(self.limit))
        query = Template(get_threat_events_query).substitute(
            limit=self.limit,
            starttime=Helper.datetime_to_string(starttime),
            endtime=Helper.datetime_to_string(endtime),
            filter_by_clause=filter_by_clause,
        )
        logging.debug("Query is: " + query)
        result = self.graphql_query(query)
        if Helper.is_error(result, "data", "explore", "results"):
            msg = "Error Object: " + json.dumps(result)
            logging.error(msg)
            raise Exception(msg)

        results = result["data"]["explore"]["results"]

        logging.info("Retrieved: " + str(len(results)) + " Domain Events")
        logging.debug("Result is:" + json.dumps(results, indent=2))

        events = []
        first = True
        future_list = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            for domain_event in results:
                if Helper.is_error(domain_event, "traceId", "value"):
                    logging.warning(
                        "Couldn't find traceId in Domain Event: "
                        + json.dumps(domain_event, indent=2)
                    )
                    continue
                if Helper.is_error(domain_event, "spanId", "value"):
                    logging.warning(
                        "Couldn't find spanId in Domain Event: "
                        + json.dumps(domain_event, indent=2)
                    )
                    continue

                trace_id = domain_event["traceId"]["value"]
                span_id = domain_event["spanId"]["value"]

                logging.info("Forking thread for span retrieval")

                future = executor.submit(
                    self.get_span_for_trace_id,
                    starttime=starttime,
                    endtime=endtime,
                    traceid=trace_id,
                    spanid=span_id,
                )
                future_list.append((domain_event, future))
                logging.info("Completed thread for span retrieval")

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

            if Helper.is_error(trace_results, "data", "spans", "results"):
                msg = "Error Object: " + json.dumps(result) + ". Couldn't get the Span."
                logging.warning(msg)
            else:
                logging.info("Found Span with id: " + span_id + ". Adding to Event.")
                domain_event["spans"] = []
                domain_event["spans"] = trace_results["data"]["spans"]["results"]
                events.append(domain_event)
                if first:
                    first = False
                    logging.info("Domain Event: " + json.dumps(domain_event, indent=3))
                logging.debug(
                    "Complete Domain Event is: " + json.dumps(domain_event, indent=2)
                )

        return events

    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


""" HELPER FUNCTIONS """

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(
            e
        ):  # TODO: make sure you capture authentication errors
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    dummy = args.get("dummy", None)
    if not dummy:
        raise ValueError("dummy not specified")

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def fetch_incidents(client: Client, last_run, first_fetch_time):
    last_fetch = last_run.get("last_fetch")

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.get_threat_events(last_fetch, datetime.now())
    demisto.info("Retrieved " + str(len(items)) + " records.")
    logging.debug("First Incident: " + json.dumps(items[0], indent=3))
    for item in items:
        incident_created_time = datetime.fromtimestamp(
            item["timestamp"]["value"] / 1000
        )
        incident = {
            "name": item["name"],
            "displayname": item["displayname"],
            "country": item["country"],
            "sourceip": item["sourceip"],
            "riskscore": item["riskscore"],
            # 'severity': item['severity'],
            "occurred": incident_created_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rawJSON": json.dumps(item),
        }

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

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = demisto.params()["url"]

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get("insecure", False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}
        first_fetch_time = demisto.params().get("first_fetch", "3 days").strip()
        securityScoreCategoryList = demisto.params().get("securityScoreCategory")
        threatCategoryList = demisto.params().get("threatCategory")
        ipReputationLevelList = demisto.params().get("ipReputationLevel")
        ipAbuseVelocityList = demisto.params().get("ipAbuseVelocity")
        limit = int(demisto.params().get("max_fetch", 100))

        _env = demisto.params().get("environment")

        environments = None
        if _env is not None and len(_env) > 0:
            environments = []
            _env_list = _env.split(",")
            for _env_item in _env_list:
                environments.append(_env_item.strip())

        apikey = demisto.params().get("credentials", {}).get("password")
        headers["Authorization"] = apikey
        headers["Content-Type"] = "application/json"

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        client.set_security_score_category_list(securityScoreCategoryList)
        client.set_threat_category_list(threatCategoryList)
        client.set_ip_reputation_level_list(ipReputationLevelList)
        client.set_ip_abuse_velocity_list(ipAbuseVelocityList)
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

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
