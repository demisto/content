import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import urllib3
from string import Template
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter, Retry


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


class Helper:
    @staticmethod
    def construct_filterby_expression(*clauses):
        non_null_list = [i for i in clauses if i is not None]
        return "filterBy: [" + ",".join(non_null_list) + "]"

    @staticmethod
    def datetime_to_string(d):
        return d.strftime(DATE_FORMAT)

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
        self.limit = None
        self.proxy = proxy
        self.span_fetch_threadpool = 10
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

    def set_span_fetch_threadpool(self, span_fetch_threadpool):
        self.span_fetch_threadpool = span_fetch_threadpool

    def set_limit(self, limit):
        self.limit = limit

    def set_environments(self, environments):
        self.environments = environments

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
            starttime=Helper.datetime_to_string(starttime),
            endtime=Helper.datetime_to_string(endtime),
            limit=self.limit,
            filter_by_clause=filter_by_clause,
        )
        demisto.info("Query is: " + query)
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
        demisto.info("Limit set to: " + str(self.limit))
        query = Template(get_threat_events_query).substitute(
            limit=self.limit,
            starttime=Helper.datetime_to_string(starttime),
            endtime=Helper.datetime_to_string(endtime),
            filter_by_clause=filter_by_clause,
        )
        return query

    def get_threat_events(
        self,
        starttime,
        endtime=datetime.now(),
    ):
        query = self.get_threat_events_query(starttime, endtime)
        demisto.debug("Query is: " + query)
        result = self.graphql_query(query)
        if Helper.is_error(result, "data", "explore", "results"):
            msg = "Error Object: " + json.dumps(result)
            demisto.error(msg)
            raise Exception(msg)

        results = result["data"]["explore"]["results"]

        demisto.info("Retrieved: " + str(len(results)) + " Domain Events")
        demisto.debug("Result is:" + json.dumps(results, indent=2))

        events = []
        first = True
        future_list = []
        with ThreadPoolExecutor(max_workers=self.span_fetch_threadpool) as executor:
            for domain_event in results:
                if Helper.is_error(domain_event, "traceId", "value"):
                    demisto.info(
                        "Couldn't find traceId in Domain Event: "
                        + json.dumps(domain_event, indent=2)
                    )
                    continue
                if Helper.is_error(domain_event, "spanId", "value"):
                    demisto.info(
                        "Couldn't find spanId in Domain Event: "
                        + json.dumps(domain_event, indent=2)
                    )
                    continue

                trace_id = domain_event["traceId"]["value"]
                span_id = domain_event["spanId"]["value"]

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
                demisto.info(msg)
            else:
                demisto.info("Found Span with id: " + span_id + ". Adding to Event.")
                domain_event["spans"] = trace_results["data"]["spans"]["results"]
                events.append(domain_event)
                if first:
                    first = False
                    demisto.info("Domain Event: " + json.dumps(domain_event, indent=3))
                demisto.debug(
                    "Complete Domain Event is: " + json.dumps(domain_event, indent=2)
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
            "severity": XSOAR_SEVERITY_BY_TRACEABLE_SEVERITY.get(
                item["severity"], IncidentSeverity.UNKNOWN
            ),
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

    base_url = demisto.params()["url"]
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers: dict = {}
        first_fetch_time = demisto.params().get("first_fetch", "3 days").strip()
        securityScoreCategoryList = demisto.params().get("securityScoreCategory")
        threatCategoryList = demisto.params().get("threatCategory")
        ipReputationLevelList = demisto.params().get("ipReputationLevel")
        ipAbuseVelocityList = demisto.params().get("ipAbuseVelocity")
        limit = int(demisto.params().get("max_fetch", 100))
        span_fetch_threadpool = int(demisto.params().get("span_fetch_threadpool", 10))

        _env = demisto.params().get("environment")

        environments = None
        if _env is not None and len(_env) > 0:
            environments = argToList(_env)

        apikey = demisto.params().get("credentials", {}).get("password")
        headers["Authorization"] = apikey
        headers["Content-Type"] = "application/json"

        client = Client(
            base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        client.set_security_score_category_list(securityScoreCategoryList)
        client.set_threat_category_list(threatCategoryList)
        client.set_ip_reputation_level_list(ipReputationLevelList)
        client.set_ip_abuse_velocity_list(ipAbuseVelocityList)
        client.set_environments(environments)
        client.set_span_fetch_threadpool(span_fetch_threadpool)
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
