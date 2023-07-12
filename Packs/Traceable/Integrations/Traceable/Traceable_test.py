#!/usr/bin/env python -W ignore::DeprecationWarning

sample_span_result = """{
  "data": {
    "spans": {
      "results": [
        {
          "id": "f7dded93dc8b49c7",
          "protocolName": "HTTP",
          "serviceName": "frontend",
          "displaySpanName": "POST /get_user",
          "userIdentifier": "xxx@outlook.zz",
          "sessionId": "00b79cf7-f47a-7903-2b72-f6c3c65ae04e",
          "ipAddress": "8.8.8.8",
          "userCountry": "United States",
          "userCity": "Houston",
          "userRoles": [
            "customer"
          ],
          "statusCode": "200",
          "errorCount": 0,
          "duration": 38,
          "startTime": 1687388481641,
          "endTime": 1687388481679,
          "traceId": "a1f93e44b31be69835cfeeac4f181869",
          "spanTags": {
            "net.peer.port": "5355",
            "http.url": "http://localhost:1111/get_user?forwardUrl=http%3A%2F%2Fdummyjon.com",
            "enduser.role": "customer",
            "net.peer.ip": "8.8.8.8",
            "net.host.ip": "8.8.8.8",
            "traceableai.enriched.api_type": "HTTP",
            "http.status_code": "200",
            "enduser.id": "xxx@outlook.zz",
            "enduser.id.rule": "0394b434-1def-4b4b-8aa7-c7d03fb8dd57",
            "span.kind": "server",
            "traceableai.module.version": "1.0.5",
            "enduser.role.rule": "0394b434-1def-4b4b-8aa7-c7d03fb8dd57",
            "servicename": "frontend",
            "http.method": "POST",
            "deployment.environment": "Fintech_app",
            "session.id": "00b79cf7-f47a-7903-2b72-f6c3c65ae04e",
            "traceableai.module.name": "proxy"
          },
          "spanResponseHeaders": {
            "content-type": "application/json"
          },
          "spanResponseCookies": {},
          "spanRequestBody": "email=xxx@outlook.zz&password=${<script alert(1) />}",
          "spanRequestHeaders": {
            "content-type": "application/json",
            "x-forwarded-for": "8.8.8.8"
          },
          "spanRequestCookies": {}
        }
      ]
    }
  }
}"""

empty_domain_event = """{
  "data": {
    "explore": {
      "results": []
    }
  }
}"""

sample_domain_event = """{
  "data": {
    "explore": {
      "results": [
        {
          "threatCategory": {
            "value": "null"
          },
          "id": {
            "value": "9dd9261a-23db-472e-9d2a-a4c3227d6502"
          },
          "name": {
            "value": "XSS Filter - Category 1: Script Tag Vector"
          },
          "type": {
            "value": "Cross Site Scripting (XSS)"
          },
          "environment": {
            "value": "Fintech_app"
          },
          "serviceName": {
            "value": "frontend"
          },
          "apiName": {
            "value": "POST /get_user"
          },
          "apiId": {
            "value": "067bb0d7-3740-3ba6-89eb-c457491fbc53"
          },
          "serviceId": {
            "value": "3d67aadf-4605-385d-bd3a-b297789046fd"
          },
          "threatActorScore": {
            "value": -2147483648
          },
          "anomalousAttribute": {
            "value": "default.password"
          },
          "eventDescription": {
            "value": "Matched Data: <script alert(1) /> found within ARGS:password: ${<script alert(1) />}"
          },
          "actorId": {
            "value": "xxx@outlook.zz"
          },
          "actorCountry": {
            "value": "United States"
          },
          "actorIpAddress": {
            "value": "8.8.8.8"
          },
          "actorDevice": {
            "value": "null"
          },
          "apiUri": {
            "value": "http://localhost:1111/get_user?forwardUrl=http%3A%2F%2Fdummyjon.com"
          },
          "traceId": {
            "value": "a1f93e44b31be69835cfeeac4f181869"
          },
          "statusCode": {
            "value": "200"
          },
          "actorEntityId": {
            "value": "null"
          },
          "actorScoreCategory": {
            "value": "null"
          },
          "securityScoreCategory": {
            "value": "LOW"
          },
          "securityScore": {
            "value": 0
          },
          "category": {
            "value": "SECURITY"
          },
          "securityEventType": {
            "value": "MODSEC"
          },
          "ipCategories": {
            "value": [
              "IP_LOCATION_TYPE_PUBLIC_PROXY",
              "IP_LOCATION_TYPE_BOT"
            ]
          },
          "ipReputationLevel": {
            "value": "CRITICAL"
          },
          "ipAbuseVelocity": {
            "value": "HIGH"
          },
          "spanId": {
            "value": "f7dded93dc8b49c7"
          },
          "actorSession": {
            "value": "00b79cf7-f47a-7903-2b72-f6c3c65ae04e"
          },
          "timestamp": {
            "value": 1687388516786
          }
        }
      ]
    }
  }
}"""


class Response:
    def __init__(self) -> None:
        pass

    status_code = 200
    text = None  # type: str


def empty_response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]

    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = empty_domain_event
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    return None


def response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]

    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = sample_domain_event
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    return None


def test_fetch_incidents_last_fetch_none(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1


def test_fetch_incidents_last_fetch_not_none(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler

    next_run, incidents = fetch_incidents(
        client, {"last_fetch": "2023-06-26T15:34:53Z"}, "3 days"
    )
    assert len(incidents) == 1


def test_fetch_incidents_no_events(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = empty_response_handler

    next_run, incidents = fetch_incidents(
        client, {"last_fetch": "2023-06-26T15:34:53Z"}, "3 days"
    )
    assert len(incidents) == 0


def test_construct_filterby_expression():
    from Traceable import Helper

    filterBy = Helper.construct_filterby_expression("a", "b", "c", None)
    assert filterBy == "filterBy: [a,b,c]"


def test_construct_key_expression_key_none():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", None)
    assert key_exp == ""


def test_construct_key_expression_in_str():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", "value")
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: IN, value: ["value"], type: ATTRIBUTE}'
    )


def test_construct_key_expression_in_int():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", 1)
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: IN, value: [1], type: ATTRIBUTE}'
    )


def test_construct_key_expression_in_int_list():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", [1, 2])
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: IN, value: [1,2], type: ATTRIBUTE}'
    )


def test_construct_key_expression_in_str_list():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", ["value1", "value2"])
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: IN, value: ["value1","value2"], type: ATTRIBUTE}'
    )


def test_construct_key_expression_in_none(caplog):
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", None)
    assert key_exp == ""
    caplog.clear()


def test_construct_key_expression_equals_str():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", "value", operator="EQUALS")
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: EQUALS, value: "value", type: ATTRIBUTE}'
    )


def test_construct_key_expression_equals_int():
    from Traceable import Helper

    key_exp = Helper.construct_key_expression("key", 5, operator="EQUALS")
    assert (
        key_exp
        == '{keyExpression: {key: "key"}, operator: EQUALS, value: 5, type: ATTRIBUTE}'
    )


def test_construct_key_expression_unknown_op():
    from Traceable import Helper

    encountered_exception = False
    try:
        Helper.construct_key_expression("key", 5, operator="NONEXISTENT")
    except Exception as e:
        assert str(e) == "Unknown Operator: NONEXISTENT"
        encountered_exception = True
    assert encountered_exception


def test_is_error():
    from Traceable import Helper

    trace_results: dict = {}
    trace_results["data"] = {}
    trace_results["data"]["spans"] = {}
    is_error = Helper.is_error(trace_results, "data", "spans", "results")
    assert is_error is True


def test_is_error_none_obj():
    from Traceable import Helper

    is_error = Helper.is_error(None, "data", "spans", "results")
    assert is_error is True


def test_graphql_query(mocker):
    from Traceable import Client
    import json

    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    mocked_post = mocker.patch("requests.post")
    resp = Response()
    resp.status_code = 200
    resp.text = json.dumps({"data": "result"})
    mocked_post.return_value = resp
    client = Client(base_url="https://mock.url", verify=False, headers=headers)

    response_obj = client.graphql_query("query")
    assert response_obj is not None
    assert "data" in response_obj
    assert response_obj["data"] == "result"


def test_errors_in_response(caplog, mocker):
    from Traceable import Client
    import json

    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    mocked_post = mocker.patch("requests.post")
    resp = Response()
    resp.status_code = 200
    resp.text = json.dumps({"error": "error string"})
    mocked_post.return_value = resp
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    result = None
    is_error, result = client.errors_in_response(resp)
    caplog.clear()
    assert is_error is True
    assert result == "error string"


def test_get_span_for_trace_id(caplog, mocker):
    from Traceable import Client
    from datetime import datetime

    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    mocked_post = mocker.patch("requests.post")
    resp = Response()
    resp.status_code = 200
    resp.text = sample_span_result
    mocked_post.return_value = resp
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    now_time = datetime.now()
    response_obj = client.get_span_for_trace_id(now_time, now_time, "traceid", "spanid")
    caplog.clear()
    assert len(response_obj) == 1


def test_get_threat_events(caplog, mocker):
    from Traceable import Client
    from datetime import datetime
    import urllib3

    now_time = datetime.now()
    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler

    events = client.get_threat_events(now_time)
    assert len(events) == 1
    caplog.clear()


def test_get_threat_events_query():
    from Traceable import Client, DATE_FORMAT
    from datetime import datetime
    import urllib3

    output_query = """{\n  explore(\n    scope: "DOMAIN_EVENT"\n    limit: 100\n    between: {\n      \
startTime: "2023-06-20T15:34:56Z"\n      endTime: "2023-06-26T15:34:53Z"\n    }\n    offset: 0\n    \
filterBy: [{keyExpression: {key: "securityScoreCategory"}, operator: IN, value: ["CRITICAL","HIGH",\
"MEDIUM","LOW"], type: ATTRIBUTE},{keyExpression: {key: "ipReputationLevel"}, operator: IN, value\
: ["CRITICAL","HIGH","MEDIUM","LOW"], type: ATTRIBUTE},{keyExpression: {key: "ipAbuseVelocity"}, operator: \
IN, value: ["CRITICAL","HIGH","MEDIUM","LOW"], type: ATTRIBUTE}]\n    orderBy: [\n      { keyExpression: { key: \
"timestamp" } }\n    ]\n  ) {\n    results {\n      threatCategory: selection(expression: {key: "threatCategory"\
}) {\n        value\n      }\n      id: selection(expression: { key: "id" }) {\n        value\n      }\n      \
name: selection(expression: { key: "name" }) {\n        value\n      }\n      type: selection(expression: { key: \
"type" }) {\n        value\n      }\n      environment: selection(expression: { key: "environment" }) {\n        \
value\n      }\n      serviceName: selection(expression: { key: "serviceName" }) {\n        value\n      }\n      \
apiName: selection(expression: { key: "apiName" }) {\n        value\n      }\n      apiId: selection(expression: { \
key: "apiId"}) {\n        value\n      }\n      serviceId: selection(expression: { key: "serviceId" }) {\n        \
value\n      }\n      threatActorScore: selection(expression: { key: "actorScore" }) {\n        value\n      }\n      \
anomalousAttribute: selection(expression: { key: "anomalousAttribute" }) {\n        value\n      }\n      \
eventDescription: selection(expression: { key: "eventDescription" }) {\n        value\n      }\n      \
actorId: selection(expression: { key: "actorId" }) {\n        value\n      }\n      actorCountry: selection(\
expression: { key: "actorCountry" }) {\n        value\n      }\n      actorIpAddress: selection(expression: { \
key: "actorIpAddress" }) {\n        value\n      }\n      actorDevice: selection(expression: { key: "actorDevice" \
}) {\n        value\n      }\n      apiUri: selection(expression: { key: "apiUri" }) {\n        value\n      \
}\n      traceId: selection(expression: { key: "traceId" }) {\n        value\n      }\n      statusCode: selection(\
expression: { key: "statusCode" }) {\n        value\n      }\n      actorEntityId: selection(expression: { \
key: "actorEntityId" }) {\n        value\n      }\n      actorScoreCategory: selection(expression: { key: \
"actorScoreCategory" }) {\n        value\n      }\n      securityScoreCategory: selection(\n        expression: { \
key: "securityScoreCategory" }\n      ) {\n        value\n      }\n      securityScore: selection(expression: { \
key: "securityScore" }) {\n        value\n      }\n      category: selection(expression: { key: "category" }) \
{\n        value\n      }\n      securityEventType: selection(expression: { key: "securityEventType" }) {\n        \
value\n      }\n      ipCategories: selection(expression: { key: "ipCategories" }) {\n        value\n      }\n      \
ipReputationLevel: selection(expression: { key: "ipReputationLevel" }) {\n        value\n      }\n      \
ipAbuseVelocity: selection(expression: { key: "ipAbuseVelocity" }) {\n        value\n      }\n      \
spanId: selection(expression: { key: "spanId" }) {\n        value\n      }\n      actorSession: \
selection(expression: { key: "actorSession" }) {\n        value\n      }\n      timestamp: selection(\
expression: { key: "timestamp" }) {\n        value\n      }\n    }\n  }\n}\n"""

    starttime = datetime.strptime("2023-06-20T15:34:56Z", DATE_FORMAT)
    endtime = datetime.strptime("2023-06-26T15:34:53Z", DATE_FORMAT)
    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    query = client.get_threat_events_query(starttime, endtime)
    assert query == output_query


def test_env_param_parsing():
    from CommonServerPython import argToList

    env = "a, b , c, d, e "
    env_list = argToList(env)
    assert len(env_list) == 5


def test_datetime_to_string():
    from Traceable import Helper, DATE_FORMAT
    from datetime import datetime

    test_date_str = "2023-06-26T15:34:53Z"
    dt_object = datetime.strptime(test_date_str, DATE_FORMAT)
    dt_str = Helper.datetime_to_string(dt_object)
    assert dt_str == test_date_str


def test_client_creation_no_headers():
    from Traceable import Client

    client = Client("https://mock.url")
    assert type(client.headers) == dict
    assert "Content-Type" in client.headers
    assert client.headers["Content-Type"] == "application/json"


def test_graphql_query_non_200(mocker, caplog, capfd):
    from Traceable import Client

    resp = Response()
    resp.status_code = 400
    resp.text = "error"
    client = Client("https://mock.url")
    mocked_post = mocker.patch("requests.post")
    mocked_post.return_value = resp
    encountered_exception = False
    try:
        client.graphql_query("query")
    except Exception as e:
        encountered_exception = True
        assert str(e) == "Error occurred: error | Status Code: 400"
    assert encountered_exception
    caplog.clear()
    capfd.readouterr()
