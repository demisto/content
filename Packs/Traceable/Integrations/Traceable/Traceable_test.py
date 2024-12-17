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

sample_api_result = """{
  "data": {
    "entities": {
      "results": [
        {
          "id": "ea0f77c0-adc2-3a69-89ea-93b1c8341d8f",
          "name": "POST /cart",
          "isExternal": true,
          "isAuthenticated": true,
          "isLearnt": true,
          "riskScore": 2,
          "riskScoreCategory": "LOW"
        },
        {
          "id": "067bb0d7-3740-3ba6-89eb-c457491fbc53",
          "name": "POST /get_user",
          "isExternal": true,
          "isLearnt": true,
          "isAuthenticated": true,
          "riskScore": 3,
          "riskScoreCategory": "MEDIUM"
        },
        {
          "id": "be344182-c100-3287-874a-cb47eac709f2",
          "name": "POST /cart",
          "isExternal": false,
          "isLearnt": true,
          "isAuthenticated": true,
          "riskScore": 2,
          "riskScoreCategory": "LOW"
        }
      ],
      "total": 3
    }
  }
}"""

sample_private_api_result = """{
  "data": {
    "entities": {
      "results": [
        {
          "id": "ea0f77c0-adc2-3a69-89ea-93b1c8341d8f",
          "name": "POST /cart",
          "isExternal": false,
          "isLearnt": true,
          "isAuthenticated": true,
          "riskScore": 2,
          "riskScoreCategory": "LOW"
        },
        {
          "id": "067bb0d7-3740-3ba6-89eb-c457491fbc53",
          "name": "POST /get_user",
          "isExternal": false,
          "isLearnt": true,
          "isAuthenticated": true,
          "riskScore": 3,
          "riskScoreCategory": "MEDIUM"
        },
        {
          "id": "be344182-c100-3287-874a-cb47eac709f2",
          "name": "POST /cart",
          "isExternal": false,
          "isLearnt": true,
          "isAuthenticated": true,
          "riskScore": 2,
          "riskScoreCategory": "LOW"
        }
      ],
      "total": 3
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

sample_domain_event_empty_api = """{
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
            "value": "null"
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


sample_domain_event_with_private_ip = """{
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
            "value": "192.168.11.20"
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
              "IP_LOCATION_TYPE_UNSPECIFIED"
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
    text = ""  # type: str


def empty_response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]

    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = empty_domain_event
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    elif "entities(" in data:
        r.text = sample_api_result
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
    elif "entities(" in data:
        r.text = sample_api_result
        return r
    return None


def response_handler_private_ip(*args, **kwargs):
    data: str = kwargs["json"]["query"]

    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = sample_domain_event_with_private_ip
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    elif "entities(" in data:
        r.text = sample_api_result
        return r
    return None


def empty_api_response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]
    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = sample_domain_event_empty_api
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    elif "entities(" in data:
        r.text = sample_api_result
        return r
    return None


def public_api_type_response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]
    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = sample_domain_event
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    elif "entities(" in data:
        r.text = sample_api_result
        return r
    return None


def private_api_type_response_handler(*args, **kwargs):
    data: str = kwargs["json"]["query"]
    r = Response()
    if "DOMAIN_EVENT" in data:
        r.text = sample_domain_event_with_private_ip
        return r
    elif "spans(" in data:
        r.text = sample_span_result
        return r
    elif "entities(" in data:
        r.text = sample_private_api_result
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
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_app_url("https://app.mock.url")
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    assert incidents[0]["ipAddressType"] == "External"
    assert incidents[0]["eventUrl"] == (
        'https://app.mock.url/security-event/9dd9261a-23db-472e-9d2a-a4c3227d6502?time=90d&env=Fintech_app'
    )


def test_fetch_incidents_no_linked_api(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_optional_api_attributes(["isExternal"])
    client.set_limit(100)

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = empty_api_response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    rawJSON = json.loads(incidents[0]["rawJSON"])
    assert rawJSON["apiType"] == "Unknown"


def test_fetch_incidents_public_api_type(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_optional_api_attributes(["isExternal", "isAuthenticated", "riskScore", "riskScoreCategory", "isLearnt"])
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = public_api_type_response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    rawJSON = json.loads(incidents[0]["rawJSON"])
    assert rawJSON["apiType"] == "External"


def test_fetch_incidents_private_api_type(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_optional_api_attributes(["isExternal", "isAuthenticated", "riskScore", "riskScoreCategory", "isLearnt"])
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = private_api_type_response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    rawJSON = json.loads(incidents[0]["rawJSON"])
    assert rawJSON["apiType"] == "Internal"
    assert rawJSON["apiIsAuthenticated"]
    assert rawJSON["apiRiskScore"] == 3
    assert rawJSON["apiRiskScoreCategory"] == 'MEDIUM'


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
    client.__commit_integration_context__()

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


def test_get_threat_events_query(capfd):
    from Traceable import Client, DATE_FORMAT
    from datetime import datetime
    import urllib3

    output_query = (
        '{\n  explore(\n    scope: "DOMAIN_EVENT"\n    limit: 100\n    between: {\n      startTime: "2023-06-20T15:34:'
        + '56.000Z"\n      endTime: "2023-06-26T15:34:53.999Z"\n    }\n    offset: 0\n    filterBy: [{keyExpression: {'
        + 'key: "securityScoreCategory"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW"], type: ATTRIBUTE},{k'
        + 'eyExpression: {key: "ipReputationLevel"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]'
        + ', type: ATTRIBUTE},{keyExpression: {key: "ipCategories"}, operator: IN, value: ["IP_LOCATION_TYPE_UNSPECIFI'
        + 'ED","IP_LOCATION_TYPE_ANONYMOUS_VPN","IP_LOCATION_TYPE_HOSTING_PROVIDER","IP_LOCATION_TYPE_PUBLIC_PROXY","I'
        + 'P_LOCATION_TYPE_TOR_EXIT_NODE","IP_LOCATION_TYPE_BOT"], type: ATTRIBUTE},{keyExpression: {key: "ipAbuseVelo'
        + 'city"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW","IP_ABUSE_VELOCITY_UNSPECIFIED"], type: ATTR'
        + 'IBUTE}]\n    orderBy: [\n      { keyExpression: { key: "timestamp" } }\n    ]\n  ) {\n    results {\n      '
        + '  actorCountry: selection(expression: {key: "actorCountry"}) { value }\nactorIpAddress: selection(expressio'
        + 'n: {key: "actorIpAddress"}) { value }\napiId: selection(expression: {key: "apiId"}) { value }\nenvironment:'
        + ' selection(expression: {key: "environment"}) { value }\neventDescription: selection(expression: {key: "even'
        + 'tDescription"}) { value }\nid: selection(expression: {key: "id"}) { value }\nipCategories: selection(expres'
        + 'sion: {key: "ipCategories"}) { value }\nname: selection(expression: {key: "name"}) { value }\nsecurityScore'
        + 'Category: selection(expression: {key: "securityScoreCategory"}) { value }\nspanId: selection(expression: {k'
        + 'ey: "spanId"}) { value }\nstatusCode: selection(expression: {key: "statusCode"}) { value }\ntimestamp: sele'
        + 'ction(expression: {key: "timestamp"}) { value }\ntraceId: selection(expression: {key: "traceId"}) { value }'
        + '\nserviceName: selection(expression: {key: "serviceName"}) { value }\nanomalousAttribute: selection(express'
        + 'ion: {key: "anomalousAttribute"}) { value }\nactorDevice: selection(expression: {key: "actorDevice"}) { val'
        + 'ue }\nactorEntityId: selection(expression: {key: "actorEntityId"}) { value }\nactorId: selection(expression'
        + ': {key: "actorId"}) { value }\nactorScoreCategory: selection(expression: {key: "actorScoreCategory"}) { val'
        + 'ue }\nactorSession: selection(expression: {key: "actorSession"}) { value }\napiName: selection(expression: '
        + '{key: "apiName"}) { value }\napiUri: selection(expression: {key: "apiUri"}) { value }\ncategory: selection('
        + 'expression: {key: "category"}) { value }\nipAbuseVelocity: selection(expression: {key: "ipAbuseVelocity"}) '
        + '{ value }\nipReputationLevel: selection(expression: {key: "ipReputationLevel"}) { value }\nsecurityEventTyp'
        + 'e: selection(expression: {key: "securityEventType"}) { value }\nsecurityScore: selection(expression: {key: '
        + '"securityScore"}) { value }\nserviceId: selection(expression: {key: "serviceId"}) { value }\nactorScore: se'
        + 'lection(expression: {key: "actorScore"}) { value }\nthreatCategory: selection(expression: {key: "threatCate'
        + 'gory"}) { value }\ntype: selection(expression: {key: "type"}) { value }\n\n    }\n  }\n}\n'
    )

    starttime = datetime.strptime("2023-06-20T15:34:56Z", DATE_FORMAT)
    endtime = datetime.strptime("2023-06-26T15:34:53Z", DATE_FORMAT)
    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    )
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    client.set_ip_categories_list(
        [
            "Unknown",
            "Anonymous VPN",
            "Hosting Provider",
            "Public Proxy",
            "TOR Exit Node",
            "BOT",
        ]
    )
    client.set_domain_event_field_list([
        "actorDevice", "actorEntityId", "actorId", "actorScoreCategory", "actorSession", "anomalousAttribute", "apiName",
        "apiUri", "category", "ipAbuseVelocity", "ipReputationLevel", "securityEventType", "securityScore", "serviceId",
        "serviceName", "actorScore", "threatCategory", "type", "nonexistent"])
    client.set_limit(100)
    # client.__commit_integration_context__()

    query = client.get_threat_events_query(starttime, endtime)
    assert query == output_query
    capfd.readouterr()


def test_get_threat_events_query_no_optional_fields(capfd):
    from Traceable import Client, DATE_FORMAT
    from datetime import datetime
    import urllib3

    output_query = (
        '{\n  explore(\n    scope: "DOMAIN_EVENT"\n    limit: 100\n    between: {\n      startTime: "2023-06-20T15:34:'
        + '56.000Z"\n      endTime: "2023-06-26T15:34:53.999Z"\n    }\n    offset: 0\n    filterBy: [{keyExpression: {'
        + 'key: "securityScoreCategory"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW"], type: ATTRIBUTE},{k'
        + 'eyExpression: {key: "ipReputationLevel"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]'
        + ', type: ATTRIBUTE},{keyExpression: {key: "ipCategories"}, operator: IN, value: ["IP_LOCATION_TYPE_UNSPECIFI'
        + 'ED","IP_LOCATION_TYPE_ANONYMOUS_VPN","IP_LOCATION_TYPE_HOSTING_PROVIDER","IP_LOCATION_TYPE_PUBLIC_PROXY","I'
        + 'P_LOCATION_TYPE_TOR_EXIT_NODE","IP_LOCATION_TYPE_BOT"], type: ATTRIBUTE},{keyExpression: {key: "ipAbuseVelo'
        + 'city"}, operator: IN, value: ["CRITICAL","HIGH","MEDIUM","LOW","IP_ABUSE_VELOCITY_UNSPECIFIED"], type: ATTR'
        + 'IBUTE}]\n    orderBy: [\n      { keyExpression: { key: "timestamp" } }\n    ]\n  ) {\n    results {\n      '
        + '  actorCountry: selection(expression: {key: "actorCountry"}) { value }\nactorIpAddress: selection(expressio'
        + 'n: {key: "actorIpAddress"}) { value }\napiId: selection(expression: {key: "apiId"}) { value }\nenvironment:'
        + ' selection(expression: {key: "environment"}) { value }\neventDescription: selection(expression: {key: "even'
        + 'tDescription"}) { value }\nid: selection(expression: {key: "id"}) { value }\nipCategories: selection(expres'
        + 'sion: {key: "ipCategories"}) { value }\nname: selection(expression: {key: "name"}) { value }\nsecurityScore'
        + 'Category: selection(expression: {key: "securityScoreCategory"}) { value }\nspanId: selection(expression: {k'
        + 'ey: "spanId"}) { value }\nstatusCode: selection(expression: {key: "statusCode"}) { value }\ntimestamp: sele'
        + 'ction(expression: {key: "timestamp"}) { value }\ntraceId: selection(expression: {key: "traceId"}) { value }'
        + '\nserviceName: selection(expression: {key: "serviceName"}) { value }\nanomalousAttribute: selection(express'
        + 'ion: {key: "anomalousAttribute"}) { value }\n\n    }\n  }\n}\n'

    )

    starttime = datetime.strptime("2023-06-20T15:34:56Z", DATE_FORMAT)
    endtime = datetime.strptime("2023-06-26T15:34:53Z", DATE_FORMAT)
    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    )
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    client.set_ip_categories_list(
        [
            "Unknown",
            "Anonymous VPN",
            "Hosting Provider",
            "Public Proxy",
            "TOR Exit Node",
            "BOT",
        ]
    )
    client.set_limit(100)
    # client.__commit_integration_context__()

    query = client.get_threat_events_query(starttime, endtime)
    assert query == output_query
    capfd.readouterr()


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
    assert type(client.headers) is dict
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
        assert str(e) == "Error occurred: error | Status Code: 400 | additional_logging: "
    assert encountered_exception
    caplog.clear()
    capfd.readouterr()


def test_get_api_endpoint_details_query():
    from Traceable import Client, Helper
    client = Client("https://mock.url")
    client.set_optional_api_attributes(["isExternal", "isAuthenticated", "riskScore", "riskScoreCategory", "isLearnt"])
    client.set_limit(100)

    ts = Helper.string_to_datetime("2023-08-21T12:41:27Z")
    query = client.get_api_endpoint_details_query(
        [
            "067bb0d7-3740-3ba6-89eb-c457491fbc53",
            "ea0f77c0-adc2-3a69-89ea-93b1c8341d8f",
            "be344182-c100-3287-874a-cb47eac709f2",
        ],
        ts,
        ts
    )
    expected_query = (
        'query entities\n{\n  entities(\n    scope: "API"\n    between: {\n      startTime: "2023-'
        + '08-21T12:41:27.000Z"\n      endTime: "2023-08-21T12:41:27.999Z"\n    }\n    offset: 0\n '
        + '   filterBy: [{keyExpression: {key: "id"}, operator: IN, value: ["067bb0d7-3740-3ba6-89e'
        + 'b-c457491fbc53","ea0f77c0-adc2-3a69-89ea-93b1c8341d8f","be344182-c100-3287-874a-cb47eac7'
        + '09f2"], type: ATTRIBUTE}]\n  ) {\n    results {\n      id\n      isExternal: attribute(e'
        + 'xpression: { key: "isExternal" })\nisAuthenticated: attribute(expression: { key: "isAuth'
        + 'enticated" })\nriskScore: attribute(expression: { key: "riskScore" })\nriskScoreCategory'
        + ': attribute(expression: { key: "riskScoreCategory" })\nisLearnt: attribute(expression: {'
        + ' key: "isLearnt" })\n\n    }\n  }\n}'

    )

    assert query == expected_query


def test_get_api_endpoint_details(mocker):
    from Traceable import Client, Helper

    resp = Response()
    resp.text = sample_api_result
    resp.status_code = 200
    client = Client("https://mock.url")
    client.set_limit(100)
    mocked_post = mocker.patch("requests.post")
    mocked_post.return_value = resp
    result = client.get_api_endpoint_details(
        [
            "067bb0d7-3740-3ba6-89eb-c457491fbc53",
            "ea0f77c0-adc2-3a69-89ea-93b1c8341d8f",
            "be344182-c100-3287-874a-cb47eac709f2",
        ],
        Helper.string_to_datetime("2023-07-23T09:07:59Z"),
        Helper.string_to_datetime("2023-07-24T09:07:59Z"),
    )
    assert len(result) == 3


def test_url_encode(capfd):
    from urllib import parse
    s = "Fintech App"
    r = parse.quote(s)
    assert r == "Fintech%20App"


def test_check_private_ip():
    from ipaddress import ip_address
    is_private = ip_address("192.168.11.20").is_private
    assert is_private

    is_private = ip_address("17.5.7.3").is_private
    assert not is_private


def test_fetch_incident_with_private_ipaddress(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3

    urllib3.disable_warnings()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_app_url("https://app.mock.url")
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler_private_ip

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    assert incidents[0]["ipAddressType"] == "Internal"
    assert incidents[0]["eventUrl"] == ('https://app.mock.url/security-event/9dd9261a-23db-472e-9d2a-a4c3227d6502?time='
                                        + '90d&env=Fintech_app')


def test_ignore_ranges_parsing():
    from Traceable import Client
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_ignore_status_codes("    400    -    499   ")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 400
    assert upper == 499

    client.set_ignore_status_codes("400-499")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 400
    assert upper == 499

    client.set_ignore_status_codes("  500  ")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("500")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("400-499, 500")
    assert len(client.ignore_status_code_tuples) == 2
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 400
    assert upper == 499
    lower, upper = client.ignore_status_code_tuples[1]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("  400    -  499  ,  500")
    assert len(client.ignore_status_code_tuples) == 2
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 400
    assert upper == 499
    lower, upper = client.ignore_status_code_tuples[1]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("  400    -  499 -- ,  500")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("  400    -   ,  500  ")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("  400      ,  500  ")
    assert len(client.ignore_status_code_tuples) == 2
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 400
    assert upper == 400
    lower, upper = client.ignore_status_code_tuples[1]
    assert lower == 500
    assert upper == 500

    client.set_ignore_status_codes("  2,600, 700-800, a-b, 3-g , r-4 , 300-400-500     ,  500  ")
    assert len(client.ignore_status_code_tuples) == 1
    lower, upper = client.ignore_status_code_tuples[0]
    assert lower == 500
    assert upper == 500


def test_is_ignored_range():
    from Traceable import Client
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_ignore_status_codes("1,300,400-499")
    assert not client.is_ignored_status_code(1)
    assert client.is_ignored_status_code(300)
    assert client.is_ignored_status_code(400)
    assert client.is_ignored_status_code(450)
    assert client.is_ignored_status_code(499)
    assert not client.is_ignored_status_code(500)


def test_process_domain_field_list():
    from Traceable import Client
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_domain_event_field_list([
        "actorDevice", "actorEntityId", "actorId", "actorScoreCategory", "actorSession", "anomalousAttribute", "apiName",
        "apiUri", "category", "ipAbuseVelocity", "ipReputationLevel", "securityEventType", "securityScore", "serviceId",
        "serviceName", "actorScore", "threatCategory", "type", "nonexistent"])
    assert len(client.domain_event_field_list) == 31
    client.set_domain_event_field_list([
        "actorDevice", "actorEntityId", "actorId", "actorScoreCategory", "actorSession", "anomalousAttribute", "apiName",
        "apiUri", "category", "ipAbuseVelocity", "ipReputationLevel", "securityEventType", "securityScore", "serviceId",
        "serviceName", "actorScore", "threatCategory"])
    assert len(client.domain_event_field_list) == 30
    client.set_domain_event_field_list([])
    assert len(client.domain_event_field_list) == 15
    client.set_domain_event_field_list(None)
    assert len(client.domain_event_field_list) == 15


def test_construct_field_selection_expression():
    from Traceable import Client
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_domain_event_field_list([
        "actorDevice", "actorEntityId", "actorId", "actorScoreCategory", "actorSession", "anomalousAttribute", "apiName",
        "apiUri", "category", "ipAbuseVelocity", "ipReputationLevel", "securityEventType", "securityScore", "serviceId",
        "serviceName", "actorScore", "threatCategory", "type", "nonexistent"])
    expression_string = client.get_domain_event_query_fields()
    expected_output = (
        'actorCountry: selection(expression: {key: "actorCountry"}) { value }\nactorIpAddress: selection(expression: {'
        + 'key: "actorIpAddress"}) { value }\napiId: selection(expression: {key: "apiId"}) { value }\nenvironment: sel'
        + 'ection(expression: {key: "environment"}) { value }\neventDescription: selection(expression: {key: "eventDes'
        + 'cription"}) { value }\nid: selection(expression: {key: "id"}) { value }\nipCategories: selection(expression'
        + ': {key: "ipCategories"}) { value }\nname: selection(expression: {key: "name"}) { value }\nsecurityScoreCate'
        + 'gory: selection(expression: {key: "securityScoreCategory"}) { value }\nspanId: selection(expression: {key: '
        + '"spanId"}) { value }\nstatusCode: selection(expression: {key: "statusCode"}) { value }\ntimestamp: selectio'
        + 'n(expression: {key: "timestamp"}) { value }\ntraceId: selection(expression: {key: "traceId"}) { value }\nse'
        + 'rviceName: selection(expression: {key: "serviceName"}) { value }\nanomalousAttribute: selection(expression:'
        + ' {key: "anomalousAttribute"}) { value }\nactorDevice: selection(expression: {key: "actorDevice"}) { value }'
        + '\nactorEntityId: selection(expression: {key: "actorEntityId"}) { value }\nactorId: selection(expression: {k'
        + 'ey: "actorId"}) { value }\nactorScoreCategory: selection(expression: {key: "actorScoreCategory"}) { value }'
        + '\nactorSession: selection(expression: {key: "actorSession"}) { value }\napiName: selection(expression: {key'
        + ': "apiName"}) { value }\napiUri: selection(expression: {key: "apiUri"}) { value }\ncategory: selection(expr'
        + 'ession: {key: "category"}) { value }\nipAbuseVelocity: selection(expression: {key: "ipAbuseVelocity"}) { va'
        + 'lue }\nipReputationLevel: selection(expression: {key: "ipReputationLevel"}) { value }\nsecurityEventType: s'
        + 'election(expression: {key: "securityEventType"}) { value }\nsecurityScore: selection(expression: {key: "sec'
        + 'urityScore"}) { value }\nserviceId: selection(expression: {key: "serviceId"}) { value }\nactorScore: select'
        + 'ion(expression: {key: "actorScore"}) { value }\nthreatCategory: selection(expression: {key: "threatCategory'
        + '"}) { value }\ntype: selection(expression: {key: "type"}) { value }\n'
    )
    assert expression_string == expected_output


def test_construct_api_attribute_selection():
    from Traceable import Client, Helper
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_optional_api_attributes(["isExternal", "isExternal", "isAuthenticated", "nonexistent"])
    expected_output = (
        'query entities\n{\n  entities(\n    scope: "API"\n    between: {\n      startTime'
        + ': "2023-08-21T12:41:27.000Z"\n      endTime: "2023-08-21T12:41:27.999Z"\n    }\n'
        + '    offset: 0\n    filterBy: [{keyExpression: {key: "id"}, operator: IN, value: '
        + '["067bb0d7-3740-3ba6-89eb-c457491fbc53","ea0f77c0-adc2-3a69-89ea-93b1c8341d8f","'
        + 'be344182-c100-3287-874a-cb47eac709f2"], type: ATTRIBUTE}]\n  ) {\n    results {\n'
        + '      id\n      isExternal: attribute(expression: { key: "isExternal" })\nisAuth'
        + 'enticated: attribute(expression: { key: "isAuthenticated" })\n\n    }\n  }\n}'

    )

    ts = Helper.string_to_datetime("2023-08-21T12:41:27Z")
    query = client.get_api_endpoint_details_query(
        [
            "067bb0d7-3740-3ba6-89eb-c457491fbc53",
            "ea0f77c0-adc2-3a69-89ea-93b1c8341d8f",
            "be344182-c100-3287-874a-cb47eac709f2",
        ],
        ts,
        ts
    )
    assert query == expected_output


def test_fetch_incidents_no_api_attributes_selection(mocker):
    from Traceable import Client, fetch_incidents
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = private_api_type_response_handler

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    rawJSON = json.loads(incidents[0]["rawJSON"])
    assert "apiType" not in rawJSON
    assert "apiIsAuthenticated" not in rawJSON
    assert "apiRiskScore" not in rawJSON
    assert "apiRiskScoreCategory" not in rawJSON


def test_fixing_timestamp():
    from datetime import datetime
    from Traceable import Helper
    now_time = datetime.now()
    now_time_str1 = Helper.datetime_to_string(now_time)
    now_time_str2 = Helper.start_datetime_to_string(now_time)
    assert now_time_str2 == (now_time_str1[:-1] + ".000Z")

    now_time_str3 = Helper.end_datetime_to_string(now_time)
    assert now_time_str3 == (now_time_str1[:-1] + ".999Z")


def test_set_app_url(mocker):
    from Traceable import Client, fetch_incidents
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_app_url(None)
    assert client.app_url == ""

    client.set_app_url("")
    assert client.app_url == ""

    client.set_app_url("https://mock.url")
    assert client.app_url == "https://mock.url"

    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = private_api_type_response_handler
    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1
    assert "eventUrl" in incidents[0]
    assert incidents[0]["eventUrl"] == ('https://mock.url/security-event/9dd9261a-23db-472e-9d2a-a4c3227d6502?time'
                                        + '=90d&env=Fintech_app')

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_app_url(None)
    client.__commit_integration_context__()
    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert "eventUrl" not in incidents[0]


def test_instance_cache(mocker):
    from Traceable import Client, fetch_incidents
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_app_url(None)
    assert client.app_url == ""

    client.set_app_url("")
    assert client.app_url == ""

    client.set_app_url("https://mock.url")
    assert client.app_url == "https://mock.url"

    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_fetch_unique_incidents(True)
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = private_api_type_response_handler
    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 1

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_app_url("https://mock.url")
    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, "3 days")
    assert len(incidents) == 0


def test_boolean_construct_key_expression(capfd):
    from Traceable import Helper
    result = Helper.construct_key_expression("key", True, operator="EQUALS")
    expected = '{keyExpression: {key: "key"}, operator: EQUALS, value: true, type: ATTRIBUTE}'
    assert result == expected

    passed = False
    try:
        result = Helper.construct_key_expression("key", True, )
    except Exception as e:
        assert str(e) == "Value of type bool doesn't allow operator IN"
        passed = True
    assert passed
    capfd.readouterr()


def test_list_instance_cache_command():
    from Traceable import list_incident_cache_command, Client, Helper
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)
    client.__commit_integration_context__()
    _str = Helper.now_time_to_string()
    client.set_integration_context_key_value("key", _str)
    es = f"[{{\"id\": \"key\", \"expiry\": \"{_str}\"}}]"
    result = list_incident_cache_command(client)
    assert json.dumps(result) == es


def test_purge_incident_cache_command():
    from Traceable import list_incident_cache_command, purge_incident_cache_command, Client, Helper
    import urllib3
    import json

    urllib3.disable_warnings()
    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)
    client.__commit_integration_context__()
    _str = Helper.now_time_to_string()
    client.set_integration_context_key_value("key", _str)
    es = f"[{{\"id\": \"key\", \"expiry\": \"{_str}\"}}]"
    result = list_incident_cache_command(client)
    assert json.dumps(result) == es
    expected = f"[{{\"id\": \"key\", \"expiry\": \"{_str}\", \"deletion_status\": \"deleted\"}}]"
    result = purge_incident_cache_command(client)
    assert len(result) > 0
    assert json.dumps(result) == expected
    assert len(list(client.integration_context.keys())) == 0


def test_test_module(mocker):
    from Traceable import test_module, Client

    headers = {}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url="https://mock.url", verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)
    client.__commit_integration_context__()

    mocked_post = mocker.patch("requests.post")
    mocked_post.side_effect = response_handler

    res = test_module(client)
    assert res == 'ok'
