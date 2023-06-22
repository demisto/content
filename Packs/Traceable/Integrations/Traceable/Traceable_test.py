#!/usr/bin/env python -W ignore::DeprecationWarning

"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import demistomock as demisto
import pytest


def test_fetch_incidents(mocker):
    def response_handler(*args, **kwargs):
        data: str = kwargs["json"]["query"]

        r = Response()
        if "DOMAIN_EVENT" in data:
            r.text = """{
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
            "value": "192.0.2.255"
          },
          "actorDevice": {
            "value": "null"
          },
          "apiUri": {
            "value": "http://localhost:8784/get_user?forwardUrl=http%3A%2F%2Fdummyjon.com"
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
            return r
        elif "spans(" in data:
            r.text = """{
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
          "ipAddress": "192.0.2.255",
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
            "net.peer.port": "56453",
            "http.url": "http://localhost:8784/get_user?forwardUrl=http%3A%2F%2Fdummyjon.com",
            "enduser.role": "customer",
            "net.peer.ip": "192.0.2.255",
            "net.host.ip": "192.0.2.255",
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
            "x-forwarded-for": "192.0.2.255"
          },
          "spanRequestCookies": {}
        }
      ]
    }
  }
}"""
            return r

    class Response:
        def __init__(self) -> None:
            pass

        status_code = 200
        text = None

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
