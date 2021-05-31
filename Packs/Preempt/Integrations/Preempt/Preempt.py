import json
from datetime import datetime, timedelta

import requests
from dateutil.parser import parse as parse_date
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Supress warning about unverified HTTPS
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if not demisto.params().get("proxy", True):
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]

API_KEY = str(demisto.params()["apiKey"])
SERVER = str(demisto.params()["server"])
LOOKBACK = timedelta(days=int(demisto.params()["lookback"]))
PUBLIC_API_URL = "%s/api/public" % SERVER
GRAPHQL_URI = "%s/graphql" % PUBLIC_API_URL
ENTITIES_URI = "%s/entities" % PUBLIC_API_URL
AUTH_HEADER = {
    "Authorization": "Bearer %s" % API_KEY
}
USE_SSL = not demisto.params().get("insecure", False)

''' HELPER FUNCTIONS '''


def api_request(uri, data):
    data = {} if data is None else data
    LOG("running request with url=%s\tdata=%s" % (uri, data))
    try:
        res = requests.post(uri,
                            verify=USE_SSL,
                            json=data,
                            headers=AUTH_HEADER)
        if res.status_code not in (200, 204):
            raise Exception('Your request failed with the following error: ' + res.reason)
    except Exception, e:
        raise
    return res


TIMELINE_LIMIT = 1000


def datetime_to_iso(d):
    return d.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def get_alerts(start_time=None, end_time=None, cursor=None, types=None, source_user_id=None):
    query = """
query ($cursor: Cursor, $startTime: DateTimeInput, $endTime: DateTimeInput, $types: [String!], $sourceUserId: UUID) {
  timeline(types: [ALERT], limit: %d, alertQuery: {types: $types}, sourceEntityQuery: {id: $sourceUserId}, startTime: $startTime, endTime: $endTime, after: $cursor) {
    cursor
    eventId
    timestamp
    ... on TimelineAlertEvent {
      incident {
        severity
        _id
        state {
          lifeCycleStage
        }
      }
      alertType
      timestamp
      startTime
      endTime
      eventLabel
      userEntity {
        _id
        primaryDisplayName
        primaryAccount {
          samAccountName
          domain
          upn
        }
      }
      endpointEntity {
        _id
        hostName
      }
    }
    relatedEvents(startTime: $startTime, limit: 30, types: [SUCCESSFUL_AUTHENTICATION, SERVICE_ACCESS], open: true) {
      eventType
      timestamp
      ... on TimelineAuthenticationEvent {
        authenticationType
        geoLocation {
          cityCode
          countryCode
          latitude
          longitude
        }
        ipAddress
      }
      ... on TimelineServiceAccessEvent {
        geoLocation {
          countryCode
          country
          latitude
          longitude
        }
        ipAddress
      }
    }
  }
}
""" % TIMELINE_LIMIT

    variables = {
        "cursor": cursor, "startTime": datetime_to_iso(start_time), "endTime": datetime_to_iso(end_time), "types": types, "sourceUserId": source_user_id
    }
    data = {
        "query": query, "variables": variables
    }

    resp = api_request(GRAPHQL_URI, data)
    alerts = resp.json()["data"]["timeline"]

    return alerts


# The command demisto.command() holds the command sent from the user.
if demisto.command() == "test-module":
    # This is the call made when pressing the integration test button.
    query = "{ aomActivities(limit: 1) { _id } }"
    variables = {}
    data = {
        "query": query, "variables": variables
    }
    res = api_request(GRAPHQL_URI, data)
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == "fetch-incidents":
    cursor = demisto.getLastRun().get("cursor")

    alerts = get_alerts(cursor=cursor,
                        start_time=datetime.utcnow() - LOOKBACK,
                        end_time=datetime.utcnow(),
                        types=["GeoLocationAnomalyAlert", "ForbiddenCountryAlert"])

    fixed_alerts = []
    # Retrieve geo-location data and external IP from the first relevant activity and put it on the alert JSON
    for alert in alerts:
        # Only interested in LOW or MEDIUM severity incidents
        if alert["incident"]["severity"] not in ["LOW", "MEDIUM"] or alert["incident"]["state"]["lifeCycleStage"] != "NEW":
            continue

        alert_start_time = parse_date(alert["startTime"])
        try:
            access = next(event for event in alert["relatedEvents"] if parse_date(
                event["timestamp"]) >= alert_start_time and event["geoLocation"])
            for field in ["geoLocation", "ipAddress"]:
                alert[field] = access[field]
            fixed_alerts.append(alert)
        except StopIteration, e:
            pass

    result = [{"Name": "Incident %s" % alert["eventId"], "rawJSON": json.dumps(alert)} for alert in fixed_alerts]

    # Store the cursor
    demisto.setLastRun({
        "cursor": alerts[-1]["cursor"] if alerts else cursor
    })

    # lastRun is a dictionary, with value "now" for key "time".
    # JSON of the incident type created by this integration
    demisto.incidents(result)
    sys.exit(0)

if demisto.command() == "preempt-add-to-watch-list":
    # The Preempt API receives the same parameters as the command
    args = {
        "entityIds": [demisto.args()["accountObjectGuid"]]
    }
    resp = api_request("%s/watch" % ENTITIES_URI, args)
    demisto.results("User added to watch list")
    sys.exit(0)

if demisto.command() == "preempt-remove-from-watch-list":
    # The Preempt API receives the same parameters as the command
    args = {
        "entityIds": [demisto.args()["accountObjectGuid"]]
    }
    resp = api_request("%s/unwatch" % ENTITIES_URI, args)
    demisto.results("User removed from watch list")
    sys.exit(0)

if demisto.command() == "preempt-get-activities":
    query = """
query ($cursor: Cursor, $startTime: DateTimeInput,  $endTime: DateTimeInput, $types: [TimelineEventType!], $authTypes: [AuthenticationType!], $sourceUserId: UUID) {
  timeline(limit: %d, types: $types, sourceEntityQuery: {id: $sourceUserId}, activityQuery: {authenticationTypes: $authTypes}, startTime: $startTime, endTime: $endTime, after: $cursor) {
    cursor
    timestamp
    eventType
    ... on TimelineSuccessfulAuthenticationEvent {
      authenticationType
      endpointEntity {
        primaryDisplayName
        hostName
      }
      userEntity {
        _id
        primaryDisplayName
        primaryAccount {
          samAccountName
          domain
          upn
        }
      }
    }
  }
}
""" % TIMELINE_LIMIT

    types = []
    auth_types = []
    for t in demisto.args().get("types", "").split(","):
        if t == "LOGIN":
            types.append("SUCCESSFUL_AUTHENTICATION")
            auth_types.append("DOMAIN_LOGIN")

    end_time = demisto.args().get("endTime")
    dt_end_time = parse_date(end_time) if end_time else datetime.utcnow()
    last_hours = int(demisto.args().get("numOfHours"))

    variables = dict({key: demisto.args().get(key) for key in ["sourceUserId"]},
                     start_time=datetime_to_iso(dt_end_time - timedelta(hours=last_hours)),
                     end_time=datetime_to_iso(dt_end_time),
                     types=(types or None),
                     authTypes=(auth_types or None))

    variables["cursor"] = demisto.args().get("cursor")

    data = {
        "query": query, "variables": variables
    }
    resp = api_request(GRAPHQL_URI, data)

    events = resp.json()["data"]["timeline"]

    cursor = events[-1]["cursor"] if len(events) == TIMELINE_LIMIT else None

    def prettyfy_result(res):
        return {
            "EventType": res["eventType"],
            "AuthenticationType": res["authenticationType"],
            "Timestamp": res["timestamp"],
            "EndpointHostName": res["endpointEntity"]["hostName"]
        }
    pretty_results = map(prettyfy_result, events)

    demisto.results({
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": json.dumps(events),
        "HumanReadable": tableToMarkdown("Activities in time frame", pretty_results, ["Timestamp", "EndpointHostName"]),
        "EntryContext": {
            'Preempt.Activities': pretty_results,
            'Preempt.Alerts.Cursor': cursor
        }
    })
    sys.exit(0)

if demisto.command() == "preempt-get-user-endpoints":
    query = """
query ($sourceUserId: UUID!) {
  entities(id: $sourceUserId) {
    associations(bindingTypes: [LOGIN, OWNERSHIP]) {
      bindingType
      ... on OriginAssociation {
        entityId
        entity {
          primaryDisplayName
          ... on EndpointEntity {
            hostName
            lastIpAddress
            staticIpAddresses
          }
        }
      }
    }
  }
}
"""

    variables = {
        "sourceUserId": demisto.args()["sourceUserId"]
    }
    data = {
        "query": query, "variables": variables
    }

    resp = api_request(GRAPHQL_URI, data)
    # Only associations are necessary. Add a flag to mark if it is ownership
    entities = resp.json()["data"]["entities"]
    if entities:
        entity = entities[0]
        ownedEndpointsId = [assoc["entityId"] for assoc in entity["associations"] if assoc["bindingType"] == "OWNERSHIP"]
        result = [dict(assoc, isOwned=(assoc["entityId"] in ownedEndpointsId))
                  for assoc in entity["associations"] if assoc["bindingType"] == "LOGIN"]
    else:
        result = []

    def prettyfy_result(endpoint):
        return {
            "Id": endpoint["entityId"],
            "HostName": endpoint["entity"]["hostName"],
            "PrimaryDisplayName": endpoint["entity"]["primaryDisplayName"],
            "IsOwnedByUser": endpoint["isOwned"],
            "LastIpAddress": endpoint["entity"]["lastIpAddress"],
            "StaticIpAddresses": endpoint["entity"]["staticIpAddresses"]
        }

    pretty_results = map(prettyfy_result, result)

    demisto.results({
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": json.dumps(result),
        "HumanReadable": tableToMarkdown("User's regular endpoints", pretty_results, ["HostName", "IsOwnedByUser"]),
        "EntryContext": {
            'Endpoint': pretty_results
        }
    })
    sys.exit(0)

if demisto.command() == "preempt-get-alerts":
    end_time = demisto.args().get("endTime")
    dt_end_time = parse_date(end_time) if end_time else datetime.utcnow()
    last_hours = int(demisto.args().get("numOfHours"))

    alerts = get_alerts(cursor=demisto.args().get("cursor"),
                        start_time=dt_end_time - timedelta(hours=last_hours),
                        end_time=dt_end_time,
                        source_user_id=demisto.args().get("sourceUserId"))

    cursor = alerts[-1]["cursor"] if len(alerts) == TIMELINE_LIMIT else None

    demisto.results({
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": json.dumps(alerts),
        "HumanReadable": tableToMarkdown("User's last 48 hours alerts", alerts),
        "EntryContext": {
            'Preempt.Alerts': alerts,
            'Preempt.Alerts.Cursor': cursor
        }
    })
    sys.exit(0)
