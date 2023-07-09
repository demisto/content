import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import base64
import re
import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS '''
handle_proxy()
params = demisto.params()
server = params["server"].rstrip('/')
prefix = server + "/awakeapi/v1"
verify = not params.get('unsecure', False)
credentials = params["credentials"]
identifier = credentials["identifier"]
password = credentials["password"]
suspicious_threshold = params["suspicious_threshold"]
malicious_threshold = params["malicious_threshold"]
authTokenRequest = {
    "loginUsername": identifier,
    "loginPassword": password
}
authTokenResponse = requests.post(prefix + "/authtoken", json=authTokenRequest, verify=verify)
authToken = authTokenResponse.json()["token"]["value"]
headers = {
    "Authentication": ("access " + authToken)
}
command = demisto.command()
args = demisto.args()
request = {}

''' HELPERS '''


# Convenient utility to marshal command arguments into the request body


def slurp(fields):
    for field in fields:
        if field in args:
            request[field] = args[field]

# Render a subset of the fields of the Contents as a markdown table


def displayTable(contents, fields):
    # We don't use a set() because we want to preserve field order
    #
    # The fields are ordered to put the most relevant information first
    presentFields = []  # type: List[str]
    # Omit table columns that are all empty
    for content in contents:
        for field in fields:
            if field in content and content[field] and field not in presentFields:
                presentFields.append(field)
    line0 = "| "
    line1 = "| "
    for field in presentFields:
        # Translate camel-case field names to title-case space-separated words
        tokens = re.findall("[a-zA-Z][A-Z]*[^A-Z]*", field)
        name = " ".join(map(lambda token: token.title(), tokens))
        line0 += name + " | "
        line1 += "--- | "
    line0 += "\n"
    line1 += "\n"
    body = ""
    for content in contents:
        body += "| "
        for field in presentFields:
            if field in content:
                value = json.dumps(content[field])
            else:
                value = ""
            body += value + " | "
        body += "\n"
    if presentFields:
        return (line0 + line1 + body)
    else:
        return "Empty results"


def returnResults(contents, outerKey, innerKey, humanReadable, dbotScore, genericContext=None):
    machineReadable = {
        "AwakeSecurity": contents,
    }
    entryContext = {
        ("AwakeSecurity." + outerKey + "(val." + innerKey + "== obj." + innerKey + ")"): contents,
    }
    if dbotScore is not None:
        machineReadable["DBotScore"] = dbotScore
        entryContext["DBotScore"] = dbotScore

    if genericContext:
        entryContext.update(genericContext)

    demisto.results({
        "Type": entryTypes['note'],
        "ContentsFormat": formats['json'],
        "Contents": json.dumps(machineReadable),
        "HumanReadable": humanReadable,
        "ReadableContentsFormat": formats['markdown'],
        "EntryContext": entryContext,
    })


def toDBotScore(indicator_type, percentile, lookup_key):
    if percentile <= suspicious_threshold:
        score = 1
    elif percentile <= malicious_threshold:
        # Something doing something out of the ordinary
        score = 2
    else:
        # Probably bad or at least not compliant with
        # company policy.
        score = 3
    return {
        "Vendor": "Awake Security",
        "Type": indicator_type,
        "Indicator": lookup_key,
        "Score": score,
        "Reliability": demisto.params().get('integrationReliability')
    }


''' COMMANDS '''


def lookup(lookup_type, lookup_key):
    path = "/lookup/" + lookup_type
    request["lookup_key"] = lookup_key
    # default value of lookback_minutes is 480
    if "lookback_minutes" not in args:
        args["lookback_minutes"] = 480
    request["lookback_minutes"] = int(args["lookback_minutes"])
    response = requests.post(prefix + path, json=request, headers=headers, verify=verify)
    if response.status_code < 200 or response.status_code >= 300:
        return_error(f'Request Failed.\nStatus code: {str(response.status_code)}'
                     f' with body {str(response.content)} with headers {response.headers}')

    return response.json()


def lookupDevice():
    lookup_key = args["device"]
    contents = lookup("device", lookup_key)
    humanReadableFields = [
        "deviceScore",
        "deviceName",
        "deviceType",
        "os",
        "osVersion",
        "commonEmail",
        "commonUsername",
        "tags",
        "recentIP",
        "activeIP",
        "nSimilarDevices",
        "ipCount",
        "applicationCount",
        # "protocols",
        "firstSeen",
        "lastSeen",
    ]
    if "deviceScore" in contents:
        dbotScore = toDBotScore("device", contents["deviceScore"], lookup_key)
    else:
        dbotScore = {
            "Vendor": "Awake Security",
            "Type": 'device',
            "Indicator": lookup_key,
            "Score": 0,
            "Reliability": demisto.params().get('integrationReliability')
        }
    humanReadable = displayTable([contents], humanReadableFields)
    contents["device"] = lookup_key
    returnResults(contents, "Devices", "device", humanReadable, dbotScore)


def lookupDomain():
    lookup_key = args["domain"]
    contents = lookup("domain", lookup_key)
    humanReadableFields = [
        "notability",
        "isAlexaTopOneMillion",
        "isDGA",
        "intelSources",
        "numAssociatedDevices",
        "numAssociatedActivities",
        "approxBytesTransferred",
        "protocols",
        "firstSeen",
        "lastSeen",
    ]
    if "notability" in contents:
        dbotScore = toDBotScore("domain", contents["notability"], lookup_key)
    else:
        dbotScore = {
            "Vendor": "Awake Security",
            "Type": 'domain',
            "Indicator": lookup_key,
            "Score": 0,
            "Reliability": demisto.params().get('integrationReliability')
        }
    humanReadable = displayTable([contents], humanReadableFields)
    contents["domain"] = lookup_key
    genericContext = {"Domain": {"Name": lookup_key}}
    returnResults(contents, "Domains", "domain", humanReadable, dbotScore, genericContext)


def lookupEmail():
    lookup_key = args["email"]
    contents = lookup("email", lookup_key)
    humanReadableFields = [
        "notabilityPercentile",
        "deviceName",
        "os",
        "deviceType",
        "application",
        "numberSimilarDevices",
        "numberSessions",
        "firstSeen",
        "lastSeen",
        "duration",
        "deviceId",
    ]
    if "notabilityPercentile" in contents:
        dbotScore = toDBotScore("email", contents["notabilityPercentile"], lookup_key)
    else:
        dbotScore = {
            "Vendor": "Awake Security",
            "Type": 'email',
            "Indicator": lookup_key,
            "Score": 0,
            "Reliability": demisto.params().get('integrationReliability')
        }
    humanReadable = displayTable(contents, humanReadableFields)
    for content in contents:
        content["email"] = lookup_key
    returnResults(contents, "Emails", "email", humanReadable, dbotScore)


def lookupIp():
    lookup_key = args["ip"]
    contents = lookup("ip", lookup_key)
    humanReadableFields = [
        "deviceCount",
        "activityCount",
        "ipFirstSeen",
        "ipLastSeen",
    ]
    dbotScore = {
        "Vendor": "Awake Security",
        "Type": 'ip',
        "Indicator": lookup_key,
        "Score": 0,
        "Reliability": demisto.params().get('integrationReliability')
    }
    # Note: No DBotScore for IP addresses as we do not score them.
    # Our product scores devices rather than IP addresses.
    humanReadable = displayTable([contents], humanReadableFields)
    contents["ip"] = lookup_key
    genericContext = {"IP": {"Address": lookup_key}}
    returnResults(contents, "IPs", "ip", humanReadable, dbotScore, genericContext)


def query(lookup_type):
    # Default to an empty query if unset
    request["queryExpression"] = ""
    slurp(["queryExpression", "startTime", "endTime"])
    nameMappings = [
        ("ipAddress", "device.ip == {}"),
        ("deviceName", "device.name like r/{}/"),
        ("domainName", "domain.name like r/{}/"),
        ("protocol", "activity.protocol == \"{}\""),
        ("tags", "\"{}\" in device.tags"),
    ]
    for (name, mapping) in nameMappings:
        if name in args:
            if "queryExpression" in request and request["queryExpression"]:
                request["queryExpression"] = request["queryExpression"] + " && " + mapping.format(args[name])
            else:
                request["queryExpression"] = mapping.format(args[name])
    path = "/query/" + lookup_type
    response = requests.post(prefix + path, json=request, headers=headers, verify=verify)
    if response.status_code < 200 or response.status_code >= 300:
        return_error(f'Request Failed.\nStatus code: {str(response.status_code)}'
                     f' with body {str(response.content)} with headers {response.headers}')
    contents = response.json()
    return request["queryExpression"], contents


def queryActivities():
    q, contents = query("activities")
    humanReadableFields = [
        "sourceIP",
        "sourceHost",
        "sourcePort",
        "destIP",
        "destHost",
        "destPort",
        "activityDeviceName",
        "activityStart",
        "activityEnd",
        "protocols",
    ]
    humanReadable = displayTable(contents, humanReadableFields)
    for content in contents:
        content["query"] = q
    returnResults(contents, "Activities", "activityId", humanReadable, None)


def queryDevices():
    q, contents = query("devices")
    humanReadableFields = [
        "notabilityPercentile",
        "deviceName",
        "os",
        "deviceType",
        "application",
        "numberSimilarDevices",
        "numberSessions",
        "firstSeen",
        "lastSeen",
        "duration",
        "deviceId",
    ]
    humanReadable = displayTable(contents, humanReadableFields)
    for content in contents:
        content["query"] = q
    returnResults(contents, "Devices", "deviceId", humanReadable, None)


def queryDomains():
    q, contents = query("domains")
    humanReadableFields = [
        "name",
        "notability",
        "created",
        "lastUpdated",
        "expiration",
        "registrantOrg",
        "registrantCountry",
        "registrarName",
        "nameservers",
        "deviceCount",
        "intelCount",
        "lastSeen",
    ]
    humanReadable = displayTable(contents, humanReadableFields)
    for content in contents:
        content["query"] = q
    returnResults(contents, "Domains", "name", humanReadable, None)


def pcapDownload():
    slurp(["monitoringPointID"])
    session = {}
    for field in ["hostA", "hostB", "startTimeRFC3339Nano", "endTimeRFC3339Nano"]:
        if field in args:
            session[field] = args[field]
    if "startTimeRFC3339Nano" in args:
        session["startTimeRFC3339Nano"] = args["startTime"]
    if "endTimeRFC3339Nano" in args:
        session["endTimeRFC3339Nano"] = args["endTime"]
    for field in ["protocol", "portA", "portB"]:
        if field in args:
            session[field] = int(args[field])
    request["sessions"] = [session]
    path = "/pcap/download"
    response = requests.post(prefix + path, json=request, headers=headers, verify=verify)
    if response.status_code < 200 or response.status_code >= 300:
        return_error(f"Request Failed.\nStatus code: {str(response.status_code)} "
                     f"with body {str(response.content)} with headers {response.headers}")
    b64 = response.json()["pcap"]
    bytes = base64.b64decode(b64)
    demisto.results(fileResult("download.pcap", bytes))


def fetchIncidents():
    threatBehaviorsString = params.get("threat_behaviors") or ""
    threatBehaviors = [threatBehavior.strip() for threatBehavior in threatBehaviorsString.split(",")]
    if threatBehaviors == [""]:
        threatBehaviors = []
    lastRun = demisto.getLastRun()
    formatString = "%Y-%m-%d %H:%M:%S+0000"
    earlyTimeString = "1970-01-01 00:00:00+0000"
    startTimeString = lastRun.get("time") or earlyTimeString
    startTime = datetime.strptime(startTimeString, formatString)
    endTime = datetime.utcnow()
    endTimeString = datetime.strftime(endTime, formatString)
    if timedelta(minutes=int(params['fetch_interval'])) <= endTime - startTime:
        jsonRequest = {
            "startTime": startTimeString,
            "endTime": endTimeString,
            "threatBehaviors": threatBehaviors
        }
        response = requests.post(prefix + "/threat-behavior/matches", json=jsonRequest, headers=headers, verify=verify)
        jsonResponse = response.json()
        matchingThreatBehaviors = jsonResponse.get("matchingThreatBehaviors", [])

        def toIncident(matchingThreatBehavior):
            # Currently the threat behavior API doesn't allow us to retrieve metadata for
            # the behaviors that matched, which is why this incident record is mostly empty
            #
            # However, we can provide the original query that the threat behavior corresponded
            # to plus the date range so that a playbook can feed them back into
            # `awake-query-{devices,activities}` to retrieving the matching devices or
            # activities that triggered the match to the threat behavior.
            return {
                "Name": matchingThreatBehavior["name"],
                "Query": matchingThreatBehavior["query"],
                "StartTime": startTimeString,
                "EndTime": endTimeString,
                "rawJSON": json.dumps(matchingThreatBehavior),
            }
        demisto.incidents(list(map(toIncident, matchingThreatBehaviors)))
        # Don't increase the low-water-mark until we actually find incidents
        #
        # This is a precaution because incidents sometimes appear in an old time
        # bucket after a delay
        if 0 < len(matchingThreatBehaviors):
            lastRun = {"time": endTimeString}
    else:
        demisto.incidents([])
    demisto.setLastRun(lastRun)


''' EXECUTION '''
LOG('command is %s' % (command))

try:
    if command == "test-module":
        # If we got this far we already successfully authenticated against the server
        demisto.results('ok')

    elif command == "fetch-incidents":
        fetchIncidents()

    elif command == "awake-query-devices":
        queryDevices()

    elif command == "awake-query-activities":
        queryActivities()

    elif command == "awake-query-domains":
        queryDomains()

    elif command == "awake-pcap-download":
        pcapDownload()

    elif command == "domain":
        lookupDomain()

    elif command == "email":
        lookupEmail()

    elif command == "ip":
        lookupIp()

    elif command == "device":
        lookupDevice()

except Exception as e:
    if command == "fetch-incidents":
        raise
    LOG(e)
    LOG.print_log()
    return_error(e)
