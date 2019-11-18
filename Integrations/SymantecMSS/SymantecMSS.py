import demistomock as demisto
from CommonServerPython import *
import tempfile
import OpenSSL.crypto
import requests
import contextlib
import xml.etree.ElementTree
import base64
import re
import time

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# CONSTANTS
SECURITY_INCIDENT_SUMMARY_NODE_XPATH = ".//SecurityIncidentSummary"
SECURITY_INCIDENT_NODE_XPATH = ".//SecurityIncident"
FETCH_MAX_INCIDENTS = 500


# PREREQUISITES
@contextlib.contextmanager
def pfx_to_pem(pfx, pfx_password):
    """ Decrypts the .pfx file to be used with requests. """
    with tempfile.NamedTemporaryFile(suffix=".pem") as t_pem:
        f_pem = open(t_pem.name, "wb")
        p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
        f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
        f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
        ca = p12.get_ca_certificates()
        if ca is not None:
            for cert in ca:
                f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        f_pem.close()
        yield t_pem.name


def load_server_url():
    """ Cleans and loads the server url from the configuration """
    url = demisto.params()["server"]
    url = re.sub("/[\/]+$/", "", url)
    url = re.sub("\/$", "", url)
    return url


def load_certificate():
    """ Loads the certificate and passphrase from the configuration """
    cert = demisto.params()["certificate"]
    cert = base64.b64decode(cert)
    passphrase = demisto.params()["passphrase"] if "passphrase" in demisto.params() else ""
    return cert, passphrase


def load_severities():
    POSSIBLE_SEVERITIES = ["Emergency", "Critical", "Warning", "Informational"]
    severities_list = None
    try:
        severities_list = demisto.params()["severities"].replace(" ", "").split(",")
    except Exception:
        raise Exception("Error parsing severities parameter.")
    for s in severities_list:
        if s not in POSSIBLE_SEVERITIES:
            raise Exception("Illegal argument in severities parameter.")
    return ",".join(severities_list)


# GLOBALS
SERVER_URL = load_server_url()
CERTIFICATE, CERTIFICATE_PASSPHRASE = load_certificate()
FETCH_SEVERITIES = load_severities()
DST = 1 if time.daylight else 0


# HELPERS


def api_call(body, headers):
    """ Makes an HTTP Post to the SWS incidents API using the configured certificate """
    with pfx_to_pem(CERTIFICATE, CERTIFICATE_PASSPHRASE) as cert:
        res = requests.post(url=SERVER_URL + "/SWS/incidents.asmx", cert=cert, data=body, headers=headers)
        if res.status_code < 200 or res.status_code >= 300:
            raise Exception(
                "Got status code " + str(res.status_code) + " with body " + res.content + " with headers " + str(
                    res.headers))
    return xml.etree.ElementTree.fromstring(res.content)


def event_to_incident(event):
    """ Converts a Symantec event to a Demisto incident """
    incident = dict()  # type: Dict[str, Any]
    incident["name"] = "Incident: %s (%s)" % (event["IncidentNumber"], event["Classification"])
    incident["occurred"] = event["TimeCreated"] + "+0%s:00" % DST
    incident["rawJSON"] = json.dumps(event)

    labels = []  # type: List[str]
    incident["labels"] = labels
    return incident


def isoformat(date):
    """ Convert a datetime object to asmx ISO format """
    return date.isoformat()[:-3] + "Z"


# FUNCTIONS
def test():
    now = datetime.utcnow()
    get_incidents_list_request(isoformat(now), None, None, 1)
    demisto.results("ok")


def fetch_incidents():
    t = datetime.utcnow()
    now = isoformat(t)

    lastRun = demisto.getLastRun() and demisto.getLastRun()["time"]
    if len(lastRun) == 0:
        t = t - timedelta(minutes=10)
        lastRun = isoformat(t)

    incidents = []
    events = get_incidents_list_request(time=lastRun, srcIp=None, severities=FETCH_SEVERITIES,
                                        maxIncidents=FETCH_MAX_INCIDENTS)
    for event in events:
        inc = event_to_incident(event)
        incidents.append(inc)

    demisto.incidents(incidents)
    demisto.setLastRun({"time": now})


def get_incidents_list(time):
    srcIp = demisto.args()["sourceIp"] if "sourceIp" in demisto.args() else None
    severities = demisto.args()["severities"] if "severities" in demisto.args() else None
    maxIncidents = demisto.args()["max"] if "max" in demisto.args() else None

    # Request events
    result = get_incidents_list_request(time, srcIp, severities, maxIncidents)

    # Set human readable
    headers = [
        "IncidentNumber",
        "TimeCreated",
        "Severity",
        "Category",
        "CountryOfOrigin",
        "DaysSeenGlobally",
        "SourceIPString",
        "Correlation",
        "HostNameList",
        "IsInternalExternal",
        "GlobalLookbackDays",
        "LatestKeyEvent",
        "CustomerSeverity",
        "CountryCode",
        "FirstSeenInLast30Days",
        "DaysSeenInLast30Days",
        "DestOrganizationName",
        "SourceOrganizationName",
        "FirstSeenGlobally",
        "CountryName",
        "UserList",
        "Classification",
        "UpdateTimestampGMT",
        "PrevalenceGlobally"
    ]
    hr = tableToMarkdown("Incidents", result, headers)

    # Set context
    context = {
        "Symantec MSS.Incidents list(val.IncidentNumber && val.IncidentNumber === obj.IncidentNumber)": result
    }

    demisto.results({
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": result,
        "EntryContext": context,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": hr
    })


def get_incidents_list_request(time, srcIp, severities, maxIncidents):
    srcIp = "<SourceIP>%s</SourceIP>" % srcIp if srcIp else ""
    severities = "<Severity>%s</Severity>" % severities if severities else ""
    maxIncidents = "<MaxIncidents>%s</MaxIncidents>" % maxIncidents if maxIncidents else ""

    body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                    <soap12:Body>
                        <IncidentGetList xmlns="https://www.monitoredsecurity.com/">
                        <StartTimeStampGMT>%s</StartTimeStampGMT>
                        %s
                        %s
                        %s
                        </IncidentGetList>
                    </soap12:Body>
                </soap12:Envelope>""" % (time, srcIp, severities, maxIncidents)
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    root = api_call(body=body, headers=headers)
    incidentNodes = root.findall(SECURITY_INCIDENT_SUMMARY_NODE_XPATH)
    result = []
    for incident in incidentNodes:
        stringIncidentXml = xml.etree.ElementTree.tostring(incident)
        stringIncidentJson = xml2json(stringIncidentXml)
        dictIncident = json.loads(stringIncidentJson)["SecurityIncidentSummary"]
        result.append(dictIncident)
    return result


def update_incident():
    # Fill in required fields from the existing incident (for the api call)
    num = demisto.args()["number"]
    dictQuery = query_incident(num=num, workflowQuery=True)
    dictWorkflowQuery = dictQuery["WorkFlowDetail"]

    # Use the supplied params, filling the missing ones from the existing workflow if possible,
    # if not possible - require from user
    status = demisto.args()["status"] if "status" in demisto.args() else dictWorkflowQuery["Status"]
    if not status:
        raise Exception("No current status, please supply a status parameter")

    resolution = demisto.args()["resolution"] if "resolution" in demisto.args() else dictWorkflowQuery["Resolution"]
    if not resolution:
        raise Exception("No current resolution, please supply a resolution parameter")

    severity = demisto.args()["severity"] if "severity" in demisto.args() else dictQuery["Severity"]
    if not severity:
        raise Exception("No current severity, please supply a severity parameter")

    # Optional params
    ref = demisto.args()["reference"] if "reference" in demisto.args() else None
    comments = demisto.args()["comments"] if "comments" in demisto.args() else None

    # Only one of them should exist
    assignToOrg = demisto.args()["assignOrganization"] if "assignOrganization" in demisto.args() else None
    assignToPerson = demisto.args()["assignPerson"] if "assignPerson" in demisto.args() else None

    if assignToOrg and assignToPerson:
        raise Exception("Unable to assign to both organization and a person, please choose only one")

    if not assignToOrg and not assignToPerson:
        if "AssignedOrganization" in dictWorkflowQuery and dictWorkflowQuery["AssignedOrganization"]:
            assignToOrg = dictWorkflowQuery["AssignedOrganization"]
        elif "AssignedPerson" in dictWorkflowQuery and dictWorkflowQuery["AssignedPerson"]:
            assignToPerson = dictWorkflowQuery["AssignedPerson"]

    # Make the request with the params
    success = update_incident_request(num, status, resolution, ref, severity, assignToOrg, assignToPerson, comments)

    # Create result
    msg = "Updated successfully" if success else "Update failed"
    result = [{"Update status": msg}]
    hr = tableToMarkdown("", result)

    demisto.results({
        "ContentsFormat": formats["text"],
        "Type": entryTypes["note"],
        "Contents": msg,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": hr
    })


def update_incident_request(num, status, resolution, ref, severity, assignToOrg, assignToPerson, comments):
    # Create optional parameter tags if needed
    ref = "<Reference>%s</Reference>" % (ref) if ref else ""
    assignToOrg = "<AssignedToOrganiztion>%s</AssignedToOrganiztion>" % (assignToOrg) if assignToOrg else ""
    assignToPerson = "<AssignedToPerson>%s</AssignedToPerson>" % (assignToPerson) if assignToPerson else ""
    comments = "<Comments>%s</Comments>" % (comments) if comments else ""

    body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                  <soap12:Body>
                    <UpdateIncidentWorkflow xmlns="https://www.monitoredsecurity.com/">
                      <IncidentNumber>%s</IncidentNumber>
                      <Status>%s</Status>
                      <Resolution>%s</Resolution>
                      %s
                      <Severity>%s</Severity>
                      %s
                      %s
                      %s
                    </UpdateIncidentWorkflow>
                  </soap12:Body>
                </soap12:Envelope>""" % (num, status, resolution, ref, severity, assignToOrg, assignToPerson, comments)
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    res = api_call(body=body, headers=headers)
    resStringXml = xml.etree.ElementTree.tostring(res)
    resStringJson = xml2json(resStringXml)
    dictRes = json.loads(resStringJson)
    res = dictRes["Envelope"]["Body"]["UpdateIncidentWorkflowResponse"]["UpdateIncidentWorkflowResult"]
    return res == "true"


def query_incident_cmd():
    result = query_incident(demisto.args()["number"], workflowQuery=True)

    # Create minimal signature list
    sigs = []
    for sig in result["SignatureList"]["Signature"]:
        sigDict = {}
        sigDict["SourceIPString"] = sig["SourceIPString"]
        sigDict["SignatureName"] = sig["SignatureName"]
        sigDict["VendorSignature"] = sig["VendorSignature"]
        sigDict["NumberBlocked"] = sig["NumberBlocked"]
        sigDict["NumberNotBlocked"] = sig["NumberNotBlocked"]
        sigs.append(sigDict)

    # Set Human readable
    flattenRelevantFields = [{
        "Incident Number": result["IncidentNumber"],
        "Time Created": result["TimeCreated"],
        "Status": result["WorkFlowDetail"]["Status"] or "",
        "Classification": result["Classification"],
        "Assigned Person": result["WorkFlowDetail"]["AssignedPerson"] or "",
        "Description": result["Description"],
        "Analyst Assessment": result["AnalystAssessment"],
        "Number of Analyzed Signatures": result["NumberOfAnalyzedSignatures"],
        "Signaturtes": json.dumps(sigs) or "",
        "Related Incidents": json.dumps(result["RelatedIncidents"]["IncidentNumber"]) or "",
        "Comment": result["IncidentComments"]["IncidentComment"]["Comment"] or ""
    }]
    headers = [
        "Incident Number",
        "Time Created",
        "Status",
        "Classification",
        "Assigned Person",
        "Description",
        "Analyst Assessment",
        "Number of Analyzed Signatures",
        "Signaturtes",
        "Related Incidents",
        "Comment"
    ]
    hr = tableToMarkdown("Incident query", flattenRelevantFields, headers)

    # Set context
    resultCtx = {
        "IncidentNumber": result["IncidentNumber"],
        "NumberOfAnalyzedSignatures": result["NumberOfAnalyzedSignatures"],
        "SignatureList": {
            "Signature": sigs
        },
        "TimeCreated": result["TimeCreated"],
        "Classification": result["Classification"],
        "Description": result["Description"],
        "AnalystAssessment": result["AnalystAssessment"],
        "CountryCode": result["CountryCode"],
        "CountryName": result["CountryName"],
        "RelatedTickets": result["RelatedTickets"],
        "WorkFlowDetail": {
            "Status": result["WorkFlowDetail"]["Status"],
            "AssignedPerson": result["WorkFlowDetail"]["AssignedPerson"]
        },
        "IncidentComments": {
            "IncidentComment": {
                "CommentedTimeStampGMT": result["IncidentComments"]["IncidentComment"]["CommentedTimeStampGMT"],
                "Comment": result["IncidentComments"]["IncidentComment"]["Comment"],
                "CommentedBy": result["IncidentComments"]["IncidentComment"]["CommentedBy"]
            }
        },
        "IncidentAttachmentItems": {
            "IncidentAttachmentItem": {
                "AttachmentNumber": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["AttachmentNumber"],
                "AttachmentName": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["AttachmentName"],
                "UploadDateGMT": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["UploadDateGMT"],
                "UploadBy": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["UploadBy"],
                "Comment": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["Comment"]
            }
        },
        "RelatedIncidents": {
            "IncidentNumber": result["RelatedIncidents"]["IncidentNumber"]
        }
    }
    context = {
        "Symantec MSS.Incident query(val.IncidentNumber && val.IncidentNumber === obj.IncidentNumber)": resultCtx
    }

    demisto.results({
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": result,
        "EntryContext": context,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": hr
    })


def query_incident(num, workflowQuery=False):
    query = query_incident_request(num) if not workflowQuery else query_incident_workflow_request(num)
    return query


def query_incident_request(num):
    body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                    <soap12:Body>
                        <IncidentQuery xmlns="https://www.monitoredsecurity.com/">
                            <IncidentNumber>%s</IncidentNumber>
                        </IncidentQuery>
                    </soap12:Body>
                </soap12:Envelope>""" % (num)
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    query = api_call(body=body, headers=headers)
    queryNode = query.find(SECURITY_INCIDENT_NODE_XPATH)
    stringQueryXml = xml.etree.ElementTree.tostring(queryNode)
    stringQueryJson = xml2json(stringQueryXml)
    dictQuery = json.loads(stringQueryJson)["SecurityIncident"]
    return dictQuery


def query_incident_workflow_request(num):
    body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                    <soap12:Body>
                        <IncidentWorkflowQuery xmlns="https://www.monitoredsecurity.com/">
                            <IncidentNumber>%s</IncidentNumber>
                        </IncidentWorkflowQuery>
                    </soap12:Body>
                </soap12:Envelope>""" % (num)
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    query = api_call(body=body, headers=headers)
    queryNode = query.find(SECURITY_INCIDENT_NODE_XPATH)
    stringQueryXml = xml.etree.ElementTree.tostring(queryNode)
    stringQueryJson = xml2json(stringQueryXml)
    dictQuery = json.loads(stringQueryJson)["SecurityIncident"]
    return dictQuery


# EXECUTION
if demisto.command() == "fetch-incidents":
    fetch_incidents()
    sys.exit(0)

if demisto.command() == "test-module":
    test()
    sys.exit(0)

if demisto.command() == "symantec-mss-update-incident":
    update_incident()
    sys.exit(0)

if demisto.command() == "symantec-mss-get-incident":
    query_incident_cmd()
    sys.exit(0)

if demisto.command() == "symantec-mss-incidents-list":
    time = demisto.args()["time"] if "time" in demisto.args() else isoformat(
        datetime.utcnow() - timedelta(hours=24))
    get_incidents_list(time)
    sys.exit(0)
