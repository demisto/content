import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import xml
import tempfile
import contextlib
import OpenSSL.crypto
from xml.sax.saxutils import escape
import re

''' GLOBALS/PARAMS '''

FETCH_MAX_INCIDENTS = 500
SECURITY_INCIDENT_NODE_XPATH = ".//SecurityIncident"
SECURITY_INCIDENT_SUMMARY_NODE_XPATH = ".//SecurityIncidentSummary"

''' PREREQUISITES '''


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
    url = re.sub("/[/]+$/", "", url)
    url = re.sub("/$", "", url)
    return url


def load_certificate():
    """ Loads the certificate and passphrase from the configuration """
    cert = demisto.params()["certificate"]
    cert = base64.b64decode(cert)
    passphrase = demisto.params()["passphrase"] if "passphrase" in demisto.params() else ""
    return cert, passphrase


def load_severities():
    possible_severities = ["Emergency", "Critical", "Warning", "Informational"]

    try:
        severities_list = demisto.params()["severities"].replace(" ", "").split(",")
    except Exception:
        raise Exception("Error parsing severities parameter.")
    for s in severities_list:
        if s not in possible_severities:
            raise Exception("Illegal argument in severities parameter.")
    return ",".join(severities_list)


''' GLOBALS/PARAMS '''

SERVER_URL = load_server_url()
CERTIFICATE, CERTIFICATE_PASSPHRASE = load_certificate()
FETCH_SEVERITIES = load_severities()
DST = 1 if time.daylight else 0

''' HELPER FUNCTIONS '''


def strip_unwanted_chars(s):
    return re.sub('&\S{1,6};', '', s)


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


''' COMMANDS + REQUESTS FUNCTIONS '''


def test():
    now = datetime.utcnow()
    get_incidents_list_request(isoformat(now), None, None, 1)
    demisto.results("ok")


def fetch_incidents():
    t = datetime.utcnow()
    now = isoformat(t)

    last_run = demisto.getLastRun() and demisto.getLastRun()["time"]
    if len(last_run) == 0:
        t = t - timedelta(minutes=10)
        last_run = isoformat(t)

    incidents = []
    events = get_incidents_list_request(time=last_run, src_ip=None, severities=FETCH_SEVERITIES,
                                        max_incidents=FETCH_MAX_INCIDENTS)
    for event in events:
        inc = event_to_incident(event)
        incidents.append(inc)

    demisto.incidents(incidents)
    demisto.setLastRun({"time": now})


def get_incidents_list(time):
    src_ip = demisto.args()["sourceIp"] if "sourceIp" in demisto.args() else None
    severities = demisto.args()["severities"] if "severities" in demisto.args() else None
    max_incidents = demisto.args()["max"] if "max" in demisto.args() else None

    # Request events
    result = get_incidents_list_request(time, src_ip, severities, max_incidents)

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


def get_incidents_list_request(time, src_ip, severities, max_incidents):
    src_ip = "<SourceIP>%s</SourceIP>" % src_ip if src_ip else ""
    severities = "<Severity>%s</Severity>" % severities if severities else ""
    max_incidents = "<MaxIncidents>%s</MaxIncidents>" % max_incidents if max_incidents else ""

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
                </soap12:Envelope>""" % (time, src_ip, severities, max_incidents)
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    root = api_call(body=body, headers=headers)
    incident_nodes = root.findall(SECURITY_INCIDENT_SUMMARY_NODE_XPATH)
    result = []
    for incident in incident_nodes:
        string_incident_xml = xml.etree.ElementTree.tostring(incident)
        string_incident_json = xml2json(string_incident_xml)
        dict_incident = json.loads(string_incident_json)["SecurityIncidentSummary"]
        result.append(dict_incident)
    return result


def update_incident():
    # Fill in required fields from the existing incident (for the api call)
    num = demisto.args()["number"]
    dict_query = query_incident(num=num, workflow_query=True)
    dict_workflow_query = dict_query["WorkFlowDetail"]

    # Use the supplied params, filling the missing ones from the existing workflow if possible,
    # if not possible - require from user
    status = demisto.args()["status"] if "status" in demisto.args() else dict_workflow_query["Status"]
    if not status:
        raise Exception("No current status, please supply a status parameter")

    resolution = demisto.args()["resolution"] if "resolution" in demisto.args() else dict_workflow_query["Resolution"]
    if not resolution:
        raise Exception("No current resolution, please supply a resolution parameter")

    severity = demisto.args()["severity"] if "severity" in demisto.args() else dict_query["Severity"]
    if not severity:
        raise Exception("No current severity, please supply a severity parameter")

    # Optional params
    ref = demisto.args()["reference"] if "reference" in demisto.args() else None
    comments = demisto.args()["comments"] if "comments" in demisto.args() else None

    # Only one of them should exist
    assign_to_org = demisto.args()["assignOrganization"] if "assignOrganization" in demisto.args() else None
    assign_to_person = demisto.args()["assignPerson"] if "assignPerson" in demisto.args() else None

    if assign_to_org and assign_to_person:
        raise Exception("Unable to assign to both organization and a person, please choose only one")

    if not assign_to_org and not assign_to_person:
        if "AssignedOrganization" in dict_workflow_query and dict_workflow_query["AssignedOrganization"]:
            assign_to_org = dict_workflow_query["AssignedOrganization"]
        elif "AssignedPerson" in dict_workflow_query and dict_workflow_query["AssignedPerson"]:
            assign_to_person = dict_workflow_query["AssignedPerson"]

    # Make the request with the params
    success = update_incident_request(num, status, resolution, ref, severity, assign_to_org, assign_to_person, comments)

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


def update_incident_request(num, status, resolution, ref, severity, assign_to_org, assign_to_person, comments):
    # Create optional parameter tags if needed
    ref = "<Reference>%s</Reference>" % (ref) if ref else ""
    assign_to_org = "<AssignedToOrganiztion>%s</AssignedToOrganiztion>" % assign_to_org if assign_to_org else ""
    assign_to_person = "<AssignedToPerson>%s</AssignedToPerson>" % assign_to_person if assign_to_person else ""
    comments = "<Comments>%s</Comments>" % comments if comments else ""

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
                </soap12:Envelope>""" % (num, status, resolution, ref, severity, assign_to_org, assign_to_person,
                                         escape(comments))
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    res = api_call(body=body, headers=headers)
    res_string_xml = xml.etree.ElementTree.tostring(res)
    res_string_json = xml2json(res_string_xml)
    dict_res = json.loads(res_string_json)
    res = dict_res["Envelope"]["Body"]["UpdateIncidentWorkflowResponse"]["UpdateIncidentWorkflowResult"]
    return res == "true"


def query_incident_cmd():
    result = query_incident(demisto.args()["number"], workflow_query=True)

    # Create minimal signature list
    sigs = []
    for sig in result["SignatureList"]["Signature"]:
        sig_dict = dict()  # type: Dict[str, Any]
        sig_dict["SourceIPString"] = sig["SourceIPString"]
        sig_dict["SignatureName"] = sig["SignatureName"]
        sig_dict["VendorSignature"] = sig["VendorSignature"]
        sig_dict["NumberBlocked"] = sig["NumberBlocked"]
        sig_dict["NumberNotBlocked"] = sig["NumberNotBlocked"]
        sigs.append(sig_dict)

    # Set Human readable
    flatten_relevant_fields = [{
        "Incident Number": result.get("IncidentNumber", ""),
        "Time Created": result.get("TimeCreated", ""),
        "Status": result.get("WorkFlowDetail", {}).get("Status", ""),
        "Classification": result.get("Classification", ""),
        "Assigned Person": result.get("WorkFlowDetail", {}).get("AssignedPerson",
                                                                "") if result.get("WorkFlowDetail", {}) else "",
        "Description": result.get("Description", ""),
        "Analyst Assessment": result.get("AnalystAssessment", ""),
        "Number of Analyzed Signatures": result.get("NumberOfAnalyzedSignatures", ""),
        "Signaturtes": json.dumps(sigs) or "",
        "Related Incidents": json.dumps(result.get("RelatedIncidents",
                                                   {}).get("IncidentNumber", "")) if result.get("RelatedIncidents",
                                                                                                {}) else "",
        "Comment": result.get("IncidentComments", {}).get("IncidentComment",
                                                          {}).get("Comment", "") if result.get("IncidentComments",
                                                                                               {}) else ""
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
    hr = tableToMarkdown("Incident query", flatten_relevant_fields, headers)

    # Set context
    result_ctx = {
        "IncidentNumber": result.get("IncidentNumber", ""),
        "NumberOfAnalyzedSignatures": result.get("NumberOfAnalyzedSignatures", ""),
        "SignatureList": {
            "Signature": sigs
        },
        "TimeCreated": result.get("TimeCreated", ""),
        "Classification": result.get("Classification", ""),
        "Description": result.get("Description", ""),
        "AnalystAssessment": result.get("AnalystAssessment", ""),
        "CountryCode": result.get("CountryCode", ""),
        "CountryName": result.get("CountryName", ""),
        "RelatedTickets": result.get("RelatedTickets", ""),
        "WorkFlowDetail": {
            "Status": result.get("WorkFlowDetail", {}).get("Status", ""),
            "AssignedPerson": result.get("WorkFlowDetail", {}).get("AssignedPerson", "")
        },
        "RelatedIncidents": {
            "IncidentNumber": result["RelatedIncidents"]["IncidentNumber"] if result.get("RelatedIncidents") else ""
        }
    }

    if result.get('IncidentComments') and result.get('IncidentComments').get('IncidentComment'):
        result_ctx["IncidentComments"] = {"IncidentComment": {
            "CommentedTimeStampGMT": result["IncidentComments"]["IncidentComment"]["CommentedTimeStampGMT"],
            "Comment": result["IncidentComments"]["IncidentComment"]["Comment"],
            "CommentedBy": result["IncidentComments"]["IncidentComment"]["CommentedBy"]
        }
        }
    else:
        result_ctx["IncidentComments"] = {}

    if result.get("IncidentAttachmentItems") and result.get('IncidentAttachmentItems').get('IncidentAttachmentItem'):
        result_ctx['IncidentAttachmentItems'] = {"IncidentAttachmentItem": {
            "AttachmentNumber": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["AttachmentNumber"],
            "AttachmentName": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["AttachmentName"],
            "UploadDateGMT": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["UploadDateGMT"],
            "UploadBy": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["UploadBy"],
            "Comment": result["IncidentAttachmentItems"]["IncidentAttachmentItem"]["Comment"]
        }
        }
    else:
        result_ctx['IncidentAttachmentItems'] = {}

    context = {
        "Symantec MSS.Incident query(val.IncidentNumber && val.IncidentNumber === obj.IncidentNumber)": result_ctx
    }

    demisto.results({
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": result,
        "EntryContext": context,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": hr
    })


def query_incident(num, workflow_query=False):
    query = query_incident_request(num) if not workflow_query else query_incident_workflow_request(num)
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
                </soap12:Envelope>""" % num
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    query = api_call(body=body, headers=headers)
    query_node = query.find(SECURITY_INCIDENT_NODE_XPATH)
    string_query_xml = xml.etree.ElementTree.tostring(query_node)
    string_query_json = xml2json(string_query_xml)
    dict_query = json.loads(string_query_json)["SecurityIncident"]
    return dict_query


def query_incident_workflow_request(num):
    body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                    <soap12:Body>
                        <IncidentWorkflowQuery xmlns="https://www.monitoredsecurity.com/">
                            <IncidentNumber>%s</IncidentNumber>
                        </IncidentWorkflowQuery>
                    </soap12:Body>
                </soap12:Envelope>""" % num
    headers = {
        "content-Type": "application/soap+xml; charset=utf-8",
        "content-Length": str(len(body))
    }

    query = api_call(body=body, headers=headers)
    query_node = query.find(SECURITY_INCIDENT_NODE_XPATH)
    string_query_xml = xml.etree.ElementTree.tostring(query_node)
    string_query_json = xml2json(string_query_xml)
    dict_query = json.loads(string_query_json)["SecurityIncident"]
    return dict_query


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    handle_proxy()
    if demisto.command() == "fetch-incidents":
        fetch_incidents()

    if demisto.command() == "test-module":
        test()

    if demisto.command() == "symantec-mss-update-incident":
        update_incident()

    if demisto.command() == "symantec-mss-get-incident":
        query_incident_cmd()

    if demisto.command() == "symantec-mss-incidents-list":
        time = demisto.args()["time"] if "time" in demisto.args() else isoformat(
            datetime.utcnow() - timedelta(hours=24))
        get_incidents_list(time)

# Log exceptions
except Exception as e:
    return_error(str(e))
