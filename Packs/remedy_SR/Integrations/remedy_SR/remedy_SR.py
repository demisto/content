import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import hashlib
import json
import os
import requests
from CommonServerUserPython import *


handle_proxy()
VERIFY_CERTIFICATE = not demisto.params().get("insecure", False)
URL = demisto.params()["server"]
XML_NS = demisto.params()["xml_ns"]
USERNAME = demisto.params()["username"]
PASSWORD = demisto.params()["password"]

HEADERS = {"Content-Type": "text/xml", "SOAPAction": ""}

GET_TICKET_BODY = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="{xml_ns}">
           <soapenv:Header>
           <wsse:Security soapenv:mustUnderstand="1"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
           <wsse:UsernameToken wsu:Id=\"\">
           <wsse:Username>sams</wsse:Username>
           <wsse:Password
            Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
            {password_digest}</wsse:Password>
           <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#
           Base64Binary">{base64_binary}</wsse:Nonce>
           <wsu:Created>{req_time}</wsu:Created>
           </wsse:UsernameToken>
           </wsse:Security>
           </soapenv:Header>
           <soapenv:Body>
              <v1:get>
                 <!--Optional:-->
                 <v1:GetServiceRequestRequest>
                    <Header>
                       <Requester>?</Requester>
                       <Submitter>
                          <Type>Remedy</Type>
                          <Value>sams</Value>
                       </Submitter>
                       <TimeStamp>
                          <Date>{date}</Date>
                          <Time>{time}</Time>
                          <TimeZone>UTC</TimeZone>
                       </TimeStamp>
                       <TransactionId>1</TransactionId>
                    </Header>
                    <Body>
                       <!--Optional:-->
                       <ResponseOptions>
                          <ShowAssignment>?</ShowAssignment>
                          <ShowAttributeList>?</ShowAttributeList>
                          <ShowCategorization>?</ShowCategorization>
                          <ShowWorklogList>?</ShowWorklogList>
                       </ResponseOptions>
                       <!--Optional:-->
                       <ServiceRequestId>{service_request_id}</ServiceRequestId>
                    </Body>
                 </v1:GetServiceRequestRequest>
              </v1:get>
           </soapenv:Body>
        </soapenv:Envelope>"""

CREATE_TICKET_BODY = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="{xml_ns}">
       <soapenv:Header> <wsse:Security soapenv:mustUnderstand="1"
       xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
       <wsse:UsernameToken wsu:Id=\"\">
       <wsse:Username>sams</wsse:Username>
       <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
       #PasswordDigest">{password_digest}</wsse:Password>
       <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0
       #Base64Binary">{base64_binary}</wsse:Nonce>
       <wsu:Created>{req_time}</wsu:Created>
       </wsse:UsernameToken>
       </wsse:Security>
       </soapenv:Header>
       <soapenv:Body>
          <v1:create>
          <!--Optional:-->
             <v1:CreateServiceRequestRequest>
                <Header>
                   <Requester>?</Requester>
                   <Submitter>
                      <Type>Remedy</Type>
                      <Value>!svcautomationdev</Value>
                   </Submitter>
                   <TimeStamp>
                      <Date>{date}</Date>
                      <Time>{time}</Time>
                      <TimeZone>UTC</TimeZone>
                   </TimeStamp>
                   <TransactionId>1</TransactionId>
                </Header>
                <Body>
                   <!--Zero or more repetitions:-->

                   <!--Zero or more repetitions:-->
                   <AttributeList>
                      <Label/>
                      <Value/>
                      <Type/>
                   </AttributeList>
                   <!--Optional:-->
                   <CauseCode/>
                   <!--Optional:-->
                   <Details>{details}</Details>
                   <MasterTicket>True</MasterTicket>
                   <!--Optional:-->
                   <NextAction>test</NextAction>
                   <!--Optional:-->
                   <PendingReason>New</PendingReason>
                   <!--Optional:-->
                   <ProblemCode>47103</ProblemCode>
                   <!--Optional:-->
                   <Requester>
                   <!--Optional:-->
                      <RequesterNTId>{requester_ntid}</RequesterNTId>
                      <!--Optional:-->
                      <RequesterPERNR>{requester_pernr}</RequesterPERNR>
                   </Requester>
                   <!--Optional:-->
                   <RequesterContactInformation>
                   <!--Optional:-->
                      <ContactInformation>
                         <!--Optional:-->
                         <ContactEmail>{contact_email}</ContactEmail>
                         <!--Optional:-->
                         <ContactName>{contact_name}</ContactName>
                         <!--Optional:-->
                         <ContactPhone>{contact_phone}</ContactPhone>
                      </ContactInformation>
                      <!--Optional:-->
                      <RequesterEmail>{requester_email}</RequesterEmail>
                      <!--Optional:-->
                      <RequesterLocation/>
                      <!--Optional:-->
                      <RequesterName>{requester_name}</RequesterName>
                      <!--Optional:-->
                      <RequesterPhone>{requester_phone}</RequesterPhone>
                      <!--Optional:-->
                      <RequesterWorkCity>{requester_work_city}</RequesterWorkCity>
                      <!--Optional:-->
                      <RequesterWorkLocation>{requester_work_location}</RequesterWorkLocation>
                      <!--Optional:-->
                      <RequesterWorkStreet>{requester_work_street}</RequesterWorkStreet>
                   </RequesterContactInformation>
                   <!--Optional:-->
                   <SolutionCode/>
                   <Source>Web</Source>
                   <SourceReference>Demisto</SourceReference>
                   <!--Optional:-->
                   <Status>Pending</Status>
                   <!--Zero or more repetitions:-->
                   <WorklogList>
                      <!--Optional:-->
                      <Details>test</Details>
                      <!--Optional:-->
                      <Subject>test</Subject>
                   </WorklogList>
                </Body>
             </v1:CreateServiceRequestRequest>
          </v1:create>
       </soapenv:Body>
    </soapenv:Envelope>"""


def http_request(body=""):  # pragma: no cover
    """Makes an API call with the given arguments"""
    response = requests.post(URL, data=body, headers=HEADERS, verify=VERIFY_CERTIFICATE)

    if response.status_code < 200 or response.status_code >= 300:
        if response.status_code == 404:
            return_error("Request Failed. with status: 404. Cannot find the requested resource. Check your Server URL")
        elif response.status_code == 500:
            json_result = json.loads(xml2json(response.content))
            return_error(
                "Request Failed. with status: "
                + str(response.status_code)
                + ". Reason is: "
                + str(json_result["Envelope"]["Body"]["Fault"]["faultstring"])
            )
        else:
            return_error("Request Failed. with status: " + str(response.status_code) + ". Reason is: " + str(response.reason))

    json_result = json.loads(xml2json(response.content))

    if "Envelope" in json_result:
        if "Body" in json_result["Envelope"]:
            if "Fault" in json_result["Envelope"]["Body"]:
                return_error("Request Failed. Reason is: " + json_result["Envelope"]["Body"]["Fault"]["faultstring"])

    return json_result


def prettify_get_ticket(json_result):
    ticket = json_result["Envelope"]["Body"]["getResponse"]["return"]["Body"]

    if not ticket:
        return_error(json_result["Envelope"]["Body"]["getResponse"]["return"]["Header"])

    pretty_ticket = {
        "ServiceRequestId": ticket["ServiceRequestId"],
        "ServiceRequestStatus": ticket["ServiceRequestStatus"],
        "Priority": ticket["Priority"],
    }
    if "Created" in ticket:
        if "When" in ticket["Created"]:
            pretty_ticket["Date"] = ticket["Created"]["When"]["Date"]
            pretty_ticket["Time"] = ticket["Created"]["When"]["Time"]

    if "Details" in ticket:
        pretty_ticket["Details"] = ticket["Details"]
    if "SourceReference" in ticket:
        pretty_ticket["SourceReference"] = ticket["SourceReference"]

    if "RequesterContactInformation" in ticket:
        if "RequesterEmail" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterEmail"] = ticket["RequesterContactInformation"]["RequesterEmail"]
        if "RequesterName" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterName"] = ticket["RequesterContactInformation"]["RequesterName"]
        if "RequesterPhone" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterPhone"] = ticket["RequesterContactInformation"]["RequesterPhone"]
        if "RequesterWorkCity" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterWorkCity"] = ticket["RequesterContactInformation"]["RequesterWorkCity"]
        if "RequesterWorkLocation" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterWorkLocation"] = ticket["RequesterContactInformation"]["RequesterWorkLocation"]
        if "RequesterWorkStreet" in ticket["RequesterContactInformation"]:
            pretty_ticket["RequesterWorkStreet"] = ticket["RequesterContactInformation"]["RequesterWorkStreet"]

        if "ContactInformation" in ticket["RequesterContactInformation"]:
            if "ContactEmail" in ticket["RequesterContactInformation"]["ContactInformation"]:
                pretty_ticket["ContactEmail"] = ticket["RequesterContactInformation"]["ContactInformation"]["ContactEmail"]
            if "ContactPhone" in ticket["RequesterContactInformation"]["ContactInformation"]:
                pretty_ticket["ContactPhone"] = ticket["RequesterContactInformation"]["ContactInformation"]["ContactPhone"]
            if "ContactName" in ticket["RequesterContactInformation"]["ContactInformation"]:
                pretty_ticket["ContactName"] = ticket["RequesterContactInformation"]["ContactInformation"]["ContactName"]

    return pretty_ticket


@logger
def remedy_get_ticket(service_request_id):
    now = datetime.utcnow()
    req_time = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    date = now.strftime("%Y-%m-%d")
    time = now.strftime("%H:%M:%S")

    nonce = os.urandom(16)
    base64_binary = base64.b64encode(nonce).decode("ascii")
    # Password_Digest = Base64 (SHA-1 (nonce + createtime + password))
    hash_object = hashlib.sha1(nonce + req_time.encode("utf-8") + PASSWORD.encode("utf-8"))  # nosec
    digest_string = hash_object.digest()
    password_digest = base64.b64encode(digest_string).decode("ascii")

    body = GET_TICKET_BODY.format(
        xml_ns=XML_NS,
        password_digest=password_digest,
        base64_binary=base64_binary,
        req_time=str(req_time),
        date=date,
        time=time,
        service_request_id=service_request_id,
    )
    response = http_request(body)

    return response


def remedy_get_ticket_command():
    service_request_id = demisto.args()["service_request_id"]
    response = remedy_get_ticket(service_request_id)
    pretty_ticket = prettify_get_ticket(response)

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": response,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "Ticket:",
                pretty_ticket,
                ["ServiceRequestId", "Priority", "ServiceRequestStatus", "RequesterEmail", "RequesterName", "RequesterPhone"],
            ),
            "EntryContext": {"Remedy.Ticket(val.ServiceRequestId == obj.ServiceRequestId)": pretty_ticket},
        }
    )


def prettify_create_ticket(json_result, requester_phone, requester_name, requester_email):
    ticket = json_result["Envelope"]["Body"]["createResponse"]["return"]["Body"]

    if not ticket:
        return_error(json_result["Envelope"]["Body"]["createResponse"]["return"]["Header"])

    pretty_ticket = {"ServiceRequestId": ticket["ServiceRequestId"]}
    pretty_ticket["RequesterPhone"] = requester_phone
    pretty_ticket["RequesterName"] = requester_name
    pretty_ticket["RequesterEmail"] = requester_email

    return pretty_ticket


@logger
def remedy_create_ticket(
    details,
    requester_ntid,
    requester_email,
    requester_name,
    requester_phone,
    requester_work_city,
    requester_work_location,
    requester_work_street,
    requester_pernr="?",
    contact_email="?",
    contact_name="?",
    contact_phone="?",
):
    now = datetime.utcnow()
    req_time = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    date = now.strftime("%Y-%m-%d")
    time = now.strftime("%H:%M:%S")

    nonce = os.urandom(16)
    base64_binary = base64.b64encode(nonce).decode("ascii")
    # Password_Digest = Base64 (SHA-1 (nonce + createtime + password))
    hash_object = hashlib.sha1(nonce + req_time.encode("utf-8") + PASSWORD.encode("utf-8"))  # nosec
    digest_string = hash_object.digest()
    password_digest = base64.b64encode(digest_string).decode("ascii")

    body = CREATE_TICKET_BODY.format(
        xml_ns=XML_NS,
        password_digest=password_digest,
        base64_binary=base64_binary,
        req_time=str(req_time),
        date=date,
        time=time,
        details=details,
        requester_ntid=requester_ntid,
        requester_email=requester_email,
        requester_name=requester_name,
        requester_phone=requester_phone,
        requester_work_city=requester_work_city,
        requester_work_location=requester_work_location,
        requester_work_street=requester_work_street,
        requester_pernr=requester_pernr,
        contact_email=contact_email,
        contact_name=contact_name,
        contact_phone=contact_phone,
    )
    response = http_request(body)

    return response


def remedy_create_ticket_command():
    args = demisto.args()
    details = args["details"]
    requester_ntid = args["requester_ntid"]
    requester_pernr = args["requester_pernr"] if "requester_pernr" in args else None
    contact_email = args["contact_email"] if "contact_email" in args else None
    contact_name = args["contact_name"] if "contact_name" in args else None
    contact_phone = args["contact_phone"] if "contact_phone" in args else None
    requester_email = args["requester_email"]
    requester_name = args["requester_name"]
    requester_phone = args["requester_phone"]
    requester_work_city = args["requester_work_city"]
    requester_work_location = args["requester_work_location"]
    requester_work_street = args["requester_work_street"]

    response = remedy_create_ticket(
        details,
        requester_ntid,
        requester_email,
        requester_name,
        requester_phone,
        requester_work_city,
        requester_work_location,
        requester_work_street,
        requester_pernr,
        contact_email,
        contact_name,
        contact_phone,
    )

    pretty_ticket = prettify_create_ticket(response, requester_phone, requester_name, requester_email)

    ec_create = {
        "ServiceRequestId": response["Envelope"]["Body"]["createResponse"]["return"]["Body"]["ServiceRequestId"],
        "Details": details,
        "RequesterNTID": requester_ntid,
        "RequesterPERNR": requester_pernr,
        "RequesterEmail": requester_email,
        "RequesterName": requester_name,
        "RequesterPhone": requester_phone,
        "RequesterWorkCity": requester_work_city,
        "RequesterWorkLocation": requester_work_location,
        "RequesterWorkStreet": requester_work_street,
        "ContactEmail": contact_email,
        "ContactName": contact_name,
        "ContactPhone": contact_phone,
    }

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": response,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "Ticket:", pretty_ticket, ["ServiceRequestId", "RequesterEmail", "RequesterName", "RequesterPhone"]
            ),
            "EntryContext": {"Remedy.Ticket(val.ServiceRequestId == obj.ServiceRequestId)": ec_create},
        }
    )


def remedy_update_ticket_command():
    raise DemistoException("This is a deprecated command")


""" EXECUTION CODE """
LOG("command is %s" % (demisto.command(),))
try:
    if demisto.command() == "test-module":
        remedy_get_ticket("SR000552078")
        demisto.results("ok")

    elif demisto.command() == "remedy-get-ticket":
        remedy_get_ticket_command()

    elif demisto.command() == "remedy-create-ticket":
        remedy_create_ticket_command()

    elif demisto.command() == "remedy-update-ticket":
        remedy_update_ticket_command()

except Exception as e:
    return_error(str(e))
