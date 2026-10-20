import demistomock as demisto
import lxml
import pytest
import sdv
from CommonServerPython import *

CIDR_INDICATORS = """
{
   "iocs":[
      {
         "id":"9891",
         "version":1,
         "modified":"2020-02-19T17:45:07.468975+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"09c8f0ad-bbb7-4b20-81f7-3b440a3274c4",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-19T17:45:07.433422+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"AWS Feed.AWS Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-19T17:45:07.468974+02:00",
         "indicator_type":"CIDR",
         "value":"18.163.0.0/16",
         "sourceInstances":[
            "AWS Feed_instance_1"
         ],
         "sourceBrands":[
            "AWS Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":1,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null
      }
   ],
   "total":1
}
"""


EMAIL_INDICATORS = """
{
   "iocs":[
      {
         "id":"7764",
         "version":2,
         "modified":"2020-02-12T17:43:42.045543+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"65230a6f-7dec-45cc-8f92-e4caeac27c3a",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:40:09.777799+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@947",
               "entryId":"2@947",
               "category":"Sighting"
               }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:42:11.48852+02:00",
         "indicator_type":"Email",
         "value":"ubuntu-appindicators@ubuntu.com",
         "source":"DBot",
         "investigationIDs":[
            "947",
            "951",
            "953",
            "955",
            "974",
            "978",
            "980",
            "982",
            "998"
         ],
         "lastSeen":"2020-02-12T17:43:42.044887+02:00",
         "firstSeen":"2020-02-12T17:42:11.248928+02:00",
         "lastSeenEntryID":"3@998",
         "firstSeenEntryID":"2@947",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"",
         "expirationSource":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-12T17:43:42.044887+02:00",
         "lastReputationRun":"2020-02-12T17:40:01.09759+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"0001-01-01T00:00:00Z"
      }
   ],
   "total":1
}
"""

URL_INDICATORS = """
{
   "iocs":[
      {
         "id":"7760",
         "version":3,
         "modified":"2020-02-13T10:38:58.302248+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"7bab5aed-1c8b-4b12-8664-a7c4efa35b45",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:34:31.186684+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@938",
               "entryId":"2@938",
               "category":"Sighting"
            },
            {
               "id":"b2204eac-c633-4d93-85fa-e6906ff56aff",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-13T10:38:42.229545+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@1102",
               "entryId":"2@1102",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:34:37.288857+02:00",
         "indicator_type":"URL",
         "value":"http://www.rsyslog.com/e/2359",
         "sourceInstances":[
            "Recorded Future",
            "CrowdStrike"
         ],
         "sourceBrands":[
            "Recorded Future",
            "CrowdStrike"
         ],
         "investigationIDs":[
            "938",
            "1102"
         ],
         "lastSeen":"2020-02-13T10:38:58.301185+02:00",
         "firstSeen":"2020-02-12T17:34:37.186588+02:00",
         "lastSeenEntryID":"3@1102",
         "firstSeenEntryID":"2@938",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z"
      }
   ],
   "total":1
}
"""

IP_INDICATORS = """
{
   "iocs":[
      {
         "id":"7848",
         "version":1,
         "modified":"2020-02-13T18:45:38.997926+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"ed7e9c36-f48f-4f65-8955-ec5319008fa7",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-13T18:45:38.959505+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"Bambenek Consulting Feed.Bambenek Consulting Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-13T18:45:38.997925+02:00",
         "indicator_type":"IP",
         "value":"52.218.100.20",
         "sourceInstances":[
            "Bambenek Consulting Feed_instance_1"
         ],
         "sourceBrands":[
            "Bambenek Consulting Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T18:45:38.997925+02:00",
         "lastReputationRun":"0001-01-01T00:00:00Z",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T18:45:35+02:00"
      }
      ],
   "total":1
}
"""

DOMAIN_INDICATORS = """
{
   "iocs":[
      {
         "id":"7757",
         "version":6,
         "modified":"2020-02-13T10:38:58.301271+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"9b7908ac-b962-489a-8987-38d736d7b168",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:31:38.59569+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@919",
               "entryId":"2@919",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:31:51.156216+02:00",
         "indicator_type":"Domain",
         "value":"www.rsyslog.com",
         "sourceInstances":[
            "CrowdStrike",
            "Recorded Future",
            "VirusTotal"
         ],
         "sourceBrands":[
            "CrowdStrike",
            "Recorded Future",
            "VirusTotal"
         ],
         "investigationIDs":[
            "919",
            "926",
            "918",
            "937",
            "938",
            "936",
            "1090",
            "1089",
            "1102"
         ],
         "lastSeen":"2020-02-13T10:38:58.301185+02:00",
         "firstSeen":"2020-02-12T17:31:51.050588+02:00",
         "lastSeenEntryID":"3@1102",
         "firstSeenEntryID":"2@919",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T10:38:58.301185+02:00",
         "lastReputationRun":"2020-02-13T10:36:23.278024+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T10:36:23.258397+02:00"
      }
   ],
   "total":1
}
"""

FILE_INDICATORS = """
{
   "iocs":[
      {
         "id":"9892",
         "version":1,
         "modified":"2020-02-19T21:06:50.554056+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"78ebd257-e159-4cd3-8bb5-390afebcc1c6",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-19T21:06:50.535091+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"560@909",
               "entryId":"560@909",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-19T21:06:50.554042+02:00",
         "indicator_type":"File",
         "value":"86d96212bfe35ed590aa4f7ace76bb51",
         "source":"DBot",
         "investigationIDs":[
            "909"
         ],
         "lastSeen":"2020-02-19T21:06:50.552883+02:00",
         "firstSeen":"2020-02-19T21:06:50.552884+02:00",
         "lastSeenEntryID":"560@909",
         "firstSeenEntryID":"560@909",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"",
         "expirationSource":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-19T21:06:50.552883+02:00",
         "lastReputationRun":"2020-02-19T21:06:48.225845+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"0001-01-01T00:00:00Z"
      }
   ],
   "total":1
}
"""

INDICATOR_QUERY = (
    'type:IP and sourceBrands:"Bambenek Consulting Feed"'
    ' and sourcetimestamp:>"2020-02-10T11:32:32 +0000" and'
    ' sourcetimestamp:<="2020-02-20T11:32:32 +0000"'
)


def test_find_indicators_by_time_frame(mocker):
    import datetime

    import pytz
    from TAXIIServer import find_indicators_by_time_frame

    def find_indicators(indicator_query):
        if indicator_query == INDICATOR_QUERY:
            return "yep"
        return "nope"

    # Set
    mocker.patch("TAXIIServer.find_indicators_loop", side_effect=find_indicators)
    mocker.patch.object(demisto, "info")

    begin_date = datetime.datetime(2020, 2, 10, 11, 32, 32, 644224, tzinfo=pytz.utc)
    end_date = datetime.datetime(2020, 2, 20, 11, 32, 32, 644224, tzinfo=pytz.utc)

    # Arrange
    result = find_indicators_by_time_frame('type:IP and sourceBrands:"Bambenek Consulting Feed"', begin_date, end_date)

    # Assert
    assert result == "yep"


def test_find_indicators_loop(mocker):
    from TAXIIServer import find_indicators_loop

    # Set
    mocker.patch.object(demisto, "searchIndicators", return_value=json.loads(IP_INDICATORS))

    # Arrange
    indicators = find_indicators_loop("q")

    # Assert
    assert len(indicators) == 1
    assert indicators[0]["value"] == "52.218.100.20"


@pytest.mark.parametrize(
    "indicator",
    [
        json.loads(IP_INDICATORS)["iocs"][0],
        json.loads(URL_INDICATORS)["iocs"][0],
        json.loads(EMAIL_INDICATORS)["iocs"][0],
        json.loads(CIDR_INDICATORS)["iocs"][0],
        json.loads(DOMAIN_INDICATORS)["iocs"][0],
        json.loads(FILE_INDICATORS)["iocs"][0],
    ],
)
def test_validate_indicators(indicator):
    from TAXIIServer import NAMESPACE, NAMESPACE_URI, get_stix_indicator

    # Arrange
    stix_indicator = get_stix_indicator(indicator)
    stix_xml = stix_indicator.to_xml(ns_dict={NAMESPACE_URI: NAMESPACE})
    xml_file = lxml.etree.fromstring(stix_xml)
    tree = lxml.etree.ElementTree(xml_file)

    # Assert
    assert sdv.validate_xml(tree)


@pytest.mark.parametrize(
    "request_headers, url_scheme, expected, is_xsiam",
    [
        ({}, "http", "http://host:9000", False),
        ({"X-Request-URI": "http://host/instance/execute"}, "https", "https://host/instance/execute/eyy", False),
        ({"X-Request-URI": "http://host/instance/execute"}, "https", "https://ext-host/xsoar/instance/execute/eyy", True),
    ],
)
def test_get_url(mocker, request_headers, url_scheme, expected, is_xsiam):
    """
    Given:
        - Case 1: Empty requests headers and http URL scheme
        - Case 2: Request header which contain the X-Request-URI header and https URL scheme

    When:
        - Getting server URL address

    Then:
        - Case 1: Ensure server URL address contain the port and the http URL scheme
        - Case 2: Ensure server URL address contain the /instance/execute endpoint and the https URL scheme
    """
    import TAXIIServer

    taxii_server = TAXIIServer.TAXIIServer(
        url_scheme="http",
        host="host",
        port=9000,
        collections={},
        certificate="",
        private_key="",
        http_server=False,
        credentials={},
    )
    TAXIIServer.SERVER = taxii_server
    if request_headers:
        mocker.patch("TAXIIServer.get_calling_context", return_value={"IntegrationInstance": "eyy"})
        mocker.patch("TAXIIServer.is_xsiam_or_xsoar_saas", return_value=is_xsiam)
    assert taxii_server.get_url(request_headers) == expected


def test_create_stix_hash_observable():
    """
    Given:
        - namespace: The XML namespace, indicator: The Demisto File indicator with a valid MD5 hash.

    When:
        - Getting a File indicator

    Then:
        - Ensure the stix hash observable is created
    """

    from TAXIIServer import create_stix_hash_observable

    namespace = "namespace"
    indicator = {"indicator_type": "File", "value": "86d96212bfe35ed590aa4f7ace76bb51"}
    observable = create_stix_hash_observable(namespace, indicator)
    assert observable


@pytest.mark.parametrize(
    "value",
    [
        "123456789",
        r"C:\Windows\System32\malware.exe",
        "malware.exe",
        "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGXrbWXrFQW",  # SSDEEP-style fuzzy hash
    ],
)
def test_create_stix_hash_observable_rejects_non_hash_values(value):
    """
    Given:
        - A File indicator whose value is not a valid MD5/SHA1/SHA256/SHA512 hash
          (a bare numeric string, a Windows file path, a file name, or a fuzzy/SSDEEP hash).

    When:
        - Building the STIX hash observable for the outbound TAXII 1 feed.

    Then:
        - A ValueError is raised instead of silently serializing an invalid CybOX Hash,
          which previously caused STIX/CybOX schema validation failures and an HTTP 500.
    """
    from TAXIIServer import create_stix_hash_observable

    indicator = {"indicator_type": "File", "value": value}

    with pytest.raises(ValueError):
        create_stix_hash_observable("namespace", indicator)


def test_create_stix_hash_observable_strips_control_characters():
    """
    Given:
        - A File indicator whose hash value is wrapped with invalid XML control characters
          (e.g. a NULL byte), as could occur with corrupted threat intelligence feed data.

    When:
        - Building the STIX hash observable.

    Then:
        - The control characters are stripped and the remaining valid hash value is used,
          so XML/CybOX serialization never fails on invalid characters.
    """
    from TAXIIServer import create_stix_hash_observable

    indicator = {"indicator_type": "File", "value": "86d96212bfe35ed590aa4f7ace76bb51\x00"}
    observable = create_stix_hash_observable("namespace", indicator)
    assert observable


def test_sanitize_for_xml_removes_control_characters():
    """
    Given:
        - A string containing NULL bytes and other control characters that are invalid in XML 1.0.

    When:
        - Sanitizing the string before it is embedded in a CybOX/STIX observable.

    Then:
        - All invalid XML control characters are removed while valid characters are preserved.
    """
    import TAXIIServer

    assert TAXIIServer.sanitize_for_xml("abc\x00def") == "abcdef"
    assert TAXIIServer.sanitize_for_xml("abc\x01\x1fdef") == "abcdef"
    assert TAXIIServer.sanitize_for_xml("normal-value.com") == "normal-value.com"
    assert TAXIIServer.sanitize_for_xml("") == ""


def test_taxii_poll_service_does_not_return_500_on_internal_error(mocker):
    """
    Given:
        - A TAXII poll request whose collection name is not configured on the server, causing
          TAXIIServer.get_poll_response to raise a ValueError synchronously (before a streaming
          Response is built). This same class of synchronous failure (e.g. a STIX/CybOX
          serialization error surfacing before streaming begins) previously propagated
          uncaught through the Flask route and crashed with an HTTP 500.

    When:
        - POSTing to the /taxii-poll-service endpoint.

    Then:
        - The server responds with a handled 400 error instead of an unhandled HTTP 500,
          and the error is reported via handle_long_running_error.
    """
    import TAXIIServer

    taxii_server = TAXIIServer.TAXIIServer(
        url_scheme="http",
        host="host",
        port=9000,
        collections={"TestCollection": "type:File"},
        certificate="",
        private_key="",
        http_server=True,
        credentials={},
    )
    TAXIIServer.SERVER = taxii_server

    mocker.patch.object(demisto, "updateModuleHealth")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")

    class FakePollRequest:
        message_type = TAXIIServer.MSG_POLL_REQUEST
        message_id = "1"
        collection_name = "UnknownCollection"  # not present in SERVER.collections
        exclusive_begin_timestamp_label = None
        inclusive_end_timestamp_label = None

    mocker.patch("TAXIIServer.get_message_from_xml", return_value=FakePollRequest())

    headers = {
        "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
        "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
        "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
    }

    with TAXIIServer.APP.test_client() as test_client:
        response = test_client.post("/taxii-poll-service", data=b"<fake/>", headers=headers)
        assert response.status_code == 400
