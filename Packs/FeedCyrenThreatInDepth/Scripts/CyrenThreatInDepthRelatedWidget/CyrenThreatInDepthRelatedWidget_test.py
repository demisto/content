import pytest
import demistomock as demisto
from CommonServerPython import Common

FILE_INDICATOR = {
    "CustomFields": {
        "cyrenfeedrelationships": [
            {
                "indicatortype": "SHA-256", "timestamp": "2020-10-28T14:45:24.921Z", "entitycategory": "malware",
                "description": "downloaded from malware ip", "relationshiptype": "downloaded from",
                "value": "0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21",
            },
        ]
    }
}

SEARCH_INDICATORS_RESPONSE = {"total": 1, "iocs": [
    {"id": "4467", "version": 4, "modified": "2020-08-09T16:38:12.862662+03:00", "sortValues":
        [" \x01\x16\x14g#Wjx\x1d\x00", "4467"],
     "comments": [
         {"id": "b96b5331-1afb-46ed-8de7-645d74243d83", "version": 0, "modified": "0001-01-01T00:00:00Z",
          "sortValues": None, "content": "Created", "user": "@DBot", "created": "2020-08-09T13:53:55.851918+03:00",
          "type": "IndicatorCommentTimeLine", "source": "2@11", "entryId": "2@11", "category": "Sighting"}],
     "account": "", "timestamp": "2020-08-09T13:53:55.907799+03:00", "indicator_type": "MITRE ATT&CK", "value": "T1345",
     "source": "DBot", "sourceInstances": ["MITRE ATT&CK"], "sourceBrands": ["MITRE ATT&CK"], "investigationIDs":
         ["11", "a2fcc0c4-c7a9-4fdb-89d9-3613aec57280"], "relatedIncCount": 1,
     "lastSeen": "2020-08-09T16:38:12.86248+03:00", "firstSeen": "2020-08-09T13:53:55.907473+03:00",
     "lastSeenEntryID": "610@a2fcc0c4-c7a9-4fdb-89d9-3613aec57280", "firstSeenEntryID": "2@11", "score": 0,
     "manualScore": False, "manualSetTime": "0001-01-01T00:00:00Z",
     "insightCache": {"id": "t1345", "version": 1, "modified": "2020-08-09T16:33:44.495265+03:00", "sortValues": None,
                      "scores": {"MITRE ATT&CK": {
                          "score": 0, "content": "## [\"T1345\"](https://ABCDEFG:8443/#/indicator/4467):\n ",
                          "contentFormat": "markdown", "timestamp": "2020-08-09T16:33:44.49526+03:00",
                          "scoreChangeTimestamp": "2020-08-09T16:33:44.49526+03:00", "isTypedIndicator": False,
                          "type": "MITRE ATT&CK", "context":
                              {"DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor && val.Vendor "
                               "== obj.Vendor)": {"Indicator": "T1345", "Score": 0, "Type": "MITRE ATT&CK",
                                                  "Vendor": "MITRE ATT&CK"},
                               "MITRE.ATT&CK(val.value && val.value = obj.value)":
                                   {"customFields": {}, "indicatorid": "4467", "value": "T1345"}}, "reliability": ""}}},
     "moduleToFeedMap": {"MITRE ATT&CK": {
         "reliability": "A+ - 3rd party enrichment", "fetchTime": "2020-08-09T16:33:44.49526+03:00",
         "sourceBrand": "MITRE ATT&CK", "sourceInstance": "MITRE ATT&CK", "moduleId": "MITRE ATT&CK",
         "expirationPolicy": "indicatorType", "expirationInterval": 0, "bypassExclusionList": False, "score": 0,
         "classifierVersion": 0, "classifierId": "", "mapperVersion": 0, "mapperId": "", "type": "MITRE ATT&CK",
         "value": "T1345", "timestamp": "0001-01-01T00:00:00Z", "fields": None, "modifiedTime": "0001-01-01T00:00:00Z",
         "ExpirationSource": {"setTime": "2020-08-09T16:38:12.845863+03:00", "source": "indicatorType", "user": "",
                              "brand": "MITRE ATT&CK", "instance": "MITRE ATT&CK", "moduleId": "MITRE ATT&CK",
                              "expirationPolicy": "indicatorType", "expirationInterval": 20160}, "rawJSON": None,
         "isEnrichment": True}}, "isShared": False, "expiration": "2020-08-23T16:38:12.845863+03:00",
     "manualExpirationTime": "0001-01-01T00:00:00Z", "expirationStatus": "active", "expirationSource":
         {"setTime": "2020-08-09T16:38:12.845863+03:00", "source": "indicatorType", "user": "", "brand": "MITRE ATT&CK",
          "instance": "MITRE ATT&CK", "moduleId": "MITRE ATT&CK", "expirationPolicy": "indicatorType",
          "expirationInterval": 20160}, "deletedFeedFetchTime": "0001-01-01T00:00:00Z",
     "calculatedTime": "2020-08-09T16:38:12.86248+03:00", "lastReputationRun": "2020-08-09T16:33:44.506101+03:00",
     "comment": "", "manuallyEditedFields": None, "modifiedTime": "2020-08-09T16:33:44.49526+03:00",
     "aggregatedReliability": ""}], "searchAfter": [" \x01\x16\x14g#Wjx\x1d\x00", "4467"]}

SEARCH_INDICATORS_EMPTY_RESPONSE = {"total": 0, "iocs": []}


def test_cyren_feed_relationship_no_indicator():
    """
    Given: no indicator
    When: Running cyren_feed_relationship command.
    Then: ValueError is raised
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    with pytest.raises(ValueError):
        cyren_feed_relationship({})


def test_cyren_feed_relationship_with_search_response(mocker):
    """
    Given: File hash indicator.
    When: Running cyren_feed_relationship command.
    Then: Verify expected results returns
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    args = {"indicator": FILE_INDICATOR}
    mocker.patch.object(demisto, "searchIndicators", return_value=SEARCH_INDICATORS_RESPONSE)
    result = cyren_feed_relationship(args)

    assert result.readable_output == ("|Indicator Type|Value|Reputation|Relationship Type|Entity Category|Timestamp UTC|\n"
                                      "|---|---|---|---|---|---|\n"
                                      "| SHA-256 "
                                      "| "
                                      "[0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21]"
                                      "(#/indicator/4467)<br> | "
                                      "None (0) | downloaded from | malware | 2020-10-28, 14:45:24 |\n")


def test_cyren_feed_relationship_without_search_response(mocker):
    """
    Given: File hash indicator.
    When: Running cyren_feed_relationship command.
    Then: Verify expected results returns
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    args = {"indicator": FILE_INDICATOR}
    mocker.patch.object(demisto, "searchIndicators", return_value=SEARCH_INDICATORS_EMPTY_RESPONSE)
    result = cyren_feed_relationship(args)

    assert result.readable_output == ("|Indicator Type|Value|Reputation|Relationship Type|Entity Category|Timestamp UTC|\n"
                                      "|---|---|---|---|---|---|\n"
                                      "| SHA-256 | 0f6dbfb291ba1b84601b0372f70db3430df636c631d074c1c2463f9e5a033f21<br> | "
                                      "None (0) | downloaded from | malware | 2020-10-28, 14:45:24 |\n")


RELATED_INDICATOR_OBJECTS_PACK = [
    ("value1", "relates to", "some-type", "2020-10-28T14:45:24.921Z", "phishing", Common.DBotScore.BAD,
     {
         "Value": "value1\n", "Reputation": "Bad (3)", "Entity Category": "phishing",
         "Relationship Type": "relates to", "Indicator Type": "some-type", "Timestamp UTC": "2020-10-28, 14:45:24",
     }),
    ("value1", "relates to", "some-type", "2020-10-28T14:45:24.921Z", "phishing", Common.DBotScore.GOOD,
     {
         "Value": "value1\n", "Reputation": "Good (1)", "Entity Category": "phishing",
         "Relationship Type": "relates to", "Indicator Type": "some-type", "Timestamp UTC": "2020-10-28, 14:45:24",
     }),
    ("value1", "relates to", "some-type", "2020-10-28T14:45:24.921Z", "phishing", Common.DBotScore.NONE,
     {
         "Value": "value1\n", "Reputation": "None (0)", "Entity Category": "phishing",
         "Relationship Type": "relates to", "Indicator Type": "some-type", "Timestamp UTC": "2020-10-28, 14:45:24",
     }),
    ("value1", "relates to", "some-type", "2020-10-28T14:45:24.921Z", "phishing", Common.DBotScore.SUSPICIOUS,
     {
         "Value": "value1\n", "Reputation": "Suspicious (2)", "Entity Category": "phishing",
         "Relationship Type": "relates to", "Indicator Type": "some-type", "Timestamp UTC": "2020-10-28, 14:45:24",
     }),
    ("value1", "relates to", "some-type", "20201028", "phishing", Common.DBotScore.SUSPICIOUS,
     {
         "Value": "value1\n", "Reputation": "Suspicious (2)", "Entity Category": "phishing",
         "Relationship Type": "relates to", "Indicator Type": "some-type", "Timestamp UTC": "20201028",
     }),
]


@pytest.mark.parametrize(("value, relationship_type, indicator_type, "
                          "timestamp, entity_category, reputation, expected_output"), RELATED_INDICATOR_OBJECTS_PACK)
def test_create_related_indicator_object(value, relationship_type, indicator_type, timestamp, entity_category,
                                         reputation, expected_output):
    """
        Given:
            - value (str): Value of feed related indicator.
            - relationship_type (str): indicator relationship type
            - indicator_type (str): indicator type
            - timestamp (str): indicator timestamp
            - entity_category (str): indicator entity category
            - reputation (int): indicator DBot score
        When:
            - Processing data to show in widget.
        Then:
            - Verify that description is being processed at it should.
        """
    from CyrenThreatInDepthRelatedWidget import create_relationship_object

    assert create_relationship_object(value, relationship_type, indicator_type,
                                      timestamp, entity_category, reputation) == expected_output
