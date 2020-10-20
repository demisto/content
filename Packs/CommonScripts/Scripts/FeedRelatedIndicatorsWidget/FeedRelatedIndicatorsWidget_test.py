import pytest
import demistomock as demisto

FILE_INDICATOR = {'CustomFields': {
    'campaign': ['pickaxe_play2'],
    'feedrelatedindicators': [
        {'description': 'https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc',
         'type': 'MITRE ATT&CK', 'value': None},
        {'description': 'https://securelist.com/lazarus-under-the-hood/77908/', 'type': 'MITRE ATT&CK', 'value': None},
        {'description': 'https://attack.mitre.org/techniques/T1496', 'type': 'MITRE ATT&CK', 'value': 'T1496'},
        {'description': 'Some Description', 'type': 'MITRE ATT&CK', 'value': None},
    ]}}

SEARCH_INDICATORS_RESPONSE = {'total': 1, 'iocs': [
    {'id': '4467', 'version': 4, 'modified': '2020-08-09T16:38:12.862662+03:00', 'sortValues':
        [' \x01\x16\x14g#Wjx\x1d\x00', '4467'],
     'comments': [
         {'id': 'b96b5331-1afb-46ed-8de7-645d74243d83', 'version': 0, 'modified': '0001-01-01T00:00:00Z',
          'sortValues': None, 'content': 'Created', 'user': '@DBot', 'created': '2020-08-09T13:53:55.851918+03:00',
          'type': 'IndicatorCommentTimeLine', 'source': '2@11', 'entryId': '2@11', 'category': 'Sighting'}],
     'account': '', 'timestamp': '2020-08-09T13:53:55.907799+03:00', 'indicator_type': 'MITRE ATT&CK', 'value': 'T1345',
     'source': 'DBot', 'sourceInstances': ['MITRE ATT&CK'], 'sourceBrands': ['MITRE ATT&CK'], 'investigationIDs':
         ['11', 'a2fcc0c4-c7a9-4fdb-89d9-3613aec57280'], 'relatedIncCount': 1,
     'lastSeen': '2020-08-09T16:38:12.86248+03:00', 'firstSeen': '2020-08-09T13:53:55.907473+03:00',
     'lastSeenEntryID': '610@a2fcc0c4-c7a9-4fdb-89d9-3613aec57280', 'firstSeenEntryID': '2@11', 'score': 0,
     'manualScore': False, 'manualSetTime': '0001-01-01T00:00:00Z',
     'insightCache': {'id': 't1345', 'version': 1, 'modified': '2020-08-09T16:33:44.495265+03:00', 'sortValues': None,
                      'scores': {'MITRE ATT&CK': {
                          'score': 0, 'content': "## ['T1345'](https://ABCDEFG:8443/#/indicator/4467):\n ",
                          'contentFormat': 'markdown', 'timestamp': '2020-08-09T16:33:44.49526+03:00',
                          'scoreChangeTimestamp': '2020-08-09T16:33:44.49526+03:00', 'isTypedIndicator': False,
                          'type': 'MITRE ATT&CK', 'context':
                              {'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor && val.Vendor '
                               '== obj.Vendor)': {'Indicator': 'T1345', 'Score': 0, 'Type': 'MITRE ATT&CK',
                                                  'Vendor': 'MITRE ATT&CK'},
                               'MITRE.ATT&CK(val.value && val.value = obj.value)':
                                   {'customFields': {}, 'indicatorid': '4467', 'value': 'T1345'}}, 'reliability': ''}}},
     'moduleToFeedMap': {'MITRE ATT&CK': {
         'reliability': 'A+ - 3rd party enrichment', 'fetchTime': '2020-08-09T16:33:44.49526+03:00',
         'sourceBrand': 'MITRE ATT&CK', 'sourceInstance': 'MITRE ATT&CK', 'moduleId': 'MITRE ATT&CK',
         'expirationPolicy': 'indicatorType', 'expirationInterval': 0, 'bypassExclusionList': False, 'score': 0,
         'classifierVersion': 0, 'classifierId': '', 'mapperVersion': 0, 'mapperId': '', 'type': 'MITRE ATT&CK',
         'value': 'T1345', 'timestamp': '0001-01-01T00:00:00Z', 'fields': None, 'modifiedTime': '0001-01-01T00:00:00Z',
         'ExpirationSource': {'setTime': '2020-08-09T16:38:12.845863+03:00', 'source': 'indicatorType', 'user': '',
                              'brand': 'MITRE ATT&CK', 'instance': 'MITRE ATT&CK', 'moduleId': 'MITRE ATT&CK',
                              'expirationPolicy': 'indicatorType', 'expirationInterval': 20160}, 'rawJSON': None,
         'isEnrichment': True}}, 'isShared': False, 'expiration': '2020-08-23T16:38:12.845863+03:00',
     'manualExpirationTime': '0001-01-01T00:00:00Z', 'expirationStatus': 'active', 'expirationSource':
         {'setTime': '2020-08-09T16:38:12.845863+03:00', 'source': 'indicatorType', 'user': '', 'brand': 'MITRE ATT&CK',
          'instance': 'MITRE ATT&CK', 'moduleId': 'MITRE ATT&CK', 'expirationPolicy': 'indicatorType',
          'expirationInterval': 20160}, 'deletedFeedFetchTime': '0001-01-01T00:00:00Z',
     'calculatedTime': '2020-08-09T16:38:12.86248+03:00', 'lastReputationRun': '2020-08-09T16:33:44.506101+03:00',
     'comment': '', 'manuallyEditedFields': None, 'modifiedTime': '2020-08-09T16:33:44.49526+03:00',
     'aggregatedReliability': ''}], 'searchAfter': [' \x01\x16\x14g#Wjx\x1d\x00', '4467']}


def test_feed_related_indicator(mocker):
    """
    Given: File hash indicator.
    When: Running feed_related_indicator command.
    Then: Verify expected results returns
    """
    from FeedRelatedIndicatorsWidget import feed_related_indicator

    args = {'indicator': FILE_INDICATOR}
    mocker.patch.object(demisto, 'searchIndicators', return_value=SEARCH_INDICATORS_RESPONSE)
    result = feed_related_indicator(args)

    assert result.readable_output == '|Type|Value|Description|\n|---|---|---|\n| MITRE ATT&CK |  | ' \
                                     '[https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc]' \
                                     '(https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc)' \
                                     '<br><br> |\n| MITRE ATT&CK |  | ' \
                                     '[https://securelist.com/lazarus-under-the-hood/77908/]' \
                                     '(https://securelist.com/lazarus-under-the-hood/77908/)<br><br> |\n| ' \
                                     'MITRE ATT&CK | [T1496](#/indicator/4467) | ' \
                                     '[https://attack.mitre.org/techniques/T1496]' \
                                     '(https://attack.mitre.org/techniques/T1496)<br><br> |\n| MITRE ATT&CK |  | ' \
                                     'Some Description<br><br> |\n'


RELATED_INDICATOR_OBJECTS_PACK = [
    ('value1', 'type1', 'https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc',
     {
         'Value': 'value1',
         'Type': 'type1',
         'Description': '[https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc]'
                        '(https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc)\n\n'
     }
     ),
    ('value1', 'type1', None,
     {
         'Value': 'value1',
         'Type': 'type1',
         'Description': '\n\n'
     }
     ),
    ('value1', 'type1', 'desc1, desc2',
     {
         'Value': 'value1',
         'Type': 'type1',
         'Description': 'desc1, desc2\n\n'
     }
     ),
    ('value1', 'type1', 'desc1, https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc',
     {
         'Value': 'value1',
         'Type': 'type1',
         'Description': 'desc1, [https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc]'
                        '(https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc)\n\n'
     }
     )

]


@pytest.mark.parametrize('value, type_, description, expected_output', RELATED_INDICATOR_OBJECTS_PACK)
def test_create_related_indicator_object(value, type_, description, expected_output):
    """
        Given:
            - value (str): Value of feed related indicator.
            - type_ (str): Type of feed related indicator.
            - description (str): Description(s) of feed related indicator.
        When:
            - Processing data to show in widget.
        Then:
            - Verify that description is being processed at it should.
        """
    from FeedRelatedIndicatorsWidget import create_related_indicator_object

    assert create_related_indicator_object(value, type_, description) == expected_output
