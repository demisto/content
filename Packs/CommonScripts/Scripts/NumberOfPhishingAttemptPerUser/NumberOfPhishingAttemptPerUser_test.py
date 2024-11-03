from NumberOfPhishingAttemptPerUser import get_relevant_incidents

from CommonServerPython import *

incident = [
    {'ModuleName': 'InnerServicesModule', 'Brand': 'Builtin', 'Category': 'Builtin', 'ID': '', 'Version': 0, 'Type': 1,
     'Contents': {
         'ErrorsPrivateDoNotUse': None, 'data': [
             {'CustomFields': {'customercityselect': '',
                               'customercountryselect': '',
                               'customerstateselect': '',
                               'dbotpredictionprobability': 0,
                               'detectionsla': {'accumulatedPause': 0,
                                                'breachTriggered': False,
                                                'dueDate': '0001-01-01T00:00:00Z',
                                                'endDate': '0001-01-01T00:00:00Z',
                                                'lastPauseDate': '0001-01-01T00:00:00Z',
                                                'runStatus': 'idle',
                                                'sla': 20, 'slaStatus': -1,
                                                'startDate': '0001-01-01T00:00:00Z',
                                                'totalDuration': 0},
                               'emailfrom': 'bark@demisto.com',
                               'emailto': 'bark@demisto.com',
                               'remediationsla': {'accumulatedPause': 0,
                                                  'breachTriggered': False,
                                                  'dueDate': '0001-01-01T00:00:00Z',
                                                  'endDate': '0001-01-01T00:00:00Z',
                                                  'lastPauseDate': '0001-01-01T00:00:00Z',
                                                  'runStatus': 'idle',
                                                  'sla': 7200,
                                                  'slaStatus': -1,
                                                  'startDate': '0001-01-01T00:00:00Z',
                                                  'totalDuration': 0},
                               'tasklist': [],
                               'timetoassignment': {'accumulatedPause': 0,
                                                    'breachTriggered': False,
                                                    'dueDate': '0001-01-01T00:00:00Z',
                                                    'endDate': '0001-01-01T00:00:00Z',
                                                    'lastPauseDate': '0001-01-01T00:00:00Z',
                                                    'runStatus': 'idle',
                                                    'sla': 0,
                                                    'slaStatus': -1,
                                                    'startDate': '0001-01-01T00:00:00Z',
                                                    'totalDuration': 0},
                               'urlsslverification': []}, 'ShardID': 0,
              'account': 'Content', 'activated': '0001-01-01T00:00:00Z',
              'attachment': None, 'autime': 1594242451076699000,
              'canvases': None, 'category': '', 'closeNotes': '',
              'closeReason': '', 'closed': '0001-01-01T00:00:00Z',
              'closingUserId': '',
              'created': '2020-07-08T14:07:31.076698991-07:00',
              'dbotCreatedBy': 'sbenyakir@paloaltonetworks.com',
              'details': '', 'droppedCount': 0,
              'dueDate': '2020-07-18T14:07:31.076698991-07:00',
              'feedBased': False, 'hasRole': False, 'id': '29432',
              'investigationId': '29432', 'isPlayground': False,
              'labels': [{'type': 'Instance',
                          'value': 'sbenyakir@paloaltonetworks.com'},
                         {'type': 'Brand', 'value': 'Manual'}],
              'lastJobRunTime': '0001-01-01T00:00:00Z',
              'lastOpen': '0001-01-01T00:00:00Z', 'linkedCount': 0,
              'linkedIncidents': None,
              'modified': '2020-07-19T01:04:21.930897901-07:00',
              'name': 'shahaf2', 'notifyTime': '0001-01-01T00:00:00Z',
              'occurred': '2020-07-08T14:07:31.076698769-07:00',
              'openDuration': 0, 'owner': 'sbenyakir@paloaltonetworks.com',
              'parent': '', 'phase': '',
              'playbookId': '566f7816-998d-4e5d-8359-056f98260fbc',
              'previousRoles': None, 'rawCategory': '',
              'rawCloseReason': '', 'rawJSON': '', 'rawName': 'shahaf2',
              'rawPhase': '', 'rawType': 'Unclassified', 'reason': '',
              'reminder': '0001-01-01T00:00:00Z', 'roles': None,
              'runStatus': 'completed', 'severity': 0, 'sla': 0,
              'sortValues': ['_score'], 'sourceBrand': 'Manual',
              'sourceInstance': 'sbenyakir@paloaltonetworks.com',
              'status': 1, 'type': 'Unclassified', 'version': 7}],
         'total': 1}, 'HumanReadable': None, 'ImportantEntryContext': None, 'EntryContext': None,
     'IgnoreAutoExtract': False, 'ReadableContentsFormat': '', 'ContentsFormat': 'json', 'File': '', 'FileID': '',
     'FileMetadata': None, 'System': '', 'Note': False, 'Evidence': False, 'EvidenceID': '', 'Tags': None,
     'Metadata': {'id': '', 'version': 0, 'modified': '0001-01-01T00:00:00Z', 'sortValues': None, 'roles': None,
                  'previousRoles': None, 'hasRole': False, 'dbotCreatedBy': '', 'ShardID': 0, 'type': 1,
                  'created': '2020-07-19T01:05:57.974757746-07:00', 'retryTime': '0001-01-01T00:00:00Z', 'user': '',
                  'errorSource': '', 'contents': '', 'format': 'json', 'investigationId': '29432', 'file': '',
                  'fileID': '', 'parentId': '280@29432', 'pinned': False, 'fileMetadata': None,
                  'parentContent': '!getIncidents query="emailto:bark@demisto.com --status:Closed"',
                  'parentEntryTruncated': False, 'system': '', 'reputations': None, 'category': '', 'note': False,
                  'isTodo': False, 'tags': None, 'tagsRaw': None, 'startDate': '0001-01-01T00:00:00Z', 'times': 0,
                  'recurrent': False, 'endingDate': '0001-01-01T00:00:00Z', 'timezoneOffset': 0, 'cronView': False,
                  'scheduled': False, 'entryTask': None, 'taskId': '', 'playbookId': '', 'reputationSize': 0,
                  'contentsSize': 0, 'brand': 'Builtin', 'instance': 'Builtin', 'IndicatorTimeline': None},
     'IndicatorTimeline': None}]


def test_get_relevant_incidents_with_results(mocker):
    """Unit test
    Given
    - get_relevant_incidents command
    - command args
    When
    - mock the raw response with a response.
    Then
    - run the get_relevant_incidents
    Validate the amount of incidents returned is 1, 1.
    """
    email_to = email_from = "bark@demisto.com"
    from_date = "2016-01-02T15:04:05Z"
    mocker.patch.object(demisto, 'executeCommand', return_value=incident)
    assert get_relevant_incidents(email_to, email_from, from_date) == (1, 1)


no_incident = [
    {'ModuleName': 'InnerServicesModule', 'Brand': 'Builtin', 'Category': 'Builtin', 'ID': '', 'Version': 0, 'Type': 1,
     'Contents': {'ErrorsPrivateDoNotUse': None, 'data': None, 'total': 0}, 'HumanReadable': None,
     'ImportantEntryContext': None, 'EntryContext': None, 'IgnoreAutoExtract': False, 'ReadableContentsFormat': '',
     'ContentsFormat': 'json', 'File': '', 'FileID': '', 'FileMetadata': None, 'System': '', 'Note': False,
     'Evidence': False, 'EvidenceID': '', 'Tags': None,
     'Metadata': {'id': '', 'version': 0, 'modified': '0001-01-01T00:00:00Z', 'sortValues': None, 'roles': None,
                  'previousRoles': None, 'hasRole': False, 'dbotCreatedBy': '', 'ShardID': 0, 'type': 1,
                  'created': '2020-07-19T11:01:20.769494+03:00', 'retryTime': '0001-01-01T00:00:00Z', 'user': '',
                  'errorSource': '', 'contents': '', 'format': 'json', 'investigationId': '951', 'file': '',
                  'fileID': '', 'parentId': '144@951', 'pinned': False, 'fileMetadata': None,
                  'parentContent': '!getIncidents query="--status:Closed fromdate: 2020-07-09T08:01:20Z"',
                  'parentEntryTruncated': False, 'system': '', 'reputations': None, 'category': '', 'note': False,
                  'isTodo': False, 'tags': None, 'tagsRaw': None, 'startDate': '0001-01-01T00:00:00Z', 'times': 0,
                  'recurrent': False, 'endingDate': '0001-01-01T00:00:00Z', 'timezoneOffset': 0, 'cronView': False,
                  'scheduled': False, 'entryTask': None, 'taskId': '', 'playbookId': '', 'reputationSize': 0,
                  'contentsSize': 0, 'brand': 'Builtin', 'instance': 'Builtin', 'IndicatorTimeline': None,
                  'mirrored': False}, 'IndicatorTimeline': None}]


def test_get_relevant_incidents_without_results(mocker):
    """Unit test
    Given
    - get_relevant_incidents command
    - command args
    When
    - mock the raw response with an empty response.
    Then
    - run the get_relevant_incidents
    Validate the amount of incidents returned is 0, 0.
    """
    email_to = email_from = "barka@demisto.com"
    from_date = "2016-01-02T15:04:05Z"
    mocker.patch.object(demisto, 'executeCommand', return_value=no_incident)
    assert get_relevant_incidents(email_to, email_from, from_date) == (0, 0)
