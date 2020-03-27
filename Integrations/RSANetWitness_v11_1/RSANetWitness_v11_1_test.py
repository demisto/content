import demistomock as demisto

<<<<<<< HEAD
=======
INCIDENT_NEW = {
    "items": [{
        "eventCount": 1,
        "alertMeta": {
            "SourceIp": ["8.8.8.8"],
            "DestinationIp": ["8.8.4.4"]
        },
        "openRemediationTaskCount": 0,
        "sources": [
            None
        ],
        "id": "INC-3",
        "journalEntries": None,
        "ruleId": None,
        "created": "2019-01-14T17:19:16.029Z",
        "priority": "Critical",
        "sealed": True,
        "status": "Assigned",
        "averageAlertRiskScore": 50,
        "lastUpdated": "2019-01-30T13:50:10.148Z",
        "lastUpdatedBy": "admin",
        "alertCount": 1,
        "createdBy": "admin",
        "deletedAlertCount": 0,
        "categories": [],
        "assignee": None,
        "title": "Test",
        "summary": "Test",
        "firstAlertTime": None,
        "totalRemediationTaskCount": 0,
        "riskScore": 50
    }],
    "pageNumber": 0,
    "pageSize": 1,
    "totalPages": 3,
    "totalItems": 3,
    "hasNext": True,
    "hasPrevious": False
}

INCIDENT_OLD = {
    "items": [{
        "eventCount": 1,
        "alertMeta": {
            "SourceIp": ["8.8.8.8"],
            "DestinationIp": ["8.8.4.4"]
        },
        "openRemediationTaskCount": 0,
        "sources": [
            "NetWitness Investigate"
        ],
        "id": "INC-2",
        "journalEntries": None,
        "ruleId": None,
        "created": "2019-01-14T17:19:16.029Z",
        "priority": "Critical",
        "sealed": True,
        "status": "Assigned",
        "averageAlertRiskScore": 50,
        "lastUpdated": "2019-01-30T13:50:10.148Z",
        "lastUpdatedBy": "admin",
        "alertCount": 1,
        "createdBy": "admin",
        "deletedAlertCount": 0,
        "categories": [],
        "assignee": None,
        "title": "Test",
        "summary": "Test",
        "firstAlertTime": None,
        "totalRemediationTaskCount": 0,
        "riskScore": 50
    }],
    "pageNumber": 1,
    "pageSize": 1,
    "totalPages": 3,
    "totalItems": 3,
    "hasNext": True,
    "hasPrevious": True
}

INCIDENT_OLDEST = {
    "items": [{
        "eventCount": 1,
        "alertMeta": {
            "SourceIp": ["8.8.8.8"],
            "DestinationIp": ["8.8.4.4"]
        },
        "openRemediationTaskCount": 0,
        "sources": [
            "NetWitness Investigate"
        ],
        "id": "INC-1",
        "journalEntries": None,
        "ruleId": None,
        "created": "2019-01-14T17:19:16.029Z",
        "priority": "Critical",
        "sealed": True,
        "status": "Assigned",
        "averageAlertRiskScore": 50,
        "lastUpdated": "2019-01-30T13:50:10.148Z",
        "lastUpdatedBy": "admin",
        "alertCount": 1,
        "createdBy": "admin",
        "deletedAlertCount": 0,
        "categories": [],
        "assignee": None,
        "title": "Test",
        "summary": "Test",
        "firstAlertTime": None,
        "totalRemediationTaskCount": 0,
        "riskScore": 50
    }],
    "pageNumber": 2,
    "pageSize": 1,
    "totalPages": 3,
    "totalItems": 3,
    "hasNext": False,
    "hasPrevious": True
}

>>>>>>> upstream/master

def test_get_timestamp(mocker):
    def mock_demisto():
        mocked_dict = {
            'server': '',
            'credentials': {
                'identifier': '',
                'password': ''
            },
            'insecure': '',
            'version': '',
            'isFetch': ''
        }
        mocker.patch.object(demisto, 'params', return_value=mocked_dict)
        import RSANetWitness_v11_1
        mocker.patch.object(RSANetWitness_v11_1, 'get_token', return_value=None)

    mock_demisto()
    from RSANetWitness_v11_1 import get_timestamp
    stamps_to_check = {
        "2019-08-13T09:56:02.000000Z",
        "2019-08-13T09:56:02.440Z",
        "2019-08-13T09:56:02Z",
        "2019-08-13T09:56:02.000000",
        "2019-08-13T09:56:02.440",
        "2019-08-13T09:56:02"
    }
    expected = "2019-08-13 09:56:02"
    for timestamp in stamps_to_check:
        result = str(get_timestamp(timestamp))
        assert expected in result, "\n\tExpected: {}\n\tResult: {}\n\tInput timestamp: {}" \
                                   "".format(expected, result, timestamp)


<<<<<<< HEAD
def test_fetch_incidents(mocker):
=======
def test_fetch_incidents_fetch_oldest_first(mocker):
    """
    Given:
        There are 2 incidents to fetch
    When:
        fetch-incidents with limit size of 1
    Then:
        The oldest incident will be fetched
    """
    def return_incidents_by_page(page_number, **kwargs):
        if page_number == 0:
            return INCIDENT_OLD
        return INCIDENT_OLDEST

>>>>>>> upstream/master
    def mock_demisto():
        mocked_dict = {
            'server': '',
            'credentials': {
                'identifier': '',
                'password': ''
            },
            'insecure': '',
            'version': '',
<<<<<<< HEAD
            'isFetch': ''
=======
            'isFetch': '',
            'fetch_limit': 1
>>>>>>> upstream/master
        }
        mocker.patch.object(demisto, 'params', return_value=mocked_dict)
        mocker.patch.object(demisto, "getLastRun", return_value={
            "timestamp": "2018-08-13T09:56:02.000000"
        })
        mocker.patch.object(demisto, 'incidents')
<<<<<<< HEAD
        incidents = [
            {
                "eventCount": 1,
                "alertMeta": {
                    "SourceIp": ["8.8.8.8"],
                    "DestinationIp": ["8.8.4.4"]
                },
                "openRemediationTaskCount": 0,
                "sources": [
                    "NetWitness Investigate"
                ],
                "id": "INC-25",
                "journalEntries": None,
                "ruleId": None,
                "created": "2019-01-14T17:19:16.029Z",
                "priority": "Critical",
                "sealed": True,
                "status": "Assigned",
                "averageAlertRiskScore": 50,
                "lastUpdated": "2019-01-30T13:50:10.148Z",
                "lastUpdatedBy": "admin",
                "alertCount": 1,
                "createdBy": "admin",
                "deletedAlertCount": 0,
                "categories": [],
                "assignee": None,
                "title": "Test",
                "summary": "Test",
                "firstAlertTime": None,
                "totalRemediationTaskCount": 0,
                "riskScore": 50}
        ]
        mocker.patch('RSANetWitness_v11_1.get_all_incidents', return_value=incidents)
=======
        mocker.patch('RSANetWitness_v11_1.get_incidents_request', return_value='1',
                     side_effect=return_incidents_by_page)
>>>>>>> upstream/master

    mock_demisto()
    from RSANetWitness_v11_1 import fetch_incidents

<<<<<<< HEAD
    fetch_incidents()
    assert demisto.incidents.call_count == 1
=======
    fetched_inc = fetch_incidents()
    # assert fetch
    assert fetched_inc[0]['labels'][0]['value'] == '"{}"'.format(INCIDENT_OLDEST['items'][0]['id'])


def test_fetch_incidents_fetch_with_last_fetched_id(mocker):
    """
    Given:
        There are 2 incidents to fetch
    When:
        fetch-incidents with limit size of 1
    Then:
        The oldest incident will be fetched
    """
    def return_incidents_by_page(page_number, **kwargs):
        if page_number == 0:
            return INCIDENT_NEW
        elif page_number == 1:
            return INCIDENT_OLD
        return INCIDENT_OLDEST

    def mock_demisto():
        mocked_dict = {
            'server': '',
            'credentials': {
                'identifier': '',
                'password': ''
            },
            'insecure': '',
            'version': '',
            'isFetch': '',
            'fetch_limit': 1
        }
        mocker.patch.object(demisto, 'params', return_value=mocked_dict)
        mocker.patch.object(demisto, "getLastRun", return_value={
            "timestamp": "2018-08-13T09:56:02.000000",
            "last_fetched_id": INCIDENT_OLD['items'][0]['id']
        })
        mocker.patch.object(demisto, 'incidents')
        mocker.patch('RSANetWitness_v11_1.get_incidents_request', return_value='1',
                     side_effect=return_incidents_by_page)

    mock_demisto()
    from RSANetWitness_v11_1 import fetch_incidents

    fetched_inc = fetch_incidents()
    # assert fetch
    assert len(fetched_inc) == 1
    assert fetched_inc[0]['labels'][0]['value'] == '"{}"'.format(INCIDENT_NEW['items'][0]['id'])


def test_get_incident(mocker):
    def mock_demisto():
        mock_args = {
            'incidentId': 'INC-3'
        }
        mocker.patch.object(demisto, 'args', return_value=mock_args)
        mocker.patch.object(demisto, 'results')
        mocker.patch('RSANetWitness_v11_1.get_incident_request', return_value=INCIDENT_NEW['items'][0])

    mock_demisto()
    from RSANetWitness_v11_1 import get_incident

    get_incident()
    results = demisto.results.call_args[0]
    # assert results
    assert "INC-3" in results[0]['HumanReadable']
>>>>>>> upstream/master
