import demistomock as demisto


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


def test_fetch_incidents(mocker):
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
        mocker.patch.object(demisto, "getLastRun", return_value={
            "timestamp": "2018-08-13T09:56:02.000000"
        })
        mocker.patch.object(demisto, 'incidents')
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

    mock_demisto()
    from RSANetWitness_v11_1 import fetch_incidents

    fetch_incidents()
    assert demisto.incidents.call_count == 1
