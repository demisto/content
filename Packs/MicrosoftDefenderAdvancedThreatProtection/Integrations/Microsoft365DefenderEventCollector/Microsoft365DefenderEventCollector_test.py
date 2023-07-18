import pytest
import re
import demistomock as demisto
import Microsoft365DefenderEventCollector
import datetime
from Microsoft365DefenderEventCollector import main, MAX_ALERTS_PAGE_SIZE, DemistoException

"""
Test:
    1. - Happy Path
    1.1 - fetch events first time - ensure dateparser was called with the first_fetch arg
    1.2 - fetch events second time - ensure demisto.getLastRun() is used instead of dataparser
    1.3 - fetch with limit - ensure limit passed in the $top query param and the result is limited

    2. - Edge cases
    2.1 - fetch with limit - ensure limit is bellow the MAX_ALERTS_PAGE_SIZE
    2.2 - authentication failed - ensure the expected error message returned
"""

REQUESTS_MATCHER = re.compile(r'https://api\.security\.microsoft\.com/api/alerts\?.*filter.*orderby.*top.*')
MOCKED_EVENTS = {
    "@odata.context": "https://api-us.securitycenter.microsoft.com/api/$metadata#Alerts",
    "value": [
        {
            "id": "test_id_1",
            "incidentId": 1,
            "investigationId": 1,
            "assignedTo": "Automation",
            "severity": "Informational",
            "status": "Resolved",
            "classification": "TruePositive",
            "investigationState": "Benign",
            "category": "SuspiciousActivity",
            "title": "test title 1",
            "description": "test description 1",
            "alertCreationTime": "2021-11-14T02:11:27.4223926Z",
            "mitreTechniques": [],
            "comments": [
                {
                    "comment": "testing",
                    "createdBy": "Automation",
                    "createdTime": "2021-11-14T02:11:37.9181822Z"
                }
            ],
            "evidence": {}
        },
        {
            "id": "test_id_2",
            "incidentId": 2,
            "investigationId": 2,
            "assignedTo": "Automation",
            "severity": "Informational",
            "status": "Resolved",
            "classification": "TruePositive",
            "investigationState": "Benign",
            "detectionSource": "AutomatedInvestigation",
            "category": "SuspiciousActivity",
            "title": "test title 2",
            "description": "test description 2",
            "alertCreationTime": "2021-11-15T02:01:41.6457398Z",
            "mitreTechniques": [],
            "comments": [
                {
                    "comment": "testing",
                    "createdBy": "Automation",
                    "createdTime": "2021-11-15T02:01:56.3449897Z"
                }
            ],
            "evidence": {}
        },
        {
            "id": "test_id_3",
            "incidentId": 3,
            "investigationId": 3,
            "assignedTo": "Automation",
            "severity": "Medium",
            "status": "Resolved",
            "investigationState": "Benign",
            "category": "None",
            "title": "test title 3",
            "description": "test description 3",
            "alertCreationTime": "2021-11-15T02:01:54.0211631Z",
            "mitreTechniques": [],
            "loggedOnUsers": [],
            "comments": [],
            "evidence": {}
        }
    ]
}
PARAMS = {
    'url': 'https://api.security.microsoft.com',
    'tenant_id': 'test_tenant_id',
    'client_id': 'test_client_id',
    'verify': 'false',
    'limit': '1000',
    'credentials': {
        'password': 'test_pass'
    },
    'first_fetch': '3 days'
}


@pytest.fixture(autouse=True, scope='function')
def mock_required(mocker, requests_mock):
    mocker.patch('Microsoft365DefenderEventCollector.MicrosoftClient.get_access_token', return_value='token')
    mocker.patch.object(demisto, 'getLastRun', return_value=None)
    mocker.patch.object(Microsoft365DefenderEventCollector, 'send_events_to_xsiam')

    requests_mock.get(
        REQUESTS_MATCHER,
        [{'json': MOCKED_EVENTS}],
    )


class TestFetchEventsHappyPath:

    def test_fetch_events_first_time(self, mocker):
        """
        Given - there is no object returned by demist.getLastRun.
        When - fetch_events called for the first time.
        Then - ensure the dateparser was called.
        """

        # prepare
        mocker.patch.object(
            Microsoft365DefenderEventCollector.dateparser,
            'parse', return_value=datetime.datetime.now())

        mocker.patch.object(demisto, 'setLastRun')
        mocker.patch.object(demisto, 'getLastRun', return_value=None)

        # run
        main(command='fetch-events', params=PARAMS)

        # validate
        Microsoft365DefenderEventCollector.dateparser.parse.assert_called_with(
            PARAMS['first_fetch'],
            settings={'TIMEZONE': 'UTC'}
        )
        last_alert_creation_time = MOCKED_EVENTS['value'][2]['alertCreationTime']
        demisto.setLastRun.assert_called_with({'after': last_alert_creation_time})
        assert Microsoft365DefenderEventCollector.send_events_to_xsiam.call_args[0][0] == MOCKED_EVENTS['value']

    def test_fetch_events_second_time(self, mocker, requests_mock):
        """
        Given - demisto.getLastRun return an object.
        When - call the main for the command fetch_events.
        Then - validate the `after` value from the returned object is used
        """
        # prepare
        stored_creation_time = MOCKED_EVENTS['value'][0]['alertCreationTime']
        mocker.patch.object(demisto, 'getLastRun', return_value={'after': stored_creation_time})
        mocker.patch.object(Microsoft365DefenderEventCollector.dateparser, 'parse')

        # run
        main(command='fetch-events', params=PARAMS)

        # validate
        assert stored_creation_time.lower() in requests_mock.request_history[0].qs['$filter'][0]
        Microsoft365DefenderEventCollector.dateparser.parse.assert_not_called()

    def test_fetch_events_with_limit(self, mocker, requests_mock):
        """
        Given -
        When - call the main for the command fetch_events.
        Then - validate the `limit` value passed as the `$top` query param
                and the len of the returned alerts is limited
        """
        # prepare
        limit = 1
        mocker.patch.object(demisto, 'getLastRun', return_value=None)

        # run
        main(command='fetch-events', params=PARAMS | {'limit': limit})

        # validate
        returned_alerts = Microsoft365DefenderEventCollector.send_events_to_xsiam.call_args[0][0]
        assert str(limit) == requests_mock.request_history[0].qs['$top'][0]
        assert len(returned_alerts) == limit


class TestFetchEventsEdgeCases:

    def test_fetch_events_with_high_limit(self, mocker, requests_mock):
        """
        Given - limit args > the max allowed MAX_ALERTS_PAGE_SIZE (10,000)
        When - call the main for the command fetch_events.
        Then - validate the `limit` value was set top 10,000 and passed as the `$top` query param
        """
        # prepare
        limit = 20000
        mocker.patch.object(demisto, 'getLastRun', return_value=None)

        # run
        main(command='fetch-events', params=PARAMS | {'limit': limit})

        # validate
        assert str(MAX_ALERTS_PAGE_SIZE) == requests_mock.request_history[0].qs['$top'][0]

    def test_test_module_failed(self, mocker):
        """
        Given - Authentication error occurred.
        When - run the test_module command
        Then - validate the expected error eas returned by `demisto.results`
        """

        # prepare
        mocker.patch.object(Microsoft365DefenderEventCollector.DefenderGetEvents,
                            'run',
                            side_effect=DemistoException('Fail to authenticate'))
        mocker.patch.object(demisto, 'results')

        # run
        main(command='test-module', params=PARAMS)

        # validate
        demisto.results.assert_called_with(Microsoft365DefenderEventCollector.AUTH_ERROR_MSG)


def test_get_events_command(mocker):
    """
    Given -
    When - call the main for the command get-events.
    Then - validate the returned result as expected.
    """
    # prepare
    mocker.patch.object(Microsoft365DefenderEventCollector, 'return_results')

    # run
    main(command='microsoft-365-defender-get-events', params=PARAMS)

    # validate
    returned_results = Microsoft365DefenderEventCollector.return_results.call_args[0][0]
    assert returned_results.outputs == MOCKED_EVENTS['value']
