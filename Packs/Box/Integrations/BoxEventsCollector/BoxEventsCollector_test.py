import json

import pytest

import demistomock as demisto
from BoxEventsCollector import BoxEventsClient, main


class TestBoxCollectEvents:
    params = {
        'credentials_json': {
            'password': json.dumps(
                {
                    'boxAppSettings': {
                        'clientID': 'I AM A CLIENT ID',
                        'clientSecret': 'I AM A CLIENT SECRET',
                        'appAuth': {
                            'publicKeyID': 'PUBLIC KEY ID',
                            'privateKey': 'I AM A PRIVATE KEY!!!',
                            'passphrase': 'passphrase',
                        },
                    },
                    'enterpriseID': '000000000',
                }
            )
        },
        'created_after': '30 days',
        'verify': False,
    }

    def test_everything_is_called_in_main(self, mocker, requests_mock):
        """Just see that the main works as intended with the mocked data.
        No really running the jwt creation as it need real value"""
        requests_mock.get(
            'https://api.box.com/2.0/events',
            json={'next_stream_position': 0, 'entries': []},
        )
        main('box-get-events', self.params)

    def test_fetch_events_is_running(self, mocker, requests_mock):
        """See that call to the fetch events function do calls set last run
        and sends the events to xsiam"""
        params = self.params.copy()
        params['limit'] = 2
        requests_mock.get(
            'https://api.box.com/2.0/events',
            [
                {
                    'json': {
                        'next_stream_position': 600,
                        'entries': [{'sample event': 'event'}],
                    }
                },
                {'json': {'next_stream_position': 601, 'entries': []}},
            ],
        )

        last_run = mocker.patch.object(demisto, 'setLastRun')
        send_events_to_xsiam = mocker.patch(
            'BoxEventsCollector.send_events_to_xsiam'
        )
        main('collect-events', params)
        assert last_run.call_args_list[0].args[0] == {'stream_position': '601'}
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 1

    @pytest.fixture(autouse=True, scope='function')
    def remove_authentication(self, mocker):
        """We don't need to authenticate in the test functions"""
        mocker.patch.object(BoxEventsClient, 'authenticate', return_value=None)
