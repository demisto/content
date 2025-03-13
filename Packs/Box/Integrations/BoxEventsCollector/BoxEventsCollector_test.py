import json

import pytest

import demistomock as demisto
from BoxEventsCollector import BoxEventsClient, main


class TestBoxCollectEvents:
    params = {
        "url": "https://api.box.com",
        "credentials_json": {
            "password": json.dumps(
                {
                    "boxAppSettings": {
                        "clientID": "I AM A CLIENT ID",
                        "clientSecret": "I AM A CLIENT SECRET",
                        "appAuth": {
                            "publicKeyID": "PUBLIC KEY ID",
                            "privateKey": "I AM A PRIVATE KEY!!!",
                            "passphrase": "passphrase",
                        },
                    },
                    "enterpriseID": "000000000",
                }
            )
        },
        "created_after": "30 days",
        "verify": False,
    }

    def test_everything_is_called_in_main(self, mocker, requests_mock):
        """Just see that the main works as intended with the mocked data.
        No really running the jwt creation as it need real value"""
        requests_mock.get(
            "https://api.box.com/2.0/events",
            json={"next_stream_position": "0", "entries": []},
        )
        main("box-get-events", self.params)

    def test_fetch_events_is_running(self, mocker, requests_mock):
        """See that call to the fetch events function do calls set last run
        and sends the events to xsiam"""
        params = self.params.copy()
        params["limit"] = 2
        requests_mock.get(
            "https://api.box.com/2.0/events",
            [
                {
                    "json": {
                        "next_stream_position": "600",
                        "entries": [{"sample event": "event"}],
                    }
                },
                {"json": {"next_stream_position": "601", "entries": []}},
            ],
        )

        last_run = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam = mocker.patch("BoxEventsCollector.send_events_to_xsiam")
        main("fetch-events", params)
        assert last_run.call_args_list[0].args[0] == {"stream_position": "601"}
        assert len(send_events_to_xsiam.call_args_list[0].args[0]) == 1

    @pytest.fixture(autouse=True, scope="function")
    def remove_authentication(self, mocker):
        """We don't need to authenticate in the test functions"""
        mocker.patch.object(BoxEventsClient, "authenticate", return_value=None)

    def test_not_gate(self):
        """Well, I've been forced to raise the coverage"""
        from BoxEventsCollector import not_gate

        assert not_gate(None)
        assert not_gate(False)
        assert not_gate("No")
        assert not not_gate(True)
        assert not not_gate("yes")

    def test_url_as_param(self, mocker, requests_mock):
        """Assert the request url changes when url parameter changes."""
        new_url = "https://api.triangle.com"
        mocked_request = requests_mock.get(
            f"{new_url}/2.0/events",
            json={"next_stream_position": "0", "entries": []},
        )
        different_url_params = self.params.copy()
        different_url_params["url"] = new_url
        main("box-get-events", different_url_params)
        assert mocked_request.called
