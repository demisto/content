import demistomock as demisto
import pytest
import json
import RedCanary


with open("./TestData/incidents.json") as f:
    data = json.load(f)


class TestFetchIncidents:
    test_collection = [
        # lastRun is time
        ({"time": "2019-12-13T17:23:22Z"}, 3, "2019-12-30T22:00:51Z"),
        # No last run
        (None, 3, "2019-12-30T22:00:51Z"),
    ]

    @pytest.mark.parametrize("lastRun, incidents_len, new_last_run", test_collection)
    def test_fetch_when_last_run_is_time(
        self, mocker, lastRun, incidents_len, new_last_run
    ):
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value=lastRun)
        mocker.patch.object(
            RedCanary, "get_unacknowledged_detections", return_value=data["data"]
        )
        mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)
        RedCanary.fetch_incidents()
        assert len(demisto.incidents.call_args[0][0]) == incidents_len
        assert demisto.setLastRun.call_args[0][0]["time"] == new_last_run
