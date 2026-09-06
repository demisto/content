import json
from datetime import datetime, timedelta

import dateparser
import demistomock as demisto
import pytest

server_url = (
    "https://vigilant.alienvault.cloud/api/2.0/alarms?page=0&size=1"
    "&sort=timestamp_occured%2Casc&timestamp_occured_gte=1547563649000"
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


alarms_data = util_load_json("./test_data/alarms_data.json")


def approximate_compare(time1, time2):
    if isinstance(time1, int):
        time1 = datetime.fromtimestamp(time1 / 1000)
    if isinstance(time2, int):
        time2 = datetime.fromtimestamp(time2 / 1000)

    return timedelta(seconds=-30) <= time1 - time2 <= timedelta(seconds=3)


@pytest.mark.parametrize(
    "alarm, expected_incident",
    [
        (
            {
                "_embedded": {
                    "alarms": [
                        {
                            "uuid": "4444444444",
                            "timestamp_occured_iso8601": "2019-07-12T06:00:38.000Z",
                        }
                    ]
                },
                "page": {"totalElements": 1861},
            },
            {
                "name": "Alarm: 4444444444",
                "occurred": "2019-07-12T06:00:38.000Z",
            },
        ),
        (
            {
                "_embedded": {
                    "alarms": [
                        {
                            "uuid": "75d464ef-2834-k73a-5af0-7967369de3a1",
                            "timestamp_occured": "1629187949000",
                        }
                    ]
                },
                "page": {"totalElements": 1861},
            },
            {
                "name": "Alarm: 75d464ef-2834-k73a-5af0-7967369de3a1",
                "occurred": "2021-08-17T08:12:29.000Z",
            },
        ),
    ],
)
def test_fetch_incidents(mocker, requests_mock, alarm, expected_incident):
    mocker.patch.object(
        demisto, "params", return_value={"fetch_limit": "1", "url": "https://vigilant.alienvault.cloud/", "lookback": "60"}
    )
    mocker.patch.object(demisto, "getLastRun", return_value={"timestamp": "1547567249000"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    from AlienVault_USM_Anywhere import fetch_incidents

    requests_mock.get(
        server_url,
        json=alarm,
    )
    fetch_incidents()
    incident = demisto.incidents.call_args[0][0][0]
    assert incident["name"] == expected_incident["name"]
    assert incident["occurred"] == expected_incident["occurred"]


def test_get_time_range():
    from AlienVault_USM_Anywhere import get_time_range
    from CommonServerPython import date_to_timestamp

    assert get_time_range(None, None, None) == (None, None)

    dt = datetime.now()
    start, end = get_time_range("Today", None, None)
    assert datetime.fromtimestamp(start / 1000).date() == dt.date()
    assert approximate_compare(dt, end)

    dt = datetime.now()
    # should ignore the start/end time values
    start, end = get_time_range("Today", "asfd", "asdf")
    assert datetime.fromtimestamp(start / 1000).date() == dt.date()
    assert approximate_compare(dt, end)

    dt = datetime.now()
    start, end = get_time_range("Yesterday", None, None)
    assert datetime.fromtimestamp(start / 1000).date() == (dt.date() - timedelta(days=1))
    assert approximate_compare(dt, end)

    start, end = get_time_range("Custom", "2019-12-30T01:02:03Z", "2019-12-30T04:05:06Z")
    assert (start, end) == (
        date_to_timestamp(dateparser.parse("2019-12-30T01:02:03Z")),
        date_to_timestamp(dateparser.parse("2019-12-30T04:05:06Z")),
    )

    start, end = get_time_range("Custom", "2019-12-30T01:02:03Z", None)
    assert start == date_to_timestamp(dateparser.parse("2019-12-30T01:02:03Z"))
    assert approximate_compare(end, datetime.now())


parsed_regular_alarm = {
    "ID": "some_uuid",
    "Priority": "low",
    "OccurredTime": "2021-08-17T08:15:57.000Z",
    "ReceivedTime": "2021-08-17T08:17:03.106Z",
    "RuleAttackID": "T1110",
    "RuleAttackTactic": ["Credential Access"],
    "RuleAttackTechnique": "Brute Force",
    "RuleDictionary": "WindowsRules-Dict",
    "RuleID": "MultipleAccountPasswordResetAttempts",
    "RuleIntent": "Delivery & Attack",
    "RuleMethod": "Multiple Account Password Reset Attempts",
    "RuleStrategy": "Anomalous User Behavior",
    "Source": {"IPAddress": "some_destination_name", "Organization": None, "Country": None},
    "Destination": {"IPAddress": "some_destination_name"},
    "Event": [
        {
            "ID": "some_specific_packet_data3",
            "OccurredTime": "2021-08-17T08:12:28.000Z",
            "ReceivedTime": "2021-08-17T08:13:22.233Z",
        },
        {
            "ID": "some_specific_packet_data2",
            "OccurredTime": "2021-08-17T08:13:41.000Z",
            "ReceivedTime": "2021-08-17T08:14:57.783Z",
        },
        {
            "ID": "some_specific_packet_data1",
            "OccurredTime": "2021-08-17T08:15:57.000Z",
            "ReceivedTime": "2021-08-17T08:17:01.325Z",
        },
    ],
    "Status": "open",
}


@pytest.mark.parametrize(
    "alarms_raw_data, parsed_alarms",
    [
        (alarms_data.get("event_timestamp_occured_iso86_missing"), [parsed_regular_alarm]),
        (alarms_data.get("alarm_timestamp_occured_iso86_missing"), [parsed_regular_alarm]),
        (alarms_data.get("regular_alarm"), [parsed_regular_alarm]),
        (alarms_data.get("event_timestamp_received_iso86_missing"), [parsed_regular_alarm]),
        (alarms_data.get("alarm_timestamp_received_iso86_missing"), [parsed_regular_alarm]),
    ],
)
def test_parse_alarms(alarms_raw_data, parsed_alarms):
    """Test Parsing of alarms from AlienVault

    Given: Alarms raw data to parse

    When: Getting alarms from AlienVault

    Then: Assert they are parsed correctly

    """
    from AlienVault_USM_Anywhere import parse_alarms

    assert parse_alarms(alarms_raw_data) == parsed_alarms


class TestFetchIncidents:
    """Covers the fetch_incidents deduplication behavior.

    All cases share a fixed watermark so the timeline reads consistently, and build their
    times from datetime to stay timezone-consistent with date_to_timestamp, which the
    integration uses to parse the alarm occurred time.
    """

    SERVER_URL = "https://vigilant.alienvault.cloud/"
    WATERMARK_TIME = datetime(2019, 1, 15, 15, 47, 29)
    LOOKBACK_MINUTES = 60
    FETCH_LIMIT = 2

    @staticmethod
    def alarm(uuid, occurred_time):
        """Build a single alarm as AlienVault returns it. Omits the uuid key when uuid is None."""
        alarm = {"timestamp_occured_iso8601": occurred_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
        if uuid is not None:
            alarm["uuid"] = uuid
        return alarm

    @staticmethod
    def alarms_response(alarms):
        """Wrap alarms in the paged envelope the alarms endpoint returns."""
        return {"_embedded": {"alarms": alarms}, "page": {"totalElements": len(alarms)}}

    @classmethod
    def alarms_url(cls):
        """The alarms request the integration is expected to send, given the shared watermark."""
        from CommonServerPython import date_to_timestamp

        start = date_to_timestamp(cls.WATERMARK_TIME - timedelta(minutes=cls.LOOKBACK_MINUTES))
        return (
            f"{cls.SERVER_URL}api/2.0/alarms?page=0&size={cls.FETCH_LIMIT}"
            f"&sort=timestamp_occured%2Casc&timestamp_occured_gte={start}"
        )

    @classmethod
    def params(cls):
        """Integration parameters matching the shared fetch configuration."""
        return {
            "fetch_limit": str(cls.FETCH_LIMIT),
            "url": cls.SERVER_URL,
            "lookback": str(cls.LOOKBACK_MINUTES),
        }

    def test_all_duplicates_advances_timestamp(self, mocker, requests_mock):
        """Regression guard: a page of only already-fetched alarms must still advance the watermark.

        Given: A previous run that already fetched every alarm the API returns in this cycle,
               where those alarms occurred after the stored timestamp.

        When: Running fetch_incidents.

        Then: No incidents are created, but the persisted timestamp advances to the newest
              occurred time in the page.
        """
        from CommonServerPython import date_to_timestamp

        older_occurred_time = self.WATERMARK_TIME + timedelta(minutes=10)
        newest_occurred_time = self.WATERMARK_TIME + timedelta(minutes=20)
        last_fetch = date_to_timestamp(self.WATERMARK_TIME)
        now_ms = date_to_timestamp(datetime.now())

        mocker.patch.object(demisto, "params", return_value=self.params())
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "timestamp": last_fetch,
                # Seeded as "now" so both survive retention eviction.
                "fetched_ids": {"duplicate-alarm-1": now_ms, "duplicate-alarm-2": now_ms},
            },
        )
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        requests_mock.get(
            self.alarms_url(),
            json=self.alarms_response(
                [
                    self.alarm("duplicate-alarm-1", older_occurred_time),
                    self.alarm("duplicate-alarm-2", newest_occurred_time),
                ]
            ),
        )

        fetch_incidents()

        assert demisto.incidents.call_args[0][0] == []

        last_run = demisto.setLastRun.call_args[0][0]
        assert last_run["timestamp"] > last_fetch, (
            f"lastRun timestamp did not advance: still {last_run['timestamp']} (expected > {last_fetch}). "
            "A fully-duplicate page stalls the fetch."
        )
        assert last_run["timestamp"] == date_to_timestamp(newest_occurred_time)
        assert set(last_run["fetched_ids"]) == {"duplicate-alarm-1", "duplicate-alarm-2"}
