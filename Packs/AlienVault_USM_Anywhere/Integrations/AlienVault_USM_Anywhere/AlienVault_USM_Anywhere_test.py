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
    def alarms_url(cls, lookback_minutes=None):
        """The alarms request the integration is expected to send.

        The request starts at the shared watermark minus the lookback window, so the caller
        passes the lookback it configured. Defaults to the shared LOOKBACK_MINUTES.
        """
        from CommonServerPython import date_to_timestamp

        if lookback_minutes is None:
            lookback_minutes = cls.LOOKBACK_MINUTES
        start = date_to_timestamp(cls.WATERMARK_TIME - timedelta(minutes=lookback_minutes))
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

    def test_skips_duplicates(self, mocker, requests_mock):
        """Only alarms absent from the dedup cache are turned into incidents.

        Given: An API page containing one alarm already present in fetched_ids and one new alarm.

        When: Running fetch_incidents.

        Then: Only the new alarm becomes an incident, while the persisted cache retains both UUIDs.

        """
        from CommonServerPython import date_to_timestamp

        duplicate_time = self.WATERMARK_TIME + timedelta(minutes=10)
        new_time = self.WATERMARK_TIME + timedelta(minutes=20)
        last_fetch = date_to_timestamp(self.WATERMARK_TIME)
        now_ms = date_to_timestamp(datetime.now())

        mocker.patch.object(demisto, "params", return_value=self.params())
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={"timestamp": last_fetch, "fetched_ids": {"already-fetched": now_ms}},
        )
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        requests_mock.get(
            self.alarms_url(),
            json=self.alarms_response(
                [
                    self.alarm("already-fetched", duplicate_time),
                    self.alarm("brand-new", new_time),
                ]
            ),
        )

        fetch_incidents()

        created_incidents = demisto.incidents.call_args[0][0]
        assert [incident["name"] for incident in created_incidents] == ["Alarm: brand-new"]

        last_run = demisto.setLastRun.call_args[0][0]
        # The new UUID joins the cache so it is suppressed next cycle.
        assert set(last_run["fetched_ids"]) == {"already-fetched", "brand-new"}
        assert last_run["timestamp"] == date_to_timestamp(new_time)

    def test_skips_item_without_uuid(self, mocker, requests_mock):
        """Alarms missing a UUID are ignored and never influence the watermark.

        Given: An API page containing an alarm with no UUID that occurred later than a
               valid alarm in the same page.

        When: Running fetch_incidents.

        Then: Only the alarm with a UUID becomes an incident, and the persisted timestamp
              reflects that alarm rather than the later UUID-less one.

        """
        from CommonServerPython import date_to_timestamp

        valid_time = self.WATERMARK_TIME + timedelta(minutes=10)
        # Later than the valid alarm, so leaking it into the watermark would be visible.
        no_uuid_time = self.WATERMARK_TIME + timedelta(minutes=45)
        last_fetch = date_to_timestamp(self.WATERMARK_TIME)

        mocker.patch.object(demisto, "params", return_value=self.params())
        mocker.patch.object(demisto, "getLastRun", return_value={"timestamp": last_fetch, "fetched_ids": {}})
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        requests_mock.get(
            self.alarms_url(),
            json=self.alarms_response(
                [
                    self.alarm("valid-alarm", valid_time),
                    self.alarm(None, no_uuid_time),
                ]
            ),
        )

        fetch_incidents()

        created_incidents = demisto.incidents.call_args[0][0]
        assert [incident["name"] for incident in created_incidents] == ["Alarm: valid-alarm"]

        last_run = demisto.setLastRun.call_args[0][0]
        assert last_run["timestamp"] == date_to_timestamp(valid_time)
        assert set(last_run["fetched_ids"]) == {"valid-alarm"}

    def test_evicts_stale_ids(self, mocker, requests_mock):
        """UUIDs older than the retention window are dropped from the persisted cache.

        Given: A dedup cache holding one entry well outside the retention window
               (lookback + 60 minutes) and one recent entry.

        When: Running fetch_incidents.

        Then: The stale UUID is evicted from fetched_ids and the recent one is kept.

        """
        from CommonServerPython import date_to_timestamp

        retention_minutes = self.LOOKBACK_MINUTES + 60
        last_fetch = date_to_timestamp(self.WATERMARK_TIME)

        now = datetime.now()
        recent_ms = date_to_timestamp(now)
        # Comfortably beyond retention so the entry is unambiguously expired.
        stale_ms = date_to_timestamp(now - timedelta(minutes=retention_minutes + 30))

        mocker.patch.object(demisto, "params", return_value=self.params())
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "timestamp": last_fetch,
                "fetched_ids": {"stale-uuid": stale_ms, "recent-uuid": recent_ms},
            },
        )
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        # No alarms returned, so the persisted cache reflects eviction alone.
        requests_mock.get(self.alarms_url(), json=self.alarms_response([]))

        fetch_incidents()

        persisted_ids = demisto.setLastRun.call_args[0][0]["fetched_ids"]
        assert "stale-uuid" not in persisted_ids
        assert "recent-uuid" in persisted_ids

    def test_caps_fetched_ids(self, mocker, requests_mock):
        """The persisted dedup cache is capped, keeping the newest entries.

        Given: A dedup cache already larger than MAX_FETCHED_IDS, where entries carry
               increasing timestamps.

        When: Running fetch_incidents.

        Then: The persisted cache is truncated to MAX_FETCHED_IDS entries and the oldest
              UUIDs are discarded, since they are closest to expiring anyway.

        """
        from AlienVault_USM_Anywhere import MAX_FETCHED_IDS
        from CommonServerPython import date_to_timestamp

        last_fetch = date_to_timestamp(self.WATERMARK_TIME)

        # All entries stay inside the retention window so eviction cannot interfere,
        # while increasing offsets make the newest/oldest ordering unambiguous.
        now = datetime.now()
        overflow = 10
        oversized_cache = {
            f"cached-uuid-{index:05d}": date_to_timestamp(now - timedelta(seconds=MAX_FETCHED_IDS + overflow - index))
            for index in range(MAX_FETCHED_IDS + overflow)
        }

        mocker.patch.object(demisto, "params", return_value=self.params())
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={"timestamp": last_fetch, "fetched_ids": oversized_cache},
        )
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        # No alarms returned, so the persisted cache reflects truncation alone.
        requests_mock.get(self.alarms_url(), json=self.alarms_response([]))

        fetch_incidents()

        persisted_ids = demisto.setLastRun.call_args[0][0]["fetched_ids"]
        assert len(persisted_ids) == MAX_FETCHED_IDS

        # The oldest entries carry the lowest indexes, so those are the ones dropped.
        assert "cached-uuid-00000" not in persisted_ids
        assert f"cached-uuid-{MAX_FETCHED_IDS + overflow - 1:05d}" in persisted_ids

    def test_zero_lookback_fetches_from_watermark(self, mocker, requests_mock):
        """A lookback of 0 starts the fetch exactly at the stored watermark.

        Given: A lookback of 0, which is the default and disables the lookback window.

        When: Running fetch_incidents.

        Then: The alarms request starts at the watermark with no window applied, so the fetch
              immediately after an upgrade does not re-request already fetched alarms.

        """
        from CommonServerPython import date_to_timestamp

        last_fetch = date_to_timestamp(self.WATERMARK_TIME)
        occurred_time = self.WATERMARK_TIME + timedelta(minutes=10)

        mocker.patch.object(
            demisto,
            "params",
            return_value={"fetch_limit": str(self.FETCH_LIMIT), "url": self.SERVER_URL, "lookback": "0"},
        )
        mocker.patch.object(demisto, "getLastRun", return_value={"timestamp": last_fetch, "fetched_ids": {}})
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "incidents")
        from AlienVault_USM_Anywhere import fetch_incidents

        requests_mock.get(
            self.alarms_url(lookback_minutes=0),
            json=self.alarms_response([self.alarm("new-alarm", occurred_time)]),
        )

        fetch_incidents()

        # No window is subtracted, so the request starts on the watermark itself.
        assert requests_mock.last_request.qs["timestamp_occured_gte"] == [str(last_fetch)]

        # Fetching still works normally with the lookback disabled.
        created_incidents = demisto.incidents.call_args[0][0]
        assert [incident["name"] for incident in created_incidents] == ["Alarm: new-alarm"]

        last_run = demisto.setLastRun.call_args[0][0]
        assert last_run["timestamp"] == date_to_timestamp(occurred_time)
        assert set(last_run["fetched_ids"]) == {"new-alarm"}
