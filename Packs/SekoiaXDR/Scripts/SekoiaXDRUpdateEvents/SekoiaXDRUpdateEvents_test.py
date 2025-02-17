import demistomock as demisto
from SekoiaXDRUpdateEvents import get_updated_alert, main  # type: ignore


def test_get_updated_alert(mocker):
    events_output = [
        {
            "uuid": "df904d2e-2c57-488f",
            "status": 0,
            "total": 0,
            "term": "sekoiaio.intake.uuid:df904d2e-2c57-488f",
            "term_lang": "es-query-string",
            "filters": [],
            "created_by": "f870d496-a37b-4aec",
            "created_by_type": "apikey",
            "created_at": "2024-04-30T13:50:04.876962Z",
            "started_at": "2024-04-25T10:00:23",
            "canceled_by": "2024-04-25T10:00:23",
            "canceled_by_type": "2024-04-25T10:00:23",
            "canceled_at": "2024-04-25T10:00:23",
            "ended_at": "2024-04-25T10:00:23",
            "earliest_time": "2024-04-25T10:00:23",
            "latest_time": "2024-04-25T15:00:23",
            "results_ttl": 1800,
            "expiration_date": "2024-04-25T10:00:23",
            "expired": False,
            "view_uuid": "2024-04-25T10:00:23",
            "community_uuids": ["52bd045f-4199-4361"],
            "only_eternal": False,
            "max_last_events": "2024-04-25T10:00:23",
            "date_field": "2024-04-25T10:00:23",
        },
        {
            "uuid": "df900000e-2007-4000f",
            "status": 0,
            "total": 0,
            "term": "sekoiaio.intake.uuid:df900000e-2007-4000f",
            "term_lang": "es-query-string",
            "filters": [],
            "created_by": "f87033333-a33b-4c",
            "created_by_type": "apikey",
            "created_at": "2024-04-33T13:50:04.876962Z",
            "started_at": "2024-04-26T10:00:23",
            "canceled_by": "2024-04-26T10:00:23",
            "canceled_by_type": "2024-04-26T10:00:23",
            "canceled_at": "2024-04-26T10:00:23",
            "ended_at": "2024-04-26T10:00:23",
            "earliest_time": "2024-04-26T10:00:23",
            "latest_time": "2024-04-26T15:00:23",
            "results_ttl": 1800,
            "expiration_date": "2024-04-26T10:00:23",
            "expired": False,
            "view_uuid": "2024-04-26T10:00:23",
            "community_uuids": ["52bd045f-4199-4361"],
            "only_eternal": False,
            "max_last_events": "2024-04-26T10:00:23",
            "date_field": "2024-04-26T10:00:23",
        },
    ]
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 3, "Contents": events_output}],
    )

    assert (
        "### Alert:\n ### Updated old events with new events in this alert with ID 0000000."
        in get_updated_alert("0000000", "earliest_time")
    )


def test_get_updated_alert_with_no_event(mocker):
    events_output = None

    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 3, "Contents": events_output}],
    )

    assert (
        "### Alert:\n ### There is no events in this alert with ID 0000000."
        in get_updated_alert("0000000", "earliest_time")
    )


def test_main(mocker):
    mocker.patch.object(
        demisto, "incident", return_value={"CustomFields": {"alertid": "alert_id"}}
    )
    mocker.patch.object(
        demisto, "args", return_value={"earliest_time": "2024-04-25T10:00:23Z"}
    )
    mocker.patch(
        "SekoiaXDRUpdateEvents.get_updated_alert",
        return_value="### Alert:\n ### Updated old events with new events in this alert with ID 0000000.",
    )
    mocker.patch.object(demisto, "results")

    main()
    assert (
        demisto.results.call_args[0][0]["HumanReadable"]
        == "### Alert:\n ### Updated old events with new events in this alert with ID 0000000."
    )
