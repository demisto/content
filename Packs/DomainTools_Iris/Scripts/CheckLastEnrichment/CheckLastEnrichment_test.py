from CheckLastEnrichment import main, time_check
from CommonServerPython import *
from freezegun import freeze_time


@freeze_time("2024-01-01 14:00:00")
def test_time_check_false():
    create_date = str(datetime.now().date())
    result = time_check(create_date)
    assert result is False


@freeze_time("2024-01-01 14:00:00")
def test_time_check_true():
    create_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    result = time_check(create_date)
    assert result is True


@freeze_time("2024-01-01 14:00:00")
def test_check_last_enrichment(mocker):
    enrich_date = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d")
    mocker.patch.object(demisto, "args", return_value={"last_enrichment": enrich_date})
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Contents"] == "yes"


@freeze_time("2024-01-01 14:00:00")
def test_check_last_enrichment_recent_date(mocker):
    last_enrichment = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d")
    mocker.patch.object(
        demisto, "args", return_value={"last_enrichment": last_enrichment}
    )
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Contents"] == "no"


@freeze_time("2024-01-01 14:00:00")
def test_check_last_enrichment_none(mocker):
    mocker.patch.object(demisto, "args", return_value={"last_enrichment": None})
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Contents"] == "yes"


@freeze_time("2024-01-01 14:00:00")
def test_main_exception(mocker):
    mocker.patch.object(demisto, "args", return_value={"invalid_key": "invalid_value"})
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    main()
    results = demisto.results.call_args[0]
    assert (
        results[0]["Contents"]
        == "Failed to execute CheckLastEnrichment. Error: 'last_enrichment'"
    )
