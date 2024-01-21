from CheckLastEnrichment import main, time_check
from CommonServerPython import *


def test_time_check_flase():
    create_date = str(datetime.now().date())
    result = time_check(create_date)
    assert result is False


def test_time_check_true():
    create_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    result = time_check(create_date)
    assert result is True


def test_check_last_enrichment(mocker):
    enrich_date = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    mocker.patch.object(demisto, 'args', return_value={
                        'last_enrichment': enrich_date})
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Contents'] == 'yes'
