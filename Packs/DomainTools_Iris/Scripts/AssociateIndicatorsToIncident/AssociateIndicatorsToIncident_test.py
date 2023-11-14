from CommonServerPython import *
from AssociateIndicatorsToIncident import main


def test_associate_existing_indicators_to_incident(mocker):
    mocker.patch.object(demisto, "context", return_value={"associatedIndicators": True})
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['HumanReadable'] == 'Related indicators are already associated.'
