from unittest.mock import patch

close_reason, close_notes, incident_id = "close_reason", "close_notes", "incident_id"
threat_id, verdict, status = "11111111-1111-1111-1111-111111111111", "inconclusive", "resolved"


@patch('demistomock.executeCommand', return_value=None)
@patch('ResolveGemAlert._get_params', return_value=(close_reason, close_notes, incident_id, threat_id, verdict, status))
def test_resolve_gem_alert(_get_params, executeCommand):
    from ResolveGemAlert import main
    main()
    executeCommand.assert_called_once_with('gem-update-threat-status', {
        "verdict": verdict,
        "reason": f"Closed from XSOAR, incident id: {incident_id}\n"
        f"\nClose Reason:\n{close_reason}"
        f"\nClose Notes:\n{close_notes}",
        "threat_id": threat_id,
        "status": status})
