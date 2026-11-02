import pytest

import GIBDRPResolveViolation as script


def test_id_comes_from_the_incident_when_not_passed():
    incident = {"CustomFields": {"gibdrpid": "v-42"}}
    assert script.violation_id({}, incident) == "v-42"


def test_an_explicit_id_wins_over_the_incident():
    incident = {"CustomFields": {"gibdrpid": "v-42"}}
    assert script.violation_id({"id": "v-99"}, incident) == "v-99"


def test_no_id_anywhere_is_an_error_not_a_silent_no_op():
    with pytest.raises(Exception, match="No Group-IB DRP violation id"):
        script.violation_id({}, {"CustomFields": {}})


def test_a_failed_change_raises_before_the_incident_is_touched(mocker):
    mocker.patch.object(script.demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "boom"}])
    mocker.patch.object(script, "is_error", return_value=True)
    mocker.patch.object(script, "get_error", return_value="boom")
    with pytest.raises(Exception, match="boom"):
        script.change_status("v-1", "reject", None)


def test_the_instance_is_forwarded_only_when_set(mocker):
    executed = mocker.patch.object(script.demisto, "executeCommand", return_value=[])
    mocker.patch.object(script, "is_error", return_value=False)
    script.change_status("v-1", "approve", None)
    assert "using" not in executed.call_args.args[1]
    script.change_status("v-1", "approve", "drp_instance_2")
    assert executed.call_args.args[1]["using"] == "drp_instance_2"


@pytest.mark.parametrize("status,approve_state", [("approve", "approved"), ("reject", "rejected")])
def test_the_decision_is_recorded_on_the_incident(mocker, status, approve_state):
    """Recording the new approve state is what stops the layout buttons from
    offering a decision that has already been made."""
    executed = mocker.patch.object(script.demisto, "executeCommand", return_value=[])
    mocker.patch.object(script, "is_error", return_value=False)

    assert script.record_decision(status) is True

    assert executed.call_args.args[0] == "setIncident"
    assert executed.call_args.args[1] == {"gibdrpapprovestate": approve_state}


def test_a_failed_record_is_reported_not_raised(mocker):
    """The decision already reached DRP and cannot be taken back, so a stale field
    is reported rather than an error that would suggest nothing happened."""
    mocker.patch.object(script.demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "boom"}])
    mocker.patch.object(script, "is_error", return_value=True)
    mocker.patch.object(script, "get_error", return_value="boom")

    assert script.record_decision("approve") is False


def _run(mocker, status, close_incident):
    """Drive main() against an instance whose change-status command answers `closeIncident`."""
    mocker.patch.object(script.demisto, "getModules", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value={"CustomFields": {"gibdrpid": "v-1"}})
    mocker.patch.object(script.demisto, "args", return_value={"status": status})
    mocker.patch.object(script, "is_error", return_value=False)
    results = mocker.patch.object(script, "return_results")

    def execute(command, args):
        if command == script.CHANGE_COMMAND:
            return [{"Type": 1, "Contents": {"id": "v-1", "status": status, "closeIncident": close_incident}}]
        return [{"Type": 1, "Contents": "ok"}]

    executed = mocker.patch.object(script.demisto, "executeCommand", side_effect=execute)
    script.main()
    return [c.args for c in executed.call_args_list], results.call_args.args[0]


def test_the_incident_stays_open_unless_the_instance_asks(mocker):
    """By default the incident closes only when Group-IB DRP resolves the violation, which is
    GIBDRPIncidentUpdate's and the postprocessing playbook's job, not this one's."""
    calls, result = _run(mocker, "approve", close_incident=False)

    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident"]
    assert result.outputs == {
        "id": "v-1",
        "status": "approve",
        "approveState": "approved",
        "incidentUpdated": True,
        "incidentClosed": False,
        "indicatorExpired": False,
    }


@pytest.mark.parametrize("status,reason", [("approve", "Resolved"), ("reject", "False Positive")])
def test_the_incident_is_closed_when_the_instance_asks(mocker, status, reason):
    """Approving closes when the instance asks; rejecting closes regardless (tested below too)."""
    calls, result = _run(mocker, status, close_incident=True)

    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident", "closeInvestigation"]
    close_args = calls[-1][1]
    assert close_args["closeReason"] == reason
    assert "v-1" not in close_args["closeNotes"]
    assert result.outputs["incidentClosed"] is True
    assert reason in result.readable_output
    # The entry names the violation id, a 64-hex string XSOAR would otherwise extract as a File indicator.
    assert result.ignore_auto_extract is True


def test_an_unknown_status_is_refused(mocker):
    mocker.patch.object(script.demisto, "args", return_value={"status": "maybe"})
    executed = mocker.patch.object(script.demisto, "executeCommand", return_value=[])
    error = mocker.patch.object(script, "return_error")

    script.main()

    executed.assert_not_called()
    assert "Invalid status" in error.call_args.args[0]


# ---------------------------------------------------------------------------
# The instance the decision goes through
# ---------------------------------------------------------------------------


def _modules(**states):
    return {name: {"brand": script.INTEGRATION_BRAND, "state": state} for name, state in states.items()} | {
        "other": {"brand": "Something else", "state": "active"}
    }


def test_an_explicit_using_wins(mocker):
    mocker.patch.object(script.demisto, "getModules", return_value=_modules(drp_1="active", drp_2="active"))
    assert script.resolve_instance({"using": "drp_2"}, {"sourceInstance": "drp_1"}) == "drp_2"


def test_the_fetching_instance_is_used_when_it_is_active(mocker):
    """Without `using` Cortex XSOAR would run the command on every instance, and the instances
    that do not own the violation fail the button."""
    mocker.patch.object(script.demisto, "getModules", return_value=_modules(drp_1="active", drp_2="active"))
    assert script.resolve_instance({}, {"sourceInstance": "drp_1"}) == "drp_1"


def test_the_only_active_instance_is_used_when_the_fetching_one_is_gone(mocker):
    mocker.patch.object(script.demisto, "getModules", return_value=_modules(drp_1="disabled", drp_2="active"))
    assert script.resolve_instance({}, {"sourceInstance": "drp_1"}) == "drp_2"


def test_no_instance_is_forced_when_several_are_active_and_none_fetched_the_incident(mocker):
    mocker.patch.object(script.demisto, "getModules", return_value=_modules(drp_1="active", drp_2="active"))
    assert script.resolve_instance({}, {}) is None


def test_main_sends_the_decision_through_the_fetching_instance(mocker):
    mocker.patch.object(script.demisto, "getModules", return_value=_modules(drp_1="active", drp_2="active"))
    mocker.patch.object(script.demisto, "incident", return_value={"CustomFields": {"gibdrpid": "v-1"}, "sourceInstance": "drp_2"})
    mocker.patch.object(script.demisto, "args", return_value={"status": "approve"})
    mocker.patch.object(script, "is_error", return_value=False)
    mocker.patch.object(script, "return_results")
    executed = mocker.patch.object(script.demisto, "executeCommand", return_value=[{"Type": 1, "Contents": {}}])

    script.main()

    change_call = next(c.args for c in executed.call_args_list if c.args[0] == script.CHANGE_COMMAND)
    assert change_call[1]["using"] == "drp_2"


# ---------------------------------------------------------------------------
# Rejecting is final
# ---------------------------------------------------------------------------


def _run_with_incident(mocker, status, incident, close_incident=False):
    mocker.patch.object(script.demisto, "getModules", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    mocker.patch.object(script.demisto, "args", return_value={"status": status})
    mocker.patch.object(script, "is_error", return_value=False)
    results = mocker.patch.object(script, "return_results")

    def execute(command, args):
        if command == script.CHANGE_COMMAND:
            return [{"Type": 1, "Contents": {"id": "v-1", "status": status, "closeIncident": close_incident}}]
        return [{"Type": 1, "Contents": "ok"}]

    executed = mocker.patch.object(script.demisto, "executeCommand", side_effect=execute)
    script.main()
    return [c.args for c in executed.call_args_list], results.call_args.args[0]


def test_rejecting_always_closes_the_incident_as_false_positive(mocker):
    """DRP does nothing more with a rejected violation, so nothing later would close the incident."""
    calls, result = _run_with_incident(mocker, "reject", {"CustomFields": {"gibdrpid": "v-1"}}, close_incident=False)

    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident", "closeInvestigation"]
    assert calls[-1][1]["closeReason"] == "False Positive"
    assert result.outputs["incidentClosed"] is True
    assert result.outputs["indicatorExpired"] is False


def test_rejecting_expires_the_indicator_when_the_incident_asks_for_it(mocker):
    incident = {"CustomFields": {"gibdrpid": "v-1", "gibdrpexpireindicatoronclose": True, "gibdrpviolationuri": "bad.example"}}
    calls, result = _run_with_incident(mocker, "reject", incident)

    # expireIndicators must run before closeInvestigation: a closed investigation refuses commands (HTTP 412).
    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident", "expireIndicators", "closeInvestigation"]
    # Cortex XSOAR 8 reads the builtin's list from indicatorsValues (value alone answers "Provide indicator(s) value(s)").
    assert calls[2][1] == {"indicatorsValues": "bad.example", "value": "bad.example"}
    assert result.outputs["indicatorExpired"] is True
    assert "expired" in result.readable_output


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("bad.example", "bad.example"),
        ("Bad.Example.", "bad.example"),
        ("//bad.example/login", "https://bad.example/login"),
        ("bad.example/login?x=1", "https://bad.example/login?x=1"),
        ("http://bad.example/login", "http://bad.example/login"),
        ("203.0.113.9", "203.0.113.9"),
        ("mail://phish@bad.example", None),
        ("tg://resolve?domain=bad", None),
        ("", None),
    ],
)
def test_indicator_value_mirrors_the_indicator_automation(uri, expected):
    """The value expired must be the one GIBDRPCreateViolationIndicator created, not the raw URI."""
    assert script.indicator_value(uri) == expected


def test_rejecting_expires_the_normalized_value_not_the_raw_uri(mocker):
    incident = {
        "CustomFields": {"gibdrpid": "v-1", "gibdrpexpireindicatoronclose": True, "gibdrpviolationuri": "//bad.example/login"}
    }
    calls, result = _run_with_incident(mocker, "reject", incident)

    assert calls[2][0] == "expireIndicators"
    assert calls[2][1]["indicatorsValues"] == "https://bad.example/login"
    assert result.outputs["indicatorExpired"] is True


def test_rejecting_skips_expiry_for_a_uri_that_never_became_an_indicator(mocker):
    incident = {
        "CustomFields": {"gibdrpid": "v-1", "gibdrpexpireindicatoronclose": True, "gibdrpviolationuri": "mail://x@bad.example"}
    }
    calls, result = _run_with_incident(mocker, "reject", incident)

    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident", "closeInvestigation"]
    assert result.outputs["indicatorExpired"] is False
    assert "could not be expired" not in result.readable_output


def test_rejecting_reports_when_the_builtin_refuses_to_expire(mocker):
    incident = {"CustomFields": {"gibdrpid": "v-1", "gibdrpexpireindicatoronclose": True, "gibdrpviolationuri": "bad.example"}}
    mocker.patch.object(script.demisto, "getModules", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    mocker.patch.object(script.demisto, "args", return_value={"status": "reject"})
    mocker.patch.object(script, "is_error", side_effect=lambda response: response.get("Type") == 4)
    mocker.patch.object(script, "get_error", side_effect=lambda response: response.get("Contents"))
    results = mocker.patch.object(script, "return_results")

    def execute(command, args):
        if command == script.CHANGE_COMMAND:
            return [{"Type": 1, "Contents": {"id": "v-1", "status": "reject", "closeIncident": False}}]
        if command == "expireIndicators":
            return [{"Type": 4, "Contents": "Provide indicator(s) value(s) in order to expire indicator(s) (7)"}]
        return [{"Type": 1, "Contents": "ok"}]

    executed = mocker.patch.object(script.demisto, "executeCommand", side_effect=execute)
    script.main()

    result = results.call_args.args[0]
    assert [c.args[0] for c in executed.call_args_list] == [
        script.CHANGE_COMMAND,
        "setIncident",
        "expireIndicators",
        "closeInvestigation",
    ]
    assert result.outputs["incidentClosed"] is True
    assert result.outputs["indicatorExpired"] is False
    assert "could not be expired" in result.readable_output


def test_approving_does_not_expire_the_indicator_even_when_it_closes(mocker):
    incident = {"CustomFields": {"gibdrpid": "v-1", "gibdrpexpireindicatoronclose": True, "gibdrpviolationuri": "bad.example"}}
    calls, result = _run_with_incident(mocker, "approve", incident, close_incident=True)

    assert [c[0] for c in calls] == [script.CHANGE_COMMAND, "setIncident", "closeInvestigation"]
    assert calls[-1][1]["closeReason"] == "Resolved"
    assert result.outputs["indicatorExpired"] is False
