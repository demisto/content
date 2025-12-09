import json


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


sample_context = load_json("test_data/context_data.json")
sample_rule_hitcount_data = sample_context.get("PANOS", {}).get("RuleHitCount", [])
sample_ha_state_data = sample_context.get("PANOS", {}).get("HAState", [])
sample_system_info = sample_context.get("PANOS", {}).get("ShowSystemInfo", {}).get("Result")


def test_get_local_rules(mocker):
    """
    Test the function with a set of sample context data and verify it returns the correct unused local rules.
    """
    from PanOSAnalyzeRuleHitCounts import get_local_rules

    total_local_rules, summaries = get_local_rules(sample_rule_hitcount_data, sample_ha_state_data, sample_system_info)

    assert total_local_rules == 4
    assert len(summaries) == 2
    assert summaries[0]["name"] == "Rule1"
    assert summaries[1]["name"] == "Rule5"


def test_analyze_panorama_rules(mocker):
    """
    Test the function with a set of sample context data and verify it returns the correct unused Panorama rules.
    """
    from PanOSAnalyzeRuleHitCounts import analyze_panorama_rules

    total_panorama_rules, unused_panorama_rules, used_panorama_rules = analyze_panorama_rules(
        sample_rule_hitcount_data, sample_ha_state_data, sample_system_info
    )

    assert total_panorama_rules == 2
    assert len(unused_panorama_rules) == 1
    assert unused_panorama_rules[0]["name"] == "Rule6"
    assert used_panorama_rules[0]["name"] == "Rule4"
    assert used_panorama_rules[0]["hostnames_with_zero_hits"] == ["PAN-VM-01"]
    assert used_panorama_rules[0]["hostnames_with_hits"] == ["PAN-VM-02"]


def test_main(mocker):
    """
    Test the main function with some necessary data missing and verify it raises the appropriate exception.
    """
    from PanOSAnalyzeRuleHitCounts import main

    context_data = sample_context
    context_data["PANOS"].pop("HAState")
    mocker.patch("PanOSAnalyzeRuleHitCounts.demisto.context", return_value=sample_context)

    mock_return_error = mocker.patch("PanOSAnalyzeRuleHitCounts.return_error", return_value=True)

    main()

    assert (
        mock_return_error.call_args[0][0] == "Failed to execute PAN-OS-AnalyzeRuleHitCounts. Error: Missing data: HAState. "
        "Please run the 'pan-os-platform-get-ha-state' command to populate this data."
    )
