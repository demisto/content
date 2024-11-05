from DSPMCreateRiskSlackBlocks import create_slack_block

# Assuming `create_slack_block` is imported from the original script


def test_create_slack_block():
    incident = {
        "incidentId": "12345",
        "riskFindingId": "67890",
        "ruleName": "Sensitive asset open to world",
        "severity": "High",
        "assetName": "test-asset",
        "assetId": "asset-123",
        "projectId": "project-abc",
        "cloudProvider": "AWS",
        "serviceType": "S3",
        "firstDetectedOn": "2024-10-01",
        "remediateInstruction": "Restrict access to this asset."
    }
    rule_names_dict = {
        "Sensitive asset open to world": "Block public access to storage assets based on cloud provider.",
        "Empty storage asset": "Delete empty storage assets based on cloud provider."
    }
    incidentLink = "https://example.com/incident/12345"

    result = create_slack_block(incident, rule_names_dict, incidentLink)

    # Check that the block structure was created with the expected keys
    assert "block" in result
    assert "blocks" in result["block"]

    # Check that the header is correct
    header = result["block"]["blocks"][0]
    assert header["type"] == "header"
    assert header["text"]["text"] == "THE FOLLOWING RISK HAS BEEN DETECTED BY THE DSPM :warning:"

    # Check the section details for incident information
    section = result["block"]["blocks"][1]
    assert section["type"] == "section"
    assert "XSOAR Incident ID" in section["text"]["text"]
    assert incident["incidentId"] in section["text"]["text"]
    assert "DSPM Risk ID" in section["text"]["text"]
    assert incident["riskFindingId"] in section["text"]["text"]

    # Check if "Remediate a Risk" option was added based on the rule name
    actions_block = result["block"]["blocks"][3]
    options = actions_block["elements"][0]["options"]
    assert any(option["value"] == "Remediate a Risk" for option in options)
    assert options[0]["text"]["text"].startswith("Remediate a Risk")


def test_create_slack_block_without_remediate_option():
    incident = {
        "incidentId": "12345",
        "riskFindingId": "67890",
        "ruleName": "Non-remediate rule",
        "severity": "Medium",
        "assetName": "test-asset",
        "assetId": "asset-456",
        "projectId": "project-xyz",
        "cloudProvider": "GCP",
        "serviceType": "Compute",
        "firstDetectedOn": "2024-10-01",
        "remediateInstruction": "No remediation needed."
    }
    rule_names_dict = {
        "Sensitive asset open to world": "Block public access to storage assets based on cloud provider.",
        "Empty storage asset": "Delete empty storage assets based on cloud provider."
    }
    incidentLink = "https://example.com/incident/12345"

    result = create_slack_block(incident, rule_names_dict, incidentLink)

    # Check that the "Remediate a Risk" option is not present
    actions_block = result["block"]["blocks"][3]
    options = actions_block["elements"][0]["options"]
    assert all(option["value"] != "Remediate a Risk" for option in options)
