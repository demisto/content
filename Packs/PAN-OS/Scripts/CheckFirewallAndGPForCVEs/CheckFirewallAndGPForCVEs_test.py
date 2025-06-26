import demistomock as demisto
import CheckFirewallAndGPForCVEs
from CommonServerPython import CommandResults


def test_check_firewall_and_gp_for_cves_affected_and_unaffected(mocker):
    """Test that the script correctly identifies affected and unaffected versions for both PAN-OS and GlobalProtect."""
    # Mock system info with one affected and one unaffected firewall
    mock_pan_os_system_info = [
        {
            "hostname": "fw-affected",
            "ip_address": "1.1.1.1",
            "sw_version": "10.2.3",
            "global_protect_client_package_version": "6.0.1",
        },
        {
            "hostname": "fw-patched",
            "ip_address": "2.2.2.2",
            "sw_version": "10.2.3-h2",  # Has hotfix
            "global_protect_client_package_version": "6.0.3",
        },
    ]

    # Mock CVE data with affected versions and hotfix
    mock_cve_json = [
        {
            "cve_id": "CVE-2072-1234",
            "cvss_severity": "Critical",
            "affected_list": [
                {
                    "product": "PAN-OS",
                    "defaultStatus": "unaffected",
                    "versions": [
                        {
                            "version": "10.2.0",
                            "lessThan": "10.2.4",
                            "status": "affected",
                            "changes": [{"at": "10.2.3-h2", "status": "unaffected"}],
                        }
                    ],
                },
                {
                    "product": "GlobalProtect App",
                    "defaultStatus": "unaffected",
                    "versions": [{"version": "6.0.0", "lessThan": "6.0.2", "status": "affected"}],
                },
            ],
        }
    ]

    # Set up mocks
    mocker.patch.object(
        demisto, "args", return_value={"pan_os_system_info_list": mock_pan_os_system_info, "cve_json": mock_cve_json}
    )
    mocker.patch.object(demisto, "error")
    mock_return_results = mocker.patch("CheckFirewallAndGPForCVEs.return_results")

    # Execute
    CheckFirewallAndGPForCVEs.main()

    # Assert
    assert mock_return_results.call_count == 1
    call_args = mock_return_results.call_args[0][0]

    assert isinstance(call_args, CommandResults)
    assert call_args.outputs_prefix == "CVE_Check"

    result = call_args.outputs
    assert result is not None
    assert isinstance(result, dict)
    assert result["CVE_ID"] == "CVE-2072-1234"
    assert result["Severity"] == "Critical"
    assert len(result["Result"]) == 2

    # Check affected firewall
    affected_fw = result["Result"][0]
    assert affected_fw["Hostname"] == "fw-affected"
    assert affected_fw["SWVersion"] == "10.2.3"
    assert affected_fw["IsFirewallVersionAffected"] is True
    assert affected_fw["GlobalProtectVersion"] == "6.0.1"
    assert affected_fw["IsGlobalProtectVersionAffected"] is True

    # Check patched firewall
    patched_fw = result["Result"][1]
    assert patched_fw["Hostname"] == "fw-patched"
    assert patched_fw["SWVersion"] == "10.2.3-h2"
    assert patched_fw["IsFirewallVersionAffected"] is False  # Fixed by hotfix
    assert patched_fw["GlobalProtectVersion"] == "6.0.3"
    assert patched_fw["IsGlobalProtectVersionAffected"] is False  # Version not in affected range
