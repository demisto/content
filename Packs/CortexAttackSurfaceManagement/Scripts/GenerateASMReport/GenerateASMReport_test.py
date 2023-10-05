import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import EntryType
import pytest


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_color_for_severity(mocker):
    """Tests color_for_severity helper function.

        Given:
            - Mock severity (string).
        When:
            - Sending severity (string) to color_for_severity helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import color_for_severity

    result = color_for_severity("High")
    assert result == "red"


def test_build_template(mocker):
    """Tests build_template command function.

        Given:
            - Mock current date and output from get_asm_args helper function.
        When:
            - Running the 'build_template' function.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from GenerateASMReport import build_template

    date_result = [
        {
            "Contents": "2022-10-26T16:06:49.164Z",
        }
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=date_result)
    args = util_load_json("test_data/args.json")
    result = build_template(args)
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, dict)
    assert result[1] == {
        "type": "header",
        "data": "ASM Investigation Summary Report",
        "layout": {
            "rowPos": 2,
            "columnPos": 2,
            "style": {
                "textAlign": "center",
                "fontSize": 28,
                "color": "black",
                "background-color": "white",
            },
        },
    }


@pytest.mark.parametrize(
    "alert_id, report_type",
    [
        ("1234", "summary"),
        ("1234", "analysis"),
    ]
)
def test_build_report(mocker, alert_id, report_type):
    """Tests build_report command function.

        Given:
            - Mock template list from build_template function and alert ID.
        When:
            - Running the 'build_report' function.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from GenerateASMReport import build_report

    template = util_load_json("test_data/template.json")
    sanepdf_raw = util_load_json("test_data/sanepdf_raw.json")
    mocker.patch.object(demisto, "executeCommand", return_value=sanepdf_raw)
    result = build_report(template, alert_id, report_type)
    assert isinstance(result, dict)
    assert result["Type"] == EntryType.ENTRY_INFO_FILE


def test_RPR_criteria(mocker):
    """Tests RPR_criteria helper function.

        Given:
            - Mock criteria_str (string).
        When:
            - Sending criteria_str (string) to RPR_criteria helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import RPR_criteria

    result = RPR_criteria("""[{"field": "provider", "value": "amazon web services", "operator": "eq"}]""")
    assert result == "(provider = amazon web services)"


def test_service_format(mocker):
    """Tests service_format helper function.

        Given:
            - Mock service API (Dict).
        When:
            - Sending service API (Dict) to service_format helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import service_format

    result = service_format({"service_type": "test", "service_name": "name", "first_observed": 1680850320000,
                             "last_observed": 1683306120000, "domain": "acme.com",
                             "details": {"tlsVersions": [{"tlsVersion": "1.2"}]}})
    assert result == [
        {
            "Field": "Service Type",
            "Value": "test"
        },
        {
            "Field": "Service Name",
            "Value": "name"
        },
        {
            "Field": "Active Classifications",
            "Value": "n/a"
        },
        {
            "Field": "Business Units",
            "Value": "n/a"
        },
        {
            "Field": "Provider",
            "Value": "n/a"
        },
        {
            "Field": "IP Addresses",
            "Value": "n/a"
        },
        {
            "Field": "Port",
            "Value": "n/a"
        },
        {
            "Field": "Protocol",
            "Value": "n/a"
        },
        {
            "Field": "First Observed",
            "Value": "2023-04-07"
        },
        {
            "Field": "Last Observed",
            "Value": "2023-05-05"
        },
        {
            "Field": "Domains",
            "Value": "acme.com"
        },
        {
            "Field": "TLS",
            "Value": "1.2"
        }
    ]


def test_asset_format(mocker):
    """Tests asset_format helper function.

        Given:
            - Mock asset API (Dict).
        When:
            - Sending asset API (Dict) to asset_format helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import asset_format

    result = asset_format({"name": "name", "type": "type", "ips": ["1.1.1.1"], "domain": "acme.com",
                           "first_observed": 1680850320000, "last_observed": 1683306120000,
                           "explainers": ["this explains stuff"],
                           "details": {"ip_ranges": {'range': {"FIRST_IP": "1.1.1.1", "LAST_IP": "2.2.2.2",
                                                               "EXPLAINERS": ["Associated with acme.com"]}}}})
    assert result == [
        {
            "Field": "Asset Name",
            "Value": "name"
        },
        {
            "Field": "Business Units",
            "Value": "n/a"
        },
        {
            "Field": "Asset Type",
            "Value": "type"
        },
        {
            "Field": "Detected Services on Asset",
            "Value": "n/a"
        },
        {
            "Field": "IPs",
            "Value": '1.1.1.1'
        },
        {
            "Field": "Domains",
            "Value": "acme.com"
        },
        {
            "Field": "Associated IP Range",
            "Value": "1.1.1.1 - 2.2.2.2"
        },
        {
            "Field": "IP Range Attribution Details",
            "Value": "Associated with acme.com"
        },
        {
            "Field": "First Observed",
            "Value": "2023-04-07"
        },
        {
            "Field": "Last Observed",
            "Value": "2023-05-05"
        },
        {
            "Field": "Explainers",
            "Value": "this explains stuff"
        }
    ]
