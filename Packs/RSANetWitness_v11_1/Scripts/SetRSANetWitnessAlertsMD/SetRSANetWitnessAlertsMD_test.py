import pytest
from SetRSANetWitnessAlertsMD import json_to_md, read_context_from_rsa_netwitness_alerts


@pytest.mark.parametrize(
    "alerts_fields",
    [
        {
            "RSA Alerts": [
                {
                    "created": "2023-07-03T11:04:16.408Z",
                    "detail": None,
                    "events": [],
                    "id": "dummy_id",
                    "riskScore": "50",
                    "source": "NetWitness Investigate",
                    "title": "sk_test300",
                    "type": "Log",
                },
                {
                    "created": "2023-07-03T11:04:24.256Z",
                    "detail": None,
                    "id": "dummy_id",
                    "riskScore": "50",
                    "source": "NetWitness Investigate",
                    "title": "sk_test300",
                    "type": "Log",
                },
            ]
        },
    ],
)
def test_json_to_md(alerts_fields):
    assert json_to_md(alerts_fields) == (
        "|ID|Title|Type|Risk Score|Created|\n"
        "|---|---|---|---|---|\n"
        "| dummy_id | sk_test300 | Log | 50 | 2023-07-03T11:04:16.408Z |\n"
        "| dummy_id | sk_test300 | Log | 50 | 2023-07-03T11:04:24.256Z |\n"
    )


@pytest.mark.parametrize(
    "alerts_incident, expected_results",
    [
        ({"CustomFields": {1: "test", 2: "test"}}, {}),
        (
            {"CustomFields": {"rsaalerts": "test", "some_key": "test"}},
            {"RSA Alerts": "test"},
        ),
    ],
)
def test_read_context_from_rsa_netwitness_alerts(
    mocker, alerts_incident, expected_results
):
    mocker.patch(
        "SetRSANetWitnessAlertsMD.demisto.incident", return_value=alerts_incident
    )
    assert read_context_from_rsa_netwitness_alerts() == expected_results
