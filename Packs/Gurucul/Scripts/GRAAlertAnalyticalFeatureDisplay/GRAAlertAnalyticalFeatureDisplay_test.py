import demistomock as demisto
import GRAAlertAnalyticalFeatureDisplay
from GRAAlertAnalyticalFeatureDisplay import (
    _alert_id_from_incident,
    _flatten_feature_counts,
    _flatten_feature_values,
    show_alert_analytical_features,
)

_INCIDENT_LABEL = {
    "id": 1,
    "sourceInstance": "instance_name",
    "labels": [{"type": "alertId", "value": "101"}],
    "CustomFields": {},
}

_INCIDENT_CUSTOM_FIELD = {
    "id": 2,
    "sourceInstance": "instance_name",
    "labels": [],
    "CustomFields": {"graalert": "AL-303"},
}


def test_alert_id_from_label():
    assert _alert_id_from_incident(_INCIDENT_LABEL) == "101"


def test_alert_id_from_graalert_fallback():
    assert _alert_id_from_incident(_INCIDENT_CUSTOM_FIELD) == "303"


def test_flatten_feature_values_dict():
    rows = _flatten_feature_values({"Login Count": [1, 2, 3]})
    assert rows == [{"Analytical Feature": "Login Count", "Values": [1, 2, 3]}]


def test_flatten_feature_counts_fallback():
    rows = _flatten_feature_counts({"Login Count": 5})
    assert rows == [{"Analytical Feature": "Login Count", "Values": 5}]


def test_show_alert_analytical_features_with_values(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT_LABEL)
    mocker.patch.object(
        GRAAlertAnalyticalFeatureDisplay,
        "execute_command",
        return_value=[{"analyticalFeatureValues": {"Login Count": [1, 2]}}],
    )
    return_results_mocker = mocker.patch.object(GRAAlertAnalyticalFeatureDisplay, "return_results")

    show_alert_analytical_features()

    GRAAlertAnalyticalFeatureDisplay.execute_command.assert_called_once_with(
        "gra-alert-get",
        {"id": "101", "using": "instance_name"},
    )
    result = return_results_mocker.call_args[0][0]
    assert result["Contents"] == [{"Analytical Feature": "Login Count", "Values": [1, 2]}]


def test_show_alert_analytical_features_no_data(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT_LABEL)
    mocker.patch.object(
        GRAAlertAnalyticalFeatureDisplay,
        "execute_command",
        return_value=[{"analyticalFeatureValues": None, "analyticalFeatures": None}],
    )
    return_results_mocker = mocker.patch.object(GRAAlertAnalyticalFeatureDisplay, "return_results")

    show_alert_analytical_features()

    return_results_mocker.assert_called_once_with("No analytical features on this alert.")
