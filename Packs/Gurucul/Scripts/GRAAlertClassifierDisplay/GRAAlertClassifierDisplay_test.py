import demistomock as demisto
import GRAAlertClassifierDisplay
from GRAAlertClassifierDisplay import _rows_from_classifier_list, show_alert_classifiers


def test_rows_from_classifier_list_json_string():
    raw = '[{"detail": "Login -> Failed attempts"}]'
    rows = _rows_from_classifier_list(raw)
    assert rows == [{"Classifier": "Login", "Detail": "Failed attempts"}]


def test_rows_from_classifier_list_plain_string():
    rows = _rows_from_classifier_list("Login anomaly")
    assert rows == [{"Classifier": "", "Detail": "Login anomaly"}]


def test_rows_from_classifier_list_empty():
    assert _rows_from_classifier_list(None) == []
    assert _rows_from_classifier_list("") == []


def test_show_alert_classifiers_renders_table(mocker):
    incident = {
        "CustomFields": {"graalertclassifierlist": '[{"detail": "Resource -> Okta"}]'},
    }
    mocker.patch.object(demisto, "incident", return_value=incident)
    return_results_mocker = mocker.patch.object(GRAAlertClassifierDisplay, "return_results")

    show_alert_classifiers()

    return_results_mocker.assert_called_once()
    result = return_results_mocker.call_args[0][0]
    assert result["Contents"] == [{"Classifier": "Resource", "Detail": "Okta"}]
    assert "Classifiers" in result["HumanReadable"]


def test_show_alert_classifiers_no_data(mocker):
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    return_results_mocker = mocker.patch.object(GRAAlertClassifierDisplay, "return_results")

    show_alert_classifiers()

    return_results_mocker.assert_called_once_with("No classifiers on this alert.")
