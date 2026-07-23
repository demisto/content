import demistomock as demisto
from CommonServerPython import *


def _alert_id_from_incident(incident: dict) -> str:
    custom_fields = incident.get("CustomFields") or {}
    gra_alert = custom_fields.get("graalert") or ""
    for label in incident.get("labels", []):
        if label.get("type") == "alertId":
            return str(label.get("value") or "")
    if gra_alert:
        return str(gra_alert).split("-")[-1]
    return ""


def _flatten_feature_values(feature_values) -> list[dict]:
    display_data: list[dict] = []
    if feature_values is None:
        return display_data

    if isinstance(feature_values, dict):
        for feature, values in feature_values.items():
            display_data.append(
                {
                    "Analytical Feature": feature,
                    "Values": values if values is not None else "",
                }
            )
        return display_data

    if isinstance(feature_values, list):
        for item in feature_values:
            if isinstance(item, dict):
                display_data.append(
                    {
                        "Analytical Feature": item.get("feature") or item.get("name") or "",
                        "Values": item.get("values") or item,
                    }
                )
    return display_data


def _flatten_feature_counts(features) -> list[dict]:
    """Fallback when only analyticalFeatures (feature → count) exists."""
    display_data: list[dict] = []
    if not isinstance(features, dict):
        return display_data
    for feature, count in features.items():
        display_data.append(
            {
                "Analytical Feature": feature,
                "Values": count,
            }
        )
    return display_data


def show_alert_analytical_features():
    incident = demisto.incident()
    alert_id = _alert_id_from_incident(incident)
    if not alert_id:
        return_results("Alert id not found on this incident.")
        return

    res = execute_command("gra-alert-get", {"id": alert_id, "using": incident["sourceInstance"]})
    if not res:
        return_results("No alert details returned.")
        return

    record = res[0] if isinstance(res, list) else res
    feature_values = record.get("analyticalFeatureValues")
    features = record.get("analyticalFeatures")

    display_data = _flatten_feature_values(feature_values)
    if not display_data:
        display_data = _flatten_feature_counts(features)

    if not display_data:
        return_results("No analytical features on this alert.")
        return

    md = tableToMarkdown(
        None,
        display_data,
        headers=["Analytical Feature", "Values"],
    )
    return_results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": display_data,
            "HumanReadable": md,
        }
    )


def main():
    try:
        show_alert_analytical_features()
    except Exception as ex:
        return_error(f"Failed to execute GRAAlertAnalyticalFeatureDisplay. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
