import json

import demistomock as demisto
from CommonServerPython import *


def _split_detail(detail: str) -> tuple[str, str]:
    text = (detail or "").strip()
    if "->" in text:
        left, right = text.split("->", 1)
        return left.strip(), right.strip()
    return "", text


def _rows_from_classifier_list(raw) -> list[dict]:
    if raw is None or raw == "":
        return []

    if isinstance(raw, list):
        parsed = raw
    elif isinstance(raw, dict):
        parsed = [raw]
    else:
        text = str(raw).strip()
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            return [{"Classifier": "", "Detail": text}]

    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        return [{"Classifier": "", "Detail": str(raw)}]

    rows: list[dict] = []
    for item in parsed:
        if isinstance(item, dict):
            detail = item.get("detail")
            if detail is None:
                detail = item.get("Detail") or ""
            classifier, value = _split_detail(str(detail))
            if not classifier and not value:
                continue
            rows.append({"Classifier": classifier, "Detail": value})
        elif item is not None and str(item).strip():
            classifier, value = _split_detail(str(item))
            rows.append({"Classifier": classifier, "Detail": value})
    return rows


def show_alert_classifiers():
    incident = demisto.incident()
    custom_fields = incident.get("CustomFields") or {}
    raw = custom_fields.get("graalertclassifierlist")
    rows = _rows_from_classifier_list(raw)

    if not rows:
        return_results("No classifiers on this alert.")
        return

    md = tableToMarkdown("Classifiers", rows, headers=["Classifier", "Detail"])
    return_results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": rows,
            "HumanReadable": md,
        }
    )


def main():
    try:
        show_alert_classifiers()
    except Exception as ex:
        return_error(f"Failed to execute GRAAlertClassifierDisplay. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
