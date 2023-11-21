import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_INCIDENT_FIELDS = {
    "rsaalerts": "RSA Alerts",
}


def read_context_from_rsa_netwitness_alerts() -> dict:
    incident = demisto.incident().get("CustomFields", {})

    data: dict = {}
    for key in KEYS_INCIDENT_FIELDS:
        if field_content := incident.get(key):
            data[KEYS_INCIDENT_FIELDS[key]] = field_content

    return data


def parse_alerts(alerts: list) -> list:
    return [
        {
            "Created": alert.get("created"),
            "Events": alert.get("events"),
            "ID": alert.get("id"),
            "Risk Score": alert.get("riskScore"),
            "Title": alert.get("title"),
            "Type": alert.get("type"),
            "Detail": alert.get("detail"),
        }
        for alert in alerts if alerts
    ]


def json_to_md(incident_fields: dict) -> str:
    return tableToMarkdown(
        name="",
        t=parse_alerts(incident_fields.get("RSA Alerts", [])),
        headers=["ID", "Title", "Type", "Risk Score", "Created", "Events", "Detail"],
        removeNull=True,
        json_transform_mapping={
            "Events": JsonTransformer(
                keys=["destination", "domain", "eventSource", "eventSourceId", "source"],
                is_nested=True,
            )
        },
    )


def main():
    incident_fields = read_context_from_rsa_netwitness_alerts()
    return_results(
        CommandResults(
            readable_output=json_to_md(incident_fields) if incident_fields else "No data to present."
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
