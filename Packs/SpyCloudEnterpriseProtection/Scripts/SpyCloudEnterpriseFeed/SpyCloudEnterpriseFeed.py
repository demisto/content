from json import dumps
from CommonServerPython import *  # noqa: F401

INCIDENT_TYPE = {
    2: "SpyCloud Informative Data",
    5: "SpyCloud Informative Data",
    20: "SpyCloud Breach Data",
    25: "SpyCloud Malware Data",
}
INCIDENT_NAME = {
    2: "SpyCloud Informative Alert on",
    5: "SpyCloud Informative Alert on",
    20: "SpyCloud Breach Alert on",
    25: "SpyCloud Malware Alert on",
}
SEVERITY_VALUE = {2: 0.5, 5: 0.5, 20: 3, 25: 4}
DEFAULT_DATE = "-1days"
DEFAULT_UNTIL = "now"


def create_custom_field(watchlist_data: dict):
    custom_fields = {
        "spyclouddocumentid": watchlist_data["document_id"],
        "spyclouddomain": watchlist_data.get("domain"),
        "spycloudemail": watchlist_data.get("email"),
        "spycloudemaildomain": watchlist_data.get("email_domain"),
        "spycloudemailusername": watchlist_data.get("email_username"),
        "spycloudfullname": watchlist_data.get("full_name"),
        "spycloudinfectedmachineid": watchlist_data.get("infected_machine_id"),
        "spycloudinfectedpath": watchlist_data.get("infected_path"),
        "spycloudinfectedtime": watchlist_data.get("infected_time"),
        "spycloudpassword": watchlist_data.get("password"),
        "spycloudpasswordplaintext": watchlist_data.get("password_plaintext"),
        "spycloudpasswordtype": watchlist_data.get("password_type"),
        "spycloudpublishdate": watchlist_data.get("spycloud_publish_date"),
        "spycloudrecordmodificationdate": watchlist_data.get(
            "record_modification_date"
        ),
        "spycloudseverity": watchlist_data.get("severity"),
        "spycloudsourceid": watchlist_data.get("source_id"),
        "spycloudtargetdomain": watchlist_data.get("target_domain"),
        "spycloudtargetsubdomain": watchlist_data.get("target_subdomain"),
        "spycloudtargeturl": watchlist_data.get("target_url"),
        "spyclouduserbrowser": watchlist_data.get("user_browser"),
        "spyclouduserhostname": watchlist_data.get("user_hostname"),
        "spycloudusername": watchlist_data.get("username"),
        "spyclouduseros": watchlist_data.get("user_os"),
        "spycloudusersysregisteredowner": watchlist_data.get(
            "user_sys_registered_owner"
        ),
        "spycloudusersystemdomain": watchlist_data.get("user_sys_domain"),
    }
    return custom_fields


def main():
    """
    This script updates the state of DomainTools Iris Detect New Domains incident and takes appropriate action based on
    the new and old values.

    Returns:
        None

    Raises:
        ValueError: If the new and old values are not valid JSON.

    """
    try:
        args = demisto.args()
        watchlist_result = []
        incidents = []
        since = args.pop("since", DEFAULT_DATE)
        until = args.pop("until", DEFAULT_UNTIL)
        since_modification_date = args.pop("since_modification_date", DEFAULT_DATE)
        until_modification_date = args.pop("until_modification_date", DEFAULT_UNTIL)
        watchlist_command = demisto.executeCommand(
            "spycloud-watchlist-data",
            {"all_results": True, "since": since, "until": until, **args},
        )
        watchlist_modified = demisto.executeCommand(
            "spycloud-watchlist-data",
            {
                "since_modification_date": since_modification_date,
                "until_modification_date": until_modification_date,
                "all_results": True,
                **args,
            },
        )
        if watchlist_command[0].get("Contents"):
            watchlist_result.extend(watchlist_command[0].get("Contents", []))
        if watchlist_modified[0].get("Contents"):
            watchlist_result.extend(watchlist_modified[0].get("Contents", []))
        for watchlist in watchlist_result:
            severity = watchlist["severity"]
            incident = {
                "type": INCIDENT_TYPE[severity],
                "name": f"{INCIDENT_NAME[severity]} {watchlist['email']}"
                if watchlist.get("email")
                else f"{INCIDENT_NAME[severity]} {watchlist['ip_addresses'][0]}",
                "rawJSON": dumps(watchlist),
                "severity": SEVERITY_VALUE[severity],
                "dbotMirrorId": watchlist["document_id"],
                "custom_fields": dumps(create_custom_field(watchlist)),
            }
            incidents.append(incident)
        return_results(CommandResults(outputs={"Watchlist": {"Data": incidents}}))
    except Exception as err:
        return_error(f"Failed to create incident. {err}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
