import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EXCLUDED_INSTANCES = {"testmodule", "d2"}


def main():
    try:
        if is_demisto_version_ge("8.0.0"):
            uri = "xsoar/public/v1/settings/integration/search"
        else:
            account_name = demisto.incidents()[0].get("account", "")
            uri = f"acc_{account_name}/settings/integration/search" if account_name else "settings/integration/search"

        result = execute_command("core-api-post", {"uri": uri, "body": {"size": 500}})
        if isinstance(result, list):
            res = result[0].get("response", {}) if result else {}
        else:
            res = (result or {}).get("response") or {}

        enabled_instance_names = [
            {"instancename": instance.get("name")}
            for instance in res.get("instances", [])
            if instance.get("enabled") == "true" and instance.get("name") not in EXCLUDED_INSTANCES
        ]

        execute_command(
            "setIncident",
            {
                "healthcheckenabledinstances": enabled_instance_names,
                "healthchecknumberofengines": res.get("engines", {}).get("total"),
            },
        )
        return_results(CommandResults(readable_output="HealthCheckIntegrations Done"))
    except Exception as e:
        return_error(f"Failed to execute HealthCheckIntegrations: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
