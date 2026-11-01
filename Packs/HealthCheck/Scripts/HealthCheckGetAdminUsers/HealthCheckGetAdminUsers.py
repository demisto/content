import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from datetime import datetime, timedelta


def main():
    try:
        # 1. Fetch script arguments and evaluate 'RunInPlaybook'
        args = demisto.args()
        run_in_playbook = argToBoolean(args.get("RunInPlaybook", False))

        api_response = demisto.executeCommand("core-api-post", {"uri": "/public_api/v1/rbac/get_users"})

        if not api_response or isError(api_response[0]):
            return_error("Failed to retrieve users")

        response_data = api_response[0].get("Contents", {})
        all_users = response_data.get("response", {}).get("reply", [])

        # Filter admin users
        admin_users = [user for user in all_users if user.get("role_name") in ["Account Admin", "Instance Administrator"]]

        total_admins = len(admin_users)

        # Calculate inactive (>30 days)
        now = datetime.utcnow()
        inactive_threshold = now - timedelta(days=30)

        inactive_count = 0

        for user in admin_users:
            last_login_ts = user.get("last_logged_in")

            if not last_login_ts:
                inactive_count += 1
                continue

            last_login = datetime.fromtimestamp(last_login_ts / 1000)

            if last_login < inactive_threshold:
                inactive_count += 1

        # 3. Branching execution path
        if run_in_playbook:
            # Playbook Path: Save metrics and update the incident
            readable_output = f"Admin User Check Complete. Total Admins: {total_admins} | Inactive (>30d): {inactive_count}"

            # Map to your target incident fields (verify exact machine names in XSIAM)
            demisto.executeCommand(
                "setIncident", {"healthchecktotaladminscount": total_admins, "healthcheckinactiveadminscount": inactive_count}
            )

            return_results(CommandResults(readable_output=readable_output))

        else:
            # Widget Path: Generate JSON for the dashboard UI chart
            chart_data = {
                "stats": [
                    {"name": "Active Admin Users", "data": [total_admins - inactive_count], "color": "rgb(0, 205, 51)"},
                    {"name": "Inactive Admins (>30 days)", "data": [inactive_count], "color": "rgb(255, 144, 0)"},
                ]
            }

            return_results({"Type": 17, "ContentsFormat": "pie", "Contents": json.dumps(chart_data)})

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
