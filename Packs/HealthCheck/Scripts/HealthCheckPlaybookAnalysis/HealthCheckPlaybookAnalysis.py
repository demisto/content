import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SET_INCIDENT_THRESHOLD = 4
PLAYBOOK_LENGTH_THRESHOLD = 30

DESCRIPTIONS = [
    'The playbook: "{}" may be a copy of a built-in playbook, you may consider using out of the box playbooks',
    'The playbook: "{}" is using a sleep command, you may consider changing it',
    'The playbook: "{}" is using the setIncident command 4 times or more, which could result with DB version violation',
    'The playbook: "{}" is using the "EmailAskUser" functionality, you may consider switching it to Data Collection',
    'The playbook: "{}" is using over 30 tasks, you may want to use sub-playbooks for better organization of playbook tasks',
]

# Shared resolutions (same for all versions)
RESOLUTION_COPY = "Consider using out of the box playbooks"
RESOLUTION_SLEEP = (
    "Consider changing it to preferred methods such as: https://xsoar.pan.dev/docs/playbooks/generic-polling "
    "https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PPOaCAO"
)
RESOLUTION_SET_INCIDENT = "Consider joining some of the setIncident tasks"

# Version-specific resolutions
RESOLUTION_EMAIL_ASK_USER_V6 = (
    "Communication Tasks: https://cortex-docs.paloaltonetworks.com/playbook-design-guide/"
    "playbook-design-guide/playbook-task-fields/communication-tasks"
)
RESOLUTION_EMAIL_ASK_USER_V8 = (
    "Communication Tasks: https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/configure-cortex-xsoar/"
    "playbooks/develop-your-playbook/task-3.-add-tasks/create-a-communication-task"
)

RESOLUTION_MULTI_TASKS_V6 = (
    "Sub-playbook Tutorial: https://cortex-docs.paloaltonetworks.com/playbook-design-guide/"
    "playbook-design-guide/configure-a-sub-playbook-loop"
)
RESOLUTION_MULTI_TASKS_V8 = (
    "Sub-playbook Tutorial: https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/configure-cortex-xsoar/"
    "playbooks/customize-your-playbook/configure-a-sub-playbook"
)


def search_playbooks(uri_prefix, system):
    """Return built-in or custom playbooks."""
    query = "system:T" if system else "system:F"
    result = execute_command("core-api-post", {"uri": f"{uri_prefix}playbook/search", "body": {"query": query}})
    if isinstance(result, list):
        result = result[0] if result else {}
    return result.get("response", {}).get("playbooks") or []


def find_top_used_playbooks(uri_prefix):
    """Store the three most frequently used playbooks from the last 30 days."""
    result = execute_command(
        "core-api-post",
        {
            "uri": f"{uri_prefix}statistics/widgets/query",
            "body": {
                "size": 3,
                "dataType": "incidents",
                "query": "",
                "dateRange": {"period": {"byFrom": "days", "fromValue": 30}},
                "widgetType": "pie",
                "params": {"groupBy": ["playbookId"], "valuesFormat": "abbreviated"},
            },
        },
    )
    if isinstance(result, list):
        result = result[0] if result else {}
    top_used = [{"playbookname": pb["name"]} for pb in result.get("response", [])]
    execute_command("setIncident", {"healthchecktopusedplaybooks": top_used})


def main():
    if is_demisto_version_ge("8.0.0"):
        uri_prefix = ""
        resolution_email = RESOLUTION_EMAIL_ASK_USER_V8
        resolution_tasks = RESOLUTION_MULTI_TASKS_V8
    else:
        account_name = demisto.incidents()[0].get("account", "")
        uri_prefix = f"acc_{account_name}/" if account_name else ""
        resolution_email = RESOLUTION_EMAIL_ASK_USER_V6
        resolution_tasks = RESOLUTION_MULTI_TASKS_V6

    custom_playbooks = search_playbooks(uri_prefix, system=False)
    builtin_names = {pb["name"] for pb in search_playbooks(uri_prefix, system=True)}

    copy_detected = []
    sleep_detected = []
    multi_set_incident = []
    email_ask_user = []
    multi_tasks = []

    for pb in custom_playbooks:
        name = pb.get("name", "")
        if any(builtin in name for builtin in builtin_names):
            copy_detected.append(name)
        if "Sleep" in pb.get("scriptIds", []):
            sleep_detected.append(name)
        if str(pb).count("Builtin|||setIncident") >= SET_INCIDENT_THRESHOLD:
            multi_set_incident.append(name)
        if "EmailAskUser" in pb.get("scriptIds", []):
            email_ask_user.append(name)
        if len(pb.get("tasks", [])) > PLAYBOOK_LENGTH_THRESHOLD:
            multi_tasks.append(name)

    res = []
    for findings, desc, resolution in [
        (copy_detected, DESCRIPTIONS[0], RESOLUTION_COPY),
        (sleep_detected, DESCRIPTIONS[1], RESOLUTION_SLEEP),
        (multi_set_incident, DESCRIPTIONS[2], RESOLUTION_SET_INCIDENT),
        (email_ask_user, DESCRIPTIONS[3], resolution_email),
        (multi_tasks, DESCRIPTIONS[4], resolution_tasks),
    ]:
        if findings:
            res.append(
                {
                    "category": "Playbooks",
                    "severity": "Low",
                    "description": desc.format(", ".join(findings)),
                    "resolution": resolution,
                }
            )

    find_top_used_playbooks(uri_prefix)
    return_results(
        CommandResults(
            readable_output="HealthCheckPlaybookAnalysis Done",
            outputs_prefix="HealthCheck.ActionableItems",
            outputs=res,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
