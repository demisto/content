import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from AtlassianJiraServiceManagementApiModule import *  # noqa: E402


def main() -> None:  # pragma: no cover
    run_atlassian_jira_service_management_integration()


from CommonServerUserPython import *  # noqa: E402  # pylint: disable=wrong-import-position

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
