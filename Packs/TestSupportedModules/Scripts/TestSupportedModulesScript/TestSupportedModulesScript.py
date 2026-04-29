import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main() -> None:
    """Main function for TestSupportedModulesScript."""
    try:
        return_results(CommandResults(
            readable_output="TestSupportedModulesScript executed successfully.",
            outputs_prefix="TestSupportedModules",
            outputs={"status": "success"},
        ))
    except Exception as e:
        return_error(f"Failed to execute TestSupportedModulesScript. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
