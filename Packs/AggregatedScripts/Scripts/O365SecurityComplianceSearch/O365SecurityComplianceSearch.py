from CommonServerPython import *


def main():
    try:
        pass
        # args = demisto.args()

    except Exception as e:
        return_error(f"Failed to execute get-endpoint-data. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
