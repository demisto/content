import demistomock as demisto
from CommonServerPython import *
from SimilarObjectApiModule import *  # noqa: E402


def main():
    try:
        args = demisto.args()
        mapped_args = ObjectArgs(args)
        finder = SimilarIncidentFinder(mapped_args)
        finder.run()
    except Exception as e:
        return_error(f"Failed to execute DBotFindSimilarIncidents. Error: {str(e)}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
