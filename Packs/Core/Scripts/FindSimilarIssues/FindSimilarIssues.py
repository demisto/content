import demistomock as demisto
from CommonServerPython import *
from FindSimilarEntitiesApiModule import *  # noqa: E402


def main():
    try:
        args = demisto.args()
        mapped_args = EntityArgs(args)
        finder = SimilarIssueFinder(mapped_args)
        finder.run()
    except Exception as e:
        return_error(f"Failed to execute FindSimilarIssues. Error: {str(e)}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
