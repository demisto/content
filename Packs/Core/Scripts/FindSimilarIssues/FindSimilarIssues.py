import demistomock as demisto
from CommonServerPython import *
from SimilarObjectApiModule import *  # noqa: E402
from CommonServerUserPython import *

def main():
    args = demisto.args()
    finder = SimilarIssueFinder(args)
    finder.run()

if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
