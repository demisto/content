import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    leftArg = args.get("left")
    rightArg = args.get("right")

    left_list = argToList(leftArg)
    right_list = argToList(rightArg)

    if not (leftArg and rightArg):
        return_results("No matches found.")
    results: set[str] = set()
    for right_val in right_list:
        results = results.union(list(filter(lambda left_val: right_val.lower() in left_val.lower(), left_list)))
    return return_results(list(results)) if results else return_results("No matches found.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
