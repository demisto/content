import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    try:
        res = demisto.executeCommand("setIndicators", {"indicatorsValues": args.get("Indicators"), "tags": args.get("Tags")})

        if is_error(res):
            raise DemistoException(f'Failed to set indicators: {str(get_error(res))}')

        return_results(CommandResults(
            readable_output=res[0]['Contents']
        ))

    except Exception as e:
        return_error(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
