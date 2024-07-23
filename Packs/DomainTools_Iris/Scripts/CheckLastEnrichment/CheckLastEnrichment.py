from CommonServerPython import *
from typing import Any


def time_check(last_check: str) -> bool:
    time_diff = datetime.now() - datetime.strptime(last_check, '%Y-%m-%d')
    return time_diff.days >= 1


def check_last_enrichment(args: dict[str, Any]) -> CommandResults:
    last_enrichment = args['last_enrichment']

    should_refresh_enrichment = "yes" if last_enrichment is None or time_check(
        last_enrichment) else "no"

    return CommandResults(
        outputs_prefix="CheckLastEnrichment",
        outputs=should_refresh_enrichment,
        readable_output=should_refresh_enrichment
    )


def main():
    try:
        return_results(check_last_enrichment(demisto.args()))
    except Exception as ex:
        return_error(
            f"Failed to execute CheckLastEnrichment. Error: {str(ex)}")


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
