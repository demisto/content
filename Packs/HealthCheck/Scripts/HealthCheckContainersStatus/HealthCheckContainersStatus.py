import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = demisto.executeCommand('demisto-api-get', {'uri': '/health/containers'})
    if is_error(res):
        return_results(res)
        return_error('Failed to execute demisto-api-get. See additional error details in the above entries.')

    containers = res[0]['Contents']['response']

    return CommandResults(
        readable_output=tableToMarkdown('Containers Status', [containers], headers=['all', 'inactive', 'running']),
        outputs_prefix='containers',
        outputs=[containers],
        raw_response=containers,
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
