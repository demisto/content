import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    urls = demisto.demistoUrls()
    outputs = {'urls': urls, 'version': demisto.demistoVersion()}
    command_results = CommandResults(outputs_prefix='ServerInfo', outputs=outputs)
    return_results(command_results)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
