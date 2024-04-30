import demistomock as demisto
from CommonServerPython import *

from FormatURLApiModule import *  # noqa: E402


def _is_valid_cidr(cidr: str) -> bool:
    """
    Will check if "url" is a valid CIDR in order to ignore it
    Args:
        cidr: the suspected input

    Returns:
        True if inout is a valid CIDR

    """
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False


def main():
    raw_urls = argToList(demisto.args().get('input'), separator='|')
    try:
        formatted_urls = format_urls(raw_urls)
        output = [{
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': [urls],
            'EntryContext': {'URL': urls},
        } for urls in formatted_urls]

        for url in output:
            demisto.results(url)

    except Exception as e:
        return_error(
            f'Failed to execute the automation. Error: \n{str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no-cover
    main()
