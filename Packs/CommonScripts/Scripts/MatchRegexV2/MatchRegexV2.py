import demistomock as demisto
from CommonServerPython import *

from typing import Dict
import re


LETTER_TO_REGEX_FLAGS = {
    'i': re.IGNORECASE,
    'm': re.MULTILINE,
    's': re.DOTALL,
    'u': re.UNICODE,
}


def parse_regex_flags(raw_flags: str = 'gim'):
    """
    parse flags user input and convert them to re flags.

    Args:
        raw_flags: string chars representing er flags

    Returns:
        (re flags, whether to return multiple matches)

    """
    raw_flags = raw_flags.lstrip('-')  # compatibility with original MatchRegex script.
    multiple_matches = 'g' in raw_flags
    raw_flags = raw_flags.replace('g', '')
    flags = re.RegexFlag(0)
    for c in raw_flags:
        if c in LETTER_TO_REGEX_FLAGS:
            flags |= LETTER_TO_REGEX_FLAGS[c]
        else:
            raise ValueError(f'Invalid regex flag "{c}".\n'
                             f'Supported flags are {", ".join(LETTER_TO_REGEX_FLAGS.keys())}')

    return flags, multiple_matches


def main(args: Dict):
    data = args.get('data')
    raw_regex = args.get('regex', '')
    group = int(args.get('group', '0'))
    context_key = args.get('contextKey', '')
    flags, multiple_matches = parse_regex_flags(args.get('flags', 'gim'))

    regex = re.compile(raw_regex, flags=flags)
    # in case group is out of range, fallback to all matching string
    if group > regex.groups:
        group = 0

    results = []
    if multiple_matches:
        regex_result = regex.search(data)
        while regex_result:
            results.append(regex_result.group(group))
            regex_result = regex.search(data, regex_result.span()[1])
    else:
        regex_result = regex.search(data)
        if regex_result:
            results = regex_result.group(group)

    results = results[0] if len(results) == 1 else results

    if results:
        human_readable = json.dumps(results)
    else:
        human_readable = 'Regex does not match.'

    context = {}
    if context_key:
        context = {context_key: results}

    # clearing the context field in order to override it instead of appending it.
    demisto.setContext('MatchRegex.results', results)
    return CommandResults(readable_output=human_readable,
                          outputs=context,
                          raw_response=results,
                          )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
