import fnmatch
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DEFAULT_ALGORITHM = 'literal'
DEFAULT_PRIORITY = 'first_match'


def make_regex(pattern: str, algorithm: str) -> str:
    """ Transform a pattern to a regex pattern.

      Supported algorithms;
        - literal
        - wildcard
        - regex
        - regmatch

      :param pattern: The pattern to be transformed.
      :param algorithm: The algorithm for `pattern`.
      :return: An regex pattern created.
    """
    if algorithm == 'literal':
        return re.escape(pattern)
    elif algorithm == 'wildcard':
        return fnmatch.translate(pattern)
    elif algorithm in ('regex', 'regmatch'):
        return pattern
    else:
        raise ValueError(f'Invalid algorithm: {algorithm}')


def extract_value(source: str,
                  extractor: Callable[[str, Optional[Dict[str, Any]]], Any],
                  dx: Optional[Dict[str, Any]]) -> Any:
    """ Extract value including dt expression

      :param source: The value to be extracted that may include dt expressions.
      :param extractor: The extractor to get real value within ${dt}.
      :param dx: The demisto context.
      :return: The value extracted.
    """
    def _extract(source: str,
                 extractor: Optional[Callable[[str,
                                               Optional[Dict[str, Any]]],
                                              Any]],
                 dx: Optional[Dict[str, Any]],
                 si: int,
                 endc: Optional[str]) -> Tuple[str, int]:
        val = ''
        ci = si
        while ci < len(source):
            if endc is not None and source[ci] == endc:
                if not extractor:
                    return '', ci + len(endc)
                xval = extractor(source[si:ci], dx)
                val += str(xval) if xval is not None else ''
                si = ci = ci + len(endc)
                endc = None
            else:
                nextec = {'(': ')', '{': '}',
                          '[': ']', '"': '"', "'": "'"}.get(source[ci])
                if nextec:
                    _, ci = _extract(source, None, dx, ci + 1, nextec)
                elif extractor and source[ci:ci + 2] == '${':
                    val += source[si:ci]
                    si = ci = ci + 2
                    endc = '}'
                elif source[ci] == '\\':
                    ci += 2
                else:
                    ci += 1
        return (val + source[si:], 0) if extractor else ('', ci)

    if source.startswith('${') and source.endswith('}'):
        return extractor(source[2:-1], dx)
    else:
        dst, _ = _extract(source, extractor, dx, 0, None)
        return dst


def extract_dt(dtstr: str, dx: Optional[Dict[str, Any]]) -> Any:
    """ Extract dt expression

      :param dtstr: The dt expressions (string within ${}).
      :param dx: The demisto context.
      :return: The value extracted.
    """
    return demisto.dt(dx, dtstr) if dx else dtstr


def iterate_mapping(mappings: Union[List[Dict[str, Any]], Dict[str, Any]]):
    """ Iterate mapping entry.

    :param mappings: The mapping table given.
    :return: Each mapping entry. {pattern:, exclude:, algorithm:, output:, next:}
    """
    if isinstance(mappings, list):
        for m in mappings:
            yield from iterate_mapping(m)
    elif isinstance(mappings, dict):
        for k, v in mappings.items():
            d = v if isinstance(v, dict) else {'output': v}
            exclude = d.get('exclude') or []
            exclude = exclude if isinstance(exclude, list) else [exclude]

            yield {
                'pattern': k,
                'exclude': exclude,
                'output': d.get('output'),
                'algorithm': d.get('algorithm'),
                'next': d.get('next')
            }
    else:
        raise ValueError(f'mappings must be an array or an object: {mappings}')


def translate(source: Any,
              mappings: Union[List[Dict[str, Any]], Dict[str, Any]],
              caseless: bool,
              priority: str,
              algorithm: str,
              context: Any) -> Tuple[Optional[List[str]], Any]:
    """ Replace the string given with the patterns.

    :param source: The string to be replaced.
    :param mappings: The mapping table to translate.
    :param caseless: Set to True for caseless comparation, False otherwise.
    :param priority: The priority order (first_match, last_match or longest_pattern).
    :param algorithm: The default algorithm for pattern match.
    :param context: The demisto context.
    :return: The mapping matched and the new value replaced by it.
    """
    matched_mapping = None
    matched_output = source
    source = str(source)
    for mapping in iterate_mapping(mappings):
        flags = re.IGNORECASE if caseless else 0
        algorithm = mapping.get('algorithm') or algorithm

        # Check if the source matches a pattern
        pattern = make_regex(mapping['pattern'], algorithm)
        match = re.fullmatch(pattern, source, flags=flags)
        if not match:
            continue

        # Check if the source matches any of exclusion patterns.
        exclude = [make_regex(x, algorithm) for x in mapping['exclude']]
        if any([re.fullmatch(x, source, flags=flags) for x in exclude]):
            continue

        # Set the output
        output = mapping.get('output')
        if output is None:
            output = demisto.args()['value']
        elif algorithm == 'regex' and isinstance(output, str):
            output = match.expand(output.replace(r'\0', r'\g<0>'))
        if isinstance(context, dict) and isinstance(output, str):
            output = extract_value(output, extract_dt, context)

        next_mappings = mapping.get('next')
        if next_mappings:
            mapping, output = translate(output, next_mappings, caseless, priority, algorithm, context)
            if not mapping:
                continue

        if priority in ('first_match', 'last_match'):
            matched_output = output
            matched_mapping = mapping
            if priority == 'first_match':
                break
        else:
            raise ValueError(f'Invalid priority: {priority}')

    return matched_mapping, matched_output


def main():
    args = demisto.args()
    value = args['value']
    mappings = args['mappings']
    algorithm = args.get('algorithm') or DEFAULT_ALGORITHM
    priority = args.get('priority') or DEFAULT_PRIORITY
    caseless = argToBoolean(args.get('caseless') or 'true')
    context = args.get('context')

    if not isinstance(value, (dict, list)):
        if isinstance(mappings, str):
            try:
                mappings = json.loads(mappings)
            except ValueError:
                raise ValueError(f'Unable to decode mappings in JSON: {mappings}')

        if isinstance(mappings, (dict, list)):
            _, value = translate(value, mappings, caseless, priority, algorithm, context)
        else:
            raise ValueError(f'mappings must be an array or an object in JSON: type={type(mappings)}')

    demisto.results(value)


if __name__ in ('__builtin__', 'builtins'):
    main()
