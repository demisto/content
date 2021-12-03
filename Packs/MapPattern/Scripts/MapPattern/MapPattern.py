import fnmatch
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DEFAULT_ALGORITHM = 'literal'
DEFAULT_PRIORITY = 'first_match'


def demisto_get(obj: Any, path: Any) -> Any:
    """
    demisto.get(), this supports a syntax of path escaped with backslash.
    """
    def split_context_path(path: str):
        nodes = []
        node = []
        itr = iter(path)
        for c in itr:
            if c == '\\':
                try:
                    node.append(next(itr))
                except StopIteration:
                    node.append('\\')
            elif c == '.':
                nodes.append(''.join(node))
                node = []
            else:
                node.append(c)
        nodes.append(''.join(node))
        return nodes

    if not isinstance(obj, dict):
        return None

    parts = split_context_path(path)
    for part in parts:
        if obj and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


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


def iterate_pattern_mapping(pattern_mapping: Union[List[Dict[str, Any]], Dict[str, Any]]):
    """ Iterate mapping entry.

    :param pattern_mapping: The pattern mapping table.
    :return: Each mapping entry. {pattern:, exclude:, algorithm:, output:, next:}
    """
    if isinstance(pattern_mapping, list):
        for m in pattern_mapping:
            yield from iterate_pattern_mapping(m)
    elif isinstance(pattern_mapping, dict):
        for k, v in pattern_mapping.items():
            d = v if isinstance(v, dict) else {'output': v}
            exclude = d.get('exclude') or []
            exclude = exclude if isinstance(exclude, list) else [exclude]

            yield {
                'pattern': k,
                'exclude': exclude,
                'output': d.get('output'),
                'algorithm': d.get('algorithm'),
                'next': d.get('next'),
                'comparison_fields': d.get('comparison_fields')
            }
    else:
        raise ValueError(f'pattern-mapping must be an array or an object: {pattern_mapping}')


class ContextData:
    def __init__(self,
                 context: Optional[Dict[str, Any]] = None,
                 arg_value: Optional[Dict[str, Any]] = None):
        """
        :param context: The demisto context.
        :param arg_value: The data of the `value` given in the argument parameters.
        """
        self.__demisto = context
        self.__value = arg_value

    def get(self, key: Optional[str] = None,) -> Any:
        """ Get the context value given the key

        :param key: The dt expressions (string within ${})
        :return: The value.
        """
        if key is not None:
            dx = self.__demisto
            if key != '.' and key.startswith('.'):
                dx = self.__value
                key = key[1:]

            if not key or key == '.':
                return dx
            elif isinstance(dx, (list, dict)):
                return demisto.dt(dx, key)
        return None


class Translator:
    def __init__(self, context: Any, arg_value: Any, ):
        """
        :param context: The demisto context.
        :param arg_value: The data of the `value` given in the argument parameters.
        """
        self.__arg_value = arg_value
        self.__context = None
        if isinstance(context, dict):
            self.__context = ContextData(context=context,
                                         arg_value=arg_value if isinstance(arg_value, dict) else None)

    def __extract_value(self,
                        source: str,
                        extractor: Callable[[str, Optional[ContextData]], Any],
                        dx: Optional[ContextData]) -> Any:
        """ Extract value including dt expression

          :param source: The value to be extracted that may include dt expressions.
          :param extractor: The extractor to get real value within ${dt}.
          :param dx: The demisto context.
          :return: The value extracted.
        """
        def _extract(source: str,
                     extractor: Optional[Callable[[str, Optional[ContextData]], Any]],
                     dx: Optional[ContextData],
                     si: int,
                     endc: Optional[str]) -> Tuple[Any, int]:
            val = None
            ci = si
            while ci < len(source):
                if endc is not None and source[ci] == endc:
                    if not extractor:
                        return '', ci + len(endc)
                    xval = extractor(source[si:ci], dx)
                    if val is None:
                        val = xval
                    elif xval is not None:
                        val = str(val) + str(xval)
                    si = ci = ci + len(endc)
                    endc = None
                else:
                    nextec = {'(': ')', '{': '}',
                              '[': ']', '"': '"', "'": "'"}.get(source[ci])
                    if nextec:
                        _, ci = _extract(source, None, dx, ci + 1, nextec)
                    elif extractor and source[ci:ci + 2] == '${':
                        if si != ci:
                            val = source[si:ci] if val is None else str(val) + source[si:ci]
                        si = ci = ci + 2
                        endc = '}'
                    elif source[ci] == '\\':
                        ci += 2
                    else:
                        ci += 1
            if not extractor:
                return ('', ci)
            elif si >= len(source):
                return (val, 0)
            elif val is None:
                return (source[si:], 0)
            else:
                return (str(val) + source[si:], 0)

        return _extract(source, extractor, dx, 0, None)[0] if source else ''

    def __extract_dt(self, dtstr: str, dx: Optional[ContextData]) -> Any:
        """ Extract dt expression

          :param dtstr: The dt expressions (string within ${}).
          :param dx: The demisto context.
          :return: The value extracted.
        """
        return dx.get(dtstr) if dx else dtstr

    def translate(self,
                  source: Any,
                  pattern_mapping: Union[List[Dict[str, Any]], Dict[str, Any]],
                  regex_flags: int,
                  priority: str,
                  algorithm: str) -> Tuple[Optional[List[str]], Any, bool]:
        """ Replace the string given with the patterns.

        :param source: The string to be replaced.
        :param pattern_mapping: The mapping table to translate.
        :param regex_flags: The regex flags for pattern matching.
        :param priority: The priority order (first_match, last_match or longest_pattern).
        :param algorithm: The default algorithm for pattern match.
        :return: The mapping matched, a new value replaced by it, and a flag if a pattern has matched or not.
        """
        matched = False
        matched_mapping = None
        matched_output = source
        source = '' if source is None else str(source)
        for mapping in iterate_pattern_mapping(pattern_mapping):
            algorithm = mapping.get('algorithm') or algorithm

            # Check if the source matches a pattern
            pattern = make_regex(mapping['pattern'], algorithm)
            match = re.fullmatch(pattern, source, flags=regex_flags)
            if not match:
                continue

            # Check if the source matches any of exclusion patterns.
            exclude = [make_regex(x, algorithm) for x in mapping['exclude']]
            if any([re.fullmatch(x, source, flags=regex_flags) for x in exclude]):
                continue

            # Set the output
            comparison_fields = None
            output = mapping.get('output')
            next_mappings = mapping.get('next')
            if output is None:
                output = self.__arg_value
                if next_mappings and isinstance(output, dict):
                    # `comparison_fields` is given
                    comparison_fields = argToList(mapping['comparison_fields'])

            elif algorithm == 'regex' and isinstance(output, str):
                output = match.expand(output.replace(r'\0', r'\g<0>'))
            if self.__context is not None and isinstance(output, str):
                output = self.__extract_value(output, self.__extract_dt, self.__context)

            if next_mappings:
                if comparison_fields is not None:
                    mapping, output, matched = self.translate_fields(
                        obj_value=output,
                        field_mapping=next_mappings,
                        regex_flags=regex_flags,
                        priority=priority,
                        algorithm=algorithm,
                        comparison_fields=comparison_fields)
                else:
                    mapping, output, matched = self.translate(
                        source=output,
                        pattern_mapping=next_mappings,
                        regex_flags=regex_flags,
                        priority=priority,
                        algorithm=algorithm)
                if not matched:
                    continue

            if priority in ('first_match', 'last_match'):
                matched = True
                matched_output = output
                matched_mapping = mapping
                if priority == 'first_match':
                    break
            else:
                raise ValueError(f'Invalid priority: {priority}')

        return matched_mapping, matched_output, matched

    def translate_fields(self,
                         obj_value: Dict[str, Any],
                         field_mapping: Dict[str, Any],
                         regex_flags: int,
                         priority: str,
                         algorithm: str,
                         comparison_fields: List[str]) -> Tuple[Optional[List[str]], Any, bool]:
        if not isinstance(field_mapping, dict):
            raise ValueError(f'field-mapping must be an array or an object in JSON: type={type(field_mapping)}')

        for path in comparison_fields:
            # Get pattern mapping
            mapping = field_mapping.get(path.replace('\\', ''))
            if mapping is None:
                continue
            if not isinstance(mapping, (dict, list)):
                raise ValueError(f'pattern-mapping must be an array or an object in JSON: type={type(mapping)}')

            # Get a value for pattern matching
            comparison_value = demisto_get(obj_value, path)
            if not isinstance(comparison_value, (dict, list)):
                matched_mapping, matched_output, matched = self.translate(
                    comparison_value, mapping, regex_flags, priority, algorithm)
                if matched:
                    return matched_mapping, matched_output, matched
        return None, obj_value, False


def main():
    args = demisto.args()
    value = args.get('value')
    mappings = args['mappings']
    algorithm = args.get('algorithm') or DEFAULT_ALGORITHM
    priority = args.get('priority') or DEFAULT_PRIORITY
    context = args.get('context')
    comparison_fields = argToList(args.get('comparison_fields'))
    regex_flags = re.IGNORECASE if argToBoolean(args.get('caseless') or 'true') else 0
    for flag in argToList(args.get('flags', '')):
        if flag in ('dotall', 's'):
            regex_flags |= re.DOTALL
        elif flag in ('multiline', 'm'):
            regex_flags |= re.MULTILINE
        elif flag in ('ignorecase', 'i'):
            regex_flags |= re.IGNORECASE
        elif flag in ('unicode', 'u'):
            regex_flags |= re.UNICODE
        else:
            raise ValueError(f'Unknown flag: {flag}')

    if isinstance(mappings, str):
        try:
            mappings = json.loads(mappings)
        except ValueError:
            raise ValueError(f'Unable to decode mappings in JSON: {mappings}')

    tr = Translator(context=context, arg_value=value)
    if comparison_fields:
        if isinstance(value, dict):
            _, value, matched = tr.translate_fields(
                obj_value=value,
                field_mapping=mappings,
                regex_flags=regex_flags,
                priority=priority,
                algorithm=algorithm,
                comparison_fields=comparison_fields)
    else:
        if not isinstance(value, (dict, list)):
            _, value, _ = tr.translate(
                source=value,
                pattern_mapping=mappings,
                regex_flags=regex_flags,
                priority=priority,
                algorithm=algorithm)

    demisto.results(value)


if __name__ in ('__builtin__', 'builtins'):
    main()
