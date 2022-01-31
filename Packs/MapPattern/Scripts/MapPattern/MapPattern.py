import fnmatch
import json
import re
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

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


def expand_match(match: re.Match, value: Any) -> Any:
    """ Return the value obtained by doing backslash substitution on the template string template

    :param match: The match object.
    :param value: The template value.
    :return: The value replaced.
    """
    if isinstance(value, dict):
        return {expand_match(match, k): expand_match(match, v) for k, v in value.items()}
    elif isinstance(value, list):
        return [expand_match(match, v) for v in value]
    elif isinstance(value, str):
        return match.expand(value.replace(r'\0', r'\g<0>'))
    else:
        return value


class Mapping:
    def __init__(self, pattern: str, repl: Union[str, Dict[str, Any]]):
        """
        :param pattern: The pattern to compare to the value.
        :param repl: The parameters for pattern matching or making outputs.
        """
        repl = repl if isinstance(repl, dict) else {'output': repl}
        exclude = repl.get('exclude') or []

        self.pattern: str = pattern
        self.exclude: List[str] = exclude if isinstance(exclude, list) else [exclude]
        self.output: Any = repl.get('output')
        self.algorithm: Optional[str] = repl.get('algorithm')
        self.next: Any = repl.get('next')
        self.ignore_syntax = bool(repl.get('ignore_syntax') or False)


def iterate_pattern_mapping(pattern_mapping: Union[List[Dict[str, Any]], Dict[str, Any]]) -> Generator[Mapping, None, None]:
    """ Iterate mapping entry.

    :param pattern_mapping: The pattern mapping table.
    :return: Each mapping entry. {pattern:, exclude:, algorithm:, output:, next:}
    """
    if isinstance(pattern_mapping, list):
        for m in pattern_mapping:
            yield from iterate_pattern_mapping(m)
    elif isinstance(pattern_mapping, dict):
        for pattern, repl in pattern_mapping.items():
            yield Mapping(pattern, repl)
    else:
        raise ValueError(f'pattern-mapping must be an array or an object: {pattern_mapping}')


class ContextData:
    def __init__(self, context: Any = None, arg_value: Optional[Dict[str, Any]] = None):
        """
        :param context: The demisto context.
        :param arg_value: The data of the `value` given in the argument parameters.
        """
        self.__demisto = context
        self.__value = arg_value

    def get(self, key: Optional[str], node: Optional[Any] = None, ignore_errors=False) -> Any:
        """ Get the context value given the key

        :param key: The dt expressions (string within ${}).
        :param node: The current node.
        :param ignore_errors: Set to True to ignore errors, otherwise False.
        :return: The value.
        """
        if key is not None:
            dx = self.__demisto
            if key != '..' and not key.startswith('..=') and key.startswith('..'):
                dx = node
                key = key[2:]
            elif key != '.' and not key.startswith('.=') and key.startswith('.'):
                dx = self.__value
                key = key[1:]

            if not key or key == '.':
                return dx
            try:
                return demisto.dt(dx, key)
            except Exception:
                if not ignore_errors:
                    raise
        return None


class Translator:
    def __init__(self, context: Any, arg_value: Any, fields_comp_mode: bool, wildcards: List[str], regex_flags: int):
        """
        :param context: The demisto context.
        :param arg_value: The data of the `value` given in the argument parameters.
        :param fields_comp_mode: True - Fields comp mode, otherwise False.
        :param wildcards: The list of the special patterns which match to any value regardless of algorithm.
        :param regex_flags: The regex flags for pattern matching.
        """
        self.__arg_value = arg_value
        self.__demisto = context
        self.__fields_comp_mode = fields_comp_mode
        self.__wildcards = wildcards
        self.__regex_flags = regex_flags
        self.__context = ContextData(context=context, arg_value=arg_value)

    def __extract_value(self, source: Any, context: ContextData, node: Optional[Any] = None) -> Any:
        """ Extract value including dt expression

        :param source: The value to be extracted that may include dt expressions.
        :param context: The context object.
        :param node: The current node.
        :return: The value extracted.
        """
        def _extract(source: str,
                     context: Optional[ContextData],
                     node: Optional[Any],
                     si: int,
                     endc: Optional[str]) -> Tuple[Any, int]:
            val = None
            ci = si
            while ci < len(source):
                if endc is not None and source[ci] == endc:
                    if not context:
                        return '', ci + len(endc)
                    xval = context.get(source[si:ci], node)
                    if val is None:
                        val = xval
                    elif xval is not None:
                        val = str(val) + str(xval)
                    si = ci = ci + len(endc)
                    endc = None
                else:
                    nextec = {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'"}.get(source[ci])
                    if nextec:
                        _, ci = _extract(source, None, node, ci + 1, nextec)
                    elif context and source[ci:ci + 2] == '${':
                        if si != ci:
                            val = source[si:ci] if val is None else str(val) + source[si:ci]
                        si = ci = ci + 2
                        endc = '}'
                    elif source[ci] == '\\':
                        ci += 2
                    else:
                        ci += 1
            if not context:
                return ('', ci)
            elif si >= len(source):
                return (val, 0)
            elif val is None:
                return (source[si:], 0)
            else:
                return (str(val) + source[si:], 0)

        if isinstance(source, dict):
            return {self.__extract_value(k, context, node): self.__extract_value(v, context, node) for k, v in source.items()}
        elif isinstance(source, list):
            return [self.__extract_value(v, context, node) for v in source]
        elif isinstance(source, str):
            return _extract(source, context, node, 0, None)[0] if source else ''
        else:
            return source

    def __match(self,
                algorithm: str,
                pattern: str,
                value: Any,
                exclusions: List[str],
                ignore_syntax=False) -> Union[bool, re.Match]:
        """ Perform the pattern matching.

          Supported algorithms:
            - literal
            - wildcard
            - regex
            - regmatch
            - dt

        :param algorithm: The algorithm for pattern match.
        :param pattern: The pattern to compare to the value.
        :param value: The value to compare to the pattern.
        :param exclusions: The list of the patterns to exclude matching results.
        :param ignore_syntax: Set to True to ignore syntax errors to the pattern, False otherwise.
        :return: False - unmatched. Returns True for matched pattern when literal, wildcard,
                 regmatch and dt is given to the algorithm.
                 Return re.Match for matched mattern pattern when regex is given to it.
                 Note: Returns True if the value matched to any of special wildcard patterns even in regex.
        """
        if algorithm == 'literal':
            value = '' if value is None else str(value)
            if pattern not in self.__wildcards:
                if pattern != value:
                    return False

            if any(x == value for x in exclusions):
                return False
        elif algorithm in ('wildcard', 'regex', 'regmatch'):
            value = '' if value is None else str(value)
            regex_match = None
            if pattern not in self.__wildcards:
                try:
                    regex = make_regex(pattern, algorithm)
                except (AttributeError, ValueError):
                    if not ignore_syntax:
                        raise
                    return False

                regex_match = re.fullmatch(regex, value, flags=self.__regex_flags)
                if not regex_match:
                    return False

            if any(re.fullmatch(make_regex(x, algorithm), value, flags=self.__regex_flags) for x in exclusions):
                return False

            if algorithm == 'regex' and isinstance(regex_match, re.Match):
                return regex_match

        elif algorithm == 'dt':
            if pattern not in self.__wildcards:
                if not self.__context.get(pattern, value, ignore_errors=ignore_syntax):
                    return False

            if any(self.__context.get(x, value, ignore_errors=ignore_syntax) for x in exclusions):
                return False
        else:
            raise ValueError(f'This function only supports literal, wildcard and dt: {algorithm}')

        return True

    def translate(self,
                  source: Any,
                  pattern_mapping: Union[List[Dict[str, Any]], Dict[str, Any]],
                  priority: str,
                  algorithm: str) -> Tuple[Any, bool]:
        """ Replace the string given with the patterns.

        :param source: The string to be replaced.
        :param pattern_mapping: The mapping table to translate.
        :param priority: The priority order (first_match, last_match or longest_pattern).
        :param algorithm: The default algorithm for pattern match.
        :return: The new value replaced by a mapping, and a flag if a pattern has matched or not.
        """
        matched = False
        matched_output = source
        for mapping in iterate_pattern_mapping(pattern_mapping):
            algorithm = mapping.algorithm or algorithm

            # Check if the source matches a pattern
            source_match = self.__match(algorithm=algorithm,
                                        pattern=mapping.pattern,
                                        value=source,
                                        exclusions=mapping.exclude,
                                        ignore_syntax=mapping.ignore_syntax)
            if not source_match:
                continue

            # Set the output
            fields_comp_mode = False
            output = mapping.output
            if output is None:
                output = self.__arg_value
                if mapping.next and isinstance(output, dict):
                    fields_comp_mode = self.__fields_comp_mode

            elif algorithm == 'regex' and isinstance(source_match, re.Match):
                output = expand_match(source_match, output)

            if self.__demisto is not None:
                # Extract values only if `context` of the arguments is given.
                output = self.__extract_value(output, self.__context, source)

            if mapping.next:
                if fields_comp_mode:
                    output, matched = self.translate_fields(
                        obj_value=output,
                        field_mapping=mapping.next,
                        priority=priority,
                        algorithm=algorithm)
                else:
                    output, matched = self.translate(
                        source=output,
                        pattern_mapping=mapping.next,
                        priority=priority,
                        algorithm=algorithm)
                if not matched:
                    continue

            if priority in ('first_match', 'last_match'):
                matched = True
                matched_output = output
                if priority == 'first_match':
                    break
            else:
                raise ValueError(f'Invalid priority: {priority}')

        return matched_output, matched

    def translate_fields(self,
                         obj_value: Dict[str, Any],
                         field_mapping: Dict[str, Any],
                         priority: str,
                         algorithm: str) -> Tuple[Any, bool]:
        """ Replace the string given with the field mapping.

        :param obj_value: The object whose values to be replaced.
        :param field_mapping: The mapping table to translate.
        :param priority: The priority order (first_match, last_match or longest_pattern).
        :param algorithm: The default algorithm for pattern match.
        :return: The new value replaced by a mapping, and a flag if a pattern has matched or not.
        """
        if not isinstance(field_mapping, dict):
            raise ValueError(f'field-mapping must be an array or an object in JSON: type={type(field_mapping)}')

        for path, mapping in field_mapping.items():
            if not isinstance(mapping, (dict, list)):
                raise ValueError(f'pattern-mapping must be an array or an object in JSON: type={type(mapping)}')

            # Get a value for pattern matching
            comparison_value = demisto_get(obj_value, path)
            if not isinstance(comparison_value, (dict, list)):
                matched_output, matched = self.translate(
                    comparison_value, mapping, priority, algorithm)
                if matched:
                    return matched_output, matched
        return obj_value, False


def main():
    args = demisto.args()
    value = args.get('value')
    try:
        mappings = args['mappings']
        algorithm = args.get('algorithm') or DEFAULT_ALGORITHM
        priority = args.get('priority') or DEFAULT_PRIORITY
        context = args.get('context')
        fields_comp_mode = argToBoolean(args.get('compare_fields') or 'false')
        wildcards = argToList(args.get('wildcards'))
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

        tr = Translator(context=context,
                        arg_value=value,
                        fields_comp_mode=fields_comp_mode,
                        wildcards=wildcards,
                        regex_flags=regex_flags)
        if fields_comp_mode:
            if isinstance(value, dict):
                value, _ = tr.translate_fields(
                    obj_value=value,
                    field_mapping=mappings,
                    priority=priority,
                    algorithm=algorithm)
        else:
            if not isinstance(value, (dict, list)):
                value, _ = tr.translate(
                    source=value,
                    pattern_mapping=mappings,
                    priority=priority,
                    algorithm=algorithm)
    except Exception as err:
        return_error(err)

    return_results(value)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
