import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import fnmatch
import json
import re
from typing import Any, Dict, Generator, List, Optional, Tuple, Union, Callable


DEFAULT_ALGORITHM = 'literal'
DEFAULT_PRIORITY = 'first_match'


def demisto_get(obj: Any, path: Any) -> Any:
    """
    demisto.get(), this supports a syntax of path escaped with backslash.
    """
    def split_context_path(path: str) -> List[str]:
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

    for part in split_context_path(path):
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

    def get(self, key: Optional[str], node: Optional[Any] = None, ignore_errors: bool = False) -> Any:
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


class Formatter:
    def __init__(self, start_marker: str, end_marker: str, keep_symbol_to_null: bool):
        if not start_marker:
            raise ValueError('start-marker is required.')

        self.__start_marker = start_marker
        self.__end_marker = end_marker
        self.__keep_symbol_to_null = keep_symbol_to_null

    @staticmethod
    def __is_end_mark(source: str, ci: int, end_marker: str) -> bool:
        if end_marker:
            return source[ci:ci + len(end_marker)] == end_marker
        else:
            c = source[ci]
            if c.isspace():
                return True
            elif c.isascii():
                return c != '_' and not c.isalnum()
            else:
                return False

    def __extract(self,
                  source: str,
                  extractor: Optional[Callable[[str,
                                                Optional[ContextData],
                                                Optional[Dict[str, Any]]],
                                               Any]],
                  dx: Optional[ContextData],
                  node: Optional[Dict[str, Any]],
                  si: int,
                  markers: Optional[Tuple[str, str]]) -> Tuple[Any, Optional[int]]:
        """ Extract a template text, or an enclosed value within starting and ending marks

        :param source: The template text, or the enclosed value starts with the next charactor of a start marker
        :param extractor: The function to extract an enclosed value as DT
        :param dx: The context data
        :param node: The current node
        :param si: The index of `source` to start extracting
        :param markers: The start and end marker to find an end position for parsing an enclosed value.
                        It must be None when the template text is given to `source`.
        :return: The extracted value and index of `source` when parsing ended.
                 The index is the next after the end marker when extracting the enclosed value.
        """
        out = None
        ci = si
        while ci < len(source):
            if markers is not None and Formatter.__is_end_mark(source, ci, markers[1]):
                key = source[si:ci] if out is None else str(out) + source[si:ci]
                if extractor:
                    if (xval := extractor(key, dx, node)) is None and self.__keep_symbol_to_null:
                        xval = markers[0] + key + markers[1]
                else:
                    xval = key
                return xval, ci + len(markers[1])
            elif extractor and source[ci:ci + len(self.__start_marker)] == self.__start_marker:
                xval, ei = self.__extract(source, extractor, dx, node,
                                          ci + len(self.__start_marker),
                                          (self.__start_marker, self.__end_marker))
                if si != ci:
                    out = source[si:ci] if out is None else str(out) + source[si:ci]

                if ei is None:
                    xval = self.__start_marker
                    ei = ci + len(self.__start_marker)

                if out is None:
                    out = xval
                elif xval is not None:
                    out = str(out) + str(xval)
                si = ci = ei
            elif markers is None:
                ci += 1
            elif endc := {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'"}.get(source[ci]):
                _, ei = self.__extract(source, None, dx, node, ci + 1, (source[ci], endc))
                ci = ci + 1 if ei is None else ei
            elif source[ci] == '\\':
                ci += 2
            else:
                ci += 1

        if markers is not None:
            # unbalanced braces, brackets, quotes, etc.
            return None, None
        elif not extractor:
            return None, ci
        elif si >= len(source):
            return out, ci
        elif out is None:
            return source[si:], ci
        else:
            return str(out) + source[si:], ci

    def build(self,
              template: Any,
              extractor: Optional[Callable[[str,
                                            Optional[ContextData],
                                            Optional[Dict[str, Any]]],
                                           Any]],
              dx: Optional[ContextData],
              node: Optional[Dict[str, Any]]) -> Any:
        """ Format a text from a template including DT expressions

        :param template: The template.
        :param extractor: The extractor to get real value within ${dt}.
        :param dx: The context instance.
        :param node: The current node.
        :return: The text built from the template.
        """
        if isinstance(template, dict):
            return {
                self.build(k, extractor, dx, node): self.build(v, extractor, dx, node)
                for k, v in template.items()}
        elif isinstance(template, list):
            return [self.build(v, extractor, dx, node) for v in template]
        elif isinstance(template, str):
            return self.__extract(template, extractor, dx, node, 0, None)[0] if template else ''
        else:
            return template


def extract_value(source: Any,
                  dx: Optional[ContextData],
                  node: Optional[Dict[str, Any]] = None) -> Any:
    """ Extract value including dt expression

    :param source: The value to be extracted that may include dt expressions.
    :param dx: The demisto context.
    :param node: The current node.
    :return: The value extracted.
    """
    def __extract_dt(dtstr: str,
                     dx: Optional[ContextData],
                     node: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return dx.get(dtstr, node) if dx else dtstr
        except Exception as err:
            demisto.debug(f'failed to extract dt from "{dtstr=}". Error: {err}')
            return None

    return Formatter('${', '}', False).build(source, __extract_dt, dx, node)


class Translator:
    def __init__(self,
                 context: Any,
                 arg_value: Any,
                 fields_comp_mode: bool,
                 wildcards: List[str],
                 regex_flags: int):
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

    def __match(self,
                algorithm: str,
                pattern: str,
                value: Any,
                exclusions: List[str],
                ignore_syntax: bool = False) -> Union[bool, re.Match]:
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
            if isinstance(value, (dict, list)):
                return False

            value = '' if value is None else str(value)
            if pattern not in self.__wildcards:
                if (self.__regex_flags & re.IGNORECASE) != 0:
                    if pattern.lower() != value.lower():
                        return False
                else:
                    if pattern != value:
                        return False

            if any(x == value for x in exclusions):
                return False
        elif algorithm in ('wildcard', 'regex', 'regmatch'):
            if isinstance(value, (dict, list)):
                return False

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
                output = extract_value(output, self.__context, source)

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
            matched_output, matched = self.translate(
                comparison_value, mapping, priority, algorithm)
            if matched:
                return matched_output, matched
        return obj_value, False


def main():
    args = demisto.args()
    value = args.get('value')
    try:
        mappings = args.get('mappings') or {}
        algorithm = args.get('algorithm') or DEFAULT_ALGORITHM
        priority = args.get('priority') or DEFAULT_PRIORITY
        context = args.get('context')
        fields_comp_mode = argToBoolean(args.get('compare_fields') or 'false')
        wildcards = argToList(args.get('wildcards'))
        default_value = args.get('default_value')
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

        matched = False
        if fields_comp_mode:
            if isinstance(value, dict):
                value, matched = tr.translate_fields(
                    obj_value=value,
                    field_mapping=mappings,
                    priority=priority,
                    algorithm=algorithm)
        else:
            if not isinstance(value, (dict, list)):
                value, matched = tr.translate(
                    source=value,
                    pattern_mapping=mappings,
                    priority=priority,
                    algorithm=algorithm)
        if default_value and not matched:
            value = default_value
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))

    return_results(value)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
