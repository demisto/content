import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import copy
import fnmatch
import hashlib
import json
import re
from email.header import decode_header
from typing import Any
from collections.abc import Callable


PATALG_BINARY: int = 0
PATALG_WILDCARD: int = 1
PATALG_REGEX: int = 2

ITERATE_NODE: int = 0
ITERATE_VALUE: int = 1
ITERATE_KEY: int = 2


class Value:
    def __init__(self, value: Any):
        self.value = value


class Ddict:
    @staticmethod
    def __search(val: dict[str, Any] | list[dict[str, Any]],
                 comps: list[str]) -> tuple[str, Any, list[str]] | None:
        for i in range(len(comps), 0, -1):
            key = '.'.join(comps[:i])

            if isinstance(val, list):
                if True not in {key in v if v else False for v in val}:
                    v = None
                else:
                    v = Value([v.get(key) if v else None for v in val])
            else:
                v = Value(val.get(key)) if key in val else None

            if v is not None:
                return (key, v.value, comps[i:])
        return None

    @staticmethod
    def search(node: dict[str, Any],
               path: str) -> tuple[str, Any, str] | None:
        """ Get a child node

        :param node: A root node.
        :param path: A path to separete a child and names under the child.
        :return: child_name, child_value, descendant_name.
        """
        res = Ddict.__search(node, path.split('.'))
        if res is None:
            return None
        return (res[0], res[1], '.'.join(res[2]))

    @staticmethod
    def set(node: dict[str, Any], path: str, value: Any):
        comps = path.split('.')
        while comps:
            parent = node
            res = Ddict.__search(parent, comps)
            if res is None:
                name = comps[0]
                comps = comps[1:]
            else:
                name, node, comps = res

            if not isinstance(node, dict):
                parent[name] = node = {}
        parent[name] = value

    @staticmethod
    def get_value(node: dict[str, Any], path: str) -> Value | None:
        val = None
        key = None
        comps = path.split('.')
        while comps:
            res = Ddict.__search(node if val is None else val, comps)
            if res is None:
                return None
            key, val, comps = res

        return None if key is None else Value(val)

    @staticmethod
    def get(node: dict[str, Any], path: str) -> Any:
        val = Ddict.get_value(node, path)
        return val.value if val else None


class ContextData:
    def __init__(self,
                 demisto: dict[str, Any] | None = None,
                 inputs: dict[str, Any] | None = None,
                 lists: dict[str, Any] | None = None,
                 incident: dict[str, Any] | None = None,
                 local: Any = None):

        self.__demisto = demisto
        self.__specials = {
            'inputs': inputs if isinstance(inputs, dict) else {},
            'lists': lists if isinstance(lists, dict) else {},
            'incident': incident if isinstance(incident, dict) else {},
            'local': delistize(local)
        }

    def get(self, key: str | None = None,
            node: Any | None = None) -> Any:
        """ Get the context value given the key

        :param key: The dt expressions (string within ${}).
        :param node: The current node.
        :return: The value.
        """
        if key is not None:
            dx = self.__demisto
            if key != '.' and not key.startswith('.=') and key.startswith('.'):
                dx = delistize(node)
                key = key[1:]
            else:
                for prefix in ['inputs', 'lists', 'incident', 'local']:
                    if prefix == key or (key.startswith(prefix)
                                         and key[len(prefix):len(prefix) + 1] in ('.', '(', '=')):
                        dx = self.__specials
                        break
            if not key or key == '.':
                return dx
            return demisto.dt(dx, key)
        return None


class CondIterator:
    def __init__(self, conds: Any, dx: ContextData | None, node: Any):
        self.__iter = conds.__iter__()
        self.__dx = dx
        self.__node = node

    def __iter__(self):
        return self

    def __next__(self):
        cond = self.__iter.__next__()
        if isinstance(cond, list | dict):
            return cond
        else:
            return extract_value(cond, self.__dx, self.__node)


class CondItemIterator:
    def __init__(self, conds: Any, dx: ContextData | None, node: dict):
        self.__iter = conds.items().__iter__()
        self.__dx = dx
        self.__node = node

    def __iter__(self):
        return self

    def __next__(self):
        k, v = self.__iter.__next__()
        k = extract_value(k, self.__dx, self.__node)
        if isinstance(v, list | dict):
            return k, v
        else:
            return k, extract_value(v, self.__dx, self.__node)


def exit_error(err_msg: str):
    raise RuntimeError(err_msg)


def lower(value: Any, recursive: bool = False, dict_value: bool = False, dict_key: bool = False) -> Any:
    if isinstance(value, list):
        if recursive:
            return [lower(v) for v in value]
        else:
            return [v.lower() if isinstance(v, str) else v for v in value]
    elif isinstance(value, dict):
        if dict_key:
            if recursive:
                value = {lower(k, recursive, dict_value, dict_key): v for k, v in value.items()}
            else:
                value = {
                    k.lower() if isinstance(k, str) else lower(k, False, False, False): v
                    for k, v in value.items()
                }
        if dict_value:
            if recursive:
                value = {k: lower(v, recursive, dict_value, dict_key) for k, v in value.items()}
            else:
                value = {
                    k: v.lower() if isinstance(v, str) else lower(v, False, False, False)
                    for k, v in value.items()
                }
        return value
    elif isinstance(value, str):
        return value.lower()
    else:
        return value


def listize(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def delistize(value: Any) -> Any:
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def marshal(value: Any) -> Any:
    if isinstance(value, list):
        values = []
        for v in value:
            if isinstance(v, list):
                values.extend(v)
            else:
                values.append(v)
        return values
    elif isinstance(value, dict):
        return {k: marshal(v) for k, v in value.items()}
    else:
        return value


def iterate_value(
        value: Any,
        type: int = ITERATE_NODE,
        recursive: bool = False):
    if isinstance(value, list):
        for v in value:
            if recursive:
                yield from iterate_value(v, type, recursive)
            elif type != ITERATE_KEY:
                yield v

    elif isinstance(value, dict):
        if type == ITERATE_NODE:
            yield value
        else:
            for k, v in value.items():
                if type == ITERATE_KEY:
                    yield k
                    if recursive:
                        yield from iterate_value(v, type, recursive)
                else:  # ITERATE_VALUE
                    if recursive:
                        yield from iterate_value(v, type, recursive)
                    else:
                        yield v
    else:
        if type != ITERATE_KEY:
            yield value


def hashdigest(value: str, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    h.update(value.encode('utf-8'))
    return h.hexdigest()


def match_pattern(
        pattern: str,
        value: Any,
        caseless: bool,
        patalg: int) -> bool:
    """ Pattern matching

    :param pattern: The pattern string.
    :param value: The value to compare with the pattern.
    :param caseless: True if the pattern matching take places in case insensitive, otherwise False.
    :param patalg: The pattern matching algorithm. Spefify any of PATALG_BINARY, PATALG_WILDCARD and PATALG_REGEX.
    :return: Return True if the value matches the pattern, otherwise False.
    """
    if patalg == PATALG_BINARY:
        if caseless:
            pattern = pattern.lower()
            if isinstance(value, list):
                return next(
                    filter(
                        lambda v: isinstance(v, str) and v.lower() == pattern,
                        value),
                    None) is not None
            elif isinstance(value, str):
                return pattern == value.lower()
        else:
            if isinstance(value, list):
                return pattern in value
            elif isinstance(value, str):
                return pattern == value
        return False

    elif patalg == PATALG_WILDCARD:
        if caseless:
            pattern = pattern.lower()
            if isinstance(value, list):
                return next(
                    filter(
                        lambda v:
                        isinstance(v, str) and fnmatch.fnmatchcase(v.lower(), pattern),
                        value),
                    None) is not None
            elif isinstance(value, str):
                return fnmatch.fnmatchcase(value.lower(), pattern)
        else:
            if isinstance(value, list):
                return next(
                    filter(
                        lambda v:
                        isinstance(v, str)
                        and fnmatch.fnmatchcase(v, pattern),
                        value),
                    None) is not None
            elif isinstance(value, str):
                return fnmatch.fnmatchcase(value, pattern)
        return False

    elif patalg == PATALG_REGEX:
        flags = re.IGNORECASE if caseless else 0

        if isinstance(value, list):
            return next(
                filter(
                    lambda v:
                        isinstance(v, str)
                        and re.fullmatch(pattern, v, flags),
                    value),
                None) is not None
        elif isinstance(value, str):
            return re.fullmatch(pattern, value, flags) is not None
        return False
    else:
        exit_error(f"Unknown pattern algorithm: '{patalg}'")
    return False


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
                  extractor: Callable[[str, ContextData | None, dict[str, Any] | None], Any] | None,
                  dx: ContextData | None,
                  node: dict[str, Any] | None,
                  si: int,
                  markers: tuple[str, str] | None) -> tuple[Any, int | None]:
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
              extractor: Callable[[str, ContextData | None, dict[str, Any] | None], Any] | None,
              dx: ContextData | None,
              node: dict[str, Any] | None) -> Any:
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


def extract_dt(dtstr: str,
               dx: ContextData | None,
               node: dict[str, Any] | None = None) -> Any:
    """ Extract dt expression

    :param dtstr: The dt expressions (string within ${}).
    :param dx: The context instance.
    :param node: The current node.
    :return: The value extracted.
    """
    try:
        return dx.get(dtstr, node) if dx else dtstr
    except Exception as err:
        demisto.debug(f'failed to extract dt from "{dtstr=}". Error: {err}')
        return None


def extract_value(source: Any,
                  dx: ContextData | None,
                  node: dict[str, Any] | None = None) -> Any:
    """ Extract value including dt expression

    :param source: The value to be extracted that may include dt expressions.
    :param dx: The demisto context.
    :param node: The current node.
    :return: The value extracted.
    """
    return Formatter('${', '}', False).build(source, extract_dt, dx, node)


def get_parent_child(root: dict, path: str) -> (
    tuple[tuple[None, None], tuple[None, None]] | tuple[tuple[dict, None], tuple[Any, str]] | tuple[tuple[Any, str],
tuple[Any, str]]):
    """ Get first and second level node

    :param root: The root node.
    :param path: The path to identify the leaf node.
    :return: (
      (
        parent node: The first level node in the hierarchy of the path
        parent path: The path based on the root node
      )
      (
        child node: The second level node in the hierarchy of the path
        child path: The path based on the parent node
      )
    )
    """
    res = Ddict.search(root, path)
    if res is None:
        if '.' not in path:
            return (None, None), (None, None)
        else:
            child = Ddict.get(root, path)
            return (root, None), (child, path)

    parent_name, parent_value, child_name = res
    if child_name:
        child_value = Ddict.get(parent_value, child_name)
        return (parent_value, parent_name), (child_value, child_name)
    else:
        return (root, None), (parent_value, parent_name)


class ExtFilter:
    def __init__(self, dx: ContextData):
        self.__dx = dx

    def __conds_iter(self, conds: list, node: Any) -> CondIterator:
        return CondIterator(conds, self.__dx, node)

    def __conds_items(self, conds: dict, node: Any) -> CondItemIterator:
        return CondItemIterator(conds, self.__dx, node)

    def __conds_extract_keys(
            self, conds: dict[str, Any], node: Any) -> dict[str, Any]:
        return {
            extract_value(k, self.__dx, node): v for k, v in conds.items()}

    def match_value(self, lhs: Any, optype: str, rhs: Any) -> bool:
        """ Matching with the conditional operator

        :param self: This instance.
        :param lhs: The left hand side value
        :param optype: The conditional operator
        :param rhs: The right hand side value
        :return: Return True if the lhs matches the rhs, otherwise False.
        """
        if optype == "is":
            if not isinstance(rhs, str):
                return False
            if rhs == "empty":
                return not bool(lhs)
            elif rhs == "null":
                return lhs is None
            elif rhs == "string":
                return isinstance(lhs, str)
            elif rhs == "integer":
                return isinstance(lhs, int)
            elif rhs == "integer string":
                try:
                    return isinstance(int(lhs, 10), int)
                except (ValueError, TypeError):
                    return False
            elif rhs == "any integer":
                try:
                    return isinstance(lhs, int) or\
                        isinstance(int(lhs, 10), int)
                except (ValueError, TypeError):
                    return False
            exit_error(f"Unknown operation filter: '{rhs}'")

        elif optype == "isn't":
            return not self.match_value(lhs, "is", rhs)

        elif optype == "===":
            rhs = self.parse_conds_json(rhs)
            try:
                return isinstance(lhs, type(rhs)) and lhs == rhs
            except (ValueError, TypeError):
                return False

        elif optype == "!==":
            rhs = self.parse_conds_json(rhs)
            try:
                return not isinstance(lhs, type(rhs)) or lhs != rhs
            except (ValueError, TypeError):
                return False

        elif optype in ("equals", "=="):
            try:
                if isinstance(lhs, int):
                    return lhs == int(rhs)
                elif isinstance(lhs, float):
                    return lhs == float(rhs)
                elif isinstance(lhs, str):
                    return lhs == str(rhs)
                else:
                    return lhs == rhs
            except (ValueError, TypeError):
                pass
            return False

        elif optype in ("doesn't equal", "!="):
            return not self.match_value(lhs, "equals", rhs)

        elif optype in ("greater or equal", ">="):
            try:
                return float(lhs) >= float(rhs)
            except (ValueError, TypeError):
                pass
            return False

        elif optype in ("greater than", ">"):
            try:
                return float(lhs) > float(rhs)
            except (ValueError, TypeError):
                pass
            return False

        elif optype in ("less or equal", "<="):
            try:
                return float(lhs) <= float(rhs)
            except (ValueError, TypeError):
                pass
            return False

        elif optype in ("less than", "<"):
            try:
                return float(lhs) < float(rhs)
            except (ValueError, TypeError):
                pass
            return False

        elif optype == "in":
            return lhs in listize(rhs)

        elif optype == "not in":
            return lhs not in listize(rhs)

        elif optype == "in caseless":
            return lower(lhs, True, True) in listize(lower(rhs, True, True))

        elif optype == "not in caseless":
            return lower(lhs, True, True) not in listize(lower(rhs, True, True))

        elif optype == "in range":
            if not isinstance(rhs, str):
                return False

            minmax = rhs.split(',')
            if len(minmax) != 2:
                exit_error(f'Invalid Range: {rhs}')

            try:
                lhs = float(lhs)
            except (ValueError, TypeError):
                return False
            return float(minmax[0]) <= lhs and lhs <= float(minmax[1])

        elif optype == "starts with":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.startswith(rhs)

        elif optype == "starts with caseless":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.lower().startswith(rhs.lower())

        elif optype == "doesn't start with":
            return not self.match_value(lhs, 'starts with', rhs)

        elif optype == "doesn't start with caseless":
            return not self.match_value(lhs, 'starts with caseless', rhs)

        elif optype == "ends with":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.endswith(rhs)

        elif optype == "ends with caseless":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.lower().endswith(rhs.lower())

        elif optype == "doesn't end with":
            return not self.match_value(lhs, 'ends with', rhs)

        elif optype == "doesn't end with caseless":
            return not self.match_value(lhs, 'ends with caseless', rhs)

        elif optype == "includes":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                rhs in lhs

        elif optype == "includes caseless":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                rhs.lower() in lower(lhs)

        elif optype == "doesn't include":
            return not self.match_value(lhs, 'includes', rhs)

        elif optype == "doesn't include caseless":
            return not self.match_value(lhs, 'includes caseless', rhs)

        elif optype == "matches":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs == rhs

        elif optype == "matches caseless":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.lower() == rhs.lower()

        elif optype == "doesn't match":
            return not self.match_value(lhs, 'matches', rhs)

        elif optype == "doesn't match caseless":
            return not self.match_value(lhs, 'matches caseless', rhs)

        elif optype == "wildcard: matches":
            return isinstance(rhs, str) and\
                match_pattern(rhs, lhs, False, PATALG_WILDCARD)

        elif optype == "wildcard: matches caseless":
            return isinstance(rhs, str) and\
                match_pattern(rhs, lhs, True, PATALG_WILDCARD)

        elif optype == "wildcard: doesn't match":
            return not isinstance(rhs, str) or\
                not match_pattern(rhs, lhs, False, PATALG_WILDCARD)

        elif optype == "wildcard: doesn't match caseless":
            return not isinstance(rhs, str) or\
                not match_pattern(rhs, lhs, True, PATALG_WILDCARD)

        elif optype == "regex: matches":
            return isinstance(rhs, str) and\
                match_pattern(rhs, lhs, False, PATALG_REGEX)

        elif optype == "regex: matches caseless":
            return isinstance(rhs, str) and\
                match_pattern(rhs, lhs, True, PATALG_REGEX)

        elif optype == "regex: doesn't match":
            return not isinstance(rhs, str) or\
                not match_pattern(rhs, lhs, False, PATALG_REGEX)

        elif optype == "regex: doesn't match caseless":
            return not isinstance(rhs, str) or\
                not match_pattern(rhs, lhs, True, PATALG_REGEX)

        elif optype == "in list":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs in rhs.split(',')

        elif optype == "in caseless list":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs.lower() in rhs.lower().split(',')

        elif optype == "not in list":
            return not self.match_value(lhs, "in list", rhs)

        elif optype == "not in caseless list":
            return not self.match_value(lhs, "in caseless list", rhs)

        elif optype == "matches any line of":
            return isinstance(rhs, str) and\
                isinstance(lhs, str) and\
                lhs in rhs.splitlines()

        elif optype == "matches any caseless line of":
            if not isinstance(rhs, str) or not isinstance(lhs, str):
                return False

            lhs = lhs.lower()
            return next(
                filter(
                    lambda x: isinstance(x, str) and x.lower() == lhs,
                    rhs.splitlines()),
                None) is not None

        elif optype == "doesn't match any line of":
            return not self.match_value(lhs, "matches any line of", rhs)

        elif optype == "doesn't match any caseless line of":
            return not self.match_value(
                lhs, "matches any caseless line of", rhs)

        elif optype == "matches any string of":
            if not isinstance(lhs, str):
                return False

            return lhs in listize(self.parse_conds_json(rhs))

        elif optype == "matches any caseless string of":
            if not isinstance(lhs, str):
                return False

            return next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_BINARY),
                    listize(self.parse_conds_json(rhs))),
                None) is not None

        elif optype == "doesn't match any string of":
            return not self.match_value(lhs, "matches any string of", rhs)

        elif optype == "doesn't match any caseless string of":
            return not self.match_value(
                lhs, "matches any caseless string of", rhs)

        elif optype == "wildcard: matches any string of":
            if not isinstance(lhs, str):
                return False

            return next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, False, PATALG_WILDCARD),
                    listize(self.parse_conds_json(rhs))),
                None) is not None

        elif optype == "wildcard: matches any caseless string of":
            if not isinstance(lhs, str):
                return False

            return next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_WILDCARD),
                    listize(self.parse_conds_json(rhs))),
                None) is not None

        elif optype == "wildcard: doesn't match any string of":
            return not self.match_value(
                lhs, "wildcard: matches any string of", rhs)

        elif optype == "wildcard: doesn't match any caseless string of":
            return not self.match_value(
                lhs, "wildcard: matches any caseless string of", rhs)

        elif optype == "regex: matches any string of":
            if not isinstance(lhs, str):
                return False

            return next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, False, PATALG_REGEX),
                    listize(self.parse_conds_json(rhs))),
                None) is not None

        elif optype == "regex: matches any caseless string of":
            if not isinstance(lhs, str):
                return False

            return next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_REGEX),
                    listize(self.parse_conds_json(rhs))),
                None) is not None

        elif optype == "regex: doesn't match any string of":
            return not self.match_value(
                lhs, "regex: matches any string of", rhs)

        elif optype == "regex: doesn't match any caseless string of":
            return not self.match_value(
                lhs, "regex: matches any caseless string of", rhs)

        else:
            exit_error(f"Unknown operation name: '{optype}'")
        return False

    def filter_with_expressions(self,
                                root: Any,
                                conds: dict | list,
                                path: str | None = None,
                                inlist: bool = False) -> Value | None:
        """ Filter the value with the conditions

        *** NOTE ***
        condition: root == 1 or ( root > 10 and root < 20 )
        expression:
        [
          {'==': 1},
          'or',
          {'>': 10, '<': 20}
        ]

        condition: root isn't integer or ( root == 1 or ( root > 10 and root < 20 ) )
        expression:
        [
          [
            {"isn't": 'integer'}
          ],
          'or',
          [
            {'==': 1},
            'or',
            {'>': 10, '<': 20}
          ]
        ]

        :param self: This instance.
        :param root: The value to filter.
        :param conds: The expressions to filter the value.
        :param path: The path to apply the conditions.
        :param inlist: True if `root` is an element in a list, False otherwise.
        :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        if isinstance(conds, dict):
            # AND conditions
            parent = None
            child = root
            if path:
                if isinstance(root, list):
                    return Value([v.value for v in [self.filter_with_expressions(
                        r, conds, path, True) for r in root] if v])
                elif not isinstance(root, dict):
                    return None
                (parent, parent_path), \
                    (child, child_name) = get_parent_child(root, path)
            else:
                child_name = ""
                parent_path = ""
                demisto.debug(f"{path=} -> {child_name=} {parent_path=}")

            for x in self.__conds_items(conds, root):
                coptype, cconds = x

                if coptype in ("is", "isn't") and \
                   isinstance(cconds, str) and cconds == "existing key":
                    if (coptype == "is") != bool(path and Ddict.get_value(root, path)):
                        return None
                else:
                    child = self.filter_value(
                        child, coptype, cconds, None, inlist and parent is None)
                    if not child:
                        return None
                    child = child.value

                if parent:
                    if isinstance(parent, dict):
                        if not isinstance(child_name, str):
                            exit_error('Internal error: no child_name')
                        else:
                            Ddict.set(parent, child_name, child)
                    else:
                        Ddict.set(root, parent_path, child)
                elif not path:
                    root = child

            return Value(root)

        elif isinstance(conds, list):
            # AND conditions by default
            ok, lop, neg = (None, None, None)
            for x in self.__conds_iter(conds, root):
                if isinstance(x, str):
                    if x == 'not':
                        neg = not neg
                    elif lop is None and neg is None:
                        lop = x
                    else:
                        exit_error('Invalid logical operators syntax')
                elif isinstance(x, dict | list):
                    val = None
                    if ok is None:
                        val = self.filter_with_expressions(
                            root, x, path, inlist)
                        ok = bool(val) ^ (neg or False)
                    elif lop is None or lop == 'and':
                        val = self.filter_with_expressions(
                            root, x, path, inlist)
                        ok = ok and (bool(val) ^ (neg or False))
                    elif lop == 'or':
                        val = self.filter_with_expressions(
                            root, x, path, inlist)
                        ok = ok or (bool(val) ^ (neg or False))
                    else:
                        exit_error(f'Invalid logical operator: {lop}')
                    lop, neg = (None, None)
                    root = val.value if val else root
                else:
                    exit_error(f'Invalid conditions format: {x}')
            return Value(root) if ok is None or ok else None
        else:
            exit_error(f'Invalid conditions format: {conds}')
        return None

    def filter_with_conditions(
            self, root: Any, conds: dict | list) -> Value | None:
        """ Filter the value with the conditions

        *** NOTE ***
        expression for 'conds':
        [
          {
            "path1": <expression> for filter_with_expressions(),
            "path2": <expression> for filter_with_expressions()
            :
          }
          'or',
          [
            'not',
            {
              "path3": <expression> for filter_with_expressions(),
              "path4": <expression> for filter_with_expressions()
              :
            },
            'or',
            {
              "path5": <expression> for filter_with_expressions(),
              "path6": <expression> for filter_with_expressions()
              :
            }
          }
        ]

        :param self: This instance.
        :param root: The value to filter.
        :param conds: The condition expression to filter the value.
        :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        if isinstance(conds, dict):
            # AND conditions
            for x in self.__conds_items(conds, root):
                if len(x) < 2 or isinstance(x[0], dict | list):
                    exit_error(f'Invalid conditions format: {x}')

                root = self.filter_with_expressions(root, x[1], x[0])
                if not root:
                    return None
                root = root.value
            return Value(root)
        elif isinstance(conds, list):
            # AND conditions by default
            ok, lop, neg = (None, None, None)
            for x in self.__conds_iter(conds, root):
                if isinstance(x, str):
                    if x == 'not':
                        neg = not neg
                    elif lop is None and neg is None:
                        lop = x
                    else:
                        exit_error('Invalid logical operators syntax')
                elif isinstance(x, dict | list):
                    val = None
                    if ok is None:
                        val = self.filter_with_conditions(root, x)
                        ok = bool(val) ^ (neg or False)
                    elif lop is None or lop == 'and':
                        val = self.filter_with_conditions(root, x)
                        ok = ok and (bool(val) ^ (neg or False))
                    elif lop == 'or':
                        val = self.filter_with_conditions(root, x)
                        ok = ok or (bool(val) ^ (neg or False))
                    else:
                        exit_error(f'Invalid logical operator: {lop}')
                    lop, neg = (None, None)
                    root = val.value if val else root
                else:
                    exit_error(f'Invalid conditions format: {x}')
            return Value(root) if ok is None or ok else None
        else:
            exit_error(f'Invalid conditions format: {conds}')
        return None

    def filter_values(
            self,
            root: list[Any],
            optype: str,
            conds: Any,
            path: str | None = None) -> Value | None:
        """ Filter values of a list with the conditions

        :param self: This instance.
        :param root: The values to filter.
        :param optype: The conditional operator.
        :param conds: The condition expression to filter the value.
        :param path: The path to apply the conditions.
        :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        return Value([v.value for v in
                      [self.filter_value(r, optype, conds, path, True) for r in root] if v])

    def filter_value(
            self,
            root: Any,
            optype: str,
            conds: Any,
            path: str | None = None,
            inlist: bool = False) -> Value | None:
        """ Filter the value with the conditions

        :param self: This instance.
        :param root: The value to filter.
        :param optype: The conditional operator.
        :param conds: The condition expression to filter the value.
        :param path: The path to apply the conditions.
        :param inlist: True if `root` is an element in a list, False otherwise.
        :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        if optype == "abort":
            exit_error(
                f"ABORT: value = {root}, conds = {conds}, path = {path}")

        elif optype == "is collectively transformed with":
            return self.filter_value(root, "is transformed with", conds, path, True)

        elif optype == "is transformed with":
            conds = listize(self.parse_conds_json(conds))

            for operation in self.__conds_iter(conds, root):
                if not isinstance(operation, dict):
                    exit_error(f'Invalid condition format: {operation}')

                for k, v in self.__conds_items(operation, root):
                    value = self.filter_value(root, k, v, path, inlist)
                    root = None if value is None else value.value

            return Value(root)

        elif optype == "is filtered with":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            if path:
                conds = {"matches conditions of": self.parse_conds_json(conds)}
                if isinstance(root, dict):
                    return self.filter_with_expressions(
                        root, conds, path, inlist)
                else:
                    return None
            else:
                return self.filter_value(root, "matches conditions of", conds)

        elif optype == "value is filtered with":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if path:
                conds = {"value matches expressions of": conds}
                if isinstance(root, dict):
                    v = {
                        k: v for k, f, v in [
                            (k,
                             self.filter_with_expressions(
                                 v,
                                 conds,
                                 path,
                                 False),
                                v) for k,
                            v in root.items()] if f and f.value}
                    return Value(v) if v else None
                else:
                    return self.filter_with_expressions(
                        root, conds, path, inlist)
            else:
                if isinstance(root, dict):
                    v = {
                        k: v for k, f, v in [
                            (k,
                             self.filter_with_expressions(
                                 v,
                                 conds,
                                 None,
                                 False),
                                v) for k,
                            v in root.items()] if f and f.value}
                    return Value(v) if v else None
                else:
                    return self.filter_with_expressions(
                        root, conds, None, inlist)

        elif optype in ("is", "isn't"):
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            if isinstance(conds, str) and conds == "existing key":
                if (optype == "is") == bool(path and Ddict.get_value(root, path)):
                    return Value(root)
                return None

        if path:
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = {optype: self.parse_conds_json(conds)}
            if isinstance(root, dict | list):
                return self.filter_with_expressions(root, conds, path, inlist)
            else:
                return None

        elif optype == "if-then-else":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if not isinstance(conds, dict):
                exit_error(f"Invalid conditions: {conds}")

            conds = self.__conds_extract_keys(conds, root)

            lconds = conds.get("if")
            if lconds:
                lhs = conds.get("lhs")
                if lhs is None:
                    lhs = copy.deepcopy(root)
                else:
                    lhs = self.parse_and_extract_conds_json(lhs, root)

                lconds = self.parse_conds_json(lconds)
                if not isinstance(lconds, dict | list):
                    exit_error(f"Invalid conditions: {lconds}")

                elif self.filter_with_expressions(lhs, lconds, path, inlist) is None:
                    lconds = conds.get("else")
                else:
                    lconds = conds.get("then")
            else:
                lconds = conds.get("then")

            if lconds:
                lconds = self.parse_conds_json(lconds)
                if not isinstance(lconds, dict | list):
                    exit_error(f"Invalid conditions: {lconds}")

                return self.filter_with_expressions(root, lconds, path, inlist)
            else:
                return Value(root)

        elif optype == "switch-case":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if not isinstance(conds, dict):
                exit_error(f"Invalid conditions: {conds}")

            conds = self.__conds_extract_keys(conds, root)

            label = "default"
            lconds = conds.get("switch")
            if lconds:
                for lexps in iterate_value(self.parse_conds_json(lconds)):
                    if not isinstance(lexps, dict):
                        exit_error(f"Invalid conditions: {lexps}")

                    for k, v in lexps.items():
                        if not isinstance(v, dict):
                            exit_error(f"Invalid conditions: {lconds}")

                        if self.filter_with_expressions(root, v, path, inlist):
                            label = k
                            break
                    else:
                        continue
                    break

            lconds = conds.get(label)
            if lconds:
                lconds = self.parse_conds_json(lconds)
                if not isinstance(lconds, dict | list):
                    exit_error(f"Invalid conditions: {lconds}")

                return self.filter_with_expressions(root, lconds, path, inlist)
            else:
                return Value(root)

        elif optype == "keeps":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if not isinstance(root, dict) and not isinstance(conds, list):
                return None

            return Value({k: v for k, v in root.items()
                          if k in list(self.__conds_iter(conds, v))})

        elif optype == "doesn't keep":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if not isinstance(root, dict) or not isinstance(conds, list):
                return None

            return Value({k: v for k, v in root.items() if k not in list(self.__conds_iter(conds, v))})

        elif optype == "matches expressions of":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            return self.filter_with_expressions(root, conds, path, inlist)

        elif optype == "matches conditions of":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            return self.filter_with_conditions(root, conds)

        elif optype == "value matches expressions of":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if isinstance(root, dict):
                v = {
                    k: v.value for k, v in {
                        k: self.filter_with_expressions(
                            v,
                            conds,
                            None,
                            False) for k,
                        v in root.items()}.items() if v}
                return Value(v) if v else None
            else:
                return self.filter_with_expressions(root, conds, None, inlist)

        elif optype == "value matches conditions of":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            conds = self.parse_conds_json(conds)
            if isinstance(root, dict):
                v = {k: v.value
                     for k, v in
                     {k: self.filter_with_conditions(v, conds)
                      for k, v in root.items()}.items() if v}
                return Value(v) if v else None
            else:
                return self.filter_with_conditions(root, conds)

        elif optype == "collects values":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            if isinstance(root, list | dict):
                return Value(list(iterate_value(root, ITERATE_VALUE)))
            else:
                return Value(root)

        elif optype == "collects keys":
            if not inlist and isinstance(root, list):
                return self.filter_values(root, optype, conds, path)

            if isinstance(root, list | dict):
                return Value(list(iterate_value(root, ITERATE_KEY)))
            else:
                return None

        elif optype == "flattens with values":
            if isinstance(root, list | dict):
                return Value(
                    list(iterate_value(root, ITERATE_VALUE, True)))
            else:
                return Value(root)

        elif optype == "flattens with keys":
            if isinstance(root, list | dict):
                return Value(
                    list(iterate_value(root, ITERATE_KEY, True)))
            else:
                return None

        """
        Filter for an entire value
        """
        if optype == "finds":
            rhs = self.extract_value(conds, root)
            lhs = root
            ok = False
            try:
                if isinstance(rhs, str):
                    if isinstance(lhs, list):
                        ok = any(isinstance(v, str) and rhs in v
                                 for v in lhs)
                    elif isinstance(lhs, str):
                        ok = rhs in lhs
            except (ValueError, TypeError):
                pass
            return Value(root) if ok else None

        elif optype == "finds caseless":
            rhs = self.extract_value(conds, root)
            lhs = root
            ok = False
            try:
                if isinstance(rhs, str):
                    if isinstance(lhs, list):
                        ok = any(isinstance(v, str) and rhs.lower() in v
                                 for v in lower(lhs))
                    elif isinstance(lhs, str):
                        ok = rhs.lower() in lower(lhs)
            except (ValueError, TypeError):
                pass
            return Value(root) if ok else None

        elif optype == "doesn't find":
            if not self.filter_value(root, "finds", conds, path):
                return Value(root)
            else:
                return None

        elif optype == "doesn't find caseless":
            if not self.filter_value(root, "finds caseless", conds):
                return Value(root)
            else:
                return None

        elif optype == "contains":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if rhs in lhs:
                return Value(root)
            else:
                return None

        elif optype == "contains caseless":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if lower(rhs, True, True) in lower(lhs, True, True):
                return Value(root)
            else:
                return None

        elif optype == "doesn't contain":
            if not self.filter_value(root, "contains", conds):
                return Value(root)
            else:
                return None

        elif optype == "doesn't contain caseless":
            if not self.filter_value(root, "contains caseless", conds):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: contains":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if isinstance(rhs, str) and\
                    match_pattern(rhs, lhs, False, PATALG_WILDCARD):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: contains caseless":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if isinstance(rhs, str) and\
                    match_pattern(rhs, lhs, True, PATALG_WILDCARD):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: doesn't contain":
            if not self.filter_value(root, "wildcard: contains", conds):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: doesn't contain caseless":
            if not self.filter_value(
                    root, "wildcard: contains caseless", conds):
                return Value(root)
            else:
                return None

        elif optype == "regex: contains":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if isinstance(rhs, str) and\
                    match_pattern(rhs, lhs, False, PATALG_REGEX):
                return Value(root)
            else:
                return None

        elif optype == "regex: contains caseless":
            rhs = self.extract_value(conds, root)
            lhs = listize(root)
            if isinstance(rhs, str) and\
                    match_pattern(rhs, lhs, True, PATALG_REGEX):
                return Value(root)
            else:
                return None

        elif optype == "regex: doesn't contain":
            if not self.filter_value(root, "regex: contains", conds):
                return Value(root)
            else:
                return None

        elif optype == "regex: doesn't contain caseless":
            if not self.filter_value(root, "regex: contains caseless", conds):
                return Value(root)
            else:
                return None

        elif optype == "contains any line of":
            rhs = self.extract_value(conds, root)
            lhs = root
            if isinstance(rhs, str) and\
                    any(self.filter_value(lhs, "contains", x)
                        for x in rhs.splitlines()):
                return Value(root)
            else:
                return None

        elif optype == "contains any caseless line of":
            rhs = self.extract_value(conds, root)
            lhs = root
            if isinstance(rhs, str) and\
                any(self.filter_value(lhs, "contains caseless", x)
                    for x in rhs.splitlines()):
                return Value(root)
            else:
                return None

        elif optype == "doesn't contain any line of":
            if not self.filter_value(root, "contains any line of", conds):
                return Value(root)
            else:
                return None

        elif optype == "doesn't contain any caseless line of":
            if not self.filter_value(
                    root, "contains any caseless line of", conds):
                return Value(root)
            else:
                return None

        elif optype == "contains any string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = listize(root)
            if next(filter(lambda r: isinstance(r, str) and r in lhs, rhs), None):
                return Value(root)
            else:
                return None

        elif optype == "contains any caseless string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = root
            if next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_BINARY),
                    rhs),
                    None):
                return Value(root)
            else:
                return None

        elif optype == "doesn't contain any string of":
            return Value(root) if not self.filter_value(
                root, "contains any string of", conds) else None

        elif optype == "doesn't contain any caseless string of":
            return Value(root) if not self.filter_value(
                root, "contains any caseless string of", conds) else None

        elif optype == "wildcard: contains any string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = root
            if next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, False, PATALG_WILDCARD),
                    rhs),
                    None):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: contains any caseless string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = root
            if next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_WILDCARD),
                    rhs),
                    None):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: doesn't contain any string of":
            if not self.filter_value(
                    root, "wildcard: contains any string of", conds):
                return Value(root)
            else:
                return None

        elif optype == "wildcard: doesn't contain any caseless string of":
            if not self.filter_value(
                root,
                "wildcard: contains any caseless string of",
                    conds):
                return Value(root)
            else:
                return None

        elif optype == "regex: contains any string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = root
            if next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, False, PATALG_REGEX),
                    rhs),
                    None):
                return Value(root)
            else:
                return None

        elif optype == "regex: contains any caseless string of":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = root
            if next(
                filter(
                    lambda r:
                        isinstance(r, str)
                        and match_pattern(r, lhs, True, PATALG_REGEX),
                    rhs),
                    None):
                return Value(root)
            else:
                return None

        elif optype == "regex: doesn't contain any string of":
            if not self.filter_value(
                    root, "regex: contains any string of", conds):
                return Value(root)
            else:
                return None

        elif optype == "regex: doesn't contain any caseless string of":
            if not self.filter_value(
                    root, "regex: contains any caseless string of", conds):
                return Value(root)
            else:
                return None

        elif optype == "is replaced with":
            return Value(self.parse_and_extract_conds_json(conds, root))

        elif optype == "is updated with":
            rhs = self.parse_and_extract_conds_json(conds, root)
            lhs = root
            if isinstance(lhs, dict) and isinstance(rhs, dict):
                lhs.update(copy.deepcopy(rhs))
            elif isinstance(lhs, list) and len(lhs) == 1 and isinstance(lhs[0], dict):
                lhs[0].update(copy.deepcopy(rhs))
            else:
                lhs = rhs
            return Value(lhs)

        elif optype == "appends":
            rhs = listize(self.parse_and_extract_conds_json(conds, root))
            lhs = listize(root)
            lhs.extend(rhs)
            return Value(lhs)

        elif optype == "json: encode array":
            params = self.parse_and_extract_conds_json(conds, root)
            indent = params.get("indent")
            return Value(json.dumps(
                root, indent=None if indent is None else int(indent)))

        """
        Filter for individual values
        """
        if not inlist and isinstance(root, list):
            return self.filter_values(root, optype, conds)

        """
        Filter for single value
        """
        if optype == "json: encode":
            params = self.parse_and_extract_conds_json(conds, root)
            indent = params.get('indent')
            return Value(
                json.dumps(
                    root, indent=None if indent is None else int(indent)))

        elif optype == "json: decode":
            return Value(json.loads(str(root)))

        elif optype == "base64: encode":
            return Value(
                base64.b64encode(
                    str(root).encode('utf-8')).decode('utf-8'))

        elif optype == "base64: decode":
            return Value(base64.b64decode(root.encode('utf-8')
                                          ).decode('utf-8', errors='ignore'))

        elif optype == "digest":
            params = self.parse_and_extract_conds_json(conds, root)
            return Value(
                hashdigest(str(root), str(params.get('algorithm', 'sha256'))))

        elif optype == "email-header: decode":
            lhs = root
            out = ''
            try:
                for decoded_s, encoding in decode_header(str(lhs)):
                    if encoding:
                        out += decoded_s.decode(encoding)
                    elif isinstance(decoded_s, bytes):
                        out += decoded_s.decode('utf-8')
                    else:
                        out += decoded_s
            except Exception:
                demisto.debug(
                    f'Failed to decode by `email-header: decode`: {lhs}')
                out = str(lhs)
            return Value(out)

        elif optype == "regex: replace":
            params = self.parse_and_extract_conds_json(conds, root)
            lhs = root

            pattern = params['pattern']
            matched = params['matched']
            flags = 0
            flags |= re.IGNORECASE if argToBoolean(params.get('caseless', False)) else 0
            flags |= re.MULTILINE if argToBoolean(params.get('multiline', False)) else 0
            flags |= re.DOTALL if argToBoolean(params.get('dotall', False)) else 0
            match = re.fullmatch(pattern, str(lhs), flags=flags)
            if not match:
                return Value(
                    params['unmatched'] if 'unmatched' in params else lhs)
            elif isinstance(matched, str):
                return Value(match.expand(matched.replace(r'\0', r'\g<0>')))
            else:
                return Value(matched)

        elif optype == "is individually transformed with":
            return self.filter_value(root, "is transformed with", conds)

        """
        Filter for single value (boolean evaluation)
        """
        rhs = self.extract_value(conds, root)
        return Value(root) if self.match_value(root, optype, rhs) else None

    def extract_value(self, source: Any, node: Any) -> Any:
        """ Extract value including dt expression

        :param self: This instance.
        :param source: The value to be extracted that may include dt expressions.
        :param node: The current node.
        :return: The value extracted.
        """
        return extract_value(source, self.__dx, node)

    def parse_conds_json(
            self,
            jstr: str) -> Any:
        """ parse a json string

        :param self: This instance.
        :param jstr: A json string.
        :return: The value extracted.
        """
        if not isinstance(jstr, str):
            return jstr
        try:
            return json.loads(jstr)
        except json.JSONDecodeError:
            return jstr

    def parse_and_extract_conds_json(
            self,
            jstr: str,
            node: Any) -> Any:
        """ parse a json string and extract value

        :param self: This instance.
        :param jstr: A json string.
        :param node: The current node.
        :return: The value extracted.
        """
        return extract_value(self.parse_conds_json(jstr), self.__dx, node)


def main():
    args = demisto.args()
    try:
        value = args['value']
        path = args.get('path', '')
        optype = args['operation']
        conds = args['filter']

        # Setup demisto context
        dx = args.get('ctx_demisto')
        if dx and isinstance(dx, str):
            dx = json.loads(dx)
        elif not dx:
            dx = value if isinstance(value, dict) else None
        dx = ContextData(
            demisto=dx,
            inputs=args.get('ctx_inputs'),
            lists=args.get('ctx_lists'),
            incident=args.get('ctx_incident'),
            local=value)

        # Extract value
        xfilter = ExtFilter(dx)
        value = xfilter.filter_value(value, optype, conds, path)
        value = value.value if value else None
        value = marshal(value)
        value = value if value is not None else []
        value = value if isinstance(value, list) else [value]
    except Exception as err:
        raise err

    demisto.results(value)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
