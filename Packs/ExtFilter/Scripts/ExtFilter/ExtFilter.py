import fnmatch
import json
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PATALG_BINARY = 0
PATALG_WILDCARD = 1
PATALG_REGEX = 2


class Value:
    def __init__(self, value: Any):
        self.value = value


class Ddict(dict):
    def __search(self, val: Union[Dict[str, Any], List[Dict[str, Any]]], comps: List[str]) -> Optional[Tuple[str, Any, List[str]]]:
        for i in range(len(comps), 0, -1):
            key = '.'.join(comps[:i])

            if isinstance(val, list):
                if True not in {key in v if v else False for v in val}:
                    v = None
                else:
                    v = Value([v.get(key) if v else None for v in val])
            elif val == self:
                v = Value(dict.get(self, key)) if key in val else None
            else:
                v = Value(val.get(key)) if key in val else None

            if v is not None:
                return (key, v.value, comps[i:])

        return None

    def search(self, path: str) -> Optional[Tuple[str, Any, str]]:
        res = self.__search(self, path.split('.'))
        if res is None:
            return None
        return (res[0], res[1], '.'.join(res[2]))

    def getValue(self, path: [str]) -> Optional[Value]:
        val = None
        comps = path.split('.')
        while comps:
            res = self.__search(self if val is None else val, comps)
            if res is None:
                return None
            _, val, comps = res

        return None if val is None else Value(val)

    def get(self, path: [str]) -> Any:
        val = self.getValue(path)
        return val.value if val else None


class ContextData:
    def __init__(self, demisto: Optional[Dict[str, Any]] = None, inputs: Optional[Dict[str, Any]] = None, lists: Optional[Dict[str, Any]] = None, incident: Optional[Dict[str, Any]] = None):
        self.__demisto = demisto
        self.__specials = {
            'inputs': inputs if isinstance(inputs, dict) else {},
            'lists': lists if isinstance(lists, dict) else {},
            'incident': incident if isinstance(incident, dict) else {}
        }

    def get(self, key: Optional[str] = None) -> Any:
        """ Get the context value for the key

          :param key: The dt expressions (string within ${}).
          :return: The value.
        """
        if key is not None:
            dx = self.__demisto
            for prefix in ['inputs', 'lists', 'incident']:
                if key.startswith(prefix + '.'):
                    key = key[len(prefix):]
                    dx = self.__specials.get(prefix)
                    break
            if dx is not None:
                return demisto.dt(dx, key)
        return None


def exit_error(err_msg: str):
    raise RuntimeError(err_msg)


def lower(value: [Any]) -> Any:
    if isinstance(value, list):
        return [lower(v) for v in value]
    elif isinstance(value, str):
        return value.lower()
    else:
        return value


def match_pattern(pattern: str, value: Any, caseless: bool, patalg: int) -> bool:
    """ Pattern matching

      :param pattern: The pattern string.
      :param value: The value to compare with the pattern.
      :param caseless: True if the pattern matching take places in case insensitive, otherwise False.
      :param patalg: The pattern matching algorithm. Spefify any of PATALG_BINARY, PATALG_WILDCARD and PATALG_REGEX.
      :return: Return True if the value matches the pattern, otherwise False.
    """
    if patalg == PATALG_BINARY:
        if caseless:
            value = lower(value)
            pattern = pattern.lower()

        if isinstance(value, list):
            return pattern in value
        elif isinstance(value, str):
            return pattern == value
        return False

    elif patalg == PATALG_WILDCARD:
        if caseless:
            value = lower(value)
            pattern = pattern.lower()

        if isinstance(value, list):
            for v in value:
                if isinstance(v, str) and fnmatch.fnmatchcase(v, pattern):
                    return True
        elif isinstance(value, str):
            return fnmatch.fnmatchcase(value, pattern)
        return False

    elif patalg == PATALG_REGEX:
        flags = re.IGNORECASE if caseless else 0

        if isinstance(value, list):
            for v in value:
                if isinstance(v, str) and re.fullmatch(pattern, v, flags) is not None:
                    return True
        elif isinstance(value, str):
            return re.fullmatch(pattern, value, flags) is not None
        return False
    else:
        exit_error('Unknown pattern algorithm: {}'.format(patalg))


def match_value(lhs: Any, optype: str, rhs: Any) -> bool:
    """ Matching by the conditional operator

      :param lhs: The left hand side value
      :param optype: The conditional operator
      :param rhs: The right hand side value
      :return: Return True if the lhs matches the rhs, otherwise False.
    """
    if optype == "is":
        if not isinstance(rhs, str):
            return False
        if rhs == "empty":
            return bool(lhs)
        elif rhs == "null":
            return lhs is None
        elif rhs == "string":
            return isinstance(lhs, str)
        elif rhs == "integer":
            return isinstance(lhs, int)
        elif rhs == "integer string":
            try:
                return isinstance(int(lhs, 10), int)
            except:
                return False
        elif rhs == "any integer":
            try:
                return isinstance(lhs, int) or isinstance(int(lhs, 10), int)
            except:
                return False
        exit_error('Unknown operation filter: {}'.format(rhs))

    elif optype == "isn't":
        return not match_value(lhs, "is", rhs)

    elif optype == "===":
        return type(lhs) == type(rhs) and lhs == rhs

    elif optype == "!==":
        return type(lhs) != type(rhs) or lhs != rhs

    elif optype in ("equals", "=="):
        try:
            if isinstance(lhs, int):
                return lhs == int(rhs)
            elif isinstance(lhs, float):
                return lhs == float(rhs)
            elif isinstance(lhs, str):
                return lhs == rhs
        except ValueError:
            return False

    elif optype in ("doesn't equal", "!="):
        return not match_value(lhs, "equals", rhs)

    elif optype in ("greater or equal", ">="):
        return isinstance(lhs, (int, float)) and lhs >= float(rhs)

    elif optype in ("greater than", ">"):
        return isinstance(lhs, (int, float)) and lhs > float(rhs)

    elif optype in ("less or equal", "<="):
        return isinstance(lhs, (int, float)) and lhs <= float(rhs)

    elif optype in ("less than", "<"):
        return isinstance(lhs, (int, float)) and lhs < float(rhs)

    elif optype == "in range":
        if not isinstance(rhs, str):
            return False

        range = rhs.split(',')
        if len(range) != 2:
            exit_error('Invalid Range: {}'.format(rhs))
        try:
            lhs = float(lhs)
        except ValueError:
            return False
        return float(range[0]) <= lhs and lhs <= float(range[1])

    elif optype == "starts with":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs.startswith(rhs)

    elif optype == "starts with caseless":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs.lower().startswith(rhs.lower())

    elif optype == "doesn't start with":
        return not match_value(lhs, 'starts with', rhs)

    elif optype == "doesn't start with caseless":
        return not match_value(lhs, 'starts with caseless', rhs)

    elif optype == "ends with":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs.endswith(rhs)

    elif optype == "ends with caseless":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs.lower().endswith(rhs.lower())

    elif optype == "doesn't end with":
        return not match_value(lhs, 'ends with', rhs)

    elif optype == "doesn't end with caseless":
        return not match_value(lhs, 'ends with caseless', rhs)

    elif optype == "includes":
        return isinstance(rhs, str) and isinstance(lhs, str) and rhs in lhs

    elif optype == "includes caseless":
        return isinstance(rhs, str) and isinstance(lhs, str) and rhs.lower() in lower(lhs)

    elif optype == "doesn't include":
        return not match_value(lhs, 'includes', rhs)

    elif optype == "doesn't include caseless":
        return not match_value(lhs, 'includes caseless', rhs)

    elif optype == "finds":
        try:
            if isinstance(lhs, list):
                return any(isinstance(v, str) and rhs in v for v in lhs)
            elif isinstance(lhs, str):
                return rhs in lhs
        except:
            return False

    elif optype == "finds caseless":
        try:
            if isinstance(lhs, list):
                return any(isinstance(v, str) and rhs.lower() in v for v in lower(lhs))
            elif isinstance(lhs, str):
                return rhs.lower() in lower(lhs)
        except:
            return False

    elif optype == "doesn't find":
        return not match_value(lhs, 'finds', rhs)

    elif optype == "doesn't find caseless":
        return not match_value(lhs, 'finds caseless', rhs)

    elif optype == "matches":
        return isinstance(lhs, str) and lhs == rhs

    elif optype == "matches caseless":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs.lower() == rhs.lower()

    elif optype == "doesn't match":
        return not match_value(lhs, 'matches', rhs)

    elif optype == "doesn't match caseless":
        return not match_value(lhs, 'matches caseless', rhs)

    elif optype == "matches wildcard":
        return isinstance(rhs, str) and isinstance(lhs, str) and fnmatch.fnmatchcase(lhs, rhs)

    elif optype == "matches caseless wildcard":
        return isinstance(rhs, str) and isinstance(lhs, str) and fnmatch.fnmatchcase(lhs.lower(), rhs.lower())

    elif optype == "doesn't match wildcard":
        return not match_value(lhs, 'matches wildcard', rhs)

    elif optype == "doesn't match caseless wildcard":
        return not match_value(lhs, 'matches caseless wildcard', rhs)

    elif optype == "matches regex":
        return isinstance(rhs, str) and isinstance(lhs, str) and re.fullmatch(rhs, lhs)

    elif optype == "matches caseless regex":
        return isinstance(rhs, str) and isinstance(lhs, str) and re.fullmatch(rhs, lhs, re.IGNORECASE)

    elif optype == "doesn't match regex":
        return not match_value(lhs, 'matches regex', rhs)

    elif optype == "doesn't match caseless regex":
        return not match_value(lhs, 'matches caseless regex', rhs)

    elif optype == "in list":
        return isinstance(rhs, str) and isinstance(lhs, str) and lhs in rhs.split(',')

    elif optype == "in caseless list":
        return isinstance(rhs, str) and isinstance(lhs, str) and lower(lhs) in rhs.lower().split(',')

    elif optype == "not in list":
        return not match_value(lhs, 'in list', rhs)

    elif optype == "not in caseless list":
        return not match_value(lhs, 'in caseless list', rhs)

    elif optype == "contains":
        return isinstance(rhs, str) and isinstance(lhs, (str, list)) and rhs in lhs

    elif optype == "contains caseless":
        return isinstance(rhs, str) and isinstance(lhs, (str, list)) and lower(rhs) in lower(lhs)

    elif optype == "doesn't contain":
        return not match_value(lhs, 'contain', rhs)

    elif optype == "doesn't contain caseless":
        return not match_value(lhs, 'contain caseless', rhs)

    elif optype == "contains any match with wildcard":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, False, PATALG_WILDCARD)

    elif optype == "contains any match with caseless wildcard":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, True, PATALG_WILDCARD)

    elif optype == "doesn't contain any match with wildcard":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, False, PATALG_WILDCARD)

    elif optype == "doesn't contain any match with caseless wildcard":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, True, PATALG_WILDCARD)

    elif optype == "contains any match with regex":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, False, PATALG_REGEX)

    elif optype == "contains any match with caseless regex":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, True, PATALG_REGEX)

    elif optype == "doesn't contain any match with regex":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, False, PATALG_REGEX)

    elif optype == "doesn't contain any match with caseless regex":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, True, PATALG_REGEX)

    elif optype == "matches wildcard":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, False, PATALG_WILDCARD)

    elif optype == "matches caseless wildcard":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, True, PATALG_WILDCARD)

    elif optype == "doesn't match wildcard":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, False, PATALG_WILDCARD)

    elif optype == "doesn't match caseless wildcard":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, True, PATALG_WILDCARD)

    elif optype == "matches regex":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, False, PATALG_REGEX)

    elif optype == "matches caseless regex":
        return isinstance(rhs, str) and match_pattern(rhs, lhs, True, PATALG_REGEX)

    elif optype == "doesn't match regex":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, False, PATALG_REGEX)

    elif optype == "doesn't match caseless regex":
        return not isinstance(rhs, str) or not match_pattern(rhs, lhs, True, PATALG_REGEX)

    elif optype == "matches any string of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and x == lhs for x in rhs)
        elif isinstance(rhs, str):
            return any(match_value(lhs, "contains", x) for x in rhs.split(','))
        else:
            return False

    elif optype == "matches any caseless string of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and lower(x) == lower(lhs) for x in rhs)
        elif isinstance(rhs, str):
            return any(match_value(lhs, "contains caseless", x) for x in rhs.split(','))
        else:
            return False

    elif optype == "doesn't match any string of":
        return not match_value(lhs, "matches any string of", rhs)

    elif optype == "doesn't match any caseless string of":
        return not match_value(lhs, "matches any caseless string of", rhs)

    elif optype == "matches any line of":
        if not isinstance(rhs, str):
            return False
        return any(match_value(lhs, "contains", x) for x in rhs.splitlines())

    elif optype == "matches any caseless line of":
        if not isinstance(rhs, str):
            return False
        return any(match_value(lhs, "contains caseless", x) for x in rhs.splitlines())

    elif optype == "doesn't match any line of":
        return not match_value(lhs, "matches any line of", rhs)

    elif optype == "doesn't match any caseless line of":
        return not match_value(lhs, "matches any caseless line of", rhs)

    elif optype == "matches any wildcard of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and match_pattern(x, lhs, False, PATALG_WILDCARD) for x in rhs)
        elif isinstance(rhs, str):
            return any(match_pattern(x, lhs, False, PATALG_WILDCARD) for x in rhs.split(','))
        else:
            return False

    elif optype == "matches any caseless wildcard of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and match_pattern(x, lhs, True, PATALG_WILDCARD) for x in rhs)
        elif isinstance(rhs, str):
            return any(match_pattern(x, lhs, True, PATALG_WILDCARD) for x in rhs.split(','))
        else:
            return False

    elif optype == "doesn't match any wildcard of":
        return not match_value(lhs, "matches any wildcard of", rhs)

    elif optype == "doesn't match any caseless wildcard of":
        return not match_value(lhs, "matches any caseless wildcard of", rhs)

    elif optype == "matches any regex of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and match_pattern(x, lhs, False, PATALG_REGEX) for x in rhs)
        elif isinstance(rhs, str):
            return any(match_pattern(x, lhs, False, PATALG_REGEX) for x in rhs.split(','))
        else:
            return False

    elif optype == "matches any caseless regex of":
        if isinstance(rhs, list):
            return any(isinstance(x, str) and match_pattern(x, lhs, True, PATALG_REGEX) for x in rhs)
        elif isinstance(rhs, str):
            return any(match_pattern(x, lhs, True, PATALG_REGEX) for x in rhs.split(','))
        else:
            return False

    elif optype == "doesn't match any regex of":
        return not match_value(lhs, "matches any regex of", rhs)

    elif optype == "doesn't match any caseless regex of":
        return not match_value(lhs, "matches any caseless regex of", rhs)

    else:
        raise RuntimeError('Unknown operation name: {}'.format(optype))
    return False


def extract_value(source: Any, extractor: Callable[[str, Optional[Dict[str, Any]]], Any], dx: Optional[ContextData]) -> Any:
    """ Extract value including dt expression

      :param source: The value to be extracted that may include dt expressions.
      :param extractor: The extractor to get real value within ${dt}.
      :param dx: The demisto context.
      :return: The value extracted.
    """
    def _extract(source: str, extractor: Optional[Callable[[str, Optional[Dict[str, Any]]], Any]], dx: Optional[Dict[str, Any]], si: int, endc: Optional[str]) -> [str, int]:
        val = ''
        ci = si
        while ci < len(source):
            if endc is not None and source[ci] == endc:
                if not extractor:
                    return ci + len(endc)
                xval = extractor(source[si:ci], dx)
                val += str(xval) if xval is not None else ''
                si = ci = ci + len(endc)
                endc = None
            else:
                nextec = {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'"}.get(source[ci])
                if nextec:
                    ci = _extract(source, None, dx, ci + 1, nextec)
                elif extractor and source[ci:ci + 2] == '${':
                    val += source[si:ci]
                    si = ci = ci + 2
                    endc = '}'
                elif source[ci] == '\\':
                    ci += 2
                else:
                    ci += 1
        return val + source[si:] if extractor else ci

    if isinstance(source, dict):
        return {extract_value(k, extractor, dx): extract_value(v, extractor, dx) for k, v in source.items()}
    elif isinstance(source, list):
        return [extract_value(v, extractor, dx) for v in source]
    elif isinstance(source, str):
        if source.startswith('${') and source.endswith('}'):
            return extractor(source[2:-1], dx)
        else:
            return _extract(source, extractor, dx, 0, None)
    else:
        return source


def extract_dt(dtstr: str, dx: Optional[ContextData]) -> Any:
    """ Extract dt expression

      :param dtstr: The dt expressions (string within ${}).
      :param dx: The demisto context.
      :return: The value extracted.
    """
    return dx.get(dtstr) if dx else dtstr


def get_parent_child(root: dict, path: str) -> Tuple[Tuple[Optional[str], Any], Tuple[Optional[str], Any]]:
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
    res = Ddict(root).search(path)
    if res is None:
        if '.' not in path:
            return ((None, None), (None, None))
        else:
            child = Ddict(root).get(path)
            return ((root, None), (child, path))

    parent_name, parent_value, child_name = res
    if child_name:
        child_value = Ddict(parent_value).get(child_name)
        return ((parent_value, parent_name), (child_value, child_name))
    else:
        return ((root, None), (parent_value, parent_name))


class ExtFilter:
    def __init__(self, dx: ContextData):
        self.__dx = dx

    def filter_by_expressions(self, root: Any, conds: Union[dict, list], path: Optional[str] = None) -> Optional[Value]:
        """ Filter the value by the conditions

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
          :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        if isinstance(conds, dict):
            # AND conditions
            parent = None
            child = root
            if path:
                if not isinstance(root, dict):
                    return None
                (parent, parent_path), (child, child_name) = get_parent_child(root, path)

            if isinstance(child, list):
                child = [v.value for v in [self.filter_by_expressions(
                    r, conds, None) for r in child] if v]
                if parent:
                    parent[child_name] = child
                else:
                    root = child
            else:
                for x in conds.items():
                    coptype, cconds = x
                    child = self.filter_value(child, coptype, cconds)
                    if not child:
                        return None
                    child = child.value

                    if coptype in ("value is filtered by", "is filtered by", "keeps", "doesn't keep"):
                        if parent:
                            parent[child_name] = child
                        else:
                            root = child

            return Value(root)

        elif isinstance(conds, list):
            # AND conditions by default
            ok, lop, neg = (None, None, None)
            for x in conds:
                if isinstance(x, str):
                    if x == 'not':
                        neg = not neg
                    elif lop is None and neg is None:
                        lop = x
                    else:
                        exit_error(f'Invalid logical operators syntax')
                else:
                    val = None
                    if ok is None:
                        val = self.filter_by_expressions(root, x, path)
                        ok = bool(val) ^ (neg or False)
                    elif lop is None or lop == 'and':
                        val = self.filter_by_expressions(root, x, path)
                        ok = ok and (bool(val) ^ (neg or False))
                    elif lop == 'or':
                        val = self.filter_by_expressions(root, x, path)
                        ok = ok or (bool(val) ^ (neg or False))
                    else:
                        exit_error(f'Invalid logical operator: {lop}')
                    lop, neg = (None, None)
                    root = val.value if val else root
            return Value(root) if ok is None or ok else None
        else:
            exit_error(f'Invalid condition format: {conds}')

    def filter_by_conditions(self, root: Value, conds: Union[dict, list]) -> Optional[Value]:
        """ Filter the value by the conditions

          *** NOTE ***
          expression for 'conds':
          [
            {
              "path1": <expression> for filter_by_expressions(),
              "path2": <expression> for filter_by_expressions()
              :
            }
            'or',
            [
              'not',
              {
                "path3": <expression> for filter_by_expressions(),
                "path4": <expression> for filter_by_expressions()
                :
              },
              'or',
              {
                "path5": <expression> for filter_by_expressions(),
                "path6": <expression> for filter_by_expressions()
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
            for x in conds.items():
                root = self.filter_by_expressions(root, x[1], x[0])
                if not root:
                    return None
                root = root.value
            return Value(root)
        elif isinstance(conds, list):
            # AND conditions by default
            ok, lop, neg = (None, None, None)
            for x in conds:
                if isinstance(x, str):
                    if x == 'not':
                        neg = not neg
                    elif lop is None and neg is None:
                        lop = x
                    else:
                        exit_error(f'Invalid logical operators syntax')
                else:
                    val = None
                    if ok is None:
                        val = self.filter_by_conditions(root, x)
                        ok = bool(val) ^ (neg or False)
                    elif lop is None or lop == 'and':
                        val = self.filter_by_conditions(root, x)
                        ok = ok and (bool(val) ^ (neg or False))
                    elif lop == 'or':
                        val = self.filter_by_conditions(root, x)
                        ok = ok or (bool(val) ^ (neg or False))
                    else:
                        exit_error(f'Invalid logical operator: {lop}')
                    lop, neg = (None, None)
                    root = val.value if val else root
            return Value(root) if ok is None or ok else None
        else:
            exit_error(f'Invalid custom condition format: {conds}')

    def filter_value(self, root: Any, optype: str, conds: Any, path: Optional[str] = None) -> Optional[Value]:
        """ Filter the value by the conditions

          :param self: This instance.
          :param root: The value to filter.
          :param optype: The conditional operator.
          :param conds: The condition expression to filter the value.
          :param path: The path to apply the conditions.
          :return: Return the filtered value in Value object if the conditions matches it, otherwise None.
        """
        if isinstance(root, list):
            return Value([v.value for v in [self.filter_value(r, optype, conds, path) for r in root] if v])

        if optype == "is filtered by":
            if path:
                conds = {
                    "matches conditions of": self.parse_conds_json(conds) if isinstance(conds, str) else conds
                }
                return self.filter_by_expressions(root, conds, path) if isinstance(root, dict) else None
            else:
                return self.filter_value(root, "matches conditions of", conds)

        if optype == "value is filtered by":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            if path:
                conds = {
                    "value matches expressions of": conds
                }
                if isinstance(root, dict):
                    return Value({k: v for k, f, v in [(k, self.filter_by_expressions(v, conds, path), v) for k, v in root.items()] if f and f.value})
                else:
                    return self.filter_by_expressions(root, conds, path)
            else:
                if isinstance(root, dict):
                    return Value({k: v for k, f, v in [(k, self.filter_by_expressions(v, conds), v) for k, v in root.items()] if f and f.value})
                else:
                    return self.filter_by_expressions(root, conds)

        elif optype in ("is", "isn't"):
            filstr = conds
            if isinstance(filstr, str) and filstr == "existing key":
                if optype == "is":
                    return Value(root) if path and Ddict(root).getValue(path) else None
                else:  # isn't
                    return Value(root) if not path or not Ddict(root).getValue(path) else None

        if path:
            conds = {
                optype: self.parse_conds_json(conds) if isinstance(conds, str) else conds
            }
            return self.filter_by_expressions(root, conds, path) if isinstance(root, dict) else None

        elif optype == "keeps":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            if not isinstance(root, dict) or not isinstance(conds, list):
                return None
            return Value({k: v for k, v in root.items() if k in conds})

        elif optype == "doesn't keep":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            if not isinstance(root, dict) or not isinstance(conds, list):
                return None
            return Value({k: v for k, v in root.items() if k not in conds})

        elif optype == "matches expressions of":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            return self.filter_by_expressions(root, conds)

        elif optype == "matches conditions of":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            return self.filter_by_conditions(root, conds)

        elif optype == "value matches expressions of":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            if isinstance(root, dict):
                return Value({k: v.value for k, v in {k: self.filter_by_expressions(v, conds) for k, v in root.items()}.items() if v})
            else:
                return self.filter_by_expressions(root, conds)

        elif optype == "value matches conditions of":
            conds = self.parse_conds_json(conds) if isinstance(conds, str) else conds
            if isinstance(root, dict):
                return Value({k: v.value for k, v in {k: self.filter_by_conditions(v, conds) for k, v in root.items()}.items() if v})
            else:
                return self.filter_by_conditions(root, conds)

        return Value(root) if match_value(root, optype, conds) else None

    def extract_value(self, source: Any) -> Any:
        """ Extract value including dt expression

          :param self: This instance.
          :param source: The value to be extracted that may include dt expressions.
          :return: The value extracted.
        """
        return extract_value(source, extract_dt, self.__dx)

    def parse_conds_json(self, jstr: str) -> Any:
        """ parse a json string and extract value

          :param self: This instance.
          :param jstr: A json string.
          :return: The value extracted.
        """
        return self.extract_value(json.loads(jstr))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    args = demisto.args()
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
    dx = ContextData(demisto=dx, inputs=args.get('ctx_inputs'), lists=args.get(
        'ctx_lists'), incident=args.get('ctx_incident'))

    # Extract value
    xfilter = ExtFilter(dx)
    conds = xfilter.extract_value(conds)
    value = xfilter.filter_value(value, optype, conds, path)
    value = value.value if value else None

    demisto.results(value)
