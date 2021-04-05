import fnmatch
import re
from typing import Any, Optional

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PATALG_BINARY = 0
PATALG_WILDCARD = 1
PATALG_REGEX = 2


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
            pattern = pattern.lower()
            if isinstance(value, list):
                return next(filter(lambda v: isinstance(v, str) and v.lower() == pattern, value), None) is not None
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
                return next(filter(lambda v: isinstance(v, str) and fnmatch.fnmatchcase(v.lower(), pattern), value), None) is not None
            elif isinstance(value, str):
                return fnmatch.fnmatchcase(value.lower(), pattern)
        else:
            if isinstance(value, list):
                return next(filter(lambda v: isinstance(v, str) and fnmatch.fnmatchcase(v, pattern), value), None) is not None
            elif isinstance(value, str):
                return fnmatch.fnmatchcase(value, pattern)
        return False

    elif patalg == PATALG_REGEX:
        flags = re.IGNORECASE if caseless else 0

        if isinstance(value, list):
            return next(filter(lambda v: isinstance(v, str) and re.fullmatch(pattern, v, flags), value), None) is not None
        elif isinstance(value, str):
            return re.fullmatch(pattern, value, flags) is not None
        return False
    else:
        exit_error(f"Unknown pattern algorithm: '{patalg}'")
    return False


def compare(lhs: Any, rhs: Any, operator: str) -> bool:
    """ Compare lhs value to rhs value.

      :param lhs: The left hand side value.
      :param lhs: The right hand side value.
      :param operator: The name of the operation.
      :return: Return True if the value matches the pattern, False otherwise.
    """
    negative_condition = None
    try:
        if operator == "===":
            negative_condition = False
            return type(lhs) == type(rhs) and lhs == rhs

        elif operator == "!==":
            negative_condition = True
            return type(lhs) != type(rhs) or lhs != rhs

        elif operator in ("==", "matches"):
            negative_condition = False
            return str(lhs) == str(rhs)

        elif operator in ("!=", "doesn't match"):
            negative_condition = True
            return compare(lhs, rhs, "==")

        elif operator == ">":
            negative_condition = False
            try:
                if isinstance(lhs, (int, float)) and isinstance(rhs, (int, float)):
                    return lhs > rhs
                return float(lhs) > float(rhs)
            except (ValueError, TypeError, AttributeError) as e:
                pass
            return str(lhs) > str(rhs)

        elif operator == ">=":
            negative_condition = False
            try:
                if isinstance(lhs, (int, float)) and isinstance(rhs, (int, float)):
                    return lhs >= rhs
                return float(lhs) > float(rhs)
            except (ValueError, TypeError, AttributeError) as e:
                pass
            return str(lhs) >= str(rhs)

        elif operator == '<':
            negative_condition = False
            return not compare(lhs, rhs, ">=")

        elif operator == '<=':
            negative_condition = False
            return not compare(lhs, rhs, ">")

        elif operator == "matches caseless":
            negative_condition = False
            return str(lhs).lower() == str(rhs).lower()

        elif operator == "doesn't match caseless":
            negative_condition = True
            return not compare(lhs, rhs, "matches caseless")

        elif operator == "wildcard: matches":
            negative_condition = False
            return match_pattern(rhs, lhs, False, PATALG_WILDCARD)

        elif operator == "wildcard: matches caseless":
            negative_condition = False
            return match_pattern(rhs, lhs, True, PATALG_WILDCARD)

        elif operator == "wildcard: doesn't match":
            negative_condition = True
            return not match_pattern(rhs, lhs, False, PATALG_WILDCARD)

        elif operator == "wildcard: doesn't match caseless":
            negative_condition = True
            return not match_pattern(rhs, lhs, True, PATALG_WILDCARD)

        elif operator == "regex: matches":
            negative_condition = False
            return match_pattern(rhs, lhs, False, PATALG_REGEX)

        elif operator == "regex: matches caseless":
            negative_condition = False
            return match_pattern(rhs, lhs, True, PATALG_REGEX)

        elif operator == "regex: doesn't match":
            negative_condition = True
            return not match_pattern(rhs, lhs, False, PATALG_REGEX)

        elif operator == "regex: doesn't match caseless":
            negative_condition = True
            return not match_pattern(rhs, lhs, True, PATALG_REGEX)

        elif operator == "in list":
            negative_condition = False
            return lhs in rhs.split(',')

        elif operator == "in caseless list":
            negative_condition = False
            return lhs.lower() in rhs.lower().split(',')

        elif operator == "not in list":
            negative_condition = True
            return not compare(lhs, "in list", rhs)

        elif operator == "not in caseless list":
            negative_condition = True
            return not compare(lhs, "in caseless list", rhs)

        else:
            raise ValueError(f'Unknown Operator: {operator}')

    except (ValueError, TypeError, AttributeError) as e:
        if negative_condition is None:
            raise
        return negative_condition
    return False


def apply_transformer_value(value: Any, transformer_value_key: Any, transformer_value: Any):
    if transformer_value_key:
        try:
            value = transformer_value if value == transformer_value_key else value
        except (ValueError, TypeError, AttributeError) as e:
            pass
    return value


if __name__ in ('__builtin__', 'builtins', '__main__'):
    args = demisto.args()
    transformer_value = args.get('value')
    transformer_value_key = args.get('transformer_value_key')
    
    lhs = apply_transformer_value(args.get('lhs'), transformer_value_key, transformer_value)
    rhs = apply_transformer_value(args.get('rhs'), transformer_value_key, transformer_value)

    if compare(lhs, rhs, args.get('operator', '')):
        value = args.get('then')
    else:
        value = args.get('else')
    
    value = apply_transformer_value(value, transformer_value_key, transformer_value)
    
    demisto.results(value)
