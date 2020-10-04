import demistomock as demisto
from CommonServerPython import *
import jmespath


def jmespath_search(expression: str, value: dict) -> dict:
    try:
        expression_compiled = jmespath.compile(expression)
    except Exception as err:
        raise Exception(f"Invalid expression - {err}")
    result = expression_compiled.search(value)
    return result


def main():
    args = demisto.args()
    value = args.get("value")
    expression = args.get("expression")
    result = jmespath_search(expression, value)
    return_results(result)


if __name__ in ['__builtin__', 'builtins']:
    main()
