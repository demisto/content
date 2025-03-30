import demistomock as demisto
import jmespath
from CommonServerPython import *


def jmespath_search(expression: str, value: dict | list) -> dict:
    try:
        expression_compiled = jmespath.compile(expression)  # pylint: disable=E1101
    except Exception as err:
        raise Exception(f"Invalid expression - {err}")
    result = expression_compiled.search(value)
    return result


def main():
    args = demisto.args()
    value = args.get("value")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception as err:
            return_error(f"The input is not valid JSON: {err}")
    expression = args.get("expression")
    result = jmespath_search(expression, value)
    return_results(result)


if __name__ in ["__builtin__", "builtins"]:
    main()
