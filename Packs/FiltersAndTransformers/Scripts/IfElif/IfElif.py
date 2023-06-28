import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import re

ARGS = demisto.args()
CONTEXT = demisto.context()
OVERRIDE_BUILTINS = {'__builtins__': None}
CONTEXT_REGEX = re.compile('\${([\S]+?)}')


def get_from_context(path: str) -> Any:
    '''Gets a value of the format from the context.'''

    result = dict_safe_get(CONTEXT, path.split('.'), KeyError)

    if result is KeyError:
        raise KeyError(f'Missing key {path!r} in context.')

    return result


def parse_condition_for_context_keys(condition: str) -> str:
    '''Parses a string for context keys.'''

    for match in CONTEXT_REGEX.findall(condition):
        replacement = get_from_context(match)
        condition = condition.replace(f'${{{match}}}', json.dumps(replacement), 1)

    return condition


def evaluate_condition(condition: str) -> bool:

    try:
        parsed_condition = parse_condition_for_context_keys(condition)
        result = eval(parsed_condition, OVERRIDE_BUILTINS)  # noqa: PGH001
    except Exception:
        raise SyntaxError(f'Invalid expression: {condition!r}')

    if not isinstance(result, bool):
        raise TypeError(f'Condition {condition!r} is not a valid boolean expression.')

    return result


def get_conditions_from_args() -> list[dict[str, str]]:
    return json.loads(ARGS['conditions'])


def main():

    try:
        *conditions, default = get_conditions_from_args()

        result = next(
            (
                condition['return']
                for condition in conditions
                if evaluate_condition(condition['condition'])
            ),
            default['else']
        )

        if path := CONTEXT_REGEX.fullmatch(result):
            result = get_from_context(path[1])

    except Exception as e:
        raise DemistoException(f'Error in IfElif Transformer:\n{e}')

    return_results(result)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
