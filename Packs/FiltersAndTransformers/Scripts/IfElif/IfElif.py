import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import re

ARGS = demisto.args()
CONTEXT = demisto.context()
OVERRIDE_BUILTINS = {'__builtins__': None}


def parse_json_for_keys(condition: str) -> str:
    '''Parses a json string for context keys.'''

    matches = re.findall('\${([\S]+?)}', condition)

    for match in matches:
        replacement = dict_safe_get(CONTEXT, match.split('.'), KeyError)

        if replacement is KeyError:
            raise replacement(f'Missing key {match!r} in context.')

        condition = condition.replace(f'${{{match}}}', json.dumps(replacement))

    return condition


def evaluate_condition(condition: str) -> bool:

    try:
        result = eval(condition, OVERRIDE_BUILTINS)  # noqa: PGH001
    except Exception:  # hide the use of eval
        raise SyntaxError(f'Invalid expression: {condition!r}')

    if not isinstance(result, bool):
        raise TypeError(f'Condition {condition!r} is not a valid boolean expression.')

    return result


def get_conditions_from_args() -> list[dict[str, str]]:
    return json.loads(parse_json_for_keys(ARGS['conditions']))


def main():

    try:
        *conditions, default = get_conditions_from_args()

        result = next(
            (
                condition['return']
                for condition in conditions
                if evaluate_condition(condition['condition'])
            ),
            default
        )
    except Exception as e:
        raise DemistoException(f'Error in IfElif Transformer:\n{e}')

    return_results(result)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
