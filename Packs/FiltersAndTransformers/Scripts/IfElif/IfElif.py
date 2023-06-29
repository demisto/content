import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json

ARGS = demisto.args()
OVERRIDE_BUILTINS = {'__builtins__': None}


def evaluate_condition(condition: str) -> bool:

    try:
        result = eval(condition, OVERRIDE_BUILTINS)  # noqa: PGH001
    except Exception:
        raise SyntaxError(f'Invalid expression: {condition!r}')

    if not isinstance(result, bool):
        raise TypeError(f'Condition {condition!r} is not a valid boolean expression.')

    return result


def main():

    try:
        *conditions, default = json.loads(ARGS['conditions'])

        result = next(
            (
                condition['return']
                for condition in conditions
                if evaluate_condition(condition['condition'])
            ),
            default['else']
        )

    except Exception as e:
        raise DemistoException(f'Error in IfElif Transformer:\n{e.args}')

    return_results(result)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
