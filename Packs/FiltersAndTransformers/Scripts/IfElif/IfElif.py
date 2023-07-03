import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json

ARGS = demisto.args()
EVAL_ARGS = {
    '__builtins__': None,
    'null': None,
    'true': True,
    'false': False,
}
EVAL_BLACKLIST = ('.__', '*', ':')


def evaluate_condition(condition: str) -> bool:
    for op in EVAL_BLACKLIST:
        condition = condition.replace(op, repr(op))
    return eval(condition, EVAL_ARGS)  # noqa: PGH001


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

        return_results(result)

    except Exception as e:
        demisto.debug(str(e))
        return_error('Error in IfElif Transformer. Make sure you entered the values correctly.')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
