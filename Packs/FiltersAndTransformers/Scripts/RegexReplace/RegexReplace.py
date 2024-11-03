import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


class Main:
    def __init__(self, input_text: str, output_format: str, regex: str, action_dt: str | None, regex_flags: int):
        self.__input_text = input_text
        self.__output_format = output_format.replace(r'\0', r'\g<0>')
        self.__pattern = re.compile(regex, flags=regex_flags)
        self.__action_dt = action_dt

    def __replace(self, m: re.Match) -> Any:
        value = m.expand(self.__output_format)
        if self.__action_dt:
            value = demisto.dt(value, self.__action_dt)
            if value is None:
                value = ''
            elif isinstance(value, bool):
                value = json.dumps(value)
            else:
                value = str(value)
        return value

    def run(self) -> Any:
        output_text = self.__pattern.sub(self.__replace, self.__input_text)
        return_results(output_text)


def main():
    args = demisto.args()
    try:
        flags = 0
        if argToBoolean(args.get('ignore_case') or False):
            flags |= re.IGNORECASE
        if argToBoolean(args.get('multi_line') or False):
            flags |= re.MULTILINE
        if argToBoolean(args.get('period_matches_newline') or False):
            flags |= re.DOTALL

        Main(input_text=args['value'],
             output_format=args.get('output_format') or '',
             regex=args['regex'],
             action_dt=args.get('action_dt'),
             regex_flags=flags).run()
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
