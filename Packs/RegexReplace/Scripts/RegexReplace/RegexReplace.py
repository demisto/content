import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Main:
    def __init__(self):
        args = demisto.args()
        flags = 0
        if argToBoolean(args.get('ignore_case') or False):
            flags |= re.IGNORECASE
        if argToBoolean(args.get('multi_line') or False):
            flags |= re.MULTILINE
        if argToBoolean(args.get('period_matches_newline') or False):
            flags |= re.DOTALL

        self.__input_text = args['value']
        self.__output_format = args.get('output_format', '').replace(r'\0', r'\g<0>')
        self.__pattern = re.compile(args['regex'], flags=flags)
        self.__action_dt = args.get('action_dt')

    def __replace(self, m):
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

    def run(self):
        output_text = self.__pattern.sub(self.__replace, self.__input_text)
        return_results(output_text)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    Main().run()
