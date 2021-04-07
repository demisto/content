import re

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

args = demisto.args()

flags = 0
if argToBoolean(args.get('ignore_case', False)):
    flags |= re.IGNORECASE

input_text = args['value']
pattern = re.compile(r'{}'.format(args['regex']), flags=flags)

output_text = pattern.sub(args['output_format'], input_text)
demisto.results(output_text)
