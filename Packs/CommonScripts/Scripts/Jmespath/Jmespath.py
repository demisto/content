import demistomock as demisto
from CommonServerPython import *
import jmespath


args = demisto.args()
value = args.get("value")
try:
    expression = jmespath.compile(args.get("expression"))
except Exception as err:
    return_error(f"Invalid expression - {err}")
result = expression.search(value)
demisto.results(result)
