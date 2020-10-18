from CommonServerPython import DemistoException

MULTIPLE_ERRORS_RESULT = DemistoException('Error in API call [400] - error\n403: access denied, authorization failed\n401: test error #1\n402: test error #2')
