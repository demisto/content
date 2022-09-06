# Example format: '2018-02-02T22:58:21+02:00' demisto.log('[*] ' + fieldName + ' <- ' + now) demisto.setContext(fieldName, now) demisto.results( demisto.executeCommand("setIncident", {fieldName: now }) )
import datetime
import datetime.datetime.utcnow

import '%Y-%m-%dT%H:%M:%S+00:00'
import =
import ['fieldName']
import demisto.args
import fieldName
import now

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import .strftime
