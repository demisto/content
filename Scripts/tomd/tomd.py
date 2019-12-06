import demistomock as demisto
from CommonServerPython import *
import tomd

return_outputs(tomd.convert(demisto.getArg('html')))
