import demistomock as demisto
from CommonServerPython import *
from markdownify import markdownify as md

return_outputs(tomd.convert(demisto.getArg('html')))
