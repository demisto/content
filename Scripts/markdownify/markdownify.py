import demistomock as demisto
from CommonServerPython import *
from markdownify import markdownify as md

return_outputs(md(demisto.getArg('html')))
