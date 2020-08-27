import logging

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# root_logger = logging.getLogger()

logging.debug("logging: this is a test")
logging.warning('Watch out! this is a warning')
demisto.results("done debug test")
