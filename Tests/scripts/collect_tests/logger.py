import logging
from logging import getLogger

logger = getLogger('collect_tests')

formatter = logging.Formatter('%(levelname)s [%(filename)s:%(lineno)s %(funcName)s() ] %(message)s')

sh = logging.StreamHandler()
sh.setFormatter(formatter)

logger.addHandler(sh)
logger.propagate = False
