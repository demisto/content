from logging import getLogger, Formatter, StreamHandler

logger = getLogger('collect_tests')

formatter = Formatter('%(levelname)s [%(filename)s:%(lineno)s %(funcName)s() ] %(message)s')

sh = StreamHandler()
sh.setFormatter(formatter)

logger.addHandler(sh)
logger.propagate = False
