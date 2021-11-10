from logging import *
from logging import RootLogger

# add success level in addition to levels imported from logging
SUCCESS = 25

root = RootLogger(WARNING)
addLevelName(SUCCESS, 'SUCCESS')


def success(msg, *args, **kwargs):
    """
    Log a message with severity 'SUCCESS' on the root logger.
    """
    root.log(SUCCESS, msg, *args, **kwargs)
