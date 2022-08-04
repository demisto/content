from logging import *

# add success level in addition to levels imported from logging
SUCCESS = 25

addLevelName(SUCCESS, 'SUCCESS')


def success(msg, *args, **kwargs):
    """
    Log a message with severity 'SUCCESS' on the root logger.
    """
    global root
    root.log(SUCCESS, msg, *args, **kwargs)
