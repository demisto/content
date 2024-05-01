import logging  # noqa: N999
from logging import *

# add success level in addition to levels imported from logging
SUCCESS = 25
__all__ = ['SUCCESS', 'success']

root = logging.root
addLevelName(SUCCESS, 'SUCCESS')


def success(msg, *args, **kwargs):
    """
    Log a message with severity 'SUCCESS' on the root logger.
    """
    root.log(SUCCESS, msg, *args, **kwargs)
