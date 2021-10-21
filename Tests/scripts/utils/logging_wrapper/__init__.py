from logging import *

# add success level in addition to levels imported from logging
SUCCESS = 25


def success(msg, *args, **kwargs):
    """
    Log a message with severity 'ERROR' on the root logger. If the logger has
    no handlers, call basicConfig() to add a console handler with a pre-defined
    format.
    """
    root.log(SUCCESS, msg, *args, **kwargs)