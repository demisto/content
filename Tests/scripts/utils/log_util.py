import logging
import os
import sys

import coloredlogs

from demisto_sdk.commands.test_content.ParallelLoggingManager import LOGGING_FORMAT, LEVEL_STYLES, ARTIFACTS_PATH


def _add_logging_level(level_name: str, level_num: int, method_name: str = None) -> None:
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `level_name` becomes an attribute of the `logging` module with the value
    `level_num`. `method_name` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.


    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> _add_logging_level('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    Args:
        level_name: The name of the level that will become an attribute of the `logging` module
        level_num: The logging value of the new level
        method_name: The method name with which the new level will be called

    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError(f'{level_name} already defined in logging module')
    if hasattr(logging, method_name):
        raise AttributeError(f'{method_name} already defined in logging module')
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError(f'{method_name} already defined in logger class')

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, **kwargs)

    def logToRoot(message, *args, **kwargs):
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, logForLevel)
    setattr(logging, method_name, logToRoot)


def install_logging(log_file_name: str, include_process_name=False) -> str:
    """
    This method install the logging mechanism so that info level logs will be sent to the console and debug level logs
    will be sent to the log_file_name only.
    Args:
        include_process_name: Whether to include the process name in the logs format, Should be used when
            using multiprocessing
        log_file_name: The name of the file in which the debug logs will be saved
    """
    if not hasattr(logging, 'success'):
        _add_logging_level('SUCCESS', 25)
    logging_format = LOGGING_FORMAT
    if include_process_name:
        logging_format = '[%(asctime)s] - [%(processName)s] - [%(threadName)s] - [%(levelname)s] - %(message)s'
    formatter = coloredlogs.ColoredFormatter(fmt=logging_format,
                                             level_styles=LEVEL_STYLES)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    log_file_path = os.path.join(ARTIFACTS_PATH, 'logs', log_file_name) if os.path.exists(
        os.path.join(ARTIFACTS_PATH, 'logs')) else os.path.join(ARTIFACTS_PATH, log_file_name)
    fh = logging.FileHandler(log_file_path)
    fh.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    fh.setLevel(logging.DEBUG)
    configure_root_logger(ch, fh)
    return log_file_path


def configure_root_logger(ch: logging.StreamHandler, fh: logging.FileHandler) -> None:
    """
    - Configures the root logger with DEBUG level
    - Removes existing handlers from the root logger and adds the console handler and the file handler.
    Args:
        ch: StreamHandler to add to the root logger
        fh: FileHandler to add to the root logger
    """
    logging.root.setLevel(logging.DEBUG)
    for h in logging.root.handlers[:]:
        logging.root.removeHandler(h)
        h.close()
    logging.root.addHandler(ch)
    logging.root.addHandler(fh)


def install_simple_logging():
    """
    This method implements logging module to print the message only with colors
    This function is implemented to support backward compatibility for functions that cannot yet support the full
    `install_logging` method capabilities
    """
    if not hasattr(logging, 'success'):
        _add_logging_level('SUCCESS', 25)
    coloredlogs.install(fmt='%(message)s',
                        level_styles=LEVEL_STYLES)
