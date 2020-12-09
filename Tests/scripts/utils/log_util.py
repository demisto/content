import sys
import coloredlogs
import os
import queue
import logging
from logging.handlers import QueueHandler, QueueListener
from threading import currentThread, Lock

ARTIFACTS_PATH = os.environ.get('CIRCLE_ARTIFACTS', '.')
LOGGING_FORMAT = '[%(asctime)s] - [%(threadName)s] - [%(levelname)s] - %(message)s'
LEVEL_STYLES = {
    'critical': {'bold': True, 'color': 'red'},
    'debug': {'color': 'cyan'},
    'error': {'color': 'red'},
    'info': {},
    'warning': {'color': 'yellow'},
    'success': {'color': 'green'}
}


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


class ParallelLoggingManager:
    """
    This is a parallel logging manager meant to be used when using logging with multithreading when some of the logs
    should be grouped together in the log file for better readability.

    This class should be created only once in every process exceution.
    Example
    -------
    >>> logging_manager = ParallelLoggingManager('debug_file.log')
    >>> logging_manager.debug('debug message')
    >>> logging_manager.info('info message')
    >>> logging_manager.warning('warning message')
    >>> logging_manager.error('error message')
    >>> logging_manager.critical('critical message')
    >>> logging_manager.success('success message')
    # The 'exception method should be called only within exception handling context
    >>> logging_manager.exception('exception message')
    # The logs will be sent to the handlers only when the 'execute_logs' method will be called by
     the thread who wrote the log messages in the first place
    >>> logging_manager.execute_logs()
    # In case we want to write a log now we can use the 'real_time=True' flag.
    >>> logging_manager.debug('debug message', real_time=True)
    >>> logging_manager.info('info message', real_time=True)
    >>> logging_manager.warning('warning message', real_time=True)
    >>> logging_manager.error('error message', real_time=True)
    >>> logging_manager.critical('critical message', real_time=True)
    >>> logging_manager.success('success message', real_time=True)
    """

    def __init__(self, log_file_name):
        """
        Initializes the logging manager:
        - Uses a different colored format for each log level (see LEVEL_STYLES)
        - Defines a FileHandler with the given log_file_name.
        - Defines a SteamHandler for stdout.
        - Defines a logger for real time logs with those handlers
        Args:
            log_file_name: The path to where the log file will be saved
        """
        if not hasattr(logging, 'success'):
            _add_logging_level('SUCCESS', 25)
        self.log_file_name = log_file_name
        formatter = coloredlogs.ColoredFormatter(fmt=LOGGING_FORMAT,
                                                 level_styles=LEVEL_STYLES)
        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.setFormatter(formatter)
        log_file_path = os.path.join(ARTIFACTS_PATH, 'logs', log_file_name) if os.path.exists(
            os.path.join(ARTIFACTS_PATH, 'logs')) else os.path.join(ARTIFACTS_PATH, log_file_name)
        self.file_handler = logging.FileHandler(log_file_path)
        self.file_handler.setFormatter(formatter)
        self.console_handler.setLevel(logging.INFO)
        self.file_handler.setLevel(logging.DEBUG)
        self.real_time_logger = logging.getLogger(f'real_time-{log_file_path}')
        self.real_time_logger.addHandler(self.file_handler)
        self.real_time_logger.addHandler(self.console_handler)
        self.real_time_logger.setLevel(logging.DEBUG)
        self.real_time_logger.propagate = False
        self.loggers = {}
        self.listeners = {}
        self.logs_lock = Lock()
        self.thread_names = set()

    def _add_logger(self, thread_name: str):
        """
        Defines a new logger, queueHandler and QueueListener for a new thread
        This method is only called if the thread name is not in the 'thread_names' set.
        Args:
            thread_name: The name of the thread that should be added
        """
        log_queue = queue.Queue(-1)
        queue_handler = QueueHandler(log_queue)
        queue_handler.setLevel(logging.DEBUG)
        logger = logging.getLogger(thread_name)
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        logger.addHandler(queue_handler)
        listener = QueueListener(log_queue, self.console_handler, self.file_handler, respect_handler_level=True)
        self.loggers[thread_name] = logger
        self.listeners[thread_name] = listener
        self.thread_names.add(thread_name)

    def debug(self, message: str, real_time: bool = False) -> None:
        """
        Executes a debug log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.debug if real_time else self.loggers[thread_name].debug
        log_method(message)

    def info(self, message: str, real_time: bool = False) -> None:
        """
        Executes an info log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.info if real_time else self.loggers[thread_name].info
        log_method(message)

    def warning(self, message: str, real_time: bool = False) -> None:
        """
        Executes a warning log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.warning if real_time else self.loggers[thread_name].warning
        log_method(message)

    def error(self, message: str, real_time: bool = False) -> None:
        """
        Executes a error log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.error if real_time else self.loggers[thread_name].error
        log_method(message)

    def critical(self, message: str, real_time: bool = False) -> None:
        """
        Executes a critical log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.critical if real_time else self.loggers[thread_name].critical
        log_method(message)

    def exception(self, message: str, real_time: bool = False) -> None:
        """
        Executes a exception log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.exception if real_time else self.loggers[thread_name].exception
        log_method(message)

    def success(self, message: str, real_time: bool = False) -> None:
        """
        Executes a success log.
        If real_time is given - will use the real_time_logger, if not - will use the thread's logger.
        If the thread logger is used - the log will not be written until 'execute_logs' is called.
        Args:
            message: The log message
            real_time: Whether to log the message now or after the next 'execute_logs' method execution.
        """
        thread_name = currentThread().getName()
        if thread_name not in self.thread_names:
            self._add_logger(thread_name)
        log_method = self.real_time_logger.success if real_time else self.loggers[thread_name].success
        log_method(message)

    def execute_logs(self) -> None:
        """
        Writes the logs from the queue to the handlers.
        """
        thread_name = currentThread().getName()
        self.logs_lock.acquire()
        self.listeners[thread_name].start()
        self.listeners[thread_name].stop()
        self.logs_lock.release()
