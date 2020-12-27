from threading import currentThread, Thread
from Tests.scripts.utils.log_util import ParallelLoggingManager


class TestParallelLoggingManager:

    def test_queue_listener_sanity(self, tmp_path):
        """
        Given:
            - a ParallelLoggingManager
        When:
            - writing logs to the log file
        Then:
            - assert logs are not written to the file until execute_logs method is called
            - assert all logs appear in file after execute_logs method is called
        """
        log_file_path = f'{tmp_path}/log_file.log'
        logging_manager = ParallelLoggingManager(log_file_path)
        logging_manager.debug('debug1')
        logging_manager.info('info1')
        logging_manager.warning('warning1')
        logging_manager.error('error1')
        logging_manager.critical('critical1')
        logging_manager.success('success1')
        # Generating exception
        try:
            _ = 1 / 0
        except Exception:
            logging_manager.exception('exception1')
        log_file_lines = self.get_log_content(log_file_path)
        assert not log_file_lines
        logging_manager.execute_logs()
        log_file_lines = self.get_log_content(log_file_path)
        for expected_in_log, log_line in zip(self.get_expected_content('1').values(), log_file_lines):
            thread_name, level, content = expected_in_log
            self.assert_log_line(log_line, thread_name, level, content)

    def test_real_time_logger_sanity(self, tmp_path):
        """
        Given:
            - a ParallelLoggingManager
        When:
            - writing logs to the log file using the flag 'real_time=True'
        Then:
            - assert logs are written to the file immediately
        """
        log_file_path = f'{tmp_path}/log_file.log'
        logging_manager = ParallelLoggingManager(log_file_path)
        expected_logs = self.get_expected_content('1')
        logging_manager.debug('debug1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['debug'])
        logging_manager.info('info1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['info'])
        logging_manager.warning('warning1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['warning'])
        logging_manager.error('error1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['error'])
        logging_manager.critical('critical1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['critical'])
        logging_manager.success('success1', real_time=True)
        self.assert_latest_log_line(log_file_path, *expected_logs['success'])

    def test_listeners_with_multiple_threads(self, tmp_path):
        """
        Given:
            - a ParallelLoggingManager
        When:
            - writing logs to the log file with 5 different threads
        Then:
            - assert logs does not appear in the file before each thread has called the 'execute_logs' method
            - assert logs are written to the file grouped together for each thread
        """
        log_file_path = f'{tmp_path}/log_file.log'
        logging_manager = ParallelLoggingManager(log_file_path)
        successful_threads_results = set()

        def thread_log_function():
            thread_name = currentThread().getName()
            logging_manager.info('test1')
            logging_manager.info('test2')
            logging_manager.info('test3')
            log_content_lines = TestParallelLoggingManager.get_log_content(logging_manager.log_file_name)
            thread_logs = [line for line in log_content_lines if thread_name in line]
            assert not thread_logs
            logging_manager.execute_logs()
            log_content_lines = TestParallelLoggingManager.get_log_content(logging_manager.log_file_name)
            first_thread_log_line = next(line for line in log_content_lines if thread_name in line)
            first_thread_log_line_index = log_content_lines.index(first_thread_log_line)
            self.assert_log_line(log_content_lines[first_thread_log_line_index], thread_name, 'INFO', 'test1')
            self.assert_log_line(log_content_lines[first_thread_log_line_index + 1], thread_name, 'INFO', 'test2')
            self.assert_log_line(log_content_lines[first_thread_log_line_index + 2], thread_name, 'INFO', 'test3')
            successful_threads_results.add(thread_name)

        threads = []
        for i in range(5):
            threads.append(Thread(target=thread_log_function))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
            assert thread.getName() in successful_threads_results

    @staticmethod
    def get_expected_content(content_postfix: str) -> dict:
        """
        Generate a dict that contains for each log level a tuple with the thread name, the log level and the content
        of the log message
        Args:
            content_postfix: the suffix that is added to each log file
        Returns:
            A dict that contains for each log level a tuple with the thread name, the log level and the content
        """
        thread_name = currentThread().getName()
        return {'debug': (thread_name, 'DEBUG', f'debug{content_postfix}'),
                'info': (thread_name, 'INFO', f'info{content_postfix}'),
                'warning': (thread_name, 'WARNING', f'warning{content_postfix}'),
                'error': (thread_name, 'ERROR', f'error{content_postfix}'),
                'critical': (thread_name, 'CRITICAL', f'critical{content_postfix}'),
                'success': (thread_name, 'SUCCESS', f'success{content_postfix}'),
                'exception': (thread_name, 'ERROR', f'exception{content_postfix}'),
                }

    @staticmethod
    def get_log_content(log_file_path: str) -> list:
        """
        Reads the log file and returns it's lines
        Args:
            log_file_path: The path of the file

        Returns:
            A list with the log file lines
        """
        with open(log_file_path, 'r') as log_file:
            log_file_lines = log_file.readlines()
        return log_file_lines

    def assert_latest_log_line(self, log_file_path: str, thread_name: str, level: str, content: str) -> None:
        """
        Assert that the last line in the log file has the thread name, log level name, and content as expected
        Args:
            log_file_path: The path to the log file
            thread_name: The expected thread name
            level: The expected level
            content: The expected log message
        """
        latest_log_line = self.get_log_content(log_file_path)[-1]
        self.assert_log_line(latest_log_line, thread_name, level, content)

    @staticmethod
    def assert_log_line(log_line: str, thread_name: str, level: str, content: str) -> None:
        """
        Assert that the line of the log file has the thread name, log level name, and content as expected
        Args:
            log_line: Given log line
            thread_name: The expected thread name
            level: The expected level
            content: The expected log message
        """
        assert thread_name in log_line
        assert level in log_line
        assert content in log_line
