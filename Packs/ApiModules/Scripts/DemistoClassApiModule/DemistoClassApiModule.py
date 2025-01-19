import demistomock as demisto  # noqa: F401
import json
import sys
import traceback

from datetime import datetime

IS_PY3 = sys.version_info[0] == 3
MIN_SUPPORTED_VERSION = "8.9.0"

LAST_RUN_TRUNCATE_SIZE = 1024
LAST_RUN_SIZE_RECOMMENDATION = 1024 ** 2  # 1MB

CLIENT_WRAPPER_FAILED = "[WARNING - ClientWrapper failed]"
EXECUTING_LOG = "Executing {}: {}"
EXECUTING_ROOT_CALLER_SUFFIX = " (root caller: {})"
FILE_PATH_LOG = "File path of entry with ID [{}] is [{}]"
EXECUTING_COMMAND_LOG = "Going to execute {}"
EXECUTE_COMMAND_DURATION_LOG = "Execution of {} took {} seconds"
LAST_RUN_IS_LOG = "LastRun is: {}"
SET_LAST_RUN_LOG = "Setting last run to: {}"
TRUNCATED_SUFFIX = "...[truncated]"
LAST_RUN_SIZE_LOG = "[WARNING] last run size exceeds recommendation: {} MB"
CREATING_INCIDENTS_LOG = "Creating {} incidents"
CREATING_INCIDENTS_SUFFIX = " with source IDs [{}]"
CREATING_INDICATORS_LOG = "Creating {} indicators"
CREATE_INDICATORS_DURATION_LOG = "createIndicators took {} seconds"

if IS_PY3:
    class ClientWrapper:
        """A content-side wrapper to the builtin client (AKA "Demisto") class.
        All methods of this class can be executed in both scripts and integrations
        (E.g., self.results). """

        def __init__(self, server):
            self._server = server
            self._log_execution_details()

        def __getattr__(self, name):
            # called whenever an AttributeError is raised
            return getattr(self._server, name)

        @property
        def exec_type(self):
            raise NotImplementedError

        @property
        def exec_name(self):
            raise NotImplementedError

        @property
        def root_caller(self):
            """Represents the name of the script which called the current command / script using executeCommand()
            """
            executed_commands = self.callingContext["context"].get("ExecutedCommands") or []
            return executed_commands[0]["name"] if executed_commands else None

        def log_failure(self):
            self.debug("{} {}".format(CLIENT_WRAPPER_FAILED, traceback.format_exc()))

        def in_execute_command_call(self):
            """Returns true if this command / script was executed using executeCommand()
            from a different script.
            """
            return self.callingContext["context"]["CommandsExecuted"]["CurrLevel"] > 0

        def _log_execution_details(self):
            """Adds an info log of the name of the command / script currently being executed.
            """
            msg = EXECUTING_LOG.format(self.exec_type, self.exec_name)
            if self.in_execute_command_call() and self.root_caller:
                msg += EXECUTING_ROOT_CALLER_SUFFIX.format(self.root_caller)
            self.info(msg) if self.exec_type == "command" else self.debug(msg)

    class ScriptClient(ClientWrapper):
        @property
        def exec_type(self):
            return "script"

        @property
        def exec_name(self):
            return self.callingContext["context"].get("ScriptName")

        def getFilePath(self, id):
            res = self._server.getFilePath(id)

            try:
                self.debug(FILE_PATH_LOG.format(id, json.dumps(res)))
            except Exception:
                self.log_failure()

            return res

        def _drop_debug_log_entry(self, entries):
            """Given a list of executeCommand results, sends the log file entry to results().
            and returns only non-log file entries.
            """
            if isinstance(entries, list):
                for idx, entry in enumerate(entries):
                    if entry["Type"] == 16:
                        self.results(entry)
                        return entries[:idx] + entries[idx + 1:]
            return entries

        def executeCommand(self, command, args):
            """A wrapper for executeCommand().
            When debug-mode is true, adds debug logs before and after the execution,
            and handles the log file entry.
            """
            start_time = None

            try:
                if self.is_debug:
                    self.debug(EXECUTING_COMMAND_LOG.format(command))
                    start_time = datetime.now()
            except Exception:
                self.log_failure()

            res = self._server.executeCommand(command, args)

            try:
                if start_time:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.debug(EXECUTE_COMMAND_DURATION_LOG.format(command, duration))
                    return self._drop_debug_log_entry(res)
            except Exception:
                self.log_failure()

            return res

    class IntegrationClient(ClientWrapper):
        @property
        def exec_type(self):
            return "command"

        @property
        def exec_name(self):
            return self.callingContext["command"]

        def _stringify_last_run(self, last_run, truncate_size=LAST_RUN_TRUNCATE_SIZE):
            """Gets a truncated string of the last run object.
            If last run is larger than 1 MB, a warning log is printed.
            """
            last_run_str = json.dumps(last_run, indent=4)
            last_run_size = len(last_run_str.encode('utf-8'))
            if last_run_size > LAST_RUN_SIZE_RECOMMENDATION:
                self.debug(
                    LAST_RUN_SIZE_LOG.format(
                        round(last_run_size / LAST_RUN_SIZE_RECOMMENDATION, 1),
                    )
                )
            if len(last_run_str) > truncate_size:
                return last_run_str[:truncate_size] + TRUNCATED_SUFFIX
            return last_run_str

        def getLastRun(self):
            last_run = self._server.getLastRun()
            try:
                self.debug(LAST_RUN_IS_LOG.format(self._stringify_last_run(last_run)))
            except Exception:
                self.log_failure()
            return last_run

        def setLastRun(self, obj):
            try:
                self.debug(SET_LAST_RUN_LOG.format(self._stringify_last_run(obj)))
            except Exception:
                self.log_failure()
            self._server.setLastRun(obj)

    def is_supported_version():
        platform_version = demisto.demistoVersion().get("version")
        try:
            def comparable_version(v): return [int(i) for i in v.split(".")]
            return comparable_version(platform_version) >= comparable_version(MIN_SUPPORTED_VERSION)
        except:
            raise ValueError(
                "Could not compare platform version {} with {}".format(
                    platform_version, MIN_SUPPORTED_VERSION
                )
            )

    def set_client_class():
        try:
            if is_supported_version():
                if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
                    return IntegrationClient(demisto)
                elif demisto.callingContext.get('context', {}).get('ScriptName'):
                    return ScriptClient(demisto)
        except Exception:
            demisto.debug("{} {}".format(CLIENT_WRAPPER_FAILED, traceback.format_exc()))

        return demisto

    if "pytest" not in sys.modules:
        demisto = set_client_class()
