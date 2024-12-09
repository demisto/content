import demistomock as demisto  # noqa: F401
import json
import sys
import traceback

from datetime import datetime

IS_PY3 = sys.version_info[0] == 3
MIN_SUPPORTED_VERSION = "8.9.0"

LAST_RUN_TRUNCATE_SIZE = 1024
LAST_RUN_SIZE_RECOMMENDATION = 1024 ** 2  # 1MB

DEMISTO_WRAPPER_FAILED = "[WARNING - DemistoWrapper failed]"
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
    class DemistoWrapper(object):
        """A content-side wrapper to the builtin Demisto class.
        All methods of this class can be executed in both scripts and integrations
        (E.g., self.results). """

        def __init__(self, demisto):
            self._demisto = demisto
            try:
                script_name = self.callingContext["context"].get("ScriptName") or ""
                command_name = self.callingContext["command"] or ""
                self.exec_type = "command" if command_name else "script"
                self.exec_name = script_name or command_name
                self.root_caller = self._get_root_caller()
                self._log_execution_details()
            except Exception:
                self.log_failure()

        def __getattr__(self, name):
            # called whenever an AttributeError is raised
            return getattr(self._demisto, name)

        def log_failure(self):
            self.debug("{} {}".format(DEMISTO_WRAPPER_FAILED, traceback.format_exc()))

        def in_execute_command_call(self):
            """Returns true if this command / script was executed using demisto.executeCommand()
            from a different script.
            """
            return self.callingContext["context"]["CommandsExecuted"]["CurrLevel"] > 0

        def _get_root_caller(self):
            """Returns the name of the script which called the current command / script using demisto.executeCommand()
            """
            executed_commands = self.callingContext["context"].get("ExecutedCommands") or []
            return executed_commands[0]["name"] if executed_commands else None

        def _log_execution_details(self):
            """Adds a debug log of the name of the command / script currently being executed.
            """
            msg = EXECUTING_LOG.format(self.exec_type, self.exec_name)
            if self.in_execute_command_call() and self.root_caller:
                msg += EXECUTING_ROOT_CALLER_SUFFIX.format(self.root_caller)
            self.debug(msg)

    class DemistoScript(DemistoWrapper):
        def getFilePath(self, id):
            res = self._demisto.getFilePath(id)

            try:
                self.debug(FILE_PATH_LOG.format(id, json.dumps(res)))
            except Exception:
                self.log_failure()

            return res

        def _drop_debug_log_entry(self, entries):
            """Given a list of executeCommand results, sends the log file entry to demisto.results()
            and returns only non-log file entries.
            """
            if isinstance(entries, list):
                for idx, entry in enumerate(entries):
                    if entry["Type"] == 16:
                        self.results(entry)
                        return entries[:idx] + entries[idx + 1:]
            return entries

        def executeCommand(self, command, args):
            """A wrapper for demisto.executeCommand.
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

            res = self._demisto.executeCommand(command, args)

            try:
                if start_time and self.is_debug:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.debug(EXECUTE_COMMAND_DURATION_LOG.format(command, duration))
                    return self._drop_debug_log_entry(res)
            except Exception:
                self.log_failure()

            return res

    class DemistoIntegration(DemistoWrapper):
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
            last_run = self._demisto.getLastRun()
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
            self._demisto.setLastRun(obj)

        def incidents(self, incidents):
            """A wrapper for demisto.incidents.
            Prints the number of incidents pulled, and if they contain their source IDs under the
            `dbotMirrorId` field, includes them as well.
            """
            try:
                if isinstance(incidents, list):
                    source_ids = []
                    for inc in incidents:
                        if "dbotMirrorId" in inc:
                            source_ids.append(str(inc["dbotMirrorId"]))
                    msg = CREATING_INCIDENTS_LOG.format(len(incidents))
                    if source_ids:
                        msg += CREATING_INCIDENTS_SUFFIX.format(", ".join(source_ids))
                    self.debug(msg)
            except Exception:
                self.log_failure()
            self._demisto.incidents(incidents)

        def createIndicators(self, indicators_batch, noUpdate=False):
            """A wrapper for demisto.createIndicators.
            Prints the number of indicators pulled, and the execution time of createIndicators().
            """
            start_time = None
            try:
                self.debug(CREATING_INDICATORS_LOG.format(len(indicators_batch)))
                start_time = datetime.now()
            except Exception:
                self.log_failure()

            self._demisto.createIndicators(indicators_batch, noUpdate)

            try:
                if start_time:
                    duration = (datetime.now() - start_time).total_seconds()
                    if self.is_debug:
                        self.debug(CREATE_INDICATORS_DURATION_LOG.format(duration))
            except Exception:
                self.log_failure()

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

    def set_demisto_class():
        try:
            if is_supported_version():
                if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
                    return DemistoIntegration(demisto)
                elif demisto.callingContext.get('context', {}).get('ScriptName'):
                    return DemistoScript(demisto)
        except Exception:
            demisto.debug("{} {}".format(DEMISTO_WRAPPER_FAILED, traceback.format_exc()))

        return demisto

    if "pytest" not in sys.modules:
        demisto = set_demisto_class()
