import demistomock as demisto  # noqa: F401
import json
import sys

from datetime import datetime

if sys.version_info[0] >= 3:
    try:
        class DemistoWrapper(Demisto):  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
            """A content-side wrapper to the builtin Demisto class.
            All methods of this class can be executed in both scripts and integrations
            (E.g., self.results). """

            def initialize(self):
                self.script_name = self.callingContext["context"].get("ScriptName") or ""
                self.command_name = self.callingContext["command"] or ""
                self.exec_type = "command" if self.command_name else "script"
                self._name = self.script_name or self.command_name
                self.root_caller = self._get_root_caller()
                self._log_execution_details()

            def in_execute_command_call(self):
                return self.callingContext["context"]["CommandsExecuted"]["CurrLevel"] > 0

            def _get_root_caller(self):
                executed_commands = self.callingContext["context"].get("ExecutedCommands") or []
                return executed_commands[0]["name"] if executed_commands else None

            def _log_execution_details(self):
                msg = self.exec_type.title() + " being called is [{}]".format(self._name)
                if self.in_execute_command_call() and self.root_caller:
                    msg += " (root caller: {})".format(self.root_caller)
                super(DemistoWrapper, self).debug(msg)

            def info(self, msg):
                if not msg.lower().startswith(self.exec_type + " being called is"):
                    super(DemistoWrapper, self).info(msg)

            def debug(self, msg):
                if not msg.lower().startswith(self.exec_type + " being called is"):
                    super(DemistoWrapper, self).debug(msg)

        class DemistoScript(DemistoWrapper):
            def getFilePath(self, id):
                res = super(DemistoScript, self).getFilePath(id)
                self.debug("File path of entry with ID [{}] is [{}]".format(id, json.dumps(res)))
                return res

            def _drop_debug_log_entry(self, entries):
                entries = [entries] if isinstance(entries, dict) else entries
                if isinstance(entries, list):
                    for idx, entry in enumerate(entries):
                        if entry["Type"] == 16:
                            entry["File"] = self.script_name + "_" + entry["File"]
                            self.results(entry)
                            return entries[:idx] + entries[idx + 1:]
                return entries[0] if len(entries) == 1 else entries

            def executeCommand(self, command, args):
                if self.is_debug:
                    self.debug("Going to execute {}".format(command))
                    start_time = datetime.now()
                    res = super(DemistoScript, self).executeCommand(command, args)
                    duration = (datetime.now() - start_time).total_seconds()
                    self.debug("{} Took {} seconds".format(command, duration))
                    return self._drop_debug_log_entry(res)
                return super(DemistoScript, self).executeCommand(command, args)

        class DemistoIntegration(DemistoWrapper):
            def _stringify_last_run(self, last_run, truncate_size=1024):
                last_run_str = json.dumps(last_run, indent=4)
                last_run_size = len(last_run_str.encode('utf-8'))
                if last_run_size > 1 * 1024 * 1024:  # 1MB
                    self.debug(
                        "[WARNING] last run is too large: {} MB".format(
                            round(last_run_size / (1 * 1024 * 1024), 1),
                        )
                    )
                if len(last_run_str) > truncate_size:
                    return last_run_str[:truncate_size] + "...[truncated]"
                return last_run_str

            def getLastRun(self):
                last_run = super(DemistoIntegration, self).getLastRun()
                self.debug("LastRun is: {}".format(self._stringify_last_run(last_run)))
                return last_run

            def setLastRun(self, obj):
                self.debug("Setting last run to: {}".format(self._stringify_last_run(obj)))
                super(DemistoIntegration, self).setLastRun(obj)

            def incidents(self, incidents):
                if isinstance(incidents, list):
                    source_ids = []
                    for inc in incidents:
                        if "dbotMirrorId" in inc:
                            source_ids.append(inc["dbotMirrorId"])
                    msg = "Creating {} incidents".format(len(incidents))
                    if source_ids:
                        msg += " with source IDs [{}]".format(", ".join(source_ids))
                    self.debug(msg)
                super(DemistoIntegration, self).incidents(incidents)

            def createIndicators(self, indicators_batch, noUpdate=False):
                self.debug("Creating {} indicators".format(len(indicators_batch)))
                start_time = datetime.now()
                super(DemistoIntegration, self).createIndicators(indicators_batch, noUpdate)
                duration = (datetime.now() - start_time).total_seconds()
                if self.is_debug:
                    self.debug("createIndicators took {} seconds".format(duration))

        if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
            demisto.__class__ = DemistoIntegration
        elif demisto.callingContext.get('context', {}).get('ScriptName'):
            demisto.__class__ = DemistoScript
        demisto.initialize()

    except NameError:
        # NameError will be raised only in tests, where a Demisto class isn't defined.
        pass
