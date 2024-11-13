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

        class DemistoScript(DemistoWrapper):
            def info(self, msg):
                if "script being called is" not in msg.lower():
                    script = demisto.callingContext['context']['ScriptName']
                    msg = "[{}] {}".format(script, msg)
                    super(DemistoScript, self).info(msg)

            def debug(self, msg):
                if "script being called is" not in msg.lower():
                    script = demisto.callingContext['context']['ScriptName']
                    msg = "[{}] {}".format(script, msg)
                    super(DemistoScript, self).debug(msg)

            def getFilePath(self, id):
                res = super(DemistoScript, self).getFilePath(id)
                self.debug("File path of entry with ID [{}] is [{}]".format(id, json.dumps(res)))
                return res

            def executeCommand(self, command, args):
                start_time = datetime.now()
                self.debug("Going to execute [{}] with args: [{}]".format(command, json.dumps(args)))
                res = super(DemistoScript, self).executeCommand(command, args)
                duration = (datetime.now() - start_time).total_seconds()
                if isinstance(res, list):
                    is_error = any(entry['Type'] == 4 for entry in res)
                elif isinstance(res, dict):
                    is_error = res['Type'] == 4
                else:
                    is_error = False
                self.debug(
                    "Finished execution of [{}] after {} seconds, success: {}".format(duration, not is_error)
                )
                return res

        class DemistoIntegration(DemistoWrapper):
            def info(self, msg):
                if "command being called is" not in msg.lower():
                    integration = demisto.callingContext['context']['IntegrationBrand']
                    instance = demisto.callingContext['context']['IntegrationInstance']
                    command = self.command()
                    msg = "[{} - {}] [{}] {}".format(integration, instance, command, msg)
                    super(DemistoIntegration, self).info(msg)

            def debug(self, msg):
                if "command being called is" not in msg.lower():
                    integration = demisto.callingContext['context']['IntegrationBrand']
                    instance = demisto.callingContext['context']['IntegrationInstance']
                    msg = "[{} - {}] {}".format(integration, instance, msg)
                    super(DemistoIntegration, self).debug(msg)

            def getLastRun(self):
                res = super(DemistoIntegration, self).getLastRun()
                self.debug("LastRun is: {}".format(json.dumps(res, indent=4)))
                return res

            def setLastRun(self, obj):
                self.debug("Setting last run to: {}".format(json.dumps(obj, indent=4)))
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
                super(DemistoIntegration, self).createIndicators(indicators_batch, noUpdate)

        args_str = json.dumps(demisto.args())
        if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
            integration = demisto.callingContext['context']['IntegrationBrand']
            instance = demisto.callingContext['context']['IntegrationInstance']
            demisto.debug(
                "Command being called is [{}] ({} - {}), args: [{}]".format(
                    demisto.command(), integration, instance, args_str
                )
            )
            demisto.__class__ = DemistoIntegration
        elif demisto.callingContext.get('context', {}).get('ScriptName'):
            script = demisto.callingContext['context']['ScriptName']
            demisto.debug("Script being called is [{}], args: [{}]".format(script, args_str))
            demisto.__class__ = DemistoScript

    except NameError:
        # NameError will be raised only in tests, where a Demisto class isn't defined.
        pass
