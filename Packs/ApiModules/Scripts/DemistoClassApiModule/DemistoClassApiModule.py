import json
import demistomock as demisto  # noqa: F401
import sys

if sys.version_info[0] >= 3:
    try:
        class DemistoWrapper(Demisto):  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
            """A content-side wrapper to the builtin Demisto class.
            All methods of this class can be executed in both scripts and integrations
            (E.g., self.results). """

        class DemistoScript(DemistoWrapper):
            def getFilePath(self, id):
                res = super(DemistoScript, self).getFilePath(id)
                self.debug("File path of entry with ID {} is: {}".format(id, str(res)))
                return res

        class DemistoIntegration(DemistoWrapper):
            def info(self, msg):
                if "command being called is" not in msg.lower():
                    super(DemistoIntegration, self).info(msg)

            def debug(self, msg):
                if "command being called is" not in msg.lower():
                    super(DemistoIntegration, self).debug(msg)

            def getLastRun(self):
                res = super(DemistoIntegration, self).getLastRun()
                self.debug("[fetch-incidents] LastRun is: {}".format(json.dumps(res, indent=4)))
                return res

            def setLastRun(self, obj):
                self.debug("[fetch-incidents] Setting last run to: {}".format(json.dumps(obj, indent=4)))
                super(DemistoIntegration, self).setLastRun(obj)

            def incidents(self, incidents):
                if isinstance(incidents, list):
                    source_ids = []
                    for inc in incidents:
                        if "dbotMirrorId" in inc:
                            source_ids.append(inc["dbotMirrorId"])
                    msg = "[fetch-incidents] Creating {} incidents".format(len(incidents))
                    if source_ids:
                        msg += " with source IDs [{}]".format(", ".join(source_ids))
                    self.debug(msg)
                super(DemistoIntegration, self).incidents(incidents)

        if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
            demisto.debug("Command being called is {}".format(demisto.command()))
            demisto.__class__ = DemistoIntegration
        elif demisto.callingContext.get('context', {}).get('ScriptName'):
            demisto.__class__ = DemistoScript

    except NameError:
        # NameError will be raised only in tests, where a Demisto class isn't defined.
        pass
