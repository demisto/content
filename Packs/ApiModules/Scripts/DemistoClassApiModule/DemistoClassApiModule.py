import demistomock as demisto  # noqa: F401
import random
import string

# Only the following integrations and scripts are using the Demisto class wrapper
DEMISTO_WRAPPER_INTEGRATIONS = ['Cortex XDR - IR', 'QRadar v3', 'SlackV3', 'ServiceNow v2']
DEMISTO_WRAPPER_SCRIPTS = ['UnzipFile', 'DBotFindSimilarIncidents', 'ParseCSV']

EXEC_ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

try:
    class DemistoWrapper(Demisto):  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
        """A content-side wrapper to the builtin Demisto class.
        All methods of this class can be executed in both scripts and integrations
        (E.g., self.results). """
        def info(self, msg, *args):
            return super(DemistoWrapper, self).info("{} [Exec ID: {}]".format(msg, EXEC_ID), *args)

        def debug(self, msg, *args):
            return super(DemistoWrapper, self).debug("{} [Exec ID: {}]".format(msg, EXEC_ID), *args)

        def error(self, msg, *args):
            return super(DemistoWrapper, self).error("{} [Exec ID: {}]".format(msg, EXEC_ID), *args)

    class DemistoScript(DemistoWrapper):
        def getFilePath(self, id):
            self.debug("Getting path of file entry with ID {}".format(id))
            return super(DemistoScript, self).getFilePath(id)

    class DemistoIntegration(DemistoWrapper):
        def incidents(self, incidents):
            if isinstance(incidents, list):
                self.debug("[fetch-incidents] Creating {} incidents".format(len(incidents)))
            super(DemistoIntegration, self).incidents(incidents)

    if demisto.callingContext.get('context', {}).get('IntegrationBrand', '') in DEMISTO_WRAPPER_INTEGRATIONS:
        demisto.__class__ = DemistoIntegration
    elif demisto.callingContext.get('context', {}).get('ScriptName', '') in DEMISTO_WRAPPER_SCRIPTS:
        demisto.__class__ = DemistoScript

except NameError:
    # NameError will be raised only in tests, where a Demisto class isn't defined.
    pass
