import demistomock as demisto  # noqa: F401
import contextlib

# Only the following integrations and scripts are using the Demisto class wrapper
DEMISTO_WRAPPER_INTEGRATIONS = ['Cortex XDR - IR', 'QRadar v3', 'SlackV3', 'ServiceNow v2']
DEMISTO_WRAPPER_SCRIPTS = ['UnzipFile', 'DBotFindSimilarIncidents', 'ParseCSV']


# NameError will be raised only in tests, where a Demisto class isn't defined.
with contextlib.suppress(NameError):
    class DemistoWrapper(Demisto):  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
        """A content-side wrapper to the builtin Demisto class.
        All methods of this class can be executed in both scripts and integrations
        (E.g., self.results). """

    class DemistoScript(DemistoWrapper):
        def getFilePath(self, id):
            self.debug("Getting path of file entry with ID {}".format(id))
            return super().getFilePath(id)

    class DemistoIntegration(DemistoWrapper):
        def incidents(self, incidents):
            if isinstance(incidents, list):
                self.debug("[fetch-incidents] Creating {} incidents".format(len(incidents)))
            super().incidents(incidents)

    if demisto.callingContext.get('context', {}).get('IntegrationBrand', '') in DEMISTO_WRAPPER_INTEGRATIONS:
        demisto.__class__ = DemistoIntegration
    elif demisto.callingContext.get('context', {}).get('ScriptName', '') in DEMISTO_WRAPPER_SCRIPTS:
        demisto.__class__ = DemistoScript
