import demistomock as demisto  # noqa: F401

DEMISTO_WRAPPER_INTEGRATIONS = ['Cortex XDR - IR', 'QRadar v3', 'SlackV3', 'ServiceNow v2']
DEMISTO_WRAPPER_SCRIPTS = ['UnzipFile', 'DBotFindSimilarIncidents', 'ParseCSV']


try:
    class DemistoWrapper(Demisto):   # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
        """Wrapper class to interface with the Demisto server via stdin, stdout"""

        def __init__(self, context):
            super().__init__(context)

    class DemistoWrapperScript(DemistoWrapper):
        def getFilePath(self, id):
            self.debug("Wrapper Class: Getting file path with id: {id}.".format(id=id))
            return super().getFilePath(id)

    class DemistoWrapperIntegration(DemistoWrapper):
        def incidents(self, incidents):
            if incidents:
                self.debug("Wrapper Class: Creating {num_incidents} incidents.".format(num_incidents=len(incidents)))
            super().incidents(incidents)

    if demisto.callingContext.get('context', {}).get('IntegrationBrand', '') in DEMISTO_WRAPPER_INTEGRATIONS:
        demisto.__class__ = DemistoWrapperIntegration
    elif demisto.callingContext.get('context', {}).get('ScriptName', '') in DEMISTO_WRAPPER_SCRIPTS:
        demisto.__class__ = DemistoWrapperScript

except NameError:
    # try except for CommonServerPython tests.
    pass
