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
                self.debug("Getting path of file entry with ID {}".format(id))
                return super(DemistoScript, self).getFilePath(id)

        class DemistoIntegration(DemistoWrapper):
            def incidents(self, incidents):
                if isinstance(incidents, list):
                    self.debug("[fetch-incidents] Creating {} incidents".format(len(incidents)))
                super(DemistoIntegration, self).incidents(incidents)

        if demisto.callingContext.get('context', {}).get('IntegrationBrand'):
            demisto.__class__ = DemistoIntegration
        elif demisto.callingContext.get('context', {}).get('ScriptName'):
            demisto.__class__ = DemistoScript

    except NameError:
        # NameError will be raised only in tests, where a Demisto class isn't defined.
        pass
