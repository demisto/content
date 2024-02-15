from __future__ import print_function
import json
import uuid
import sys

SERVER_ERROR_MARKER = '[ERROR-fd5a7750-7182-4b38-90ba-091824478903]'


class DemistoWrapper(Demisto):
    """Wrapper class to interface with the Demisto server via stdin, stdout"""
    INTEGRATION = 'Integration'
    SCRIPT = 'Script'

    def __init__(self, context):
        super().__init__(context)
        self.is_integration = self.callingContext['integration']
        self.item_type = self.INTEGRATION if self.is_integration else self.SCRIPT

    def raise_exception_if_not_implemented(self, implemented_item_type, function_name):
        """

        :param implemented_item_type: Integration or Script, type that te function works with
        :param function_name: The calling function name

        :return:
        """
        if self.item_type != implemented_item_type:
            raise Exception('Demisto object has no function `{function_name}` for {item_type}.'.format(
                function_name=function_name, item_type=self.item_type))

    def long_running_heartbeat_thread(self, enable=True):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'long_running_heartbeat_thread')
        super.long_running_heartbeat_thread(enable)

    def log(self, msg):
        super().log(msg)

    def investigation(self):
        return super().investigation()

    def incidents(self, incidents=None):
        return super().incidents(incidents)

    def incident(self):
        return super().incident().incidents()

    def alerts(self):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'alerts')
        return super().alerts()

    def get_incidents(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'get_incidents')
        return super().get_incidents()

    def get_alerts(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'get_alerts')
        return super().get_alerts()

    def alert(self):
        return super().alert()

    def parentEntry(self):
        return super().parentEntry()

    def context(self):
        return super().context()

    def integrationInstance(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'integrationInstance')
        return super().integrationInstance()

    def args(self):
        return super().args()

    def uniqueFile(self):
        return super().uniqueFile()

    def getFilePath(self, id):
        return super().getFilePath(id)

    def getLastRun(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getLastRun')
        return super().getLastRun()

    def setLastRun(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setLastRun')
        return super().setLastRun(value)

    def getLastMirrorRun(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getLastMirrorRun')
        return super().getLastMirrorRun()

    def setLastMirrorRun(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setLastMirrorRun')
        return super().setLastMirrorRun(value)

    def internalHttpRequest(self, method, uri, body=None):
        return super().internalHttpRequest(method, uri, body)

    def getIntegrationContext(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getIntegrationContext')
        return super().getIntegrationContext()

    def setIntegrationContext(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setIntegrationContext')
        return super().setIntegrationContext(value)

    def getIntegrationContextVersioned(self, refresh=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getIntegrationContextVersioned')
        return super().getIntegrationContextVersioned(refresh)

    def setIntegrationContextVersioned(self, value, version, sync=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setIntegrationContextVersioned')
        return super().setIntegrationContextVersioned(value, version, sync)

    def searchRelationships(self, filter=None):
        return super().searchRelationships(filter)

    def getLicenseID(self):
        return super().getLicenseID()

    def createIncidents(self, incidents, lastRun=None, userID=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createIncidents')
        return super().createIncidents(incidents, lastRun, userID)

    def createAlerts(self, alerts, lastRun=None, userID=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createAlerts')
        return super().createAlerts(alerts, lastRun, userID)

    def createIndicators(self, indicators, lastRun=None, noUpdate=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createIndicators')
        return super().createIndicators(indicators, lastRun, noUpdate)

    def command(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'command')
        return super().command()

    def executeCommand(self, command, args):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'executeCommand')
        return super().executeCommand(command, args)

    def results(self, results):
        super().results(results)

    def fetchResults(self, incidents_or_alerts):
        """ used to encapsulate/hide 'incidents' from the code """
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'fetchResults')
        super().fetchResults(incidents_or_alerts)

    def credentials(self, credentials):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'credentials')
        super().credentials(credentials)


# TODO: handle self._heartbeat_thread
try:
    # try except for CommonServerPython tests.
    # demisto._heartbeat_enabled = False
    # demisto._heartbeat_thread.join()
    demisto = DemistoWrapper(context)  # type:ignore [name-defined] # noqa: F821 # pylint: disable=E0602
except NameError:
    pass

