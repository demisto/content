from __future__ import print_function
import json
import uuid
import sys

SERVER_ERROR_MARKER = '[ERROR-fd5a7750-7182-4b38-90ba-091824478903]'


class Demisto:
    """Wrapper class to interface with the Demisto server via stdin, stdout"""
    INTEGRATION = 'Integration'
    SCRIPT = 'Script'

    def __init__(self, context):
        self.callingContext = context
        self.is_integration = self.callingContext['integration']
        self.item_type = self.INTEGRATION if self.is_integration else self.SCRIPT
        self.is_debug = False
        self._args = dict(self.callingContext.get(u'args', {}))
        if 'demisto_machine_learning_magic_key' in self._args:
            import os
            os.environ['DEMISTO_MACHINE_LEARNING_MAGIC_KEY'] = self._args['demisto_machine_learning_magic_key']
        is_debug = self.callingContext.get('context', {}).get('IsDebug', False)
        if is_debug:
            self.is_debug = True
            self._args.pop('debug-mode', '')
        self.__stdout_lock = None
        self._stdout_lock_timeout = 60
        self._heartbeat_enabled = False
        if context.get('command') == 'long-running-execution' and context.get('is_running_heartbeat'):
            self.long_running_heartbeat_thread()

    def raise_exception_if_not_implemented(self, implemented_item_type, function_name):
        """

        :param implemented_item_type: Integration or Script, type that te function works with
        :param function_name: The calling function name

        :return:
        """
        if self.item_type != implemented_item_type:
            raise Exception('Demisto object has no function `{function_name}` for {item_type}.'.format(
                function_name=function_name, item_type=self.item_type))

    def enable_multithreading(self):
        from threading import Lock
        if self.__stdout_lock is None:
            self.__stdout_lock = Lock()

    def long_running_heartbeat_thread(self, enable=True):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'long_running_heartbeat_thread')
        if self._heartbeat_enabled == enable:
            # nothing to do as state hasn't changed
            return
        self._heartbeat_enabled = enable
        if self._heartbeat_enabled:
            self.info("starting heartbeat thread")
            self.enable_multithreading()

            def send_heartbeat():
                import time
                counter = 0
                while True:
                    time.sleep(self.callingContext.get('heartbeat_interval', 30))
                    if not self._heartbeat_enabled:
                        self.info("heartbeat disabled. Existing heartbeat thread.")
                        return
                    self.heartbeat("heartbeat counter: " + str(counter))
                    counter += 1

            import threading
            self._heartbeat_thread = threading.Thread(target=send_heartbeat)
            self._heartbeat_thread.setDaemon(True)
            self._heartbeat_thread.start()

    def log(self, msg):
        if self.is_integration:
            self.__do_no_res({'type': 'entryLog', 'args': {'message': 'Integration log: ' + msg}})
        else:
            self.__do_no_res({'type': 'entryLog', 'args': {'message': msg}})

    def investigation(self):
        return self.callingContext[u'context'][u'Inv']

    def incidents(self, incidents=None):
        if self.is_integration:
            self.results({'Type': 1, 'Contents': json.dumps(incidents), 'ContentsFormat': 'json'})
        else:
            return self.callingContext[u'context'][u'Incidents']

    def incident(self):
        if self.is_integration():
            return self.get_incidents()[0]
        else:
            return self.incidents()[0]

    def alerts(self):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'alerts')
        return self.incidents()

    def get_incidents(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'get_incidents')
        return self.callingContext[u'context'][u'Incidents']

    def get_alerts(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'get_alerts')
        return self.get_incidents()

    def alert(self):
        return self.incident()

    def parentEntry(self):
        return self.callingContext[u'context'][u'ParentEntry']

    def context(self):
        return self.callingContext[u'context'][u'ExecutionContext']

    def integrationInstance(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'integrationInstance')
        return self.callingContext[u'context'][u'IntegrationInstance']

    def args(self):
        return self._args

    def uniqueFile(self):
        return str(uuid.uuid4())

    def getFilePath(self, id):
        return self.__do({'type': 'getFileByEntryID', 'command': 'getFilePath', 'args': {'id': id}})

    def getLastRun(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getLastRun')
        return self.__do({'type': 'executeCommand', 'command': 'getLastRun', 'args': {}})

    def setLastRun(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setLastRun')
        return self.__do({'type': 'executeCommand', 'command': 'setLastRun', 'args': {'value': value}})

    def getLastMirrorRun(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getLastMirrorRun')
        return self.__do({'type': 'executeCommand', 'command': 'getLastMirrorRun', 'args': {}})

    def setLastMirrorRun(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setLastMirrorRun')
        return self.__do({'type': 'executeCommand', 'command': 'setLastMirrorRun', 'args': {'value': value}})

    def internalHttpRequest(self, method, uri, body=None):
        return self.__do({'type': 'executeCommand', 'command': 'internalHttpRequest',
                          'args': {'method': method, 'uri': uri, 'body': body}})

    def getIntegrationContext(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getIntegrationContext')
        resObj = self.__do({'type': 'executeCommand', 'command': 'getIntegrationContext', 'args': {'refresh': False}})
        return resObj['context']

    def setIntegrationContext(self, value):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setIntegrationContext')
        return self.__do({'type': 'executeCommand', 'command': 'setIntegrationContext',
                          'args': {'value': value, 'version': {"version": -1, "sequenceNumber": -1, "primaryTerm": -1},
                                   'sync': False}})

    def getIntegrationContextVersioned(self, refresh=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getIntegrationContextVersioned')
        return self.__do({'type': 'executeCommand', 'command': 'getIntegrationContext', 'args': {'refresh': refresh}})

    def setIntegrationContextVersioned(self, value, version, sync=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'setIntegrationContextVersioned')
        return self.__do({'type': 'executeCommand', 'command': 'setIntegrationContext',
                          'args': {'value': value, 'version': version, 'sync': sync}})

    def searchRelationships(self, filter=None):
        return self.__do({'type': 'executeCommand', 'command': 'searchRelationships', 'args': {'filter': filter}})

    def getLicenseID(self):
        return self.__do({'type': 'executeCommand', 'command': 'getLicenseID', 'args': {}})['id']

    def createIncidents(self, incidents, lastRun=None, userID=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createIncidents')
        return self.__do({'type': 'executeCommand', 'command': 'createIncidents',
                          'args': {'incidents': incidents, 'lastRun': lastRun, 'userID': userID}})

    def createAlerts(self, alerts, lastRun=None, userID=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createAlerts')
        return self.__do({'type': 'executeCommand', 'command': 'createAlerts',
                          'args': {'alerts': alerts, 'lastRun': lastRun, 'userID': userID}})

    def createIndicators(self, indicators, lastRun=None, noUpdate=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'createIndicators')
        return self.__do({'type': 'executeCommand', 'command': 'createIndicators',
                          'args': {'indicators': indicators, 'lastRun': lastRun, 'noUpdate': noUpdate}})

    def searchIndicators(self, value=None, query=None, size=None, page=None, sort=None, fromDate=None, toDate=None,
                         searchAfter=None, populateFields=None):
        return self.__do({'type': 'executeCommand', 'command': 'searchIndicators',
                          'args': {'value': value, 'query': query, 'size': size, 'page': page, 'sort': sort,
                                   'fromDate': fromDate, 'searchAfter': searchAfter, 'toDate': toDate,
                                   'populateFields': populateFields}})

    def getIndexHash(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getIndexHash')
        return self.__do({'type': 'executeCommand', 'command': 'getIndexHash'})

    def updateModuleHealth(self, err, is_error=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'updateModuleHealth')
        return self.__do(
            {'type': 'executeCommand', 'command': 'updateModuleHealth', 'args': {'err': err, 'isError': is_error}})

    def addEntry(self, id, entry, username=None, email=None, footer=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'addEntry')
        return self.__do({'type': 'executeCommand', 'command': 'addEntry', 'args': {'id': id, 'username': username,
                                                                                    'email': email, 'entry': entry,
                                                                                    'footer': footer}})

    def directMessage(self, message, username=None, email=None, anyoneCanOpenIncidents=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'directMessage')
        tmp = self.__do({'type': 'executeCommand', 'command': 'directMessage',
                         'args': {'message': message,
                                  'username': username,
                                  'email': email,
                                  'anyoneCanOpenIncidents': anyoneCanOpenIncidents,
                                  'anyoneCanOpenAlerts': anyoneCanOpenIncidents}})
        if tmp is not None:
            return tmp["res"]

    def mirrorInvestigation(self, id, mirrorType, autoClose=False):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'mirrorInvestigation')
        return self.__do({'type': 'executeCommand', 'command': 'mirrorInvestigation', 'args': {'id': id,
                                                                                               'mirrorType': mirrorType,
                                                                                               'autoClose': autoClose}})

    def findUser(self, username="", email=""):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'findUser')
        return self.__do(
            {'type': 'executeCommand', 'command': 'findUser', 'args': {'username': username, 'email': email}})

    def handleEntitlementForUser(self, incidentID, guid, email, content, taskID=""):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'handleEntitlementForUser')
        return self.__do({'type': 'executeCommand', 'command': 'handleEntitlementForUser',
                          'args': {'incidentID': incidentID, 'alertID': incidentID,
                                   'guid': guid, 'taskID': taskID, 'email': email, 'content': content}})

    def mapObject(self, sourceObject, mapper, mapperType=""):
        return self.__do({'type': 'executeCommand', 'command': 'mapObject',
                          'args': {'source': sourceObject, 'mapper': mapper, 'mapperType': mapperType}})

    def getAutoFocusApiKey(self):
        resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': 'autofocus'}})
        if resObj is not None:
            return resObj['value']

    def getLicenseCustomField(self, key):
        resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': key}})
        if resObj is not None:
            return resObj['value']

    def _apiCall(self, name, params=None, data=None):
        self.raise_exception_if_not_implemented(self.INTEGRATION, '_apiCall')
        return self.__do(
            {'type': 'executeCommand', 'command': '_apiCall', 'args': {'name': name, 'params': params, 'data': data}})

    def params(self):
        if self.is_integration:
            return self.callingContext.get(u'params', {})
        else:
            return {}

    def command(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'command')
        return self.callingContext.get(u'command', '')

    def isFetch(self):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'isFetch')
        """ used to encapsulate/hide 'fetch-incident' command from the code """
        return self.command() == 'fetch-incidents'

    def get(self, obj, field, defaultParam=None):
        """ Get the field from the given dict using dot notation """
        parts = field.split('.')
        for part in parts:
            if obj and part in obj:
                obj = obj[part]
            else:
                return defaultParam
        return obj

    def gets(self, obj, field):
        return str(self.get(obj, field))

    def getArg(self, arg, defaultParam=None):
        return self.get(self.callingContext, 'args.' + arg, defaultParam)

    def execute(self, module, command, args):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'execute')
        return self.__do({'type': 'execute', 'module': module, 'command': command.strip(), 'args': args})

    def executeCommand(self, command, args):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'executeCommand')
        return self.__do({'type': 'executeCommand', 'command': command.strip(), 'args': args})

    def demistoUrls(self):
        return self.__do({'type': 'demistoUrls'})

    def demistoVersion(self):
        return self.__do({'type': 'demistoVersion'})

    def heartbeat(self, msg):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'heartbeat')
        return self.__do_no_res({'type': 'executeCommand', 'command': 'heartbeat', 'args': {'message': msg}})

    def info(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'info', 'args': argsObj})

    def error(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'error', 'args': argsObj})

    def exception(self, ex):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'exception')
        return self.__do({'type': 'exception', 'command': 'exception', 'args': ex})

    def debug(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'debug', 'args': argsObj})

    def getAllSupportedCommands(self):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'getAllSupportedCommands')
        return self.__do({'type': 'getAllModulesSupportedCmds'})

    def getModules(self):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'getModules')
        return self.__do({'type': 'getAllModules'})

    def setContext(self, name, value):
        self.raise_exception_if_not_implemented(self.SCRIPT, 'setContext')
        return self.__do({'type': 'setContext', 'name': name, 'value': value})

    def getParam(self, p):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'getParam')
        return self.get(self.callingContext, 'params.' + p)

    def dt(self, data, q):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'dt')
        return self.__do({'type': 'dt', 'name': q, 'value': data})['result']

    def __do_lock(self, lock, timeout):
        if sys.version_info.major >= 3:
            return lock.acquire(timeout=timeout)
        else:
            # python 2 doesn't have timeout we use polling
            if timeout < 0:
                return lock.acquire()
            start = time.time()  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
            while (time.time() - start) < timeout:  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
                if lock.acquire(False):
                    return True
                time.sleep(0.1)  # type:ignore  [name-defined] # noqa: F821 # pylint: disable=E0602
            # didn't get the lock
            return False

    def __do_no_res(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\n')
            sys.stdout.flush()
        finally:
            if lock is not None:
                lock.release()

    def __do(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            # Watch out, there is a duplicate copy of this method
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\n')
            sys.stdout.flush()
            data = globals()['__readWhileAvailable']()
            error_index = data.find(SERVER_ERROR_MARKER)
            if error_index > -1:
                offset = error_index + len(SERVER_ERROR_MARKER)
                raise ValueError(data[offset:])
            return json.loads(data)
        finally:
            if lock is not None:
                lock.release()

    def convert(self, results):
        """ Convert whatever result into entry """
        self.raise_exception_if_not_implemented(self.SCRIPT, 'convert')
        if type(results) is dict:
            if 'Contents' in results and 'ContentsFormat' in results:
                return results
            else:
                return {'Type': 1, 'Contents': json.dumps(results), 'ContentsFormat': 'json'}
        if type(results) is list:
            res = []
            for r in results:
                res.append(self.convert(r))
            return res
        if sys.version_info.major >= 3 and type(results) is bytes:
            return {'Type': 1, 'Contents': results.decode('utf-8'), 'ContentsFormat': 'text'}
        return {'Type': 1, 'Contents': str(results), 'ContentsFormat': 'text'}

    def __convert(self, results):
        """ Convert whatever result into entry """
        self.raise_exception_if_not_implemented(self.INTEGRATION, '__convert')
        if type(results) is dict:
            if 'Contents' in results and 'ContentsFormat' in results:
                return results
            else:
                return {'Type': 1, 'Contents': json.dumps(results), 'ContentsFormat': 'json'}
        if type(results) is list:
            res = []
            for r in results:
                res.append(self.__convert(r))
            return res
        if sys.version_info.major >= 3 and type(results) is bytes:
            return {'Type': 1, 'Contents': results.decode('utf-8'), 'ContentsFormat': 'text'}
        return {'Type': 1, 'Contents': str(results), 'ContentsFormat': 'text'}

    def results(self, results):
        res = []
        if self.is_integration:
            converted = self.__convert(results)
        else:
            converted = self.convert(results)
        if type(converted) is list:
            res = converted
        else:
            res.append(converted)

        self.__do_no_res({'type': 'result', 'results': res})

    def fetchResults(self, incidents_or_alerts):
        """ used to encapsulate/hide 'incidents' from the code """
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'fetchResults')
        self.incidents(incidents_or_alerts)

    def credentials(self, credentials):
        self.raise_exception_if_not_implemented(self.INTEGRATION, 'credentials')
        self.results({'Type': 1, 'Contents': json.dumps(credentials), 'ContentsFormat': 'json'})


if "demisto" not in locals():
    try:
        # try except for CommonServerPython tests.
        demisto = Demisto(context)  # type:ignore [name-defined] # noqa: F821 # pylint: disable=E0602
    except NameError:
        pass

try:
    import __builtin__
    from StringIO import StringIO
except ImportError:
    # Python 3
    import builtins as __builtin__  # type:ignore[no-redef]
    from io import StringIO


def demisto_print(*args):
    global demisto
    output = StringIO()
    __builtin__.print(*args, file=output)
    result = output.getvalue().strip()
    demisto.log(result)     # pylint: disable=E9012


print = demisto_print
