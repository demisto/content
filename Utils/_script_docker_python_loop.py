import os
import threading
import sys
import json
import traceback

if sys.version_info[0] < 3:
    import Queue as queue
else:
    import queue

__read_thread = None
__input_queue = None

win = sys.platform.startswith('win')
if win:
    __input_queue = queue.Queue()


def read_input_loop():
    global __input_queue
    while True:
        line = sys.stdin.readline()
        __input_queue.put(line)
        if line == '':
            break


def __readWhileAvailable():
    if win:
        # An ugly solution - just open a blocking thread to handle input
        global __input_queue
        global __read_thread
        if not __read_thread:
            __read_thread = threading.Thread(target=read_input_loop)
            __read_thread.daemon = True
            __read_thread.start()
        buff = ''
        # Now, read from the queue. First read we block and wait and then wait for timeout.
        buff += __input_queue.get()
        return buff
    else:
        # Wait for the first char from stdin
        buff = sys.stdin.readline()
        # While available, read all the other chars
        return buff


"""Demisto instance for scripts only"""

template_code = '''
from __future__ import print_function
import json
import uuid
import sys

class Demisto:
    """Wrapper class to interface with the Demisto server via stdin, stdout"""

    def __init__(self, context):
        self.callingContext = context
        args = self.args()
        if 'demisto_machine_learning_magic_key' in  args:
            import os
            os.environ['DEMISTO_MACHINE_LEARNING_MAGIC_KEY'] = args['demisto_machine_learning_magic_key']

    def log(self, msg):
        json.dump({'type': 'entryLog', 'args': {'message': msg}}, sys.stdout)
        sys.stdout.write('\\n')
        sys.stdout.flush()

    def investigation(self):
        return self.callingContext[u'context'][u'Inv']

    def incidents(self):
        return self.callingContext[u'context'][u'Incidents']

    def parentEntry(self):
        return self.callingContext[u'context'][u'ParentEntry']

    def context(self):
        return self.callingContext[u'context'][u'ExecutionContext']

    def args(self):
        return self.callingContext.get(u'args', {})

    def uniqueFile(self):
        return str(uuid.uuid4())

    def getFilePath(self, id):
        return self.__do({'type': 'getFileByEntryID', 'command': 'getFilePath', 'args': {'id': id}})

    def getLicenseID(self):
        return self.__do({'type': 'executeCommand', 'command': 'getLicenseID', 'args': {}})['id']

    def get(self, obj, field):
        """ Get the field from the given dict using dot notation """
        parts = field.split('.')
        for part in parts:
            if obj and part in obj:
                obj = obj[part]
            else:
                return None
        return obj

    def gets(self, obj, field):
        return str(self.get(obj, field))

    def getArg(self, arg):
        return self.get(self.callingContext, 'args.' + arg)

    def execute(self, module, command, args):
        return self.__do({'type': 'execute', 'module': module, 'command': command.strip(), 'args': args})

    def executeCommand(self, command, args):
        return self.__do({'type': 'executeCommand', 'command': command.strip(), 'args': args})

    def demistoUrls(self):
        return self.__do({'type': 'demistoUrls'})

    def info(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'info', 'args': argsObj})

    def error(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'error', 'args': argsObj})

    def exception(self, ex):
        return self.__do({'type': 'exception', 'command': 'exception', 'args': ex})

    def debug(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'debug', 'args': argsObj})

    def getAllSupportedCommands(self):
        return self.__do({'type': 'getAllModulesSupportedCmds'})

    def getModules(self):
        return self.__do({'type': 'getAllModules'})

    def setContext(self, name, value):
        return self.__do({'type': 'setContext', 'name': name, 'value': value})

    def dt(self, data, q):
        return self.__do({'type': 'dt', 'name': q, 'value': data})['result']

    def __do(self, cmd):
        # Watch out there is another defintion like this
        # prepare command to send to server
        json.dump(cmd, sys.stdout)
        sys.stdout.write('\\n')

        # send command to Demisto server
        sys.stdout.flush()

        # wait to receive response from Demisto server
        data = globals()['__readWhileAvailable']()
        if data.find('$$##') > -1:
            raise ValueError(data[4:])
        return json.loads(data)


    def convert(self, results):
        """ Convert whatever result into entry """
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


    def results(self, results):
        res = []
        converted = self.convert(results)
        if type(converted) is list:
            res = converted
        else:
            res.append(converted)

        json.dump({'type': 'result', 'results': res}, sys.stdout)
        sys.stdout.write('\\n')
        sys.stdout.flush()

demisto = Demisto(context)

try:
    import __builtin__
    from StringIO import StringIO
except ImportError:
    # Python 3
    import builtins as __builtin__
    from io import StringIO

def demisto_print(*args):
    global demisto
    output = StringIO()
    __builtin__.print(*args, file=output)
    result = output.getvalue().strip()
    demisto.log(result)

print = demisto_print

###CODE_HERE###
'''

"""Demisto instance for integrations only"""

integ_template_code = '''
from __future__ import print_function
import json
import uuid
import sys

class Demisto:
    """Wrapper class to interface with the Demisto server via stdin, stdout"""

    def __init__(self, context):
        self.callingContext = context
        args = self.args()
        if 'demisto_machine_learning_magic_key' in  args:
            import os
            os.environ['DEMISTO_MACHINE_LEARNING_MAGIC_KEY'] = args['demisto_machine_learning_magic_key']

    def log(self, msg):
        json.dump({'type': 'entryLog', 'args': {'message': 'Integration log: ' + msg}}, sys.stdout)
        sys.stdout.write('\\n')
        sys.stdout.flush()

    def investigation(self):
        return self.callingContext[u'context'][u'Inv']

    def incidents(self):
        return self.callingContext[u'context'][u'Incidents']

    def parentEntry(self):
        return self.callingContext[u'context'][u'ParentEntry']

    def context(self):
        return self.callingContext[u'context'][u'ExecutionContext']

    def integrationInstance(self):
        return self.callingContext[u'context'][u'IntegrationInstance']

    def args(self):
        return self.callingContext.get(u'args', {})

    def uniqueFile(self):
        return str(uuid.uuid4())

    def getFilePath(self, id):
        return self.__do({'type': 'getFileByEntryID', 'command': 'getFilePath', 'args': {'id': id}})

    def getLastRun(self):
        return self.__do({'type': 'executeCommand', 'command': 'getLastRun', 'args': {}})

    def setLastRun(self, value):
        return self.__do({'type': 'executeCommand', 'command': 'setLastRun', 'args': {'value': value}})

    def getIntegrationContext(self):
        return self.__do({'type': 'executeCommand', 'command': 'getIntegrationContext', 'args': {}})

    def setIntegrationContext(self, value):
        return self.__do({'type': 'executeCommand', 'command': 'setIntegrationContext', 'args': {'value': value}})

    def getLicenseID(self):
            return self.__do({'type': 'executeCommand', 'command': 'getLicenseID', 'args': {}})['id']

    def params(self):
        return self.callingContext.get(u'params', {})

    def command(self):
        return self.callingContext.get(u'command', '')

    def get(self, obj, field):
        """ Get the field from the given dict using dot notation """
        parts = field.split('.')
        for part in parts:
            if obj and part in obj:
                obj = obj[part]
            else:
                return None
        return obj

    def demistoUrls(self):
        return self.__do({'type': 'demistoUrls'})

    def info(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'info', 'args': argsObj})

    def error(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'error', 'args': argsObj})

    def debug(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'debug', 'args': argsObj})

    def gets(self, obj, field):
        return str(self.get(obj, field))

    def getArg(self, arg):
        return self.get(self.callingContext, 'args.' + arg)

    def getParam(self, p):
        return self.get(self.callingContext, 'params.' + p)

    def dt(self, data, q):
        return self.__do({'type': 'dt', 'name': q, 'value': data})['result']

    def __do(self, cmd):
        # Watch out there is another defintion like this
        json.dump(cmd, sys.stdout)
        sys.stdout.write('\\n')
        sys.stdout.flush()
        data = globals()['__readWhileAvailable']()
        if data.find('$$##') > -1:
            raise ValueError(data[4:])
        return json.loads(data)

    def __convert(self, results):
        """ Convert whatever result into entry """
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
        converted = self.__convert(results)
        if type(converted) is list:
            res = converted
        else:
            res.append(converted)
        json.dump({'type': 'result', 'results': res}, sys.stdout)
        sys.stdout.write('\\n')
        sys.stdout.flush()

    def incidents(self, incidents):
        self.results({'Type': 1, 'Contents': json.dumps(incidents), 'ContentsFormat': 'json'})

    def credentials(self, credentials):
        self.results({'Type': 1, 'Contents': json.dumps(credentials), 'ContentsFormat': 'json'})

demisto = Demisto(context)

try:
    import __builtin__
    from StringIO import StringIO
except ImportError:
    # Python 3
    import builtins as __builtin__
    from io import StringIO

def demisto_print(*args):
    global demisto
    output = StringIO()
    __builtin__.print(*args, file=output)
    result = output.getvalue().strip()
    demisto.log(result)

print = demisto_print

###CODE_HERE###
'''

# rollback file system to its previous state
# delete home dir and tmp dir


# notifies demisto server that the current executed script is completed
# and the process is ready to execute the next script
def send_script_completed():
    json.dump({'type': 'completed'}, sys.stdout)
    sys.stdout.write('\\n')
    sys.stdout.flush()


def send_script_exception(exc_type, exc_value, exc_traceback):
    ex_string = traceback.format_exception(exc_type, exc_value, exc_traceback)
    if ex_string == 'None\n':
        ex_string = str(ex)

    json.dump({'type': 'exception', 'args': {'exception': ex_string}}, sys.stdout)
    sys.stdout.write('\\n')
    sys.stdout.flush()


def send_pong():
    json.dump({'type': 'pong'}, sys.stdout)
    sys.stdout.write('\\n')
    sys.stdout.flush()


# receives ping and sends back pong until we get something else
# the the function stopped and returns the received string
def do_ping_pong():
    while True:
        ping = __readWhileAvailable()
        if ping == 'ping\n':
            send_pong()  # return pong to server to indicate that everything is fine
        else:
            return ping


backup_env_vars = {}
for key in os.environ.keys():
    backup_env_vars[key] = os.environ[key]


def rollback_system():
    os.environ = {}
    for key in backup_env_vars.keys():
        os.environ[key] = backup_env_vars[key]


while True:
    contextString = do_ping_pong()
    if contextString == '':
        # finish executing python
        break

    contextJSON = json.loads(contextString)

    code_string = contextJSON['script']
    contextJSON.pop('script', None)

    is_integ_script = contextJSON['integration']
    complete_code = ''
    if is_integ_script:
        complete_code = integ_template_code.replace('###CODE_HERE###', code_string)
    else:
        complete_code = template_code.replace('###CODE_HERE###', code_string)

    try:
        code = compile(complete_code, '<string>', 'exec')

        sub_globals = {
            '__readWhileAvailable': __readWhileAvailable,
            'context': contextJSON,
            'win': win
        }

        exec(code, sub_globals, sub_globals)  # guardrails-disable-line

    except Exception as ex:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        send_script_exception(exc_type, exc_value, exc_traceback)
    except SystemExit:
        # print 'Will not stop on sys.exit(0)'
        pass

    rollback_system()

    # ping back to Demisto server that script is completed
    send_script_completed()

    # if the script running on native python then terminate the process after finished the script
    is_python_native = contextJSON['native']
    if is_python_native:
        break


if __read_thread:
    __read_thread.join(timeout=1)
