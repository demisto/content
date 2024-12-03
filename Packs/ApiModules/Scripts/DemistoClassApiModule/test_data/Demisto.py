class Demisto:
    def __init__(self, context, is_debug):
        self.callingContext = context
        self.is_debug = is_debug

    def debug(self, _):
        pass

    def results(self, _):
        pass

    def getFilePath(self, id):
        return {'id': id, 'path': 'test/test.txt', 'name': 'test.txt'}

    def executeCommand(self, *_):
        return [{"Type": 16}, {"Type": 4}]

    def getLastRun(self):
        return {"lastRun": "2018-10-24T14:13:20+00:00"}

    def setLastRun(self, _):
        pass

    def incidents(self, _):
        pass

    def createIndicators(self, *_):
        pass
