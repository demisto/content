class Runtime:
    powerState = None

    def __init__(self, powerState):
        self.powerState = powerState


class VM:
    runtime = None

    def __init__(self, powerState='poweredOn'):
        self.runtime = Runtime(powerState)

    def RelocateVM_Task(self):
        pass

    def Destroy_Task(self):
        pass

    def UnregisterVM(self):
        pass

    def CloneVM_Task(self):
        pass

    def list(self):
        pass

    def FilterSpec(self):
        pass

    def PowerOn(self):
        pass

    def PowerOff(self):
        pass

    def Suspend(self):
        pass

    def ResetVM_Task(self):
        pass

    def RebootGuest(self):
        pass

    def CreateSnapshot(self):
        pass


class Folder:
    def RegisterVM_Task(self):
        pass

    def CreateVM_Task(self):
        pass


class Category:
    def __init__(self):
        pass

    def list(self):
        pass

    def get(self):
        pass


class Tag:
    def list_tags_for_category(self):
        pass

    def get(self):
        pass


class TagAssociation:
    def attach(self):
        pass

    def list_attached_objects(self):
        pass


class Tagging:
    Category = Category()
    Tag = Tag()
    TagAssociation = TagAssociation()


class Vcenter:
    VM = VM()


class VsphereClient:
    tagging = Tagging()
    vcenter = Vcenter()


class Si:
    def RetrieveContent(self):
        pass

    def RetrieveServiceContent(self):
        pass


class VirtualMachineRelocateSpec:
    folder = None
    host = None
    pool = None
    datastore = None
    disks = None


class CloneSpec:
    location = None
    template = False
    powerOn = False


# cloning

class Config:
    template = None
    vmPathName = None
    guestFullName = None
    instanceUuid = None
    powerState = None
    name = None
    uuid = None

    def __init__(self, name, instanceUuid):
        self.name = name
        self.instanceUuid = instanceUuid


class Guest:
    ipAddress = None
    hostName = None

    def __init__(self, ipAddress, hostName):
        self.ipAddress = ipAddress
        self.hostName = hostName


class Summary:
    guest = None
    runtime = None
    config = None

    def __init__(self, ipAddress=None, hostName=None, name='test_name', instanceUuid='12345'):
        self.config = Config(name, instanceUuid)
        self.guest = Guest(ipAddress, hostName)
        self.runtime = Runtime('poweredOff')


class Result:
    summary = Summary()
    snapshot = None


class Info:
    state = 'success'
    result = Result()


class Task:
    info = Info()


class Child:
    summary = Summary()
    snapshot = None

    def __init__(self, summary):
        self.summary = summary


class ViewManager:
    view = None

    def __init__(self, children):
        self.view = children

    def CreateContainerView(self):
        pass


class EventManager:
    def QueryEvents(self):
        pass


class Content:
    viewManager = ViewManager({})
    eventManager = EventManager()
    rootFolder = None


class Snapshot:
    name = None
    childSnapshotList = None

    def __init__(self, name, childSnapshotList):
        self.name = name
        self.childSnapshotList = childSnapshotList


class Datastore:
    name = None

    def __init__(self, name):
        self.name = name


class Host:
    datastore = []

    def __init__(self, names):
        for name in names:
            self.datastore.append(Datastore(name))


class ConfigSpec:
    name = None
    numCPUs = None
    cpuAllocation = None
    memoryAllocation = None
    memoryMB = None
    files = None
    guestId = None

class FileInfo:
    vmPathName = None

class ResourceAllocationInfo:
    limit = None

class FilterSpec:
    eventTypeId = None
    entity = None
    time = None
    userName = None
    maxCount = None
