class VM:
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



class Runtime:
    powerState = None


class Summary:
    guest = None
    runtime = None
    config = None

    def __init__(self, ipAddress=None, hostName=None, name='test_name', instanceUuid='12345'):
        self.config = Config(name, instanceUuid)
        self.guest = Guest(ipAddress, hostName)
        self.runtime = Runtime()





class Result:
    summary = Summary()
    snapshot = None


class Info:
    state = 'success'
    result = Result()


class Task:
    info = Info()
