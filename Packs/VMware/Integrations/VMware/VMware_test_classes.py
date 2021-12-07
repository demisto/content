

class VM:
    def RelocateVM_Task(self):
        pass
    def Destroy_Task(self):
        pass


class Info:
    state = 'success'


class Task:
    info = Info()


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


class VsphereClient:
    tagging = Tagging()


class Si:
    def RetrieveContent(self):
        pass


class VirtualMachineRelocateSpec:
    folder = None
    host = None
    pool = None
    datastore = None
    disks = None

