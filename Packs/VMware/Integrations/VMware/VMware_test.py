import pyVim.task
import pytest
from mock.mock import patch

import VMware
from collections import namedtuple
from pyVmomi import vim
from VMwaretestclasses import Si, VsphereClient, VM, VirtualMachineRelocateSpec, Task, Folder, CloneSpec, Summary, \
    Content, Child, ViewManager, Snapshot, Host, ConfigSpec, FileInfo, ResourceAllocationInfo, EventManager

# sys.modules['vmware.vapi.vsphere.client'] = MagicMock()
# sys.modules['com.vmware.vapi.std_client'] = MagicMock()

category = namedtuple('category', ['name', 'id'])
tag = namedtuple('tag', ['name', 'id'])
obj = namedtuple('obj', ['name', 'id', 'type'])

PARAMS_GET_TAG = [
    ({'category': 'test1', 'tag': 'tag-test'}, '1'),
    ({'category': 'test1', 'tag': 'tag'}, None),
    ({'category': 'tet1', 'tag': 'tag'}, None)]

PARAMS_GET_VM_FILTERS = [
    ({'ip': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'name': None, 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'name': 'test_vm', 'uuid': None, 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': None, 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': None},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': None, 'name': 'test_vm', 'uuid': '12345', 'hostname': None},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '1234', 'hostname': 'test_host'},
     False),
    ({'ip': '1111', 'name': 'test_vm', 'uuid': None, 'hostname': None},
     {'ipAddress': '1111', 'name': 'tet_vm', 'uuid': '12345', 'hostname': 'test_host'},
     False),
    ({'ip': '1111', 'name': 'test_vm', 'uuid': None, 'hostname': None},
     {'ipAddress': '111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     False)
]

PARAMS_GET_VMS = [
    ({'ip': '1111', 'name': 'test_vm1', 'uuid': '12341', 'hostname': 'test_host1'}),
    ({'ip': '2222', 'name': 'test_vm2', 'uuid': '12342', 'hostname': 'test_host2'}),
    ({'ip': '3333', 'name': 'test_vm3', 'uuid': '12343', 'hostname': 'test_host3'})
]

PARAMS_CREATE_SNAPSHOT = [({'vm-uuid': '12345', 'memory': 'True', 'quiesce': 'True'}),
                          {'vm-uuid': '12345', 'memory': 'False', 'quiesce': 'False'}]

PARAMS_GET_SNAPSHOTS = [
    ([Snapshot('test1', [Snapshot('test3', [])]), Snapshot('test2', [])], 'test2', [Snapshot('test2', [])]),
    ([Snapshot('test1', [Snapshot('test3', [])]), Snapshot('test2', [])], 'test3', [Snapshot('test3', [])]),
    ([Snapshot('test1', [Snapshot('test3', [])]), Snapshot('test2', [])], 'test1',
     [Snapshot('test1', [Snapshot('test3', [])])]),
    ([Snapshot('test1', [Snapshot('test3', [])]), Snapshot('test2', [])], 'test4', [])]


def create_children():
    return [Child(Summary(args.get('ip'), args.get('hostname'), args.get('name'), args.get('uuid'))) for args in
            PARAMS_GET_VMS]


@pytest.mark.parametrize('args, params, res', PARAMS_GET_VM_FILTERS)
def test_apply_get_vms_filters(args, params, res):
    summary = Summary(params.get('ipAddress'), params.get('hostname'), params.get('name'), params.get('uuid'))
    assert VMware.apply_get_vms_filters(args, summary) == res


@pytest.mark.parametrize('args, res', PARAMS_GET_TAG)
def test_get_tag(monkeypatch, args, res):
    client = VsphereClient()
    monkeypatch.setattr(client.tagging.Category, 'list', lambda: ['test1'])
    monkeypatch.setattr(client.tagging.Category, "get", lambda cat: category('test1', '1'))
    monkeypatch.setattr(client.tagging.Tag, "list_tags_for_category", lambda cat: ['tag-test'])
    monkeypatch.setattr(client.tagging.Tag, "get", lambda tag_name: tag('tag-test', '1'))

    assert VMware.get_tag(client, args) == res


def test_create_vm_config_creator(monkeypatch):
    monkeypatch.setattr(vim.vm, 'ConfigSpec', lambda: ConfigSpec())
    monkeypatch.setattr(vim.vm, 'FileInfo', lambda: FileInfo())
    monkeypatch.setattr(vim, 'ResourceAllocationInfo', lambda: ResourceAllocationInfo())

    args = {
        'name': 'test1',
        'cpu-allocation': '2',
        'memory': '32',
        'cpu-num': '4',
        'virtual-memory': '32',
        '': '1'
    }
    res = VMware.create_vm_config_creator(Host(['test1', 'test2']), args)

    assert res.name == args.get('name')
    assert res.numCPUs == int(args.get('cpu-num'))
    assert res.cpuAllocation.limit == int(args.get('cpu-allocation'))
    assert res.memoryAllocation.limit == int(args.get('memory'))
    assert res.memoryMB == int(args.get('virtual-memory'))
    assert res.files.vmPathName == '[test1]test1'
    assert res.guestId == args.get('guestId')


# def test_add_tag(monkeypatch):
#     client = VsphereClient()
#     monkeypatch.setattr(VMware, 'get_tag', value=lambda tag_id: '1')
#     monkeypatch.setattr(client.tagging.TagAssociation, 'attach', lambda tag_id, uuid: None)
#
#     res = VMware.add_tag(client, {'uuid': '1', 'tag': 'test', 'category': 'test'})
#     assert 'test' in res.get('HumanReadable')


def test_list_vms_by_tag(monkeypatch):
    client = VsphereClient()
    objs = [obj('vm1', '1', 'VirtualMachine'),
            obj('vm2', '2', 'VirtualMachine'),
            obj('not_vm', '3', 'not_vm')]
    monkeypatch.setattr(VMware, 'get_tag', value=lambda v_client, tag_id: '1')
    monkeypatch.setattr(client.tagging.TagAssociation, 'list_attached_objects',
                        lambda tag_name: objs)
    monkeypatch.setattr(client.vcenter.VM, 'FilterSpec', lambda vms: vms)
    monkeypatch.setattr(client.vcenter.VM, 'list',
                        lambda vms: [obj('vm' + vm_id, vm_id, 'VirtualMachine') for vm_id in vms])

    res = VMware.list_vms_by_tag(client, {'tag': 'test_tag', 'category': 'test_category'})

    assert len(res.get('Contents')) == 2
    assert 'Virtual Machines with Tag test_tag' in res.get('HumanReadable')


def test_create_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'create_vm_config_creator', lambda host, args: {})
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: Folder())
    monkeypatch.setattr(Folder, 'CreateVM_Task', lambda this, config, pool, host: Task())

    res = VMware.create_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool'})

    data = res.get('Contents')
    assert data.get('Name') == 'test_name'
    assert data.get('Deleted') == 'False'
    assert 'Virtual Machine' in res.get('HumanReadable')


def test_get_vms(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: Content())
    monkeypatch.setattr(ViewManager, 'CreateContainerView',
                        lambda this, container, view_type, recursive: ViewManager(create_children()))
    monkeypatch.setattr(VMware, 'apply_get_vms_filters', lambda args, summary: True)

    res = VMware.get_vms(si, {})

    data = res.get('Contents')
    for i in range(0, len(PARAMS_GET_VMS)):
        args = PARAMS_GET_VMS[i]
        assert data[i].get('Name') == args.get('name')
        assert data[i].get('IP') == args.get('ip')
        assert data[i].get('HostName') == args.get('hostname')
        assert data[i].get('UUID') == args.get('uuid')
        assert data[i].get('Deleted') == 'False'
    assert 'Virtual Machines' in res.get('HumanReadable')


def test_clone_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(vim.vm, 'CloneSpec', lambda: CloneSpec())
    monkeypatch.setattr(vim.vm, 'RelocateSpec', lambda: VirtualMachineRelocateSpec())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: obj)
    monkeypatch.setattr(VM, 'CloneVM_Task', lambda this, folder, name, spec: Task())

    res = VMware.clone_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool',
                               'datastore': 'test_datastore', 'template': False, 'powerOn': False, 'uuid': '12345'})
    data = res.get('Contents')
    assert data.get('Name') == 'test_name'
    assert data.get('Deleted') == 'False'
    assert 'Virtual Machine' in res.get('HumanReadable')


def test_relocate_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(vim, 'VirtualMachineRelocateSpec', lambda: VirtualMachineRelocateSpec())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: obj)
    monkeypatch.setattr(VM, 'RelocateVM_Task', lambda this, spec, priority: Task())

    res = VMware.relocate_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool', 'datastore': None})
    assert res.get('HumanReadable') == 'Virtual Machine was relocated successfully.'


def test_delete_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'Destroy_Task', lambda this: Task())

    res = VMware.delete_vm(si, {'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was deleted successfully.'
    assert {'UUID': '12345', 'Deleted': 'True'} in res.get('EntryContext').values()


def test_register_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(vim, 'VirtualMachineRelocateSpec', lambda: VirtualMachineRelocateSpec())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: Folder())
    monkeypatch.setattr(Folder, 'RegisterVM_Task', lambda this, path, name, asTemplate, pool, host: Task())

    res = VMware.register_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool', 'path': None,
                                  'asTemplate': False})
    assert res.get('HumanReadable') == 'Virtual Machine was registered successfully.'


def test_unregister_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'UnregisterVM', lambda this: None)

    res = VMware.unregister_vm(si, {'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was unregistered successfully.'


def test_power_on(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOff'))
    monkeypatch.setattr(VM, 'PowerOn', lambda this: Task())

    res = VMware.power_on(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'poweredOn'
    assert res.get('HumanReadable') == 'Virtual Machine was powered on successfully.'


def test_power_off(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOn'))
    monkeypatch.setattr(VM, 'PowerOff', lambda this: Task())

    res = VMware.power_off(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'poweredOff'
    assert res.get('HumanReadable') == 'Virtual Machine was powered off successfully.'


def test_suspend(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOn'))
    monkeypatch.setattr(VM, 'Suspend', lambda this: Task())

    res = VMware.suspend(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'suspended'
    assert res.get('HumanReadable') == 'Virtual Machine was suspended successfully.'


def test_hard_reboot(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'ResetVM_Task', lambda this: Task())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)

    res = VMware.hard_reboot(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'HardRebooted'
    assert res.get('HumanReadable') == 'Virtual Machine was rebooted successfully.'


def test_soft_reboot(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'RebootGuest', lambda this: None)

    res = VMware.soft_reboot(si, {'uuid': '12345'})

    assert res == 'A request to reboot the guest has been sent.'


@pytest.mark.parametrize('args', PARAMS_CREATE_SNAPSHOT)
def test_create_snapshot(monkeypatch, args):
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'CreateSnapshot', lambda this, name, description, memory, quiesce: Task())
    monkeypatch.setattr(pyVim.task, 'WaitForTask', lambda task: None)

    res = VMware.create_snapshot(si, args)

    assert 'Snapshot 12345' in res


@pytest.mark.parametrize('snapshots, snapname, res', PARAMS_GET_SNAPSHOTS)
def test_get_snapshots(monkeypatch, snapshots, snapname, res):
    result = VMware.get_snapshots(snapshots, snapname)
    if len(result) > 0:
        assert result[0].name == res[0].name
        assert len(result[0].childSnapshotList) == len(res[0].childSnapshotList)
    else:
        assert len(res) == 0


def test_get_events(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveServiceContent', lambda: Content())
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOn'))
    monkeypatch.setattr(EventManager, 'QueryEvents', lambda: Content())
    monkeypatch.setattr(vim.event.EventFilterSpec, 'QueryEvents', lambda: Content())

    monkeypatch.setattr(ViewManager, 'CreateContainerView',
                        lambda this, container, view_type, recursive: ViewManager(create_children()))
    monkeypatch.setattr(VMware, 'apply_get_vms_filters', lambda args, summary: True)

    res = VMware.get_vms(si, {})