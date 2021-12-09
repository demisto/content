import pytest
import VMware
from collections import namedtuple
from pyVmomi import vim
from VMwaretestclasses import Si, VsphereClient, VM, VirtualMachineRelocateSpec, Task, Folder, CloneSpec, Summary

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


def test_add_tag(monkeypatch):
    client = VsphereClient()
    monkeypatch.setattr(VMware, 'get_tag', value=lambda tag_id: '1')
    monkeypatch.setattr(client.tagging.TagAssociation, 'attach', lambda tag_id, uuid: None)

    res = VMware.add_tag(client, {'uuid': '1', 'tag': 'test', 'category': 'test'})
    assert 'test' in res.get('HumanReadable')


def test_list_vms_by_tag(monkeypatch):
    client = VsphereClient()
    objs = [obj('vm1', '1', 'VirtualMachine'),
            obj('vm2', '2', 'VirtualMachine'),
            obj('not_vm', '3', 'not_vm')]
    monkeypatch.setattr(VMware, 'get_tag', value=lambda tag_id: '1')
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


def test_clone_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(vim.vm, 'CloneSpec', lambda: CloneSpec())
    monkeypatch.setattr(vim.vm, 'RelocateSpec', lambda: VirtualMachineRelocateSpec())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda uuid: VM())
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
    monkeypatch.setattr(VMware, 'get_vm', lambda uuid: VM())
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: obj)
    monkeypatch.setattr(VM, 'RelocateVM_Task', lambda this, spec, priority: Task())

    res = VMware.relocate_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool', 'datastore': None})
    assert res.get('HumanReadable') == 'Virtual Machine was relocated successfully.'


def test_delete_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda uuid: VM())
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
    monkeypatch.setattr(VMware, 'get_vm', lambda uuid: VM())
    monkeypatch.setattr(VM, 'UnregisterVM', lambda this: None)

    res = VMware.unregister_vm({'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was unregistered successfully.'
