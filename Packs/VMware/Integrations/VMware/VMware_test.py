# from vmware.vapi.vsphere.client import VsphereClient
from collections import namedtuple

import pytest
import VMware
from pyVmomi import vim
from VMware_test_classes import Si, VsphereClient, VM, VirtualMachineRelocateSpec, Task

category = namedtuple('category', ['name', 'id'])
tag = namedtuple('tag', ['name', 'id'])
vm = namedtuple('vm', ['name', 'id'])

PARAMS_GET_TAG = [
    ({'category': 'test1', 'tag': 'tag-test'}, '1'),
    ({'category': 'test1', 'tag': 'tag'}, None),
    ({'category': 'tet1', 'tag': 'tag'}, None)]


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


# def test_list_vms_by_tag(monkeypatch):
#     client = VsphereClient()
#     monkeypatch.setattr(VMware, 'get_tag', value=lambda tag_id: '1')
#     monkeypatch.setattr(client.tagging.TagAssociation, 'list_attached_objects', lambda tag_id, uuid: ['vm1', 'vm2'])


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


def test_relocate_vm(monkeypatch):
    si = Si()
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda uuid: VM())
    monkeypatch.setattr(VM, 'Destroy_Task', lambda this, spec, priority: Task())

    res = VMware.relocate_vm(si, {'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was deleted successfully.'
    assert {'UUID': '12345', 'Deleted': 'True'} in res.get('EntryContext').values()
