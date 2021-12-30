import pyVim.task
import pytest
import VMware
from datetime import datetime
from collections import namedtuple
from pyVmomi import vim
from test_data.VMwaretestclasses import Si, VsphereClient, VM,\
    VirtualMachineRelocateSpec, Task, Folder, CloneSpec, Summary, \
    Content, Child, ViewManager, Snapshot, Host, ConfigSpec, FileInfo, ResourceAllocationInfo, EventManager, \
    Event

category = namedtuple('category', ['name', 'id'])
tag = namedtuple('tag', ['name', 'id'])
obj = namedtuple('obj', ['name', 'id', 'type'])

PARAMS_GET_TAG = [
    ({'category': 'test1', 'tag': 'tag-test'}, '1'),
    ({'category': 'test1', 'tag': 'tag'}, None),
    ({'category': 'tet1', 'tag': 'tag'}, None)]

PARAMS_GET_VM_FILTERS = [
    ({'ip': '1111', 'vm_name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'vm_name': None, 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'vm_name': 'test_vm', 'uuid': None, 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': None, 'vm_name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': '1111', 'vm_name': 'test_vm', 'uuid': '12345', 'hostname': None},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '12345', 'hostname': 'test_host'},
     True),
    ({'ip': None, 'vm_name': 'test_vm', 'uuid': '12345', 'hostname': None},
     {'ipAddress': '1111', 'name': 'test_vm', 'uuid': '1234', 'hostname': 'test_host'},
     False),
    ({'ip': '1111', 'vm_name': 'test_vm', 'uuid': None, 'hostname': None},
     {'ipAddress': '1111', 'name': 'tet_vm', 'uuid': '12345', 'hostname': 'test_host'},
     False),
    ({'ip': '1111', 'vm_name': 'test_vm', 'uuid': None, 'hostname': None},
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

EVENTS = [
    {'key': '1', 'message': 'reboot VM', 'user_name': 'test_user',
     'created_time': datetime(2021, 12, 16, 10, 10, 10)},
    {'key': '2', 'message': 'shutdown VM', 'user_name': 'test_user2',
     'created_time': datetime(2021, 12, 15, 10, 10, 10)},
    {'key': '3', 'message': 'hard reboot VM', 'user_name': 'test_user',
     'created_time': datetime(2021, 12, 13, 10, 10, 10)}
]

PARAMS_GET_EVENTS = [
    ({'vm-uuid': '123', 'user': 'test_user,test_user2', 'start_date': '2019-10-23T00:00:00',
      'end_date': '2021-12-16T12:00:00', 'event-type': '', 'limit': '50'},
     EVENTS,
     3),
    ({'vm-uuid': '123', 'user': 'test_user', 'start_date': '2019-10-23T00:00:00',
      'end_date': '2021-12-16T12:00:00', 'event-type': '', 'limit': '50'},
     [EVENTS[0], EVENTS[2]],
     2),
    ({'vm-uuid': '123', 'user': 'test_user2', 'start_date': '2019-10-23T00:00:00',
      'end_date': '2021-12-16T12:00:00', 'event-type': 'reboot VM', 'limit': '50'},
     [EVENTS[1]],
     1)
]

PARAMS_GET_PRIORITY = [
    ("highPriority", vim.VirtualMachine.MovePriority().highPriority),
    ("lowPriority", vim.VirtualMachine.MovePriority().lowPriority),
    ("defualt", vim.VirtualMachine.MovePriority().defaultPriority)
]

ARG_LIST = [({'limit': '2', 'page_size': '3'}, 2, False, 3),
            ({'page_size': '3', 'page': '4'}, 12, True, 3),
            ({}, 50, False, None)]

PARAMS_PARSE = [
    ({'url': 'test.com:443', 'credentials': {'identifier': 'test', 'password': 'testpass'}}, 'test.com:443',
     'test.com', '443', 'test', 'testpass'),
    ({'url': 'https://test.com:443', 'credentials': {'identifier': 'test', 'password': 'testpass'}},
     'https://test.com:443', 'https://test.com', '443', 'test', 'testpass')
]


def create_children():
    return [Child(Summary(args.get('ip'), args.get('hostname'), args.get('name'), args.get('uuid'))) for args in
            PARAMS_GET_VMS]


def create_events(events_list):
    return [Event(args.get('key'), args.get('message'), args.get('user_name'), args.get('created_time')) for args in
            events_list]


@pytest.mark.parametrize('params, full_url, url, port, username, password', PARAMS_PARSE)
def test_parse_params(params, full_url, url, port, username, password):
    """
       Given:
           - Instance parameters.

       When:
           - Connecting to vcenter.

       Then:
           - Make sure that parameters parsed correctly.
   """
    full_url_from_func, url_from_func, port_from_func, user_name_from_func, password_from_func = VMware.parse_params(
        params)
    assert full_url_from_func == full_url
    assert url_from_func == url
    assert port_from_func == port
    assert user_name_from_func == username
    assert password_from_func == password


@pytest.mark.parametrize('args, limit, is_manual, page_size', ARG_LIST)
def test_get_limit(args, limit, is_manual, page_size):
    """
       Given:
           - pagination arguments.

       When:
           - Running a list command.

       Then:
           - Make sure that the correct amount of results to display is returned.
   """
    res_limit, res_is_manual, res_page_size = VMware.get_limit(args)

    assert res_limit == limit
    assert res_is_manual == is_manual
    assert res_page_size == page_size


@pytest.mark.parametrize('input_val, output', PARAMS_GET_PRIORITY)
def test_get_priority(input_val, output):
    """
       Given:
           - Priority string.

       When:
           - Running a relocate command

       Then:
           - Make sure a correct vmware priority object is returned.
       """
    assert VMware.get_priority(input_val) == output


@pytest.mark.parametrize('args, params, res', PARAMS_GET_VM_FILTERS)
def test_apply_get_vms_filters(args, params, res):
    """
       Given:
           - Filter argumnets.

       When:
           - Running a get-vms command

       Then:
           - Make sure only vms containing filter values returned.
   """
    summary = Summary(params.get('ipAddress'), params.get('hostname'), params.get('name'), params.get('uuid'))
    assert VMware.apply_get_vms_filters(args, summary) == res


@pytest.mark.parametrize('args, res', PARAMS_GET_TAG)
def test_get_tag(monkeypatch, args, res):
    """
       Given:
           - Tag and Category name.

       When:
           - Running a tag related command.

       Then:
           - Make sure a correct tag is returned, or None if tag does not exist.
   """
    client = VsphereClient()
    monkeypatch.setattr(client.tagging.Category, 'list', lambda: ['test1'])
    monkeypatch.setattr(client.tagging.Category, "get", lambda cat: category('test1', '1'))
    monkeypatch.setattr(client.tagging.Tag, "list_tags_for_category", lambda cat: ['tag-test'])
    monkeypatch.setattr(client.tagging.Tag, "get", lambda tag_name: tag('tag-test', '1'))

    assert VMware.get_tag(client, args) == res


def test_create_vm_config_creator(monkeypatch):
    """
       Given:
           - Create VM argumnets.

       When:
           - Running a create-vm command

       Then:
           - Make sure a correct vmware create_vm config object is returned.
   """
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
    assert res.guestId == args.get('guest-id')


def test_list_vms_by_tag(monkeypatch):
    """
       Given:
           - Tag name and Category.

       When:
           - Running a list vms by tag.

       Then:
           - Make sure a correct vm list is returned.
   """
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
    """
       Given:
           - Create vm arguments.

       When:
           - Running a create-vm command

       Then:
           - Make sure a vm is created and the correct arguments are returned.
   """
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'create_vm_config_creator', lambda host, args: {})
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: Folder())
    monkeypatch.setattr(Folder, 'CreateVM_Task', lambda this, config, pool, host: Task())

    res = VMware.create_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool'})

    data = res.get('Contents')
    assert data.get('Name') == 'test_name'
    assert not data.get('Deleted')
    assert 'Virtual Machine' in res.get('HumanReadable')


def test_get_vms(monkeypatch):
    """
       Given:
           -

       When:
           - Running a get-vms command.

       Then:
           - Make sure a correct list of vms are returned .
   """
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
        assert not data[i].get('Deleted')
    assert 'Virtual Machines' in res.get('HumanReadable')


def test_clone_vm(monkeypatch):
    """
       Given:
           - Clone vm arguments.

       When:
           - Running a clone-vm command

       Then:
           - Make sure the correct results are returned.
   """
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
    assert not data.get('Deleted')
    assert 'Virtual Machine' in res.get('HumanReadable')


def test_relocate_vm(monkeypatch):
    """
       Given:
           - Relocate vm arguments.

       When:
           - Running a relocate-vm command

       Then:
           - Make sure the correct results are returned.
   """
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
    """
       Given:
           - Delete vm UUID.

       When:
           - Running a delete-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM("poweredOff"))
    monkeypatch.setattr(VM, 'Destroy_Task', lambda this: Task())

    res = VMware.delete_vm(si, {'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was deleted successfully.'
    assert {'UUID': '12345', 'Deleted': True} in res.get('EntryContext').values()


def test_register_vm(monkeypatch):
    """
       Given:
           - Register vm arguments.

       When:
           - Running a register-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(si, 'RetrieveContent', lambda: {})
    monkeypatch.setattr(vim, 'VirtualMachineRelocateSpec', lambda: VirtualMachineRelocateSpec())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VMware, 'search_for_obj', lambda content, type_obj, obj: Folder())
    monkeypatch.setattr(Folder, 'RegisterVM_Task', lambda this, path, name, asTemplate, pool, host: Task())

    res = VMware.register_vm(si, {'folder': 'test_folder', 'host': 'test_host', 'pool': 'test_pool', 'path': None,
                                  'as_template': False})
    assert res.get('HumanReadable') == 'Virtual Machine was registered successfully.'


def test_unregister_vm(monkeypatch):
    """
       Given:
           - VM UUID to unregister.

       When:
           - Running a unregister-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'UnregisterVM', lambda this: None)

    res = VMware.unregister_vm(si, {'uuid': '12345'})
    assert res.get('HumanReadable') == 'Virtual Machine was unregistered successfully.'


def test_power_on(monkeypatch):
    """
       Given:
           - VM UUID to power on.

       When:
           - Running a poweron-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOff'))
    monkeypatch.setattr(VM, 'PowerOn', lambda this: Task())

    res = VMware.power_on(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'poweredOn'
    assert res.get('HumanReadable') == 'Virtual Machine was powered on successfully.'


def test_power_off(monkeypatch):
    """
       Given:
           - VM UUID to power off.

       When:
           - Running a poweroff-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOn'))
    monkeypatch.setattr(VM, 'PowerOff', lambda this: Task())

    res = VMware.power_off(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'poweredOff'
    assert res.get('HumanReadable') == 'Virtual Machine was powered off successfully.'


def test_suspend(monkeypatch):
    """
       Given:
           - VM UUID to suspend.

       When:
           - Running a suspend-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM('powerOn'))
    monkeypatch.setattr(VM, 'Suspend', lambda this: Task())

    res = VMware.suspend(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'suspended'
    assert res.get('HumanReadable') == 'Virtual Machine was suspended successfully.'


def test_hard_reboot(monkeypatch):
    """
       Given:
           - VM UUID to hard reboot.

       When:
           - Running a hard-reboot-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'ResetVM_Task', lambda this: Task())
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)

    res = VMware.hard_reboot(si, {'uuid': '12345'})

    assert res.get('EntryContext').values()[0].get('State') == 'HardRebooted'
    assert res.get('HumanReadable') == 'Virtual Machine was rebooted successfully.'


def test_soft_reboot(monkeypatch):
    """
       Given:
           - VM UUID to soft reboot.

       When:
           - Running a sot-reboot-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'RebootGuest', lambda this: None)

    res = VMware.soft_reboot(si, {'uuid': '12345'})

    assert res == 'A request to reboot the guest has been sent.'


@pytest.mark.parametrize('args', PARAMS_CREATE_SNAPSHOT)
def test_create_snapshot(monkeypatch, args):
    """
       Given:
           - VM UUID to create snapshot for.

       When:
           - Running a create-snapshot command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(VM, 'CreateSnapshot', lambda this, name, description, memory, quiesce: Task())
    monkeypatch.setattr(pyVim.task, 'WaitForTask', lambda task: None)

    res = VMware.create_snapshot(si, args)

    assert 'Snapshot 12345' in res


@pytest.mark.parametrize('snapshots, snapname, res', PARAMS_GET_SNAPSHOTS)
def test_get_snapshots(monkeypatch, snapshots, snapname, res):
    """
       Given:
           - VM arguments to get snapshots for.

       When:
           - Running a get-snapshots-vm command

       Then:
           - Make sure the correct results are returned.
   """
    result = VMware.get_snapshots(snapshots, snapname)
    if len(result) > 0:
        assert result[0].name == res[0].name
        assert len(result[0].childSnapshotList) == len(res[0].childSnapshotList)
    else:
        assert len(res) == 0


@pytest.mark.parametrize('args, event_list, res_len', PARAMS_GET_EVENTS)
def test_get_events(monkeypatch, args, event_list, res_len):
    """
       Given:
           - Get events arguments.

       When:
           - Running a get-events command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(si, 'RetrieveServiceContent', lambda: Content())
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    monkeypatch.setattr(vim.event.EventFilterSpec.ByEntity, '__init__', lambda this, entity, recursion: None)
    monkeypatch.setattr(EventManager, 'QueryEvents', lambda this, filter_spec: create_events(event_list))

    res = VMware.get_events(si, args)

    assert len(res.get('Contents')) == res_len
    assert 'VM test_vm_name Events' in res.get('HumanReadable')


def test_change_nic_state(monkeypatch):
    """
       Given:
           - VM UUID to change nic for.

       When:
           - Running a change-nic-vm command

       Then:
           - Make sure the correct results are returned.
   """
    si = Si()
    monkeypatch.setattr(VMware, 'get_vm', lambda v_client, uuid: VM())
    # monkeypatch.setattr(builtins, 'isinstance', lambda dev, dev_type: True)
    monkeypatch.setattr(VMware, 'wait_for_tasks', lambda si_obj, tasks: None)
    monkeypatch.setattr(VM, 'ReconfigVM_Task', lambda this, spec: Task())

    res = VMware.change_nic_state(si, {'vm-uuid': '1234', 'nic-state': 'connect', 'nic-number': '123'})

    assert res.get('Contents').values()[0].get('UUID') == '1234'
    assert res.get('Contents').values()[0].get('NICState') == 'connected'
    assert 'Virtual Machine\'s NIC was connected successfully' in res.get('HumanReadable')
